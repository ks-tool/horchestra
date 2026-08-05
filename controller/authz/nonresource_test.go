package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/internal/memory"
)

// scrapeRole is the ClusterRole a collector needs now that /metrics is off the allowlist.
func scrapeRole(urls ...string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "ClusterRole"},
		ObjectMeta: metav1.ObjectMeta{Name: "scraper"},
		Spec:       rbacv1.RoleSpec{Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, NonResourceURLs: urls}}},
	}
}

func bindCluster(subject string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "ClusterRoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: "scrape"},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: subject}},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "scraper"},
		},
	}
}

// loadPolicy seeds objs and compiles the policy off them.
func loadPolicy(t *testing.T, objs ...types.Object) *Casbin {
	t.Helper()
	store := memory.New()
	for _, o := range objs {
		mustPut(t, store, o)
	}
	return mustCasbin(t, context.Background(), store)
}

func pathAttr(t *testing.T, method, path string, id *authn.Identity) Attributes {
	t.Helper()
	return AttributesFromRequest(httptest.NewRequest(method, path, nil), id)
}

// TestNonResourceURLGrant: /metrics is no longer on the allowlist, so a scrape is served only
// to a caller a rule names — and the rule is read off the very path that was refused, instead
// of the resource permission the handler used to demand in its place.
func TestNonResourceURLGrant(t *testing.T) {
	prom := &authn.Identity{Name: "prometheus"}
	bob := &authn.Identity{Name: "bob"}
	cb := loadPolicy(t, scrapeRole("/metrics"), bindCluster("prometheus"))
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		method string
		path   string
		id     *authn.Identity
		want   bool
	}{
		{"the named subject scrapes", http.MethodGet, "/metrics", prom, true},
		{"nobody else does", http.MethodGet, "/metrics", bob, false},
		{"the grant is one path, not a prefix", http.MethodGet, "/metrics/debug", prom, false},
		{"and one method: the verb IS the method", http.MethodPost, "/metrics", prom, false},
		{"a path nothing names stays refused", http.MethodGet, "/logs", prom, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := cb.Authorize(ctx, pathAttr(t, tc.method, tc.path, tc.id))
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.want {
				t.Errorf("authorize(%s %s) = %v, want %v", tc.method, tc.path, ok, tc.want)
			}
		})
	}
}

// TestNonResourceURLPrefixWildcard: a trailing "*" matches by prefix and nothing else is a
// pattern, so a grant cannot widen into a subtree nobody wrote down.
func TestNonResourceURLPrefixWildcard(t *testing.T) {
	prom := &authn.Identity{Name: "prometheus"}
	cb := loadPolicy(t, scrapeRole("/openapi/*"), bindCluster("prometheus"))
	ctx := context.Background()

	for path, want := range map[string]bool{
		"/openapi/v3":                    true,
		"/openapi/v3/apis/horchestra.io": true,
		"/openapi":                       false, // the prefix is "/openapi/", so the parent is not in it
		"/metrics":                       false,
	} {
		ok, err := cb.Authorize(ctx, pathAttr(t, http.MethodGet, path, prom))
		if err != nil {
			t.Fatal(err)
		}
		// The allowlist already serves /openapi to everyone, so only the negative case that
		// this grant does not cover is meaningful there; assert the grant itself.
		if got := cb.allowsPath(pathAttr(t, http.MethodGet, path, prom)); got != want {
			t.Errorf("grant covers %s = %v, want %v (authorize=%v)", path, got, want, ok)
		}
	}
}

// TestNonResourceURLsNeedAClusterBinding: a path is not in any namespace, so a namespaced
// RoleBinding naming the same ClusterRole confers its resource rules there and none of its
// paths — otherwise a tenant with rights in its own namespace would read the whole fleet's
// metrics through a ClusterRole it merely referenced.
func TestNonResourceURLsNeedAClusterBinding(t *testing.T) {
	prom := &authn.Identity{Name: "prometheus"}
	nsBinding := &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "scrape"},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "prometheus"}},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "scraper"},
		},
	}
	cb := loadPolicy(t, scrapeRole("/metrics"), nsBinding)

	ok, err := cb.Authorize(context.Background(), pathAttr(t, http.MethodGet, "/metrics", prom))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("a namespaced RoleBinding granted a cluster-wide path")
	}
}

// TestAdminReachesEveryPath: the super-admin group is defined by holding everything, and the
// non-resource half used to be decided before that was consulted — so the one identity that
// cannot be refused an object could be refused a path.
func TestAdminReachesEveryPath(t *testing.T) {
	admin := &authn.Identity{Name: "root", Groups: []string{AdminGroup}}
	cb := loadPolicy(t)

	for _, path := range []string{"/metrics", "/logs", "/nonsense"} {
		ok, err := cb.Authorize(context.Background(), pathAttr(t, http.MethodGet, path, admin))
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("the cluster admin was refused %s", path)
		}
	}
}

// TestNonResourceRequestCarriesItsMethodAsVerb: a path has no operation of its own, so the verb
// is the HTTP method. Without it every non-resource request carried an empty verb and no rule
// could match one.
func TestNonResourceRequestCarriesItsMethodAsVerb(t *testing.T) {
	for method, want := range map[string]string{
		http.MethodGet: "get", http.MethodPost: "post", http.MethodDelete: "delete",
	} {
		if got := pathAttr(t, method, "/metrics", nil).Verb; got != want {
			t.Errorf("verb for %s = %q, want %q", method, got, want)
		}
	}
}
