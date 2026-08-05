package authz

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/internal/memory"
)

func TestCasbinAuthorize(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	mustPut(t, store, &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{Name: "app-reader"},
		Spec: rbacv1.RoleSpec{Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"get", "list"}},
		}},
	})
	mustPut(t, store, &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: "alice-reader"},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}},
			RoleRef:  rbacv1.RoleRef{Kind: "Role", Name: "app-reader"},
		},
	})

	cb, err := NewCasbin()
	if err != nil {
		t.Fatalf("new casbin: %v", err)
	}
	if err := cb.LoadFromStore(ctx, store); err != nil {
		t.Fatalf("load: %v", err)
	}

	alice := &authn.Identity{Name: "alice"}
	admin := &authn.Identity{Name: "root", Groups: []string{"system:masters"}}
	bob := &authn.Identity{Name: "bob"}

	cases := []struct {
		name string
		user *authn.Identity
		at   Attributes
		want bool
	}{
		{"alice get application", alice, appAt("get", "app1"), true},
		{"alice list applications", alice, appAt("list", ""), true},
		{"alice delete forbidden", alice, appAt("delete", "app1"), false},
		{"alice nodes forbidden", alice, Attributes{Verb: "get", Group: corev1.GroupName, Resource: "nodes", Name: "n1", ResourceRequest: true}, false},
		{"admin group allows anything", admin, appAt("delete", "app1"), true},
		{"bob denied", bob, appAt("get", "app1"), false},
		// A path addressing no object is judged by the allowlist, not waved through: discovery
		// is served to any authenticated caller, anything else outside the resource tree is not.
		{"discovery is served", bob, Attributes{Verb: "get", Path: "/apis"}, true},
		{"an unlisted non-resource path is refused", bob, Attributes{Verb: "get", Path: "/logs"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := tc.at
			at.User = tc.user
			ok, err := cb.Authorize(ctx, at)
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("authorize = %v, want %v", ok, tc.want)
			}
		})
	}
}

// TestCasbinWildcard: a Role with the "*" wildcard on apiGroups/resources/verbs (Kubernetes
// "all" semantics) authorizes any verb on any resource within the bound namespace.
func TestCasbinWildcard(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	mustPut(t, store, &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{Name: "editor"},
		Spec: rbacv1.RoleSpec{Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
		}},
	})
	mustPut(t, store, &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: "eve-editor"},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "eve"}},
			RoleRef:  rbacv1.RoleRef{Kind: "Role", Name: "editor"},
		},
	})

	cb, err := NewCasbin()
	if err != nil {
		t.Fatalf("new casbin: %v", err)
	}
	if err := cb.LoadFromStore(ctx, store); err != nil {
		t.Fatalf("load: %v", err)
	}
	eve := &authn.Identity{Name: "eve"}
	frank := &authn.Identity{Name: "frank"}

	// Wildcard verbs: every verb on the bound resource passes.
	for _, verb := range []string{"get", "list", "create", "update", "delete"} {
		at := appAt(verb, "app1")
		at.User = eve
		if ok, err := cb.Authorize(ctx, at); err != nil || !ok {
			t.Fatalf("wildcard Role must allow %q on applications: ok=%v err=%v", verb, ok, err)
		}
	}
	// Wildcard apiGroup/resource: a different resource passes too.
	nodes := Attributes{User: eve, Verb: "delete", Group: corev1.GroupName, Resource: "nodes", Name: "n1", ResourceRequest: true}
	if ok, err := cb.Authorize(ctx, nodes); err != nil || !ok {
		t.Fatalf("wildcard Role must allow delete on nodes: ok=%v err=%v", ok, err)
	}
	// An unbound user is still denied.
	at := appAt("get", "app1")
	at.User = frank
	if ok, _ := cb.Authorize(ctx, at); ok {
		t.Fatal("unbound user must be denied under a wildcard Role")
	}
}

func appAt(verb, name string) Attributes {
	return Attributes{Verb: verb, Group: corev1.GroupName, Resource: "applications", Name: name, ResourceRequest: true}
}
