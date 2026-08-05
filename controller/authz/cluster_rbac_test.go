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

func clusterRole(name string, rules ...rbacv1.PolicyRule) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "ClusterRole"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       rbacv1.RoleSpec{Rules: rules},
	}
}

func clusterBinding(name, user, clusterRoleName string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "ClusterRoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: user}},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: clusterRoleName},
		},
	}
}

func bindingToClusterRole(namespace, name, user, clusterRoleName string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: user}},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: clusterRoleName},
		},
	}
}

// TestClusterRoleBinding: a ClusterRoleBinding grants its ClusterRole's rules cluster-wide —
// in every namespace and for cluster-scoped resources — under the compiled Casbin engine.
func TestClusterRoleBinding(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	appReader := rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"get", "list"}}
	nodeReader := rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"nodes"}, Verbs: []string{"list"}}
	mustPut(t, store, clusterRole("fleet-viewer", appReader, nodeReader))
	mustPut(t, store, clusterBinding("carol-fleet", "carol", "fleet-viewer"))

	cb := mustCasbin(t, ctx, store)
	carol := &authn.Identity{Name: "carol"}
	nodes := Attributes{User: carol, Verb: "list", Group: corev1.GroupName, Resource: "nodes", ResourceRequest: true}

	cases := []struct {
		name string
		at   Attributes
		want bool
	}{
		{"apps in team-a", nsApp(carol, "list", "team-a"), true},
		{"apps in team-b", nsApp(carol, "get", "team-b"), true},
		{"cluster-scoped nodes", nodes, true},
		{"no write (not granted)", nsApp(carol, "create", "team-a"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := cb.Authorize(ctx, tc.at)
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("authorize = %v, want %v", ok, tc.want)
			}
		})
	}

	// A ClusterRoleBinding subject sees every namespace in the self-service listing.
	if _, seesAll, err := AccessibleNamespaces(ctx, store, testScheme(), carol); err != nil || !seesAll {
		t.Fatalf("ClusterRoleBinding subject must see all namespaces (seesAll=%v, err=%v)", seesAll, err)
	}
}

// TestRoleBindingToClusterRole: a namespaced RoleBinding may reference a ClusterRole,
// granting its rules only within that binding's namespace.
func TestRoleBindingToClusterRole(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	appReader := rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"list"}}
	mustPut(t, store, clusterRole("viewer", appReader))
	mustPut(t, store, bindingToClusterRole("team-a", "dave-view", "dave", "viewer"))

	cb := mustCasbin(t, ctx, store)
	dave := &authn.Identity{Name: "dave"}

	if ok, err := cb.Authorize(ctx, nsApp(dave, "list", "team-a")); err != nil || !ok {
		t.Fatalf("RoleBinding→ClusterRole must grant in-namespace: ok=%v err=%v", ok, err)
	}
	if ok, _ := cb.Authorize(ctx, nsApp(dave, "list", "team-b")); ok {
		t.Fatal("RoleBinding→ClusterRole must NOT grant in another namespace")
	}
}
