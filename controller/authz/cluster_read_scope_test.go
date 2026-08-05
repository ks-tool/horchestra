package authz

import (
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/internal/memory"
)

// TestSeesAllRequiresNamespacedRead: seesAll hands over the whole Namespace inventory and the
// otherwise admin-only unfiltered watch, justified by the subject "already reading some resource
// in every namespace". That premise holds only for a cluster-wide read on a NAMESPACED resource:
// the ordinary fleet-viewer grant (nodes: get,list) reads cluster-scoped objects whose contents
// say nothing about any tenant, so it must leave the caller scoped to its own RoleBindings.
func TestSeesAllRequiresNamespacedRead(t *testing.T) {
	cases := []struct {
		name string
		rule rbacv1.PolicyRule
		want bool
	}{
		{
			name: "cluster-scoped read only",
			rule: rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"nodes"}, Verbs: []string{"get", "list"}},
			want: false,
		},
		{
			name: "namespaced read",
			rule: rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"get", "list"}},
			want: true,
		},
		{
			name: "namespaced subresource read",
			rule: rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications/status"}, Verbs: []string{"get"}},
			want: true,
		},
		{
			name: "wildcard resource",
			rule: rbacv1.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get"}},
			want: true,
		},
		{
			name: "unregistered resource",
			rule: rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"widgets"}, Verbs: []string{"get"}},
			want: false,
		},
		{
			name: "namespaced resource in the wrong group",
			rule: rbacv1.PolicyRule{APIGroups: []string{"other.io"}, Resources: []string{"applications"}, Verbs: []string{"get"}},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := memory.New()
			mustPut(t, store, clusterRole("viewer", tc.rule))
			mustPut(t, store, clusterBindingRef("viewer-bind", "dave", "ClusterRole", "viewer"))

			_, seesAll, err := AccessibleNamespaces(ctx, store, testScheme(), &authn.Identity{Name: "dave"})
			if err != nil {
				t.Fatalf("AccessibleNamespaces: %v", err)
			}
			if seesAll != tc.want {
				t.Fatalf("seesAll = %v, want %v", seesAll, tc.want)
			}
		})
	}
}
