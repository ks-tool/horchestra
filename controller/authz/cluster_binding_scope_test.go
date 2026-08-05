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

// clusterBindingRef is clusterBinding with an explicit roleRef Kind, to cover a binding whose
// roleRef the Casbin projection skips (it emits rules only for Kind "ClusterRole").
func clusterBindingRef(name, user, kind, roleName string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "ClusterRoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: user}},
			RoleRef:  rbacv1.RoleRef{Kind: kind, Name: roleName},
		},
	}
}

// TestClusterBindingSeesAllRequiresRead: seesAll — the flag that hands a caller the whole
// namespace inventory and, through the pods alias, every tenant's workloads — must follow from
// the permissions a ClusterRoleBinding actually confers, never from its mere existence. A
// binding whose roleRef dangles, whose Kind is not ClusterRole, or whose ClusterRole grants no
// read must leave the caller scoped to their own RoleBindings.
func TestClusterBindingSeesAllRequiresRead(t *testing.T) {
	readRule := rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"get", "list"}}
	writeOnlyRule := rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"create", "delete"}}
	wildcardRule := rbacv1.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}

	cases := []struct {
		name        string
		clusterRole *rbacv1.ClusterRole // nil = do not create it (dangling roleRef)
		refKind     string
		refName     string
		wantSeesAll bool
	}{
		{
			name:        "cluster-wide read grants seesAll",
			clusterRole: clusterRole("fleet-viewer", readRule),
			refKind:     "ClusterRole", refName: "fleet-viewer",
			wantSeesAll: true,
		},
		{
			name:        "wildcard rule grants seesAll",
			clusterRole: clusterRole("fleet-admin", wildcardRule),
			refKind:     "ClusterRole", refName: "fleet-admin",
			wantSeesAll: true,
		},
		{
			name:        "dangling roleRef grants nothing",
			clusterRole: nil,
			refKind:     "ClusterRole", refName: "does-not-exist",
			wantSeesAll: false,
		},
		{
			name:        "write-only ClusterRole grants nothing",
			clusterRole: clusterRole("deployer", writeOnlyRule),
			refKind:     "ClusterRole", refName: "deployer",
			wantSeesAll: false,
		},
		{
			name:        "roleRef Kind Role is not a cluster grant",
			clusterRole: clusterRole("fleet-viewer", readRule),
			refKind:     "Role", refName: "fleet-viewer",
			wantSeesAll: false,
		},
		{
			name:        "ClusterRole with no rules grants nothing",
			clusterRole: clusterRole("empty"),
			refKind:     "ClusterRole", refName: "empty",
			wantSeesAll: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.New()
			defer func() { _ = store.Close() }()
			ctx := context.Background()

			if tc.clusterRole != nil {
				mustPut(t, store, tc.clusterRole)
			}
			mustPut(t, store, clusterBindingRef("dave-cluster", "dave", tc.refKind, tc.refName))
			// A RoleBinding in one namespace, so a denied seesAll still leaves the real scope.
			mustPut(t, store, binding("team-a", "dave-local", "dave", "viewer"))

			dave := &authn.Identity{Name: "dave"}
			accessible, seesAll, err := AccessibleNamespaces(ctx, store, testScheme(), dave)
			if err != nil {
				t.Fatalf("accessible: %v", err)
			}
			if seesAll != tc.wantSeesAll {
				t.Fatalf("seesAll = %v, want %v", seesAll, tc.wantSeesAll)
			}
			if seesAll {
				return
			}
			if !accessible["team-a"] || len(accessible) != 1 {
				t.Fatalf("accessible = %v, want exactly {team-a} from the RoleBinding", accessible)
			}
		})
	}
}

// TestClusterBindingForAnotherSubjectIsIgnored: a qualifying ClusterRoleBinding that does not
// name the caller must not widen the caller's scope.
func TestClusterBindingForAnotherSubjectIsIgnored(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	readRule := rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"list"}}
	mustPut(t, store, clusterRole("fleet-viewer", readRule))
	mustPut(t, store, clusterBindingRef("carol-cluster", "carol", "ClusterRole", "fleet-viewer"))
	mustPut(t, store, binding("team-a", "dave-local", "dave", "viewer"))

	_, seesAll, err := AccessibleNamespaces(ctx, store, testScheme(), &authn.Identity{Name: "dave"})
	if err != nil {
		t.Fatalf("accessible: %v", err)
	}
	if seesAll {
		t.Fatal("dave must not inherit carol's cluster-wide visibility")
	}
}
