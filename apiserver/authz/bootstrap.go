package authz

import (
	"context"
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
)

// Default node RBAC. A node-agent authenticates with the group system:nodes and a
// CN equal to its node name; these objects let it register its own Node and read
// the desired Application set out of the box. Writes to Node are further confined
// to the node's own object by admission, so the create/update grant here cannot
// touch another node.
const (
	NodeRoleName    = "system:node"
	NodeBindingName = "system:node"
	nodesGroup      = "system:nodes"
)

func nodeRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{Name: NodeRoleName},
		Spec: rbacv1.RoleSpec{Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{corev1.GroupName}, Resources: []string{"nodes"}, Verbs: []string{"create", "get", "update", "patch"}},
			{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications", "persistentvolumes"}, Verbs: []string{"get", "list", "watch"}},
		}},
	}
}

func nodeBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: NodeBindingName},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "Group", Name: nodesGroup}},
			RoleRef:  rbacv1.RoleRef{Kind: "Role", Name: NodeRoleName},
		},
	}
}

// SeedDefaults reconciles the default node RBAC on every controller startup,
// matching how kube-apiserver reconciles its own default roles. The node Role is
// upserted — created if absent, otherwise updated to the current default rules —
// so a permission added to the default across an upgrade reaches a cluster that was
// first seeded by an older version (an operator's ad-hoc edit to this
// system-managed Role is reverted, which is intended). The RoleBinding is only
// created if absent, so a binding an operator deletes to lock nodes out is
// recreated, while extra subjects an operator adds are preserved.
func SeedDefaults(ctx context.Context, store storage.Storage) error {
	if err := upsert(ctx, store, nodeRole()); err != nil {
		return err
	}
	if _, err := store.Create(ctx, nodeBinding()); err != nil && !errors.Is(err, storage.ErrAlreadyExists) {
		return err
	}
	return nil
}

// upsert updates obj if it exists, else creates it (Update assigns a fresh
// resourceVersion and requires no prior read).
func upsert(ctx context.Context, store storage.Storage, obj types.Object) error {
	_, err := store.Update(ctx, obj)
	if errors.Is(err, storage.ErrNotFound) {
		_, err = store.Create(ctx, obj)
	}
	return err
}
