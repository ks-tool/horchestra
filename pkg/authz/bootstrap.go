package authz

import (
	"context"
	"encoding/json"
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/storage"
)

// Default node RBAC. A node-agent authenticates with the group system:nodes and
// a CN equal to its node name; these objects let it register its own Node and
// read the desired Application set out of the box. Writes to Node are further
// confined to the node's own object by the NodeRestriction admission plugin, so
// the create/update grant here cannot touch another node.
const (
	NodeRoleName    = "system:node"
	NodeBindingName = "system:node"
	nodesGroup      = "system:nodes"
)

func nodeRole() *v1.Role {
	return &v1.Role{
		TypeMeta:   v1.RoleResource.TypeMeta(),
		ObjectMeta: metav1.ObjectMeta{Name: NodeRoleName},
		Spec: v1.RoleSpec{Rules: []v1.PolicyRule{
			{APIGroups: []string{v1.GroupName}, Resources: []string{"nodes"}, Verbs: []string{"create", "get", "update", "patch"}},
			{APIGroups: []string{v1.GroupName}, Resources: []string{"applications", "persistentvolumes"}, Verbs: []string{"get", "list", "watch"}},
		}},
	}
}

func nodeBinding() *v1.RoleBinding {
	return &v1.RoleBinding{
		TypeMeta:   v1.RoleBindingResource.TypeMeta(),
		ObjectMeta: metav1.ObjectMeta{Name: NodeBindingName},
		Spec: v1.RoleBindingSpec{
			Subjects: []v1.Subject{{Kind: "Group", Name: nodesGroup}},
			RoleRef:  v1.RoleRef{Kind: "Role", Name: NodeRoleName},
		},
	}
}

// SeedDefaults reconciles the default node RBAC on every controller startup,
// matching how kube-apiserver reconciles its own default roles. The node Role is
// upserted — created if absent, otherwise updated to the current default rules —
// so a permission added to the default across an upgrade reaches a cluster that
// was first seeded by an older version (an operator's ad-hoc edit to this
// system-managed Role is reverted, which is intended). The RoleBinding is only
// created if absent, so a binding an operator deletes to lock nodes out is
// recreated, while extra subjects an operator adds are preserved.
func SeedDefaults(ctx context.Context, store storage.Storage) error {
	role, err := toUnstructured(nodeRole())
	if err != nil {
		return err
	}
	if err := upsert(ctx, store, v1.RoleResource.GVK, role); err != nil {
		return err
	}
	binding, err := toUnstructured(nodeBinding())
	if err != nil {
		return err
	}
	if _, err := store.Create(ctx, v1.RoleBindingResource.GVK, binding); err != nil && !errors.Is(err, storage.ErrAlreadyExists) {
		return err
	}
	return nil
}

// upsert updates obj if it exists, else creates it (bolt's Update assigns a fresh
// resourceVersion and requires no prior read).
func upsert(ctx context.Context, store storage.Storage, gvk schema.GroupVersionKind, obj *unstructured.Unstructured) error {
	_, err := store.Update(ctx, gvk, obj)
	if errors.Is(err, storage.ErrNotFound) {
		_, err = store.Create(ctx, gvk, obj)
	}
	return err
}

func toUnstructured(obj any) (*unstructured.Unstructured, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return u, nil
}
