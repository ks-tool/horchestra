package admission

import (
	"context"

	"k8s.io/apimachinery/pkg/api/meta"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/apiserver/authn"
)

// NodeGroup is the group carried by a node-agent's client certificate. An
// identity in this group is treated as a node (its certificate CN is the node
// name) and is confined by nodeRestriction.
const NodeGroup = "system:nodes"

// nodeRestriction confines a node identity (group system:nodes) to mutating the
// single Node whose name equals the identity name — its certificate CN — the
// same way kube-apiserver's NodeRestriction scopes a kubelet to its own Node.
// A node may not create, update or delete any other resource, nor another
// node's Node object. It is a no-op for every non-node identity (admins, users,
// unauthenticated internal calls), so the restriction never widens their reach.
type nodeRestriction struct{}

func (nodeRestriction) Admit(context.Context, *Attributes) error { return nil }

func (nodeRestriction) Validate(ctx context.Context, a *Attributes) error {
	id := authn.FromContext(ctx)
	if id == nil || !hasGroup(id.Groups, NodeGroup) {
		return nil
	}
	if a.GVK.Group != corev1.GroupName || a.GVK.Kind != "Node" {
		return Forbidden("node %q may not %s %s: nodes may write only their own Node",
			id.Name, verb(a.Operation), a.GVK.Kind)
	}
	acc, err := meta.Accessor(a.Object)
	if err != nil {
		return err
	}
	if name := acc.GetName(); name != id.Name {
		return Forbidden("node %q may not %s Node %q: only its own Node",
			id.Name, verb(a.Operation), name)
	}
	return nil
}

func hasGroup(groups []string, want string) bool {
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}

func verb(op Operation) string {
	switch op {
	case Create:
		return "create"
	case Update:
		return "update"
	case Delete:
		return "delete"
	default:
		return string(op)
	}
}
