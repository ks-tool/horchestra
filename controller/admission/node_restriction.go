package admission

import (
	"context"
	"maps"
	"reflect"
	"slices"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/authn"
)

// NodeGroup is the group carried by a node-agent's client certificate. An
// identity in this group is treated as a node (its certificate CN is the node
// name) and is confined by nodeRestriction.
const NodeGroup = "system:nodes"

// nodeRestriction confines a node identity (group system:nodes) to reporting the status
// of the single Node whose name equals the identity name — its certificate CN — the same
// way kube-apiserver's NodeRestriction scopes a kubelet to its own Node, plus a status-only
// tightening: a node may not touch any other resource, another node's Node, nor its own
// Node.spec. Spec carries operator intent a node must not self-grant — Unschedulable
// (cordon), Maintenance, machine-config — so a compromised or buggy node cannot exempt
// itself from drift-reversion or reschedule work away by writing its own spec. It is a
// no-op for every non-node identity and for the credential-less gRPC stream (whose
// heartbeat is separately confined to the status subresource).
type nodeRestriction struct{ lister Lister }

func (nodeRestriction) Admit(context.Context, *Attributes) error { return nil }

func (n nodeRestriction) Validate(ctx context.Context, a *Attributes) error {
	id := authn.FromContext(ctx)
	if id == nil || !slices.Contains(id.Groups, NodeGroup) {
		return nil
	}
	if a.GVK.Group == certv1.GroupName && a.GVK.Kind == "CertificateSigningRequest" {
		// A node's rotation CSR is allowed here — the CSR approval loop's selfnodeclient
		// predicate confines it to a certificate for the node's own CN.
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
	incoming, ok := a.Object.(*corev1.Node)
	if !ok {
		return nil
	}
	// status-only, on create as well as update. A node declares nothing about itself beyond what
	// it observed: not the spec (Unschedulable, Maintenance, machine-config) and not the LABELS,
	// which are the operator's placement intent and live in metadata like every other object's.
	// Allowing either would let a node self-label into a placement pool (tier=secure) it was
	// never granted — the same self-grant the update path refuses.
	if a.Operation == Create {
		if !reflect.DeepEqual(incoming.Spec, corev1.NodeSpec{}) {
			return Forbidden("node %q may not create its own Node with a non-empty spec: nodes report only status", id.Name)
		}
		if len(incoming.Labels) > 0 {
			return Forbidden("node %q may not label its own Node: placement labels are the operator's, "+
				"and the ones derived from a node's own report are computed by the control plane", id.Name)
		}
		return nil
	}
	// An update may not change spec. Without a lister (unit tests) the guard is skipped.
	if a.Operation != Update || n.lister == nil {
		return nil
	}
	stored, err := n.storedNode(ctx, id.Name)
	if err != nil {
		return err
	}
	if stored != nil && !maps.Equal(incoming.Labels, stored.Labels) {
		return Forbidden("node %q may not change its own Node's labels: placement is the operator's to decide", id.Name)
	}
	if stored != nil && !reflect.DeepEqual(incoming.Spec, stored.Spec) {
		return Forbidden("node %q may not update its own Node.spec: nodes report only status", id.Name)
	}
	return nil
}

// storedNode returns the persisted Node named name, or nil if none exists yet.
func (n nodeRestriction) storedNode(ctx context.Context, name string) (*corev1.Node, error) {
	list, err := n.lister.List(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, obj := range list {
		if node, ok := obj.(*corev1.Node); ok && node.Name == name {
			return node, nil
		}
	}
	return nil, nil
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
