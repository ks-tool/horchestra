package admission

import (
	"context"
	"slices"
	"strings"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// nodePolicy keeps the two halves of a Node's placement labels apart: spec.labels is what an
// operator says the machine is FOR, status.labels is what the control plane derived from what
// the machine reported. A spec entry under the reserved domain would shadow a derived one at
// every lookup, which is a way to label an amd64 box as arm64 — or to move a node into a
// topology domain it is not in — through a field nothing else validates.
//
// Refusing is cheaper than resolving. Any precedence rule leaves both keys stored and the
// question "which won" answerable only by reading the code; refusing means a Node carries one
// value per key and an operator finds out at the write, naming the key.
type nodePolicy struct{}

func (nodePolicy) Admit(context.Context, *Attributes) error { return nil }

func (nodePolicy) Validate(_ context.Context, a *Attributes) error {
	if a.Operation == Delete || a.IsSubresource() {
		return nil
	}
	node, ok := a.Object.(*corev1.Node)
	if !ok {
		return nil
	}
	var reserved []string
	for k := range node.Labels {
		if strings.HasPrefix(k, corev1.LabelDomain) {
			reserved = append(reserved, k)
		}
	}
	if len(reserved) == 0 {
		return nil
	}
	slices.Sort(reserved) // map order would make the message differ run to run
	return Forbidden("spec.labels: %s — the %s domain holds the labels the control plane derives from the node's own report (status.labels); label it with a key of your own",
		strings.Join(reserved, ", "), corev1.LabelDomain)
}
