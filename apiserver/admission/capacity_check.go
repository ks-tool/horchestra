package admission

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// capacityCheck refuses an Application whose requests would push its target
// node's total application requests past that node's capacity. Each application
// is pinned to one node (spec.nodeName), so the constraint is per-node: the sum
// of the effective requests of the applications on spec.nodeName must fit within
// that node's reported capacity for each of CPU and memory.
type capacityCheck struct{ lister Lister }

func (capacityCheck) Admit(context.Context, *Attributes) error { return nil }

func (c capacityCheck) Validate(ctx context.Context, a *Attributes) error {
	if c.lister == nil || a.Operation == Delete {
		return nil
	}
	app, ok := a.Object.(*corev1.Application)
	if !ok {
		return nil // not an Application — nothing to account
	}
	if app.Spec.Resources.EffectiveRequests().IsZero() {
		return nil // no requests declared — nothing to account
	}
	if len(app.Spec.NodeName) == 0 {
		return nil // node is required by the input schema; nothing to attribute otherwise
	}

	total, err := c.totalRequestsOnNode(ctx, app)
	if err != nil {
		return err
	}
	capacity, err := c.nodeCapacity(ctx, app.Spec.NodeName)
	if err != nil {
		return err
	}
	if over := exceeds(total, capacity); len(over) > 0 {
		return Forbidden("application %q rejected: requests exceed capacity of node %q (%s)",
			app.Name, app.Spec.NodeName, strings.Join(over, ", "))
	}
	return nil
}

// totalRequestsOnNode sums the effective requests of every application pinned to
// the same node as app, substituting app's new requests for its stored copy (so
// an update is measured against its replacement, and a create adds on top of the
// set already on that node).
func (c capacityCheck) totalRequestsOnNode(ctx context.Context, app *corev1.Application) (corev1.ResourceAmounts, error) {
	list, err := c.lister.List(ctx, resourceMeta("Application"), metav1.ListOptions{})
	if err != nil {
		return corev1.ResourceAmounts{}, err
	}
	total := app.Spec.Resources.EffectiveRequests()
	for _, obj := range list {
		other, ok := obj.(*corev1.Application)
		if !ok || other.Name == app.Name {
			continue // exclude the stored copy of the app under review
		}
		if other.Spec.NodeName != app.Spec.NodeName {
			continue // only applications on the same node compete for its capacity
		}
		total = total.Add(other.Spec.Resources.EffectiveRequests())
	}
	return total, nil
}

// nodeCapacity is the reported capacity of the named node. A node that has not
// reported status yet yields a zero capacity, meaning "unconstrained" — an
// application pinned to it is admitted and waits, rather than being blocked. In
// the default chain nodeExists has already rejected a node that does not exist at
// all, so here a zero capacity means "registered but not yet reported".
func (c capacityCheck) nodeCapacity(ctx context.Context, name string) (corev1.ResourceAmounts, error) {
	list, err := c.lister.List(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		return corev1.ResourceAmounts{}, err
	}
	for _, obj := range list {
		if node, ok := obj.(*corev1.Node); ok && node.Name == name {
			return node.Status.Capacity, nil
		}
	}
	return corev1.ResourceAmounts{}, nil
}

// exceeds reports, per resource, where total is over a positive capacity. A zero
// capacity means that resource is unconstrained and is skipped.
func exceeds(total, capacity corev1.ResourceAmounts) []string {
	var over []string
	if !capacity.CPU.IsZero() && total.CPU.Cmp(capacity.CPU) > 0 {
		over = append(over, fmt.Sprintf("cpu %s > %s", total.CPU.String(), capacity.CPU.String()))
	}
	if !capacity.Memory.IsZero() && total.Memory.Cmp(capacity.Memory) > 0 {
		over = append(over, fmt.Sprintf("memory %s > %s", total.Memory.String(), capacity.Memory.String()))
	}
	return over
}
