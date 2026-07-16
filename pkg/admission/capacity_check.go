package admission

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "ks-tool.dev/horchestra/api/v1"
)

// Lister reads objects the admission chain needs beyond the one under review.
// storage.Storage satisfies it, so capacityCheck sees the live Applications and
// Nodes without depending on the whole storage surface.
type Lister interface {
	List(ctx context.Context, gvk schema.GroupVersionKind) (*unstructured.UnstructuredList, error)
}

// capacityCheck refuses an Application whose requests would push its target
// node's total application requests past that node's capacity. Each application
// is pinned to one node (spec.node), so the constraint is per-node: the sum of
// the effective requests of the applications on spec.node must fit within that
// node's reported capacity for each of CPU and memory.
type capacityCheck struct{ lister Lister }

func (capacityCheck) Admit(context.Context, *Attributes) error { return nil }

func (c capacityCheck) Validate(ctx context.Context, a *Attributes) error {
	if c.lister == nil || a.Operation == Delete {
		return nil
	}
	app, ok := a.Object.(*v1.Application)
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
func (c capacityCheck) totalRequestsOnNode(ctx context.Context, app *v1.Application) (v1.ResourceAmounts, error) {
	list, err := c.lister.List(ctx, v1.ApplicationResource.GVK)
	if err != nil {
		return v1.ResourceAmounts{}, err
	}
	total := app.Spec.Resources.EffectiveRequests()
	for i := range list.Items {
		obj, err := v1.Decode(v1.ApplicationResource.GVK, &list.Items[i])
		if err != nil {
			continue
		}
		other, ok := obj.(*v1.Application)
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
func (c capacityCheck) nodeCapacity(ctx context.Context, name string) (v1.ResourceAmounts, error) {
	list, err := c.lister.List(ctx, v1.NodeResource.GVK)
	if err != nil {
		return v1.ResourceAmounts{}, err
	}
	for i := range list.Items {
		obj, err := v1.Decode(v1.NodeResource.GVK, &list.Items[i])
		if err != nil {
			continue
		}
		if node, ok := obj.(*v1.Node); ok && node.Name == name {
			return node.Status.Capacity, nil
		}
	}
	return v1.ResourceAmounts{}, nil
}

// exceeds reports, per resource, where total is over a positive capacity. A zero
// capacity means that resource is unconstrained and is skipped.
func exceeds(total, capacity v1.ResourceAmounts) []string {
	var over []string
	if !capacity.CPU.IsZero() && total.CPU.Cmp(capacity.CPU) > 0 {
		over = append(over, fmt.Sprintf("cpu %s > %s", total.CPU.String(), capacity.CPU.String()))
	}
	if !capacity.Memory.IsZero() && total.Memory.Cmp(capacity.Memory) > 0 {
		over = append(over, fmt.Sprintf("memory %s > %s", total.Memory.String(), capacity.Memory.String()))
	}
	return over
}
