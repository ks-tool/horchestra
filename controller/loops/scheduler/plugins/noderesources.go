package plugins

import (
	"context"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// NodeResourcesFitName is the plugin's registry name.
const NodeResourcesFitName = "NodeResourcesFit"

// NodeResourcesFit serves three points for CPU/memory: Filter (does the app's request
// still fit the node's capacity given what is already requested there), Score (rank by
// resulting dominant-resource utilization — spread prefers the least-loaded node,
// binpack the most-loaded), and Reserve (debit the node so two placements in one pass
// don't overcommit).
type NodeResourcesFit struct {
	handle  framework.Handle
	binpack bool
}

// NewNodeResourcesFit builds the plugin; binpack packs tightly (else it spreads).
func NewNodeResourcesFit(binpack bool, h framework.Handle) *NodeResourcesFit {
	return &NodeResourcesFit{handle: h, binpack: binpack}
}

func (*NodeResourcesFit) Name() string { return NodeResourcesFitName }

func (p *NodeResourcesFit) Filter(_ context.Context, _ *framework.CycleState, app *corev1.Application, node *framework.NodeInfo) *framework.Status {
	after := node.Requested.Add(app.Spec.Resources.EffectiveRequests())
	// unconstrainedZero=false: a zero-capacity node fits nothing here (the strict
	// scheduler polarity), the opposite of capacityCheck's admission backstop, over the
	// same ResourceAmounts.Exceeds — so predicate and backstop never disagree.
	if over := after.Exceeds(node.Node.Status.Capacity, false); len(over) > 0 {
		return framework.NewStatus(framework.Unschedulable, "insufficient cpu/memory")
	}
	return nil
}

func (p *NodeResourcesFit) Score(_ context.Context, _ *framework.CycleState, app *corev1.Application, node *framework.NodeInfo) (int64, *framework.Status) {
	used := node.Requested.Add(app.Spec.Resources.EffectiveRequests())
	util := dominant(node.Node.Status.Capacity, used)
	if p.binpack {
		return int64(util * float64(framework.MaxNodeScore)), nil
	}
	return int64((1 - util) * float64(framework.MaxNodeScore)), nil
}

func (p *NodeResourcesFit) Reserve(_ context.Context, _ *framework.CycleState, app *corev1.Application, node string) *framework.Status {
	if ni, ok := p.handle.Snapshot().Get(node); ok {
		ni.Reserve(app.Spec.Resources.EffectiveRequests())
	}
	return nil
}

func (p *NodeResourcesFit) Unreserve(_ context.Context, _ *framework.CycleState, app *corev1.Application, node string) {
	if ni, ok := p.handle.Snapshot().Get(node); ok {
		ni.Unreserve(app.Spec.Resources.EffectiveRequests())
	}
}

// dominant is a node's dominant-resource utilization — the larger of its cpu and memory
// used/capacity ratios. Capacity is non-zero in both dimensions here (NodeSchedulable
// filtered zero-capacity nodes out before scoring).
func dominant(capacity, used corev1.ResourceAmounts) float64 {
	cpu := float64(used.CPU.MilliValue()) / float64(capacity.CPU.MilliValue())
	mem := float64(used.Memory.Value()) / float64(capacity.Memory.Value())
	if cpu > mem {
		return cpu
	}
	return mem
}
