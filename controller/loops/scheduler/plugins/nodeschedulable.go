// Package plugins holds horchestra's built-in scheduler plugins, each serving one or
// more framework extension points: NodeSchedulable and NodeResourcesFit filter and
// score nodes, VolumeBinding provisions and co-schedules storage, and DefaultBinder
// writes the placement. They are registered into a framework.Registry and selected by
// a profile; a deployment can add or replace any of them without touching the engine.
package plugins

import (
	"context"
	"time"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// NodeSchedulableName is the plugin's registry name.
const NodeSchedulableName = "NodeSchedulable"

// NodeSchedulable filters out nodes that cannot take new work: cordoned
// (spec.unschedulable), not self-reported Ready, with a stale heartbeat, or not yet
// reporting capacity in both dimensions (placing there would over-commit blindly).
type NodeSchedulable struct {
	handle  framework.Handle
	timeout time.Duration
}

// NewNodeSchedulable builds the plugin with the node-ready heartbeat timeout.
func NewNodeSchedulable(timeout time.Duration, h framework.Handle) *NodeSchedulable {
	return &NodeSchedulable{handle: h, timeout: timeout}
}

func (*NodeSchedulable) Name() string { return NodeSchedulableName }

func (p *NodeSchedulable) Filter(_ context.Context, _ *framework.CycleState, _ *corev1.Application, node *framework.NodeInfo) *framework.Status {
	n := node.Node
	if n.Spec.Unschedulable {
		return framework.NewStatus(framework.Unschedulable, "node is cordoned")
	}
	if !n.Status.Ready {
		return framework.NewStatus(framework.Unschedulable, "node is not ready")
	}
	if n.Status.Capacity.CPU.IsZero() || n.Status.Capacity.Memory.IsZero() {
		return framework.NewStatus(framework.Unschedulable, "node has not reported capacity")
	}
	hb := n.Status.Heartbeat.Time
	if hb.IsZero() || p.handle.Clock().Sub(hb) > p.timeout {
		return framework.NewStatus(framework.Unschedulable, "node heartbeat is stale")
	}
	return nil
}
