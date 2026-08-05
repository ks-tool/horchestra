package plugins

import (
	"context"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// RoutedNetworkName is the plugin's registry name.
const RoutedNetworkName = "RoutedNetwork"

// RoutedNetwork keeps a workload that asked for its own network off the nodes that cannot give it
// one.
//
// Without this the placement is made on capacity alone and the refusal happens at the far end of
// the system: the node accepts the workload, the agent finds no helper, and the start fails with a
// message an operator has to correlate back to a scheduling decision made somewhere else. A filter
// makes the same fact answerable where the decision is: such a workload stays Pending, and the
// reason names what is missing.
//
// A host-network workload matches every node, which is every workload on a fleet that runs no
// helper at all — the filter is silent there by construction rather than by a flag.
type RoutedNetwork struct{}

// NewRoutedNetwork builds the plugin. No Handle: the decision is a pure function of what the app
// asked for and what the node advertises.
func NewRoutedNetwork() *RoutedNetwork { return &RoutedNetwork{} }

func (*RoutedNetwork) Name() string { return RoutedNetworkName }

func (*RoutedNetwork) Filter(_ context.Context, _ *framework.CycleState, app *corev1.Application, node *framework.NodeInfo) *framework.Status {
	if app.OnHostNetwork() {
		return nil
	}
	if node.Node.Status.RoutedNetwork {
		return nil
	}
	return framework.NewStatus(framework.Unschedulable,
		"node has no network helper, so it cannot give a workload a network of its own")
}
