package plugins

import (
	"context"
	"slices"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// RuntimeClassName is the plugin's registry name.
const RuntimeClassName = "RuntimeClass"

// RuntimeClass filters out nodes that do not advertise the runtime an Application requests
// via spec.runtimeClassName. An empty runtimeClassName matches every node (the node's
// default runtime); a named class fits only nodes whose status.runtimes contains it, so an
// app requesting a class no node supports stays pending rather than failing at start.
type RuntimeClass struct{}

// NewRuntimeClass builds the plugin. It needs no Handle — the decision is a pure function
// of the app's requested class and the node's advertised runtimes.
func NewRuntimeClass() *RuntimeClass { return &RuntimeClass{} }

func (*RuntimeClass) Name() string { return RuntimeClassName }

func (*RuntimeClass) Filter(_ context.Context, _ *framework.CycleState, app *corev1.Application, node *framework.NodeInfo) *framework.Status {
	class := app.Spec.RuntimeClassName
	if class == "" {
		return nil // default runtime — every node qualifies
	}
	if slices.Contains(node.Node.Status.Runtimes, class) {
		return nil
	}
	return framework.NewStatus(framework.Unschedulable, "node does not advertise runtime class "+class)
}
