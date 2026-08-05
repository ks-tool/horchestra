package plugins

import (
	"context"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// DefaultBinderName is the plugin's registry name.
const DefaultBinderName = "DefaultBinder"

// DefaultBinder binds an Application to its chosen node by writing spec.nodeName
// through the control plane (where admission re-validates the placement).
type DefaultBinder struct {
	handle framework.Handle
}

// NewDefaultBinder builds the plugin.
func NewDefaultBinder(h framework.Handle) *DefaultBinder { return &DefaultBinder{handle: h} }

func (*DefaultBinder) Name() string { return DefaultBinderName }

func (p *DefaultBinder) Bind(ctx context.Context, _ *framework.CycleState, app *corev1.Application, node string) *framework.Status {
	if err := p.handle.BindApp(ctx, app.Namespace, app.Name, node); err != nil {
		return framework.AsError(err)
	}
	return nil
}
