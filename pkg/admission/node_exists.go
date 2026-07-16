package admission

import (
	"context"
	"fmt"

	v1 "ks-tool.dev/horchestra/api/v1"
)

// nodeExists rejects an Application whose spec.node names a Node that does not
// exist. An application is pinned to exactly one node, so a typo or a not-yet-
// registered node would otherwise create an application that silently never runs
// (no agent claims it). This runs regardless of the app's resource requests —
// unlike capacityCheck, which only accounts apps that declare requests.
type nodeExists struct{ lister Lister }

func (nodeExists) Admit(context.Context, *Attributes) error { return nil }

func (c nodeExists) Validate(ctx context.Context, a *Attributes) error {
	if c.lister == nil || a.Operation == Delete {
		return nil
	}
	app, ok := a.Object.(*v1.Application)
	if !ok || len(app.Spec.NodeName) == 0 {
		return nil // not an Application, or node absent (the input schema requires it)
	}
	list, err := c.lister.List(ctx, v1.NodeResource.GVK)
	if err != nil {
		return err
	}
	for i := range list.Items {
		if list.Items[i].GetName() == app.Spec.NodeName {
			return nil
		}
	}
	return fmt.Errorf("spec.nodeName: node %q does not exist", app.Spec.NodeName)
}
