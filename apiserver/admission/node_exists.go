package admission

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// nodeExists rejects an Application whose spec.nodeName names a Node that does not
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
	app, ok := a.Object.(*corev1.Application)
	if !ok || len(app.Spec.NodeName) == 0 {
		return nil // not an Application, or node absent (the input schema requires it)
	}
	list, err := c.lister.List(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, obj := range list {
		if node, ok := obj.(*corev1.Node); ok && node.Name == app.Spec.NodeName {
			return nil
		}
	}
	return fmt.Errorf("spec.nodeName: node %q does not exist", app.Spec.NodeName)
}
