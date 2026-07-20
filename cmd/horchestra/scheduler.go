//go:build !agentonly

package main

import (
	"context"
	"fmt"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/apiserver/service"
	"github.com/ks-tool/horchestra/scheduler"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
)

// schedClient adapts the apiserver Service to the scheduler's Cluster port. Reads
// are typed lists; Assign patches spec.nodeName THROUGH the service, so admission
// (capacity, node-exists) re-validates the placement. It runs in-process with no
// authn context, so nodeRestriction (which confines system:nodes callers) is a
// no-op — the scheduler is a trusted internal writer.
type schedClient struct{ svc *service.Service }

var (
	_ scheduler.Cluster = schedClient{}
	_ scheduler.Watcher = schedClient{}
)

func (c schedClient) Applications(ctx context.Context) ([]corev1.Application, error) {
	objs, err := c.svc.List(ctx, coreMeta("Application", ""), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]corev1.Application, 0, len(objs))
	for _, o := range objs {
		if a, ok := o.(*corev1.Application); ok {
			out = append(out, *a)
		}
	}
	return out, nil
}

func (c schedClient) Nodes(ctx context.Context) ([]corev1.Node, error) {
	objs, err := c.svc.List(ctx, coreMeta("Node", ""), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]corev1.Node, 0, len(objs))
	for _, o := range objs {
		if n, ok := o.(*corev1.Node); ok {
			out = append(out, *n)
		}
	}
	return out, nil
}

func (c schedClient) Assign(ctx context.Context, app, node string) error {
	patch := []byte(fmt.Sprintf(`{"spec":{"nodeName":%q}}`, node))
	_, err := c.svc.Patch(ctx, coreMeta("Application", app), apitypes.MergePatchType, patch)
	return err
}

// Watch coalesces the Application and Node change streams into a single wake
// signal. It is only a nudge — the scheduler re-lists on every wake and a resync
// timer backs it up — so a lossy or dropped event self-corrects.
func (c schedClient) Watch(ctx context.Context) (<-chan struct{}, error) {
	appCh, err := c.svc.Watch(ctx, coreMeta("Application", ""), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	nodeCh, err := c.svc.Watch(ctx, coreMeta("Node", ""), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-appCh:
				if !ok {
					appCh = nil
				}
			case _, ok := <-nodeCh:
				if !ok {
					nodeCh = nil
				}
			}
			select {
			case out <- struct{}{}:
			default: // a wake is already pending — coalesce
			}
		}
	}()
	return out, nil
}

func coreMeta(kind, name string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: kind, Name: name}
}
