// Package clientset adapts the apiserver Service to the typed Cluster ports the in-tree control
// loops consume — one Client satisfies all three (scheduler, ApplicationSet, node-CSR). Every
// read is a typed List/Get and every write goes THROUGH the service, so admission re-validates it
// and the loops stay decoupled from storage. It runs in-process with no authn context — a trusted
// internal writer, so nodeRestriction (which confines system:nodes callers) is a no-op on its
// writes.
package clientset

import (
	"context"
	"encoding/json"
	"fmt"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/loops/appset"
	"github.com/ks-tool/horchestra/controller/loops/nodecsr"
	"github.com/ks-tool/horchestra/controller/loops/scheduler"
	"github.com/ks-tool/horchestra/controller/service"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"
)

// Client is the single adapter over the Service used by every in-process control loop.
type Client struct{ svc *service.Service }

// New builds a Client over the given service.
func New(svc *service.Service) *Client { return &Client{svc: svc} }

var (
	_ scheduler.Cluster = (*Client)(nil)
	_ appset.Cluster    = (*Client)(nil)
	_ nodecsr.Cluster   = (*Client)(nil)
)

func (c *Client) Applications(ctx context.Context) ([]corev1.Application, error) {
	return listAs[corev1.Application](ctx, c.svc, coreMeta("Application", "", ""))
}

func (c *Client) Nodes(ctx context.Context) ([]corev1.Node, error) {
	return listAs[corev1.Node](ctx, c.svc, coreMeta("Node", "", ""))
}

func (c *Client) Volumes(ctx context.Context) ([]corev1.PersistentVolume, error) {
	return listAs[corev1.PersistentVolume](ctx, c.svc, coreMeta("PersistentVolume", "", ""))
}

func (c *Client) ApplicationSets(ctx context.Context) ([]corev1.ApplicationSet, error) {
	return listAs[corev1.ApplicationSet](ctx, c.svc, coreMeta("ApplicationSet", "", ""))
}

func (c *Client) CSRs(ctx context.Context) ([]certv1.CertificateSigningRequest, error) {
	return listAs[certv1.CertificateSigningRequest](ctx, c.svc, certMeta("CertificateSigningRequest", ""))
}

func (c *Client) Assign(ctx context.Context, namespace, app, node string) error {
	patch := []byte(fmt.Sprintf(`{"spec":{"placement":{"nodeName":%q}}}`, node))
	_, err := c.svc.Patch(ctx, coreMeta("Application", namespace, app), apitypes.MergePatchType, patch)
	return err
}

func (c *Client) AssignVolume(ctx context.Context, namespace, pv, node string) error {
	patch := []byte(fmt.Sprintf(`{"spec":{"node":%q}}`, node))
	_, err := c.svc.Patch(ctx, coreMeta("PersistentVolume", namespace, pv), apitypes.MergePatchType, patch)
	return err
}

func (c *Client) CreateVolume(ctx context.Context, namespace, name string, size resource.Quantity) error {
	pv := &corev1.PersistentVolume{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "PersistentVolume"},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.PersistentVolumeSpec{Size: size},
	}
	return c.create(ctx, corev1.GroupVersion.WithKind("PersistentVolume"), pv)
}

func (c *Client) CreateApplication(ctx context.Context, app *corev1.Application) error {
	return c.create(ctx, corev1.GroupVersion.WithKind("Application"), app)
}

func (c *Client) UpdateApplication(ctx context.Context, app *corev1.Application) error {
	return c.update(ctx, corev1.GroupVersion.WithKind("Application"), app)
}

func (c *Client) DeleteApplication(ctx context.Context, namespace, name string) error {
	return c.svc.Delete(ctx, coreMeta("Application", namespace, name), metav1.DeleteOptions{})
}

func (c *Client) Services(ctx context.Context) ([]corev1.Service, error) {
	return listAs[corev1.Service](ctx, c.svc, coreMeta("Service", "", ""))
}

func (c *Client) CreateService(ctx context.Context, svc *corev1.Service) error {
	return c.create(ctx, corev1.GroupVersion.WithKind("Service"), svc)
}

func (c *Client) UpdateService(ctx context.Context, svc *corev1.Service) error {
	return c.update(ctx, corev1.GroupVersion.WithKind("Service"), svc)
}

func (c *Client) DeleteService(ctx context.Context, namespace, name string) error {
	return c.svc.Delete(ctx, coreMeta("Service", namespace, name), metav1.DeleteOptions{})
}

// UpdateSet and DeleteSet are the cascade's two writes: releasing the child-teardown finalizer
// once a deleted set's children are gone, and erasing the set that was waiting on them. UpdateSet
// is a spec-path write rather than the status subresource because a finalizer is metadata, and
// the guard that keeps finalizers out of client hands is a no-op for this loop, which carries no
// request identity.
func (c *Client) UpdateSet(ctx context.Context, set *corev1.ApplicationSet) error {
	return c.update(ctx, corev1.GroupVersion.WithKind("ApplicationSet"), set)
}

func (c *Client) DeleteSet(ctx context.Context, namespace, name string) error {
	return c.svc.Delete(ctx, coreMeta("ApplicationSet", namespace, name), metav1.DeleteOptions{})
}

func (c *Client) UpdateSetStatus(ctx context.Context, set *corev1.ApplicationSet) error {
	return c.updateStatus(ctx, corev1.GroupVersion.WithKind("ApplicationSet"), set)
}

// UpdateAppStatus writes an Application's status through the status subresource, which is what
// keeps it from waking every watcher of the spec.
// UpdateNode is the ipam loop's one spec write: the slice of the routed range this node hands out.
// A spec write and not a status one because it is a DECISION about the node rather than an
// observation of it — and because status is the node's own to report.
func (c *Client) UpdateNode(ctx context.Context, node *corev1.Node) error {
	return c.update(ctx, corev1.GroupVersion.WithKind("Node"), node)
}

func (c *Client) UpdateAppStatus(ctx context.Context, app *corev1.Application) error {
	return c.updateStatus(ctx, corev1.GroupVersion.WithKind("Application"), app)
}

func (c *Client) UpdateCSRStatus(ctx context.Context, csr *certv1.CertificateSigningRequest) error {
	return c.updateStatus(ctx, certv1.GroupVersion.WithKind("CertificateSigningRequest"), csr)
}

func (c *Client) DeleteCSR(ctx context.Context, name string) error {
	return c.svc.Delete(ctx, certMeta("CertificateSigningRequest", name), metav1.DeleteOptions{})
}

// WatchKind opens a coalesced change stream for one Kind, adapting the service's typed WatchEvent
// channel to the loop.Manager's struct{} nudge. It is only a wake — every loop re-lists on each
// signal and a resync timer backs it up — so a lossy event self-corrects. The Manager opens one
// per distinct Kind and fans it to the loops that watch it.
func (c *Client) WatchKind(ctx context.Context, kind types.ObjectMeta) (<-chan struct{}, error) {
	raw, err := c.svc.Watch(ctx, kind, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-raw:
				if !ok {
					return
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

// namespaceOf is the namespace an internal writer is authoritative about: the object's own. The
// service takes it as an argument rather than reading it out of the body, so the one place that
// decides namespace is the caller, not the JSON.
func nameOfObj(obj any) string {
	if m, ok := obj.(metav1.Object); ok {
		return m.GetName()
	}
	return ""
}

func namespaceOf(obj any) string {
	if m, ok := obj.(metav1.Object); ok {
		return m.GetNamespace()
	}
	return ""
}

// create/update/updateStatus marshal obj and write it through the service so admission runs.
func (c *Client) create(ctx context.Context, gvk schema.GroupVersionKind, obj any) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = c.svc.Create(ctx, gvk, data, namespaceOf(obj))
	return err
}

func (c *Client) update(ctx context.Context, gvk schema.GroupVersionKind, obj any) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = c.svc.Update(ctx, gvk, data, namespaceOf(obj), nameOfObj(obj))
	return err
}

func (c *Client) updateStatus(ctx context.Context, gvk schema.GroupVersionKind, obj any) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = c.svc.UpdateSubresource(ctx, gvk, "status", data, namespaceOf(obj))
	return err
}

// listAs lists a Kind through the service and returns the typed values. PT is the *T pointer that
// implements types.Object. A single-Kind List is homogeneous, so a non-empty list yielding zero
// matches means T was paired with the wrong meta.Kind — a programming error surfaced loudly here
// rather than silently returned as an empty slice.
func listAs[T any, PT interface {
	*T
	types.Object
}](ctx context.Context, svc *service.Service, meta types.ObjectMeta) ([]T, error) {
	objs, err := svc.List(ctx, meta, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(objs))
	for _, o := range objs {
		if v, ok := o.(PT); ok {
			out = append(out, *v)
		}
	}
	if len(out) == 0 && len(objs) > 0 {
		return nil, fmt.Errorf("clientset: List of kind %q returned %d objects, none of the expected type %T", meta.Kind, len(objs), out)
	}
	return out, nil
}

func coreMeta(kind, namespace, name string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: kind, Namespace: namespace, Name: name}
}

func certMeta(kind, name string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: certv1.GroupVersion.String(), Kind: kind, Name: name}
}
