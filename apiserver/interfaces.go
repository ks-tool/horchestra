package apiserver

import (
	"context"

	"github.com/ks-tool/horchestra/api/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

type Service interface {
	Get(ctx context.Context, m types.ObjectMeta) (types.Object, error)
	List(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error)
	Watch(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) (<-chan metav1.WatchEvent, error)
	Create(ctx context.Context, gvk schema.GroupVersionKind, data []byte) (types.Object, error)
	Update(ctx context.Context, gvk schema.GroupVersionKind, data []byte) (types.Object, error)
	UpdateSubresource(ctx context.Context, gvk schema.GroupVersionKind, subresource string, data []byte) (types.Object, error)
	Patch(ctx context.Context, m types.ObjectMeta, pt k8stypes.PatchType, data []byte) (types.Object, error)
	Delete(ctx context.Context, m types.ObjectMeta) error
	Rollback(ctx context.Context, m types.ObjectMeta, uid string, targetRV int64) (types.Object, error)
}

// LogStreamer streams an application's logs from the node it runs on (the
// controller<->agent gRPC transport satisfies it). Absent (nil), the log endpoint
// reports it is unavailable.
type LogStreamer interface {
	StreamLogs(ctx context.Context, node, app string, follow bool, tail int64) (<-chan []byte, func() error, error)
}
