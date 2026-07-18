package storage

import (
	"context"
	"errors"

	"github.com/ks-tool/horchestra/api/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrConflict      = errors.New("modified concurrently")
)

type Storage interface {
	Create(ctx context.Context, obj types.Object) (types.Object, error)
	Update(ctx context.Context, obj types.Object) (types.Object, error)
	UpdateSubresource(ctx context.Context, subresource string, obj types.Object) (types.Object, error)
	Rollback(ctx context.Context, meta types.ObjectMeta, uid string, targetRV int64) (types.Object, error)
	Delete(ctx context.Context, meta types.ObjectMeta) error
	Get(ctx context.Context, meta types.ObjectMeta) (types.Object, error)
	List(ctx context.Context, meta types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error)
	Watch(ctx context.Context, meta types.ObjectMeta, opts metav1.ListOptions) (<-chan metav1.WatchEvent, error)
	Close() error
}
