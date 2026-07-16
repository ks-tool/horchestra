package storage

import (
	"context"
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrConflict      = errors.New("modified concurrently")
)

type Storage interface {
	Create(ctx context.Context, gvk schema.GroupVersionKind, obj *unstructured.Unstructured) (*unstructured.Unstructured, error)
	Get(ctx context.Context, gvk schema.GroupVersionKind, name string) (*unstructured.Unstructured, error)
	List(ctx context.Context, gvk schema.GroupVersionKind) (*unstructured.UnstructuredList, error)
	Update(ctx context.Context, gvk schema.GroupVersionKind, obj *unstructured.Unstructured) (*unstructured.Unstructured, error)
	Delete(ctx context.Context, gvk schema.GroupVersionKind, name string) error
	Watch(ctx context.Context, gvk schema.GroupVersionKind) (<-chan metav1.WatchEvent, error)
	Close() error
}
