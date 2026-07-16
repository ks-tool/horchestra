package apiserver

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

type gvkKey struct{}

func withGVK(ctx context.Context, gvk schema.GroupVersionKind) context.Context {
	return context.WithValue(ctx, gvkKey{}, gvk)
}

func gvkFromContext(ctx context.Context) schema.GroupVersionKind {
	gvk, _ := ctx.Value(gvkKey{}).(schema.GroupVersionKind)
	return gvk
}
