package bolt

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"

	v1 "ks-tool.dev/horchestra/api/v1"
)

func TestCRUDWatch(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()

	gvk := v1.GroupVersion.WithKind("Application")
	ctx := context.Background()

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, err := st.Watch(wctx, gvk)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	obj := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "demo"},
		"spec":     map[string]any{"image": "reg/app:v1"},
	}}

	created, err := st.Create(ctx, gvk, obj)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(created.GetUID()) == 0 || len(created.GetResourceVersion()) == 0 {
		t.Fatalf("uid/rv not stamped: %q / %q", created.GetUID(), created.GetResourceVersion())
	}
	if created.GetCreationTimestamp().Time.IsZero() {
		t.Fatal("creationTimestamp not stamped")
	}

	got, err := st.Get(ctx, gvk, "demo")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GetName() != "demo" {
		t.Fatalf("get name = %q", got.GetName())
	}

	list, err := st.List(ctx, gvk)
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("list: err=%v n=%d", err, len(list.Items))
	}

	select {
	case e := <-ch:
		if e.Type != string(watch.Added) {
			t.Fatalf("watch event type = %s", e.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no watch event received")
	}

	if _, err := st.Create(ctx, gvk, obj); err == nil {
		t.Fatal("expected AlreadyExists on duplicate create")
	}

	if err := st.Delete(ctx, gvk, "demo"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.Get(ctx, gvk, "demo"); err == nil {
		t.Fatal("expected NotFound after delete")
	}
}
