package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/apiserver/admission"
	"github.com/ks-tool/horchestra/apiserver/internal/memory"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"
)

const apiVersion = "test.horchestra.io/v1"

var widgetGVK = schema.GroupVersionKind{Group: "test.horchestra.io", Version: "v1", Kind: "Widget"}

type widget struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              widgetSpec `json:"spec"`
}

type widgetSpec struct {
	Image string `json:"image,omitempty"`
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	sch := scheme.New()
	sch.AddKnownTypes(widgetGVK, func() types.Object { return new(widget) })
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	return New(store, sch, admission.DefaultChain(nil))
}

func metaFor(name string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: apiVersion, Kind: "Widget", Name: name}
}

func TestService_CRUD(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Create from a body that omits apiVersion/kind — admission must stamp them.
	created, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"db"},"spec":{"image":"postgres:16"}}`))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	w := created.(*widget)
	if w.Name != "db" {
		t.Errorf("name = %q, want db", w.Name)
	}
	if w.APIVersion != apiVersion || w.Kind != "Widget" {
		t.Errorf("TypeMeta = %s/%s, want %s/Widget (admission defaulting)", w.APIVersion, w.Kind, apiVersion)
	}
	if w.ResourceVersion == "" {
		t.Error("resourceVersion not assigned")
	}
	if w.Spec.Image != "postgres:16" {
		t.Errorf("spec.image = %q, want postgres:16", w.Spec.Image)
	}

	// Duplicate → 409.
	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"db"},"spec":{}}`)); !apierrors.IsAlreadyExists(err) {
		t.Errorf("duplicate Create err = %v, want AlreadyExists", err)
	}
	// Missing name → 422.
	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"spec":{"image":"x"}}`)); !apierrors.IsInvalid(err) {
		t.Errorf("nameless Create err = %v, want Invalid", err)
	}

	// Get.
	got, err := svc.Get(ctx, metaFor("db"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.(*widget).Spec.Image != "postgres:16" {
		t.Errorf("Get spec.image = %q", got.(*widget).Spec.Image)
	}
	if _, err := svc.Get(ctx, metaFor("missing")); !apierrors.IsNotFound(err) {
		t.Errorf("Get(missing) err = %v, want NotFound", err)
	}

	// Update at the current resourceVersion.
	updBody := fmt.Sprintf(`{"metadata":{"name":"db","resourceVersion":%q},"spec":{"image":"postgres:17"}}`, w.ResourceVersion)
	updated, err := svc.Update(ctx, widgetGVK, []byte(updBody))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.(*widget).Spec.Image != "postgres:17" {
		t.Errorf("Update spec.image = %q, want postgres:17", updated.(*widget).Spec.Image)
	}
	// Same (now stale) resourceVersion → 409.
	if _, err := svc.Update(ctx, widgetGVK, []byte(updBody)); !apierrors.IsConflict(err) {
		t.Errorf("stale Update err = %v, want Conflict", err)
	}
	// Update of a missing object → 404.
	if _, err := svc.Update(ctx, widgetGVK, []byte(`{"metadata":{"name":"ghost"},"spec":{}}`)); !apierrors.IsNotFound(err) {
		t.Errorf("Update(missing) err = %v, want NotFound", err)
	}

	// Merge patch.
	patched, err := svc.Patch(ctx, metaFor("db"), apitypes.MergePatchType, []byte(`{"spec":{"image":"postgres:18"}}`))
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if patched.(*widget).Spec.Image != "postgres:18" {
		t.Errorf("Patch spec.image = %q, want postgres:18", patched.(*widget).Spec.Image)
	}
	// Unsupported patch type → 415.
	if _, err := svc.Patch(ctx, metaFor("db"), apitypes.StrategicMergePatchType, []byte(`{}`)); !apierrors.IsUnsupportedMediaType(err) {
		t.Errorf("strategic Patch err = %v, want UnsupportedMediaType", err)
	}

	// List.
	list, err := svc.List(ctx, metaFor(""), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("List len = %d, want 1", len(list))
	}

	// Delete, then it is gone.
	if err := svc.Delete(ctx, metaFor("db")); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Get(ctx, metaFor("db")); !apierrors.IsNotFound(err) {
		t.Errorf("Get after Delete err = %v, want NotFound", err)
	}
	if err := svc.Delete(ctx, metaFor("db")); !apierrors.IsNotFound(err) {
		t.Errorf("Delete(missing) err = %v, want NotFound", err)
	}
}
