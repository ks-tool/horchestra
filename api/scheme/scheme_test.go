package scheme

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ks-tool/horchestra/api/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ptrObject is a pointer-backed Object: it satisfies types.Object through the
// embedded metav1.TypeMeta (pointer receiver), like the real apis/*/v1 kinds.
type ptrObject struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

// valueObject is a value-backed Object: a value-receiver GetObjectKind, so a
// constructor can return it without a pointer — which registration must reject.
type valueObject struct {
	gvk schema.GroupVersionKind
}

func (v valueObject) GetObjectKind() schema.ObjectKind {
	return &metav1.TypeMeta{APIVersion: v.gvk.GroupVersion().String(), Kind: v.gvk.Kind}
}

const appAPIVersion = "test.horchestra.io/v1"

var appGVK = schema.GroupVersionKind{Group: "test.horchestra.io", Version: "v1", Kind: "App"}

func appFunc() types.Object {
	return &ptrObject{TypeMeta: metav1.TypeMeta{APIVersion: appAPIVersion, Kind: "App"}}
}

// requirePanic runs fn and fails unless it panics with a message containing want.
func requirePanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic containing %q, got none", want)
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, want) {
			t.Fatalf("panic = %q, want it to contain %q", msg, want)
		}
	}()
	fn()
}

func TestAddKnownTypes_PointerObject(t *testing.T) {
	s := New()
	s.AddKnownTypes(appGVK, appFunc)

	if got := len(s.m); got != 1 {
		t.Fatalf("expected 1 registered type, got %d", got)
	}

	obj, err := s.New(appGVK)
	if err != nil {
		t.Fatalf("New(%s) returned error: %v", appGVK, err)
	}
	if _, ok := obj.(*ptrObject); !ok {
		t.Fatalf("New(%s) returned %T, want *ptrObject", appGVK, obj)
	}
}

func TestNew_ReturnsFreshInstance(t *testing.T) {
	s := New()
	s.AddKnownTypes(appGVK, appFunc)

	a, err := s.New(appGVK)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	b, err := s.New(appGVK)
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	if a == b {
		t.Fatal("New returned the same instance twice; constructor should produce a fresh object")
	}
}

func TestNew_UnknownKind(t *testing.T) {
	s := New()
	if _, err := s.New(appGVK); err == nil {
		t.Fatalf("New(%s) on empty scheme should return an error", appGVK)
	}
}

func TestAddKnownTypes_NoOp(t *testing.T) {
	tests := []struct {
		name string
		fn   ObjectFunc
	}{
		{"nil func", nil},
		{"func returns nil interface", func() types.Object { return nil }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := New()
			s.AddKnownTypes(appGVK, tc.fn) // must not panic
			if got := len(s.m); got != 0 {
				t.Fatalf("expected nothing registered, got %d entries", got)
			}
		})
	}
}

func TestAddKnownTypes_PanicsOnNonPointer(t *testing.T) {
	s := New()
	requirePanic(t, "must be a pointer", func() {
		s.AddKnownTypes(appGVK, func() types.Object { return valueObject{gvk: appGVK} })
	})
	if got := len(s.m); got != 0 {
		t.Fatalf("nothing should be registered after a panic, got %d entries", got)
	}
}

func TestAddKnownTypes_PanicsOnDuplicate(t *testing.T) {
	s := New()
	s.AddKnownTypes(appGVK, appFunc)

	requirePanic(t, "duplicate object kind", func() {
		s.AddKnownTypes(appGVK, appFunc)
	})
	if got := len(s.m); got != 1 {
		t.Fatalf("duplicate registration should leave one entry, got %d", got)
	}
}

func TestAddResource_RegistersConstructorAndMetadata(t *testing.T) {
	s := New()
	s.AddResource(appGVK, appFunc, Resource{Plural: "apps", ShortNames: []string{"ap"}})

	// The constructor is registered like AddKnownTypes.
	if _, err := s.New(appGVK); err != nil {
		t.Fatalf("New after AddResource: %v", err)
	}

	r, ok := s.Resource(appGVK)
	if !ok {
		t.Fatalf("Resource(%s) not found after AddResource", appGVK)
	}
	if r.Plural != "apps" {
		t.Errorf("plural = %q, want apps", r.Plural)
	}
	// Singular defaults to the lowercased kind.
	if r.Singular != "app" {
		t.Errorf("singular = %q, want app (defaulted)", r.Singular)
	}
}

func TestAddResource_PanicsOnMissingPlural(t *testing.T) {
	s := New()
	requirePanic(t, "plural is required", func() {
		s.AddResource(appGVK, appFunc, Resource{})
	})
}

func TestResources_ReturnsCopy(t *testing.T) {
	s := New()
	s.AddResource(appGVK, appFunc, Resource{Plural: "apps"})

	got := s.Resources()
	if len(got) != 1 {
		t.Fatalf("Resources len = %d, want 1", len(got))
	}
	// Mutating the returned map must not affect the scheme's registry.
	delete(got, appGVK)
	if _, ok := s.Resource(appGVK); !ok {
		t.Fatal("mutating the Resources() copy affected the scheme")
	}
}

func TestGroupResource(t *testing.T) {
	// Registered as a resource: uses the registered plural.
	s := New()
	s.AddResource(appGVK, appFunc, Resource{Plural: "applications"})
	if gr := s.GroupResource(appGVK); gr.Group != "test.horchestra.io" || gr.Resource != "applications" {
		t.Errorf("registered GroupResource = %s, want test.horchestra.io/applications", gr)
	}

	// Not registered as a resource: falls back to the kind->resource heuristic.
	s2 := New()
	s2.AddKnownTypes(appGVK, appFunc)
	if gr := s2.GroupResource(appGVK); gr.Group != "test.horchestra.io" || gr.Resource != "apps" {
		t.Errorf("fallback GroupResource = %s, want test.horchestra.io/apps", gr)
	}
}

func TestDecode(t *testing.T) {
	s := New()
	s.AddKnownTypes(appGVK, appFunc)

	// Valid apiVersion/kind resolves to a fresh typed object.
	obj, err := s.Decode([]byte(`{"apiVersion":"test.horchestra.io/v1","kind":"App"}`))
	if err != nil {
		t.Fatalf("Decode(valid): %v", err)
	}
	if _, ok := obj.(*ptrObject); !ok {
		t.Fatalf("Decode returned %T, want *ptrObject", obj)
	}

	// Unknown kind -> error (no type registered).
	if _, err := s.Decode([]byte(`{"apiVersion":"test.horchestra.io/v1","kind":"Nope"}`)); err == nil {
		t.Error("Decode(unknown kind) should error")
	}
	// Missing kind -> error.
	if _, err := s.Decode([]byte(`{"apiVersion":"test.horchestra.io/v1"}`)); err == nil {
		t.Error("Decode(missing kind) should error")
	}
	// Invalid JSON -> error.
	if _, err := s.Decode([]byte(`{not json`)); err == nil {
		t.Error("Decode(invalid json) should error")
	}
}

func TestKnownTypes(t *testing.T) {
	s := New()
	v2GVK := schema.GroupVersionKind{Group: "test.horchestra.io", Version: "v2", Kind: "App"}
	s.AddKnownTypes(appGVK, appFunc)
	s.AddKnownTypes(v2GVK, func() types.Object {
		return &ptrObject{TypeMeta: metav1.TypeMeta{APIVersion: "test.horchestra.io/v2", Kind: "App"}}
	})

	if got := len(s.AllKnownTypes()); got != 2 {
		t.Errorf("AllKnownTypes len = %d, want 2", got)
	}
	if got := len(s.KnownTypes(appGVK.GroupVersion())); got != 1 {
		t.Errorf("KnownTypes(v1) len = %d, want 1", got)
	}
	if got := len(s.KnownTypes(v2GVK.GroupVersion())); got != 1 {
		t.Errorf("KnownTypes(v2) len = %d, want 1", got)
	}
}
