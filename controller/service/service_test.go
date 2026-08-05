package service

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/admission"
	"github.com/ks-tool/horchestra/controller/internal/memory"

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
	Mode  string `json:"mode,omitempty" jsonschema:"enum=auto,enum=manual,default=auto"`
}

// defaultWidgetMode is what the tag above declares; the tests read it from here so the two
// cannot drift apart in the test itself.
const defaultWidgetMode = "auto"

// newTestService registers the widget as a RESOURCE, not merely a known type, so it carries a
// compiled input schema like every real Kind and these tests run the same write path production
// does — schema first, then decode, then admission.
func newTestService(t *testing.T) *Service {
	t.Helper()
	sch := scheme.New()
	sch.AddResource(widgetGVK, func() types.Object { return new(widget) }, scheme.Resource{Plural: "widgets"})
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	return New(store, sch, admission.DefaultChain(nil, nil))
}

func metaFor(name string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: apiVersion, Kind: "Widget", Name: name}
}

// TestService_RejectsInvalidName locks the DNS-1123 name guard: a name carrying '/', ',', ':' or
// uppercase (which would traverse the node state dir or inject an overlay mount option) is
// rejected at Create, while a clean DNS-1123 name is accepted.
func TestService_RejectsInvalidName(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	for _, name := range []string{`app,lowerdir=/`, `../../etc`, `a/b`, `Foo`, `bad:name`} {
		body := fmt.Sprintf(`{"metadata":{"name":%q},"spec":{}}`, name)
		if _, err := svc.Create(ctx, widgetGVK, []byte(body), ""); !apierrors.IsInvalid(err) {
			t.Errorf("Create(name=%q) err = %v, want Invalid", name, err)
		}
	}
	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"ok-1.web"},"spec":{}}`), ""); err != nil {
		t.Errorf("valid DNS-1123 name rejected: %v", err)
	}
}

// TestService_ValidatesTheBodyAgainstTheSchema locks the wiring, not the schema's own rules
// (api/scheme tests those): every write decodes through one place, so the shape check reaches
// create, update and patch alike. A misspelled field is the case that needs the raw body — it
// decodes to nothing, so without this the write succeeds and the field the author wrote is
// silently absent from the stored object.
func TestService_ValidatesTheBodyAgainstTheSchema(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	bad := []byte(`{"metadata":{"name":"w1"},"spec":{"imgae":"x"}}`)
	_, err := svc.Create(ctx, widgetGVK, bad, "")
	if !apierrors.IsInvalid(err) {
		t.Fatalf("Create with an unknown spec field err = %v, want Invalid", err)
	}
	if !strings.Contains(err.Error(), "imgae") {
		t.Errorf("the error must name the offending field, got %v", err)
	}

	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"w1"},"spec":{"image":"x"}}`), ""); err != nil {
		t.Fatalf("a well-shaped body must pass: %v", err)
	}
	if _, err := svc.Update(ctx, widgetGVK, bad, "", "w1"); !apierrors.IsInvalid(err) {
		t.Errorf("Update with an unknown spec field err = %v, want Invalid", err)
	}
	patch := []byte(`{"spec":{"imgae":"x"}}`)
	if _, err := svc.Patch(ctx, metaFor("w1"), apitypes.MergePatchType, patch); !apierrors.IsInvalid(err) {
		t.Errorf("Patch introducing an unknown field err = %v, want Invalid", err)
	}
}

// TestService_StoresTheSchemaDefaults locks the wiring: a field the author left out is filled
// from its schema default and PERSISTED, so a reader of the stored object sees what will
// actually happen instead of an empty field whose meaning lives in some consumer.
func TestService_StoresTheSchemaDefaults(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	out, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"w1"},"spec":{}}`), "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := out.(*widget).Spec.Mode; got != defaultWidgetMode {
		t.Errorf("spec.mode = %q, want the declared default %q", got, defaultWidgetMode)
	}
	stored, err := svc.Get(ctx, metaFor("w1"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := stored.(*widget).Spec.Mode; got != defaultWidgetMode {
		t.Errorf("stored spec.mode = %q, want %q — the default must be persisted, not applied on the way out", got, defaultWidgetMode)
	}

	// What the author DID write is never overwritten.
	out, err = svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"w2"},"spec":{"mode":"manual"}}`), "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := out.(*widget).Spec.Mode; got != "manual" {
		t.Errorf("spec.mode = %q, want the authored manual", got)
	}
}

// TestService_PatchCannotRewriteIdentity locks the fix for the cross-object patch IDOR: a patch
// addressed to one object must not rewrite metadata.name/namespace (nor null resourceVersion) to
// land the write on — or overwrite — a different object. Storage keys the update by the object's
// own name, so without re-binding identity the patch would clobber the victim.
func TestService_PatchCannotRewriteIdentity(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"db"},"spec":{"image":"safe"}}`), ""); err != nil {
		t.Fatalf("create db: %v", err)
	}
	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"victim"},"spec":{"image":"victim-image"}}`), ""); err != nil {
		t.Fatalf("create victim: %v", err)
	}

	// Patch addressed to "db" that tries to rewrite the name to "victim" and null the
	// resourceVersion — it must apply to "db" and never touch "victim".
	patched, err := svc.Patch(ctx, metaFor("db"), apitypes.MergePatchType,
		[]byte(`{"metadata":{"name":"victim","resourceVersion":null},"spec":{"image":"pwned"}}`))
	if err != nil {
		t.Fatalf("patch db: %v", err)
	}
	if got := patched.(*widget).Name; got != "db" {
		t.Fatalf("patch rewrote identity: name = %q, want db", got)
	}

	list, err := svc.List(ctx, metaFor(""), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("object count = %d, want 2 (patch must not create a new object)", len(list))
	}
	byName := map[string]*widget{}
	for _, o := range list {
		w := o.(*widget)
		byName[w.Name] = w
	}
	if v := byName["victim"]; v == nil || v.Spec.Image != "victim-image" {
		t.Fatalf("victim overwritten via cross-name patch: %+v", v)
	}
	if d := byName["db"]; d == nil || d.Spec.Image != "pwned" {
		t.Fatalf("patch should apply to db: %+v", d)
	}
}

func TestService_CRUD(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Create from a body that omits apiVersion/kind — admission must stamp them.
	created, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"db"},"spec":{"image":"postgres:16"}}`), "")
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
	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"db"},"spec":{}}`), ""); !apierrors.IsAlreadyExists(err) {
		t.Errorf("duplicate Create err = %v, want AlreadyExists", err)
	}
	// Missing name → 422.
	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"spec":{"image":"x"}}`), ""); !apierrors.IsInvalid(err) {
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
	updated, err := svc.Update(ctx, widgetGVK, []byte(updBody), "", "")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.(*widget).Spec.Image != "postgres:17" {
		t.Errorf("Update spec.image = %q, want postgres:17", updated.(*widget).Spec.Image)
	}
	// Same (now stale) resourceVersion → 409.
	if _, err := svc.Update(ctx, widgetGVK, []byte(updBody), "", ""); !apierrors.IsConflict(err) {
		t.Errorf("stale Update err = %v, want Conflict", err)
	}
	// Update of a missing object → 404.
	if _, err := svc.Update(ctx, widgetGVK, []byte(`{"metadata":{"name":"ghost"},"spec":{}}`), "", ""); !apierrors.IsNotFound(err) {
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
	if err := svc.Delete(ctx, metaFor("db"), metav1.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Get(ctx, metaFor("db")); !apierrors.IsNotFound(err) {
		t.Errorf("Get after Delete err = %v, want NotFound", err)
	}
	if err := svc.Delete(ctx, metaFor("db"), metav1.DeleteOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("Delete(missing) err = %v, want NotFound", err)
	}
}
