package admission

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/authn"
)

// tenantCtx is a client request context: a low-privilege authenticated user, the caller this
// plugin guards against. The in-process loops carry no identity at all.
func tenantCtx() context.Context {
	return authn.WithIdentity(context.Background(), &authn.Identity{Name: "tenant", Groups: []string{"team-a"}})
}

func appGVK() schema.GroupVersionKind { return corev1.GroupVersion.WithKind("Application") }

// ownedChild is a rendered ApplicationSet child as the loop writes it.
func ownedChild(name string) *corev1.Application {
	controller := true
	return &corev1.Application{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "team-a",
			Name:        name,
			Labels:      map[string]string{corev1.LabelApplicationSet: "web", corev1.LabelComponent: "api"},
			Annotations: map[string]string{corev1.AnnAppsetSpecHash: "abc123"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet",
				Name: "web", UID: "set-uid", Controller: &controller,
			}},
		},
		Spec: corev1.ApplicationSpec{Image: "example.com/app:v1"},
	}
}

// plainApp is a directly-authored Application: no set owns it.
func plainApp(name string) *corev1.Application {
	return &corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: name},
		Spec:       corev1.ApplicationSpec{Image: "example.com/app:v1"},
	}
}

// TestChildOwnershipRejectsForgedOwnerReference: the controller ownerReference is a delete
// authority — the appset loop destroys any child whose named set is gone, with no RBAC check and
// no audit record — so a client must not be able to write one. A caller holding update but not
// delete could otherwise have the control plane delete an object for them.
func TestChildOwnershipRejectsForgedOwnerReference(t *testing.T) {
	controller := true
	forged := []metav1.OwnerReference{{
		APIVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet",
		Name: "no-such-set", Controller: &controller,
	}}

	t.Run("create is refused", func(t *testing.T) {
		app := ownedChild("victim")
		app.Labels, app.Annotations = nil, nil
		app.OwnerReferences = forged
		err := childOwnership{}.Admit(tenantCtx(), &Attributes{GVK: appGVK(), Operation: Create, Object: app})
		if err == nil {
			t.Fatal("a client-supplied controller ownerReference was accepted on create")
		}
		if _, ok := err.(*ForbiddenError); !ok {
			t.Fatalf("err = %T (%v), want *ForbiddenError", err, err)
		}
	})

	t.Run("update cannot add one", func(t *testing.T) {
		stored := plainApp("plain")
		incoming := plainApp("plain")
		incoming.OwnerReferences = forged
		attrs := &Attributes{GVK: appGVK(), Operation: Update, Object: incoming, OldObject: stored}
		if err := (childOwnership{}).Admit(tenantCtx(), attrs); err != nil {
			t.Fatalf("admit: %v", err)
		}
		if len(incoming.OwnerReferences) != 0 {
			t.Fatalf("ownerReferences = %+v, want the stored (empty) set", incoming.OwnerReferences)
		}
		if corev1.AppsetOwner(incoming) != nil {
			t.Fatal("the forged reference survived the update: the loop would delete this object")
		}
	})
}

// TestChildOwnershipPinsRenderMetadata: the loop decides "already converged" from the STORED
// child's spec-hash annotation, and a merge patch preserves it automatically — so a client that
// can edit the annotation, or edit the spec while the annotation stays, defeats drift reversion
// permanently. Both are refused: the metadata is carried over and the spec is not the client's.
func TestChildOwnershipPinsRenderMetadata(t *testing.T) {
	t.Run("reserved metadata is carried over verbatim", func(t *testing.T) {
		stored := ownedChild("web-api")
		incoming := ownedChild("web-api")
		incoming.Annotations[corev1.AnnAppsetSpecHash] = "forged"
		incoming.Labels[corev1.LabelApplicationSet] = "other-set"
		attrs := &Attributes{GVK: appGVK(), Operation: Update, Object: incoming, OldObject: stored}
		if err := (childOwnership{}).Admit(tenantCtx(), attrs); err != nil {
			t.Fatalf("admit: %v", err)
		}
		if got := incoming.Annotations[corev1.AnnAppsetSpecHash]; got != "abc123" {
			t.Fatalf("spec hash = %q, want the stored abc123", got)
		}
		if got := incoming.Labels[corev1.LabelApplicationSet]; got != "web" {
			t.Fatalf("set label = %q, want the stored web", got)
		}
	})

	t.Run("a spec change on an owned child is refused", func(t *testing.T) {
		stored := ownedChild("web-api")
		incoming := ownedChild("web-api")
		incoming.Spec.Image = "attacker/backdoor:latest"
		attrs := &Attributes{GVK: appGVK(), Operation: Update, Object: incoming, OldObject: stored}
		if err := (childOwnership{}).Admit(tenantCtx(), attrs); err != nil {
			t.Fatalf("admit: %v", err)
		}
		err := childOwnership{}.Validate(tenantCtx(), attrs)
		if err == nil {
			t.Fatal("the image of an ApplicationSet child was substituted")
		}
		if _, ok := err.(*ForbiddenError); !ok {
			t.Fatalf("err = %T (%v), want *ForbiddenError", err, err)
		}
	})

	t.Run("an unowned application is still the client's to edit", func(t *testing.T) {
		stored := plainApp("plain")
		incoming := plainApp("plain")
		incoming.Spec.Image = "example.com/app:v2"
		attrs := &Attributes{GVK: appGVK(), Operation: Update, Object: incoming, OldObject: stored}
		if err := (childOwnership{}).Admit(tenantCtx(), attrs); err != nil {
			t.Fatalf("admit: %v", err)
		}
		if err := (childOwnership{}).Validate(tenantCtx(), attrs); err != nil {
			t.Fatalf("a plain Application was refused: %v", err)
		}
	})
}

// TestChildOwnershipIgnoresTheLoop: the appset loop writes through the in-process clientset with
// no authn identity, and it is the legitimate author of every field this plugin pins — so its
// own create of a rendered child, and its own re-render of one, must pass untouched.
func TestChildOwnershipIgnoresTheLoop(t *testing.T) {
	ctx := context.Background()

	child := ownedChild("web-api")
	if err := (childOwnership{}).Admit(ctx, &Attributes{GVK: appGVK(), Operation: Create, Object: child}); err != nil {
		t.Fatalf("the loop's own child create was refused: %v", err)
	}
	if corev1.AppsetOwner(child) == nil {
		t.Fatal("the loop's controller ownerReference was stripped")
	}

	stored := ownedChild("web-api")
	rerendered := ownedChild("web-api")
	rerendered.Spec.Image = "example.com/app:v2"
	rerendered.Annotations[corev1.AnnAppsetSpecHash] = "def456"
	attrs := &Attributes{GVK: appGVK(), Operation: Update, Object: rerendered, OldObject: stored}
	if err := (childOwnership{}).Admit(ctx, attrs); err != nil {
		t.Fatalf("the loop's own re-render was refused: %v", err)
	}
	if err := (childOwnership{}).Validate(ctx, attrs); err != nil {
		t.Fatalf("the loop's own re-render was refused: %v", err)
	}
	if got := rerendered.Annotations[corev1.AnnAppsetSpecHash]; got != "def456" {
		t.Fatalf("spec hash = %q, want the loop's new def456", got)
	}
}

// TestChildOwnershipSkipsStatus: a node reports an owned child's status through the status
// subresource, which carries none of this metadata and must not be read as a spec change.
func TestChildOwnershipSkipsStatus(t *testing.T) {
	stored := ownedChild("web-api")
	incoming := ownedChild("web-api")
	incoming.Status.Phase = corev1.AppPhaseRunning
	attrs := &Attributes{GVK: appGVK(), Operation: Update, Object: incoming, OldObject: stored, Subresource: "status"}
	if err := (childOwnership{}).Admit(tenantCtx(), attrs); err != nil {
		t.Fatalf("admit on the status subresource: %v", err)
	}
	if err := (childOwnership{}).Validate(tenantCtx(), attrs); err != nil {
		t.Fatalf("validate on the status subresource: %v", err)
	}
}
