package admission

import (
	"context"
	"slices"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/authn"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func asClient(t *testing.T) context.Context {
	t.Helper()
	return authn.WithIdentity(context.Background(), &authn.Identity{Name: "alice"})
}

func appWithFinalizers(name string, fins ...string) *corev1.Application {
	return &corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Finalizers: fins},
		// Placed on purpose: an unplaced app is not held by the node-teardown finalizer at all
		// (nothing would ever report its workload gone), so an unplaced fixture would have that
		// finalizer stripped for a reason that has nothing to do with what these tests assert.
		Spec: corev1.ApplicationSpec{
			Image:     "reg/app:v1",
			Placement: corev1.Placement{NodeName: "node-1"},
		},
	}
}

// TestAClientCannotAddAFinalizer: a finalizer is a VETO on deletion, so one an identity can write
// is an object that identity can make permanently undeletable — by anyone, admin included, since
// nothing in the control plane knows what an invented finalizer waits for and nothing will ever
// clear it. For an Application that also pins its running workload against every attempt to
// remove it.
func TestAClientCannotAddAFinalizer(t *testing.T) {
	p := finalizerOwnership{}
	created := appWithFinalizers("web", "evil.example/never-delete-me")
	if err := p.Admit(asClient(t), &Attributes{Operation: Create, Object: created}); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	// What survives is the control plane's own hold, added because the app is placed — never the
	// one the client wrote.
	if slices.Contains(created.Finalizers, "evil.example/never-delete-me") {
		t.Errorf("a client's finalizer survived create: %v", created.Finalizers)
	}
	if !slices.Equal(created.Finalizers, []string{corev1.FinalizerNodeTeardown}) {
		t.Errorf("finalizers = %v, want only the control plane's teardown hold", created.Finalizers)
	}

	stored := appWithFinalizers("web", "horchestra.io/node-teardown")
	updated := appWithFinalizers("web", "horchestra.io/node-teardown", "evil.example/never-delete-me")
	if err := p.Admit(asClient(t), &Attributes{Operation: Update, Object: updated, OldObject: stored}); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if len(updated.Finalizers) != 1 || updated.Finalizers[0] != "horchestra.io/node-teardown" {
		t.Errorf("finalizers = %v, want only the stored one", updated.Finalizers)
	}
}

// TestAClientCannotClearAFinalizer is the same rule read the other way, and it is the half that
// loses data rather than leaking it: dropping another party's veto releases an object whose
// teardown never happened, so the workload keeps running with nothing left pointing at it.
func TestAClientCannotClearAFinalizer(t *testing.T) {
	stored := appWithFinalizers("web", "horchestra.io/node-teardown")
	updated := appWithFinalizers("web")
	if err := (finalizerOwnership{}).Admit(asClient(t),
		&Attributes{Operation: Update, Object: updated, OldObject: stored}); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if len(updated.Finalizers) != 1 {
		t.Errorf("a client cleared a finalizer: %v", updated.Finalizers)
	}
}

// TestTheControlPlaneOwnsTheList: the in-process loops carry no authn identity, which is exactly
// what lets them add and clear their own entries. Without this the mechanism could not work at
// all — nobody would be able to write the finalizer the deletion waits on.
func TestTheControlPlaneOwnsTheList(t *testing.T) {
	stored := appWithFinalizers("web")
	updated := appWithFinalizers("web", "horchestra.io/node-teardown")
	if err := (finalizerOwnership{}).Admit(context.Background(),
		&Attributes{Operation: Update, Object: updated, OldObject: stored}); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if len(updated.Finalizers) != 1 {
		t.Errorf("the control plane's own write was reverted: %v", updated.Finalizers)
	}
}

// TestAClientCannotStampADeletion: the timestamp is the record that a teardown is under way, and
// every consumer acts on it — the node stops the workload, the cascade starts. A client able to
// write it would trigger all of that by a route that never asked whether they may delete.
func TestAClientCannotStampADeletion(t *testing.T) {
	now := metav1.Now()
	marked := appWithFinalizers("web", "horchestra.io/node-teardown")
	marked.DeletionTimestamp = &now
	err := (finalizerOwnership{}).Validate(asClient(t),
		&Attributes{Operation: Update, Object: marked, OldObject: appWithFinalizers("web", "horchestra.io/node-teardown")})
	if err == nil {
		t.Fatal("a client stamped a deletion timestamp on a live object")
	}
	if !strings.Contains(err.Error(), "deletionTimestamp") {
		t.Errorf("the refusal does not name the field: %v", err)
	}

	// An object already being deleted keeps its stamp through an update — otherwise the control
	// plane could not touch a deleting object at all, which is when it has the most to do.
	deleting := appWithFinalizers("web", "horchestra.io/node-teardown")
	deleting.DeletionTimestamp = &now
	if err := (finalizerOwnership{}).Validate(asClient(t),
		&Attributes{Operation: Update, Object: deleting, OldObject: deleting}); err != nil {
		t.Errorf("an update to an already-deleting object was refused: %v", err)
	}
}

// TestPlacementDecidesTheTeardownHold: the finalizer names something that must HAPPEN — a node
// confirming the workload is gone — so it belongs on an app that has a node and on no other. An
// unplaced app holding it would wait forever for a message nobody is going to send, which is an
// object nobody can delete.
func TestPlacementDecidesTheTeardownHold(t *testing.T) {
	p := finalizerOwnership{}
	// The scheduler's bind is an in-process write with no identity — the case the revert must
	// not swallow, since it is exactly when an app first acquires something to tear down.
	bound := appWithFinalizers("web")
	if err := p.Admit(context.Background(), &Attributes{Operation: Update, Object: bound,
		OldObject: appWithFinalizers("web")}); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if !slices.Contains(bound.Finalizers, corev1.FinalizerNodeTeardown) {
		t.Errorf("a placed app is not held for teardown: %v", bound.Finalizers)
	}

	unbound := appWithFinalizers("web", corev1.FinalizerNodeTeardown)
	unbound.Spec.Placement.NodeName = ""
	if err := p.Admit(context.Background(), &Attributes{Operation: Update, Object: unbound,
		OldObject: appWithFinalizers("web", corev1.FinalizerNodeTeardown)}); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if slices.Contains(unbound.Finalizers, corev1.FinalizerNodeTeardown) {
		t.Errorf("an app that lost its node is still held, so nothing can delete it: %v", unbound.Finalizers)
	}
}

// TestTheHoldIsNotReappliedToADeletingObject is the deadlock this hit on the stand. The release
// is an ordinary update of an object that is STILL placed — placement is what the object has
// until the moment it is erased — so re-deriving the hold from placement put back exactly what
// the node's report had just earned the right to remove, and the object waited forever on a
// message that had already arrived.
func TestTheHoldIsNotReappliedToADeletingObject(t *testing.T) {
	now := metav1.Now()
	releasing := appWithFinalizers("web") // the node-server has just dropped the hold
	releasing.DeletionTimestamp = &now
	stored := appWithFinalizers("web", corev1.FinalizerNodeTeardown)
	stored.DeletionTimestamp = &now

	if err := (finalizerOwnership{}).Admit(context.Background(),
		&Attributes{Operation: Update, Object: releasing, OldObject: stored}); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if slices.Contains(releasing.Finalizers, corev1.FinalizerNodeTeardown) {
		t.Errorf("the teardown hold was re-applied to an object being deleted: %v", releasing.Finalizers)
	}
}
