package admission

import (
	"context"
	"slices"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/authn"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
)

// finalizerOwnership keeps metadata.finalizers out of client hands, on every Kind.
//
// A finalizer is a VETO on deletion: the object is not erased while the list is non-empty, it is
// stamped with a deletionTimestamp and waits. That is exactly what makes it dangerous to leave
// client-writable — an identity holding only `update` could append a finalizer of its own
// invention to any object and make it permanently undeletable by anyone, including an admin,
// because nothing in the control plane knows what that finalizer is waiting for and nothing will
// ever clear it. The object would then hold its name, its uid allocation and, for an Application,
// its running workload, against every attempt to remove it.
//
// So the list is the control plane's alone: an identified caller may set none at create and change
// none at update, where the stored values are carried over verbatim — the same shape childOwnership
// uses for the appset's render metadata and csrPolicy for its requester annotations. The in-process
// control loops carry no authn identity, which is what lets THEM add and clear their own entries
// while a client cannot touch any.
//
// It deliberately does not care WHICH finalizers a caller wrote: adding one is as damaging as
// removing one (clearing another party's veto releases an object whose teardown never happened),
// so both are simply reverted to what is stored.
type finalizerOwnership struct{}

func (finalizerOwnership) Admit(ctx context.Context, a *Attributes) error {
	if a.Operation == Delete || a.IsSubresource() {
		return nil // a delete carries no new metadata, and a status write may not touch any
	}
	// The revert applies to a CLIENT's write only. The in-process loops carry no authn identity,
	// and gating the whole plugin on that is a trap this was written into once: the scheduler's
	// bind is such a write, so returning early for it meant the finalizer was never stamped on
	// exactly the apps that had just acquired the node that would have to tear them down.
	if authn.FromContext(ctx) != nil {
		if acc, err := apimeta.Accessor(a.Object); err == nil {
			var stored []string
			if a.OldObject != nil {
				if old, err := apimeta.Accessor(a.OldObject); err == nil {
					stored = old.GetFinalizers()
				}
			}
			if !slices.Equal(acc.GetFinalizers(), stored) {
				acc.SetFinalizers(slices.Clone(stored))
			}
		}
	}
	holdPlacedWorkload(a.Object)
	holdSetCascade(a.Object)
	return nil
}

// holdSetCascade puts the child-teardown finalizer on every ApplicationSet. Unlike a workload's
// hold this needs no condition: a set OWNS a cascade whether or not it has rendered a child yet,
// and the loop that releases the hold is the same one that would have created them.
func holdSetCascade(obj any) {
	set, ok := obj.(*corev1.ApplicationSet)
	if !ok || set.Deleting() {
		return // a deletion in flight owns its own list; see holdPlacedWorkload
	}
	if !slices.Contains(set.Finalizers, corev1.FinalizerChildTeardown) {
		set.Finalizers = append(set.Finalizers, corev1.FinalizerChildTeardown)
	}
}

// holdPlacedWorkload puts the node-teardown finalizer on an Application that has a node, so its
// object outlives the delete and the node gets to confirm the workload is gone.
//
// It keys on placement rather than on every Application because the finalizer names something
// that must HAPPEN, and for an unplaced app nothing has to: no node holds a workload, so nothing
// would ever report one gone and the object would wait forever for a message nobody sends.
//
// The other direction matters just as much: an app that loses its node — the scheduler unbinding
// it, an author clearing the pin — drops the finalizer, because the thing it was waiting for
// stopped existing. Leaving it on would make an already-unplaced object undeletable.
func holdPlacedWorkload(obj any) {
	app, ok := obj.(*corev1.Application)
	if !ok {
		return
	}
	// A deletion in flight owns its own finalizer list, and touching it here is a deadlock the
	// stand found: the node reports the workload gone, the node-server takes the hold off, and
	// this put it straight back — because the app is still placed, which it is right up to the
	// moment it is erased. The object then waited forever on a report that had already arrived.
	if app.Deleting() {
		return
	}
	held := slices.Contains(app.Finalizers, corev1.FinalizerNodeTeardown)
	switch placed := app.Spec.Placement.NodeName != ""; {
	case placed && !held:
		app.Finalizers = append(app.Finalizers, corev1.FinalizerNodeTeardown)
	case !placed && held:
		app.Finalizers = slices.DeleteFunc(app.Finalizers,
			func(f string) bool { return f == corev1.FinalizerNodeTeardown })
	}
}

// Validate is where the deletion timestamp is held, for the same reason and by the same rule: it
// is the control plane's record that a deletion is under way, and a client that could stamp it
// would have every consumer of the object — the node that runs the workload, the loop that owns
// the cascade — act on a teardown nobody requested. Unlike the finalizer list this is REFUSED
// rather than reverted: a caller writing it is asking for something the API does not offer (delete
// the object) by a route that bypasses the check that decides whether they may.
func (finalizerOwnership) Validate(ctx context.Context, a *Attributes) error {
	if a.Operation == Delete || a.IsSubresource() || authn.FromContext(ctx) == nil {
		return nil
	}
	acc, err := apimeta.Accessor(a.Object)
	if err != nil || acc.GetDeletionTimestamp() == nil {
		return nil
	}
	var stored bool
	if a.OldObject != nil {
		if old, err := apimeta.Accessor(a.OldObject); err == nil {
			stored = old.GetDeletionTimestamp() != nil
		}
	}
	if !stored {
		return Forbidden("metadata.deletionTimestamp: the control plane stamps this when a " +
			"deletion is requested — delete the object instead of marking it deleted")
	}
	return nil
}
