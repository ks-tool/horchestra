package appset

import (
	"context"
	"errors"
	"slices"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// orphaningSet is a set deleted with `--cascade=orphan`: the service recorded the caller's
// propagation policy as the orphan finalizer, which is what the loop reads.
func orphaningSet(name, ns string, children ...string) corev1.ApplicationSet {
	set := deletingSet(name, ns, children...)
	set.Finalizers = append(set.Finalizers, metav1.FinalizerOrphanDependents)
	return set
}

// TestOrphanDeleteReleasesInsteadOfReaping: the default cascade answers "the set authored these
// workloads"; `--cascade=orphan` answers "the set merely filed them". A fleet-wide agent rendered
// by nodeSpread must not stop collecting on every node because the object that manages it was
// retired.
func TestOrphanDeleteReleasesInsteadOfReaping(t *testing.T) {
	f := &fakeCluster{
		sets: []corev1.ApplicationSet{orphaningSet("tier", "default", "web")},
		apps: map[string]corev1.Application{"tier-web": ownedChild("tier-web", "tier", "default")},
	}

	New(f, Config{}).reconcileOnce(context.Background())

	if len(f.deleted) != 0 {
		t.Fatalf("a preserved child was deleted: %v", f.deleted)
	}
	child, ok := f.apps["tier-web"]
	if !ok {
		t.Fatal("the child is gone")
	}
	if ref := corev1.AppsetOwner(&child); ref != nil {
		t.Errorf("the released child still names a set as its controller: %+v", ref)
	}
	for _, key := range corev1.ReservedChildLabels() {
		if _, ok := child.Labels[key]; ok {
			t.Errorf("the released child still carries the reserved label %q — it could not be "+
				"re-created from its own manifest", key)
		}
	}
	if _, ok := child.Annotations[corev1.AnnAppsetSpecHash]; ok {
		t.Error("the released child still carries the render digest of a set that no longer exists")
	}
	// The hold ends in the same pass: what it waits for is the release, and nothing on any node
	// changed, so there is no teardown for a node to confirm. Both holds go — an orphan marker
	// left behind would hang the object on a finalizer nothing else removes.
	if !slices.Contains(f.setUpdates, "tier") || !slices.Contains(f.setDeletes, "tier") {
		t.Errorf("the set was not released and erased once its children were let go: updates=%v deletes=%v",
			f.setUpdates, f.setDeletes)
	}
	if got := f.sets[0].Finalizers; len(got) != 0 {
		t.Errorf("the released set still carries %v", got)
	}
}

// TestAReleasedChildSurvivesTheOrphanSweep is the half that actually keeps it running. The
// GC-first sweep destroys any Application whose owning set is gone — so a release that left the
// ownerReference in place would preserve the child exactly until the next reconcile.
func TestAReleasedChildSurvivesTheOrphanSweep(t *testing.T) {
	f := &fakeCluster{
		sets: []corev1.ApplicationSet{orphaningSet("tier", "default", "web")},
		apps: map[string]corev1.Application{"tier-web": ownedChild("tier-web", "tier", "default")},
	}
	c := New(f, Config{})
	c.reconcileOnce(context.Background())

	// The set is erased; the next pass sees the child with no set at all — the orphan case.
	f.sets = nil
	c.reconcileOnce(context.Background())

	if len(f.deleted) != 0 {
		t.Fatalf("the orphan sweep reaped a released child: %v", f.deleted)
	}
	if _, ok := f.apps["tier-web"]; !ok {
		t.Fatal("the released child did not survive a reconcile without its set")
	}
}

// TestAReleasedChildIsNotReadoptedByANamesake: released is a one-way door. Re-creating the same
// set must not silently take the workloads back — the adoption guard keys on the ownerReference,
// which is gone, so the set sees a foreign object under the name it wants and leaves it alone.
func TestAReleasedChildIsNotReadoptedByANamesake(t *testing.T) {
	released := ownedChild("tier-web", "tier", "default")
	corev1.ReleaseAppsetChild(&released)
	f := &fakeCluster{
		sets: []corev1.ApplicationSet{deletingSet("tier", "default", "web")},
		apps: map[string]corev1.Application{"tier-web": released},
	}
	f.sets[0].ObjectMeta.DeletionTimestamp = nil // a live namesake, not the deleted one

	New(f, Config{}).reconcileOnce(context.Background())

	if slices.Contains(f.updated, "tier-web") {
		t.Error("a namesake set rewrote an object it does not own")
	}
	if slices.Contains(f.deleted, "tier-web") {
		t.Error("a namesake set reaped an object it does not own")
	}
}

// TestAFailedReleaseHoldsTheSet: the finalizer is the only thing standing between a half-released
// bundle and children nobody can account for, so a set whose release did not go through keeps its
// hold and is retried, rather than being erased over a child that still names it.
func TestAFailedReleaseHoldsTheSet(t *testing.T) {
	f := &failingUpdates{fakeCluster: &fakeCluster{
		sets: []corev1.ApplicationSet{orphaningSet("tier", "default", "web")},
		apps: map[string]corev1.Application{"tier-web": ownedChild("tier-web", "tier", "default")},
	}}

	New(f, Config{}).reconcileOnce(context.Background())

	if len(f.setDeletes) != 0 {
		t.Errorf("the set was erased while a child still named it: %v", f.setDeletes)
	}
	if len(f.setUpdates) != 0 {
		t.Errorf("the hold was released while a child still named it: %v", f.setUpdates)
	}
	if len(f.deleted) != 0 {
		t.Errorf("a preserved child was deleted after the release failed: %v", f.deleted)
	}
}

// failingUpdates refuses every Application update, standing in for a release that cannot land.
type failingUpdates struct{ *fakeCluster }

func (f *failingUpdates) UpdateApplication(context.Context, *corev1.Application) error {
	return errors.New("storage is unavailable")
}
