package service

import (
	"context"
	"slices"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func orphanOpts() metav1.DeleteOptions {
	policy := metav1.DeletePropagationOrphan
	return metav1.DeleteOptions{PropagationPolicy: &policy}
}

func deletableSet(fins ...string) *corev1.ApplicationSet {
	return &corev1.ApplicationSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet"},
		ObjectMeta: metav1.ObjectMeta{Name: "tier", Namespace: "default", Finalizers: fins},
	}
}

func setMeta() types.ObjectMeta {
	return types.ObjectMeta{
		ApiVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet",
		Namespace: "default", Name: "tier",
	}
}

// TestOrphanIsRecordedOnTheObject: `kubectl delete --cascade=orphan` states a policy on a request
// that is over long before the controller acts on the deletion. The object is the only thing that
// outlives both, so the intent is written onto it as the orphan finalizer — Kubernetes' own
// marker, which is why no client has to be taught anything.
func TestOrphanIsRecordedOnTheObject(t *testing.T) {
	store := &deleteFakeStore{cur: deletableSet(corev1.FinalizerChildTeardown)}

	if err := newDeleteService(t, store).Delete(context.Background(), setMeta(), orphanOpts()); err != nil {
		t.Fatalf("delete --cascade=orphan: %v", err)
	}
	if store.erased {
		t.Fatal("the set was erased on the spot, with children still pointing at it")
	}
	set, ok := store.updated.(*corev1.ApplicationSet)
	if !ok {
		t.Fatalf("stamped object = %T, want an ApplicationSet", store.updated)
	}
	if !slices.Contains(set.Finalizers, metav1.FinalizerOrphanDependents) {
		t.Errorf("finalizers = %v, want the orphan marker among them", set.Finalizers)
	}
	if set.DeletionTimestamp == nil {
		t.Error("the deletion was recorded without a timestamp")
	}
}

// TestAnOrdinaryDeleteStampsNoOrphanMarker: the default is the cascade, and it must stay the
// default — a marker added to every deletion would preserve every child of every set.
func TestAnOrdinaryDeleteStampsNoOrphanMarker(t *testing.T) {
	store := &deleteFakeStore{cur: deletableSet(corev1.FinalizerChildTeardown)}

	if err := newDeleteService(t, store).Delete(context.Background(), setMeta(), metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	set := store.updated.(*corev1.ApplicationSet)
	if slices.Contains(set.Finalizers, metav1.FinalizerOrphanDependents) {
		t.Errorf("an ordinary delete asked for orphans: %v", set.Finalizers)
	}
}

// TestOrphanIsRefusedWhereNothingCouldBeOrphaned: an Application owns nothing, so the policy names
// a relationship that does not exist. Refused rather than ignored — a caller told "orphaned" about
// an object with no dependents has been told something false, and would find out by the workload
// being gone.
func TestOrphanIsRefusedWhereNothingCouldBeOrphaned(t *testing.T) {
	store := &deleteFakeStore{cur: deletableApp(corev1.FinalizerNodeTeardown)}

	err := newDeleteService(t, store).Delete(context.Background(), deleteMeta(), orphanOpts())
	if err == nil {
		t.Fatal("--cascade=orphan on an Application was accepted")
	}
	if !strings.Contains(err.Error(), "no dependents") {
		t.Errorf("error = %q, want it to say the Kind has no dependents", err)
	}
	if store.erased || store.updated != nil {
		t.Error("a refused delete still touched the object")
	}
}

// TestOrphanOnADeletionAlreadyInFlight: a second delete does not restart the clock, but it may
// still be the one that says to orphan — the caller was allowed to issue it, and the first
// request may simply have omitted the flag.
func TestOrphanOnADeletionAlreadyInFlight(t *testing.T) {
	set := deletableSet(corev1.FinalizerChildTeardown)
	stamp := metav1.Now()
	set.DeletionTimestamp = &stamp
	store := &deleteFakeStore{cur: set}

	if err := newDeleteService(t, store).Delete(context.Background(), setMeta(), orphanOpts()); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	updated, ok := store.updated.(*corev1.ApplicationSet)
	if !ok {
		t.Fatal("the orphan marker was not written onto a deletion already in flight")
	}
	if !slices.Contains(updated.Finalizers, metav1.FinalizerOrphanDependents) {
		t.Errorf("finalizers = %v, want the orphan marker", updated.Finalizers)
	}
	if !updated.DeletionTimestamp.Equal(&stamp) {
		t.Error("the second delete moved the deletion timestamp")
	}
}
