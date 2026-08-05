package service

import (
	"context"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/admission"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// deleteFakeStore records which of the two endings a DELETE reached: an erase, or an update that
// stamped the object instead.
type deleteFakeStore struct {
	storage.Storage
	cur     types.Object
	erased  bool
	updated types.Object
}

func (f *deleteFakeStore) Get(context.Context, types.ObjectMeta) (types.Object, error) {
	return f.cur, nil
}
func (f *deleteFakeStore) Delete(context.Context, types.ObjectMeta) error {
	f.erased = true
	return nil
}
func (f *deleteFakeStore) Update(_ context.Context, obj types.Object) (types.Object, error) {
	f.updated = obj
	return obj, nil
}

func deletableApp(fins ...string) *corev1.Application {
	return &corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", Finalizers: fins},
		Spec:       corev1.ApplicationSpec{Image: "reg/web:v1"},
	}
}

func deleteMeta() types.ObjectMeta {
	return types.ObjectMeta{
		ApiVersion: corev1.GroupVersion.String(), Kind: "Application",
		Namespace: "default", Name: "web",
	}
}

func newDeleteService(t *testing.T, store *deleteFakeStore) *Service {
	t.Helper()
	sch := scheme.New()
	corev1.AddToScheme(sch)
	return New(store, sch, admission.Chain{})
}

// TestDeleteWithoutAFinalizerStillErases is the behaviour every object has today, and the one the
// two-phase path must not disturb: nothing is waiting, so nothing waits.
func TestDeleteWithoutAFinalizerStillErases(t *testing.T) {
	store := &deleteFakeStore{cur: deletableApp()}
	if err := newDeleteService(t, store).Delete(context.Background(), deleteMeta(), metav1.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !store.erased {
		t.Error("an object nothing is holding was not erased")
	}
	if store.updated != nil {
		t.Error("an object with no finalizer was stamped instead of erased")
	}
}

// TestDeleteWithAFinalizerStampsInstead: the record of an intended deletion has to be the object.
// Erasing first meant a node learned a workload was gone by its ABSENCE from the next desired
// state — so the object had to disappear before the workload did, and in between there was no
// state to observe, which is precisely when an operator goes looking.
func TestDeleteWithAFinalizerStampsInstead(t *testing.T) {
	store := &deleteFakeStore{cur: deletableApp("horchestra.io/node-teardown")}
	if err := newDeleteService(t, store).Delete(context.Background(), deleteMeta(), metav1.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if store.erased {
		t.Fatal("an object with a finalizer was erased while something was still holding it")
	}
	acc, ok := store.updated.(*corev1.Application)
	if !ok {
		t.Fatalf("nothing was stamped: %#v", store.updated)
	}
	if acc.DeletionTimestamp == nil {
		t.Error("the object was written back without a deletion timestamp")
	}
	if len(acc.Finalizers) != 1 {
		t.Errorf("the finalizer was dropped by the stamp: %v", acc.Finalizers)
	}
}

// TestDeleteIsIdempotentWhileHeld: a client retrying a delete — or a controller re-issuing one —
// must not move the clock. The timestamp is what a grace period is measured from, so restarting
// it on every retry would let a caller keep a workload alive by asking to delete it.
func TestDeleteIsIdempotentWhileHeld(t *testing.T) {
	first := metav1.NewTime(metav1.Now().Add(-time.Hour))
	held := deletableApp("horchestra.io/node-teardown")
	held.DeletionTimestamp = &first
	store := &deleteFakeStore{cur: held}
	if err := newDeleteService(t, store).Delete(context.Background(), deleteMeta(), metav1.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if store.erased {
		t.Error("a second delete erased an object still being torn down")
	}
	if store.updated != nil {
		t.Error("a second delete rewrote the object, moving the deletion clock")
	}
	if !held.DeletionTimestamp.Equal(&first) {
		t.Errorf("the deletion timestamp moved: %v -> %v", first, held.DeletionTimestamp)
	}
}
