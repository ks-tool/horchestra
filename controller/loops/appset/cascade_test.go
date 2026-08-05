package appset

import (
	"context"
	"slices"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func deletingSet(name, ns string, children ...string) corev1.ApplicationSet {
	now := metav1.Now()
	set := corev1.ApplicationSet{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			DeletionTimestamp: &now,
			Finalizers:        []string{corev1.FinalizerChildTeardown},
		},
	}
	for _, c := range children {
		set.Spec.Applications = append(set.Spec.Applications,
			corev1.NamedApplicationSpec{Name: c, Spec: corev1.ApplicationSpec{Image: "reg/x:v1"}})
	}
	return set
}

// TestACascadeDeletesChildrenBeforeReleasingTheSet is the ordering the finalizer exists to buy.
// The set used to be erased FIRST and its children reaped afterwards by the orphan sweep, so in
// between they ran with nothing pointing at them — and with the loop down in between, they stayed
// that way.
func TestACascadeDeletesChildrenBeforeReleasingTheSet(t *testing.T) {
	set := deletingSet("tier", "default", "web")
	child := ownedChild("tier-web", "tier", "default")
	f := &fakeCluster{sets: []corev1.ApplicationSet{set}, apps: map[string]corev1.Application{"tier-web": child}}

	New(f, Config{}).reconcileOnce(context.Background())

	if !slices.Contains(f.deleted, "tier-web") {
		t.Errorf("the cascade did not delete the child: %v", f.deleted)
	}
	if len(f.setDeletes) != 0 {
		t.Errorf("the set was erased while a child was still standing: %v", f.setDeletes)
	}
	if len(f.setUpdates) != 0 {
		t.Errorf("the hold was released while a child was still standing: %v", f.setUpdates)
	}
}

// TestTheSetGoesOnlyWhenNothingIsLeft: a child's own delete is a request too — it carries the
// node-teardown finalizer — so "no children" means every node confirmed its workload gone, not
// that the deletes were issued.
func TestTheSetGoesOnlyWhenNothingIsLeft(t *testing.T) {
	f := &fakeCluster{
		sets: []corev1.ApplicationSet{deletingSet("tier", "default", "web")},
		apps: map[string]corev1.Application{},
	}
	New(f, Config{}).reconcileOnce(context.Background())

	if !slices.Contains(f.setUpdates, "tier") {
		t.Errorf("the cascade hold was never released: %v", f.setUpdates)
	}
	if !slices.Contains(f.setDeletes, "tier") {
		t.Errorf("a set with no children left was not erased: %v", f.setDeletes)
	}
	if got := f.sets[0].Finalizers; slices.Contains(got, corev1.FinalizerChildTeardown) {
		t.Errorf("the released set still carries the hold: %v", got)
	}
}

// TestADeletingSetRendersNothing: a set on its way out must not re-create the children it is
// tearing down. Falling through to the ordinary converge would have it recreate every child it
// had just deleted, forever.
func TestADeletingSetRendersNothing(t *testing.T) {
	f := &fakeCluster{
		sets: []corev1.ApplicationSet{deletingSet("tier", "default", "web")},
		apps: map[string]corev1.Application{},
	}
	New(f, Config{}).reconcileOnce(context.Background())
	if len(f.created) != 0 {
		t.Errorf("a set being deleted created children: %v", f.created)
	}
}
