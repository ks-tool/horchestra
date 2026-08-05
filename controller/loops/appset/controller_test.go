package appset

import (
	"context"
	"slices"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeCluster struct {
	sets    []corev1.ApplicationSet
	nodes   []corev1.Node
	apps    map[string]corev1.Application
	created []string
	updated []string
	deleted []string
	// setUpdates/setDeletes record the cascade's own two writes on the SET.
	setUpdates []string
	setDeletes []string
	// services is the namespace's whole Service list, including any this set does not own.
	services   map[string]corev1.Service
	svcCreated []string
	svcUpdated []string
	svcDeleted []string
}

func (f *fakeCluster) ApplicationSets(context.Context) ([]corev1.ApplicationSet, error) {
	return f.sets, nil
}
func (f *fakeCluster) Nodes(context.Context) ([]corev1.Node, error) { return f.nodes, nil }
func (f *fakeCluster) Applications(context.Context) ([]corev1.Application, error) {
	out := make([]corev1.Application, 0, len(f.apps))
	for _, a := range f.apps {
		out = append(out, a)
	}
	return out, nil
}
func (f *fakeCluster) CreateApplication(_ context.Context, app *corev1.Application) error {
	f.apps[app.Name] = *app
	f.created = append(f.created, app.Name)
	return nil
}
func (f *fakeCluster) UpdateApplication(_ context.Context, app *corev1.Application) error {
	f.apps[app.Name] = *app
	f.updated = append(f.updated, app.Name)
	return nil
}
func (f *fakeCluster) DeleteApplication(_ context.Context, _, name string) error {
	delete(f.apps, name)
	f.deleted = append(f.deleted, name)
	return nil
}
func (f *fakeCluster) UpdateSetStatus(context.Context, *corev1.ApplicationSet) error { return nil }

func (f *fakeCluster) Services(context.Context) ([]corev1.Service, error) {
	out := make([]corev1.Service, 0, len(f.services))
	for _, s := range f.services {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b corev1.Service) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (f *fakeCluster) CreateService(_ context.Context, svc *corev1.Service) error {
	if f.services == nil {
		f.services = map[string]corev1.Service{}
	}
	f.services[svc.Name] = *svc
	f.svcCreated = append(f.svcCreated, svc.Name)
	return nil
}

func (f *fakeCluster) UpdateService(_ context.Context, svc *corev1.Service) error {
	f.services[svc.Name] = *svc
	f.svcUpdated = append(f.svcUpdated, svc.Name)
	return nil
}

func (f *fakeCluster) DeleteService(_ context.Context, _, name string) error {
	delete(f.services, name)
	f.svcDeleted = append(f.svcDeleted, name)
	return nil
}

func (f *fakeCluster) UpdateSet(_ context.Context, set *corev1.ApplicationSet) error {
	for i := range f.sets {
		if f.sets[i].Name == set.Name && f.sets[i].Namespace == set.Namespace {
			f.sets[i] = *set
		}
	}
	f.setUpdates = append(f.setUpdates, set.Name)
	return nil
}

func (f *fakeCluster) DeleteSet(_ context.Context, _, name string) error {
	f.setDeletes = append(f.setDeletes, name)
	return nil
}

// ownedChild is a child the appset controller owns — it carries the controller ownerReference
// (the authority) as well as the reserved label.
func ownedChild(name, set, ns string) corev1.Application {
	controller := true
	a := corev1.Application{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	a.Labels = map[string]string{corev1.LabelApplicationSet: set, corev1.LabelComponent: "c"}
	a.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet", Name: set, Controller: &controller,
	}}
	return a
}

func TestReconcileCreatesChildren(t *testing.T) {
	f := &fakeCluster{
		sets: []corev1.ApplicationSet{*bundleSet("web", "team", comp("a", "a:v1"))},
		apps: map[string]corev1.Application{},
	}
	New(f, Config{}).reconcileOnce(context.Background())
	if !slices.Contains(f.created, "web-a") {
		t.Fatalf("created = %v, want to include web-a", f.created)
	}
}

func TestReconcilePrunesRemovedChildren(t *testing.T) {
	f := &fakeCluster{
		sets: []corev1.ApplicationSet{*bundleSet("web", "team", comp("a", "a:v1"))},
		apps: map[string]corev1.Application{
			"web-a": ownedChild("web-a", "web", "team"),
			"web-b": ownedChild("web-b", "web", "team"), // no longer listed → pruned
		},
	}
	New(f, Config{}).reconcileOnce(context.Background())
	if !slices.Contains(f.deleted, "web-b") {
		t.Fatalf("web-b must be pruned, deleted = %v", f.deleted)
	}
	if slices.Contains(f.deleted, "web-a") {
		t.Fatalf("web-a is still listed and must not be pruned, deleted = %v", f.deleted)
	}
}

func TestReconcileGCsOrphans(t *testing.T) {
	f := &fakeCluster{
		// no ApplicationSets, but a child owned (by ownerReference) by a gone set → GC'd
		apps: map[string]corev1.Application{"web-a": ownedChild("web-a", "web", "team")},
	}
	New(f, Config{}).reconcileOnce(context.Background())
	if !slices.Contains(f.deleted, "web-a") {
		t.Fatalf("an orphaned child must be GC'd, deleted = %v", f.deleted)
	}
}

func TestReconcileDoesNotTouchLabelSquatter(t *testing.T) {
	// An app that squats the reserved label but carries NO controller ownerReference is not
	// owned — a label-only guard would have GC'd/pruned it; the ownerReference guard must not.
	squatter := corev1.Application{ObjectMeta: metav1.ObjectMeta{
		Name: "web-a", Namespace: "team", Labels: map[string]string{corev1.LabelApplicationSet: "web"},
	}}
	f := &fakeCluster{apps: map[string]corev1.Application{"web-a": squatter}}
	New(f, Config{}).reconcileOnce(context.Background())
	if len(f.deleted) != 0 {
		t.Fatalf("a label-squatting app without our ownerReference must never be touched, deleted = %v", f.deleted)
	}
}

// runningChild is an owned child the node reports as Running on node. Its spec-hash
// annotation is absent, so the set always renders something different — i.e. it is a child
// pending an update, which is what the rollout tests need.
func runningChild(name, set, ns, node string) corev1.Application {
	a := ownedChild(name, set, ns)
	a.Generation = 1
	a.Spec.Placement.NodeName = node
	a.Status = corev1.ApplicationStatus{Phase: corev1.AppPhaseRunning, ObservedGeneration: 1}
	return a
}

func readyNode(name string) corev1.Node {
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.NodeStatus{Ready: true}}
}

func threeChildSet(t *testing.T) corev1.ApplicationSet {
	t.Helper()
	return *bundleSet("web", "team", comp("a", "a:v1"), comp("b", "b:v1"), comp("c", "c:v1"))
}

// TestRollingUpdateHoldsAtBudget: with maxUnavailable=1 only one changed child is updated per
// pass — the rest wait for it to come back Running, so a broken version stalls instead of
// reaching the whole set. Without a strategy every changed child converges at once.
func TestRollingUpdateHoldsAtBudget(t *testing.T) {
	existing := func() map[string]corev1.Application {
		return map[string]corev1.Application{
			"web-a": runningChild("web-a", "web", "team", "n1"),
			"web-b": runningChild("web-b", "web", "team", "n1"),
			"web-c": runningChild("web-c", "web", "team", "n1"),
		}
	}

	set := threeChildSet(t)
	set.Spec.Rollout.MaxUnavailable = 1
	f := &fakeCluster{sets: []corev1.ApplicationSet{set}, nodes: []corev1.Node{readyNode("n1")}, apps: existing()}
	New(f, Config{}).reconcileOnce(context.Background())
	if len(f.updated) != 1 || f.updated[0] != "web-a" {
		t.Fatalf("updated = %v, want exactly the first child (budget 1)", f.updated)
	}

	// No strategy → the whole set converges in one pass (the pre-rollout behaviour).
	plain := threeChildSet(t)
	f2 := &fakeCluster{sets: []corev1.ApplicationSet{plain}, nodes: []corev1.Node{readyNode("n1")}, apps: existing()}
	New(f2, Config{}).reconcileOnce(context.Background())
	if len(f2.updated) != 3 {
		t.Fatalf("updated = %v, want all three without a rollout budget", f2.updated)
	}
}

// TestRollingUpdateFixesBrokenChildrenFreely: an already-broken child is updated regardless
// of the budget — taking down something that is not running costs no availability, and the
// opposite rule DEADLOCKS the set: once every child is broken the budget is spent and the
// very change that would fix them can never land (found on a live node).
func TestRollingUpdateFixesBrokenChildrenFreely(t *testing.T) {
	broken := runningChild("web-a", "web", "team", "n1")
	broken.Status.Phase = corev1.AppPhaseFailed
	set := threeChildSet(t)
	set.Spec.Rollout.MaxUnavailable = 1
	f := &fakeCluster{
		sets:  []corev1.ApplicationSet{set},
		nodes: []corev1.Node{readyNode("n1")},
		apps: map[string]corev1.Application{
			"web-a": broken,
			"web-b": runningChild("web-b", "web", "team", "n1"),
			"web-c": runningChild("web-c", "web", "team", "n1"),
		},
	}
	New(f, Config{}).reconcileOnce(context.Background())
	if len(f.updated) != 1 || f.updated[0] != "web-a" {
		t.Fatalf("updated = %v, want the broken child fixed and the healthy ones held", f.updated)
	}
}

// TestRollingUpdateEveryChildBrokenIsNotDeadlocked: the degenerate case of the same rule —
// a set whose children are ALL down accepts the fix on all of them at once.
func TestRollingUpdateEveryChildBrokenIsNotDeadlocked(t *testing.T) {
	apps := map[string]corev1.Application{}
	for _, n := range []string{"web-a", "web-b", "web-c"} {
		child := runningChild(n, "web", "team", "n1")
		child.Status.Phase = corev1.AppPhaseFailed
		apps[n] = child
	}
	set := threeChildSet(t)
	set.Spec.Rollout.MaxUnavailable = 1
	f := &fakeCluster{sets: []corev1.ApplicationSet{set}, nodes: []corev1.Node{readyNode("n1")}, apps: apps}
	New(f, Config{}).reconcileOnce(context.Background())
	if len(f.updated) != 3 {
		t.Fatalf("updated = %v, want all three — a fully broken set must not be deadlocked by its own budget", f.updated)
	}
}

// TestSameNodeWithholdsSiblingsUntilAnchorIsPlaced: the anchor is created alone and placed by
// the scheduler; only then are the siblings created, pinned to its node. Creating them
// unpinned would scatter the set, and pinning them later would move running workloads.
func TestSameNodeWithholdsSiblingsUntilAnchorIsPlaced(t *testing.T) {
	set := threeChildSet(t)
	set.Spec.Placement.Mode = corev1.PlacementSameNode
	f := &fakeCluster{
		sets:  []corev1.ApplicationSet{set},
		nodes: []corev1.Node{readyNode("n1")},
		apps:  map[string]corev1.Application{},
	}
	c := New(f, Config{})

	c.reconcileOnce(context.Background())
	if len(f.created) != 1 || f.created[0] != "web-a" {
		t.Fatalf("created = %v, want only the anchor web-a", f.created)
	}

	anchor := f.apps["web-a"] // the scheduler places the anchor
	anchor.Spec.Placement.NodeName = "n1"
	f.apps["web-a"] = anchor

	f.created = nil
	c.reconcileOnce(context.Background())
	if len(f.created) != 2 {
		t.Fatalf("created = %v, want both siblings once the anchor is placed", f.created)
	}
	for _, name := range []string{"web-b", "web-c"} {
		if got := f.apps[name].Spec.Placement.NodeName; got != "n1" {
			t.Fatalf("sibling %s nodeName = %q, want the anchor's node n1", name, got)
		}
	}
}

// TestStatusRunningRequiresTheAppPhase: the rollup's "running" is the same signal the rollout
// gates on — a child placed on a live node whose workload is NOT running counts as scheduled,
// never as running, so the set cannot report health it does not have.
func TestStatusRunningRequiresTheAppPhase(t *testing.T) {
	nodes := []corev1.Node{readyNode("n1")}
	running := runningChild("web-a", "web", "team", "n1")
	failed := runningChild("web-b", "web", "team", "n1")
	failed.Status.Phase = corev1.AppPhaseFailed

	st := buildStatus(&corev1.ApplicationSet{}, map[string]corev1.Application{"web-a": running, "web-b": failed}, 2, nodes)
	if st.Scheduled != 2 {
		t.Fatalf("scheduled = %d, want 2", st.Scheduled)
	}
	if st.Running != 1 {
		t.Fatalf("running = %d, want 1 — a Failed workload on a Ready node is not running", st.Running)
	}
}

// TestRollingUpdateWaitsForTheObservedGeneration is the regression test for what a live node
// exposed: gating on phase alone lets a BROKEN version cross the whole set. When a node
// cannot apply a new spec it keeps the previous workload running and keeps reporting
// Running — only the generation it reports converging tells the two apart, so a child whose
// node is still on the old generation is NOT available and cannot be traded for a healthy one.
func TestRollingUpdateWaitsForTheObservedGeneration(t *testing.T) {
	stale := runningChild("web-a", "web", "team", "n1")
	stale.Generation = 2
	stale.Status.ObservedGeneration = 1 // Running, but the node still runs the old spec

	set := threeChildSet(t)
	set.Spec.Rollout.MaxUnavailable = 1
	f := &fakeCluster{
		sets:  []corev1.ApplicationSet{set},
		nodes: []corev1.Node{readyNode("n1")},
		apps: map[string]corev1.Application{
			"web-a": stale,
			"web-b": runningChild("web-b", "web", "team", "n1"),
			"web-c": runningChild("web-c", "web", "team", "n1"),
		},
	}
	New(f, Config{}).reconcileOnce(context.Background())
	if !slices.Equal(f.updated, []string{"web-a"}) {
		t.Fatalf("updated = %v, want only the child that is already off its target generation", f.updated)
	}
}
