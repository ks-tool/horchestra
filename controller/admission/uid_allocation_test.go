package admission

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

func nsWithRange(name, rng string) corev1.Namespace {
	ns := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if rng != "" {
		ns.Annotations = map[string]string{corev1.UIDRangeAnnotation: rng}
	}
	return ns
}

func appWithUID(ns, name string, uid int64) corev1.Application {
	return corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.ApplicationSpec{SecurityContext: &corev1.SecurityContext{RunAsUser: &uid}},
	}
}

// TestNamespaceGetsItsOwnBlock: each namespace is handed a private block of host ids, and two
// namespaces never get the same one — the block is what separates one tenant's data from the next.
func TestNamespaceGetsItsOwnBlock(t *testing.T) {
	u := uidAllocation{lister: fakeLister{namespaces: []corev1.Namespace{
		nsWithRange("a", corev1.IDRange{Min: corev1.WorkloadUIDBase, Size: corev1.WorkloadUIDBlock}.String()),
	}}}
	ns := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "b"}}
	if err := u.Admit(t.Context(), &Attributes{Operation: Create, Object: &ns}); err != nil {
		t.Fatal(err)
	}
	got, err := corev1.ParseIDRange(ns.Annotations[corev1.UIDRangeAnnotation])
	if err != nil {
		t.Fatalf("namespace must be annotated with a parseable block: %v", err)
	}
	if got.Min == corev1.WorkloadUIDBase {
		t.Fatalf("block %s collides with the one namespace \"a\" already holds", got)
	}
	if got.Min != corev1.WorkloadUIDBase+corev1.WorkloadUIDBlock {
		t.Errorf("want the first free block, got %s", got)
	}

	// An existing block is never moved: it is what the namespace's data is already owned by.
	pinned := nsWithRange("c", "2000000000/1000")
	if err := u.Admit(t.Context(), &Attributes{Operation: Create, Object: &pinned}); err != nil {
		t.Fatal(err)
	}
	if pinned.Annotations[corev1.UIDRangeAnnotation] != "2000000000/1000" {
		t.Errorf("an assigned block must survive, got %q", pinned.Annotations[corev1.UIDRangeAnnotation])
	}
}

// TestApplicationGetsADistinctIDInItsBlock: the workload's id comes from the control plane, out
// of its own namespace's block, and no two workloads in a namespace share one.
func TestApplicationGetsADistinctIDInItsBlock(t *testing.T) {
	block := corev1.IDRange{Min: corev1.WorkloadUIDBase, Size: corev1.WorkloadUIDBlock}
	u := uidAllocation{lister: fakeLister{
		namespaces: []corev1.Namespace{nsWithRange("team", block.String())},
		apps:       []corev1.Application{appWithUID("team", "first", block.Min)},
	}}
	app := corev1.Application{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "team"}}
	if err := u.Admit(t.Context(), &Attributes{Operation: Create, Object: &app}); err != nil {
		t.Fatal(err)
	}
	sc := app.Spec.SecurityContext
	if sc == nil || sc.RunAsUser == nil {
		t.Fatal("the workload must be given an id")
	}
	if *sc.RunAsUser == block.Min {
		t.Fatal("the id must not collide with the one the sibling application already holds")
	}
	if !block.Contains(*sc.RunAsUser) {
		t.Fatalf("id %d is outside the namespace block %s", *sc.RunAsUser, block)
	}
	// The group is the namespace's, not the workload's own: with distinct uids the group is the
	// only thing left that can let two workloads share a PersistentVolume.
	if sc.RunAsGroup == nil || *sc.RunAsGroup != block.Min {
		t.Errorf("runAsGroup must be the namespace's group %d, got %v", block.Min, sc.RunAsGroup)
	}

	// An id already on the object is never reassigned — the workload's data is owned by it.
	pinned := appWithUID("team", "third", block.Min+500)
	if err := u.Admit(t.Context(), &Attributes{Operation: Create, Object: &pinned}); err != nil {
		t.Fatal(err)
	}
	if *pinned.Spec.SecurityContext.RunAsUser != block.Min+500 {
		t.Error("an assigned id must survive admission unchanged")
	}
}

// TestWorkloadCannotBorrowAnotherNamespacesID is the point of the whole thing. Workloads share
// the host PID namespace, so an id is a tenancy boundary: if a manifest could name an id out of
// someone else's block, /proc/<pid>/root would hand it that tenant's rootfs, volumes and secrets.
func TestWorkloadCannotBorrowAnotherNamespacesID(t *testing.T) {
	mine := corev1.IDRange{Min: corev1.WorkloadUIDBase, Size: corev1.WorkloadUIDBlock}
	theirs := corev1.IDRange{Min: corev1.WorkloadUIDBase + corev1.WorkloadUIDBlock, Size: corev1.WorkloadUIDBlock}
	u := uidAllocation{lister: fakeLister{namespaces: []corev1.Namespace{
		nsWithRange("mine", mine.String()),
		nsWithRange("theirs", theirs.String()),
	}}}

	stolen := appWithUID("mine", "thief", theirs.Min)
	err := u.Validate(t.Context(), &Attributes{Operation: Create, Object: &stolen})
	if err == nil {
		t.Fatal("an id from another namespace's block must be refused")
	}
	if !strings.Contains(err.Error(), "outside namespace") {
		t.Errorf("the refusal must say why, got: %v", err)
	}

	// The same check covers the gid, which carries group ownership of everything written.
	gid := theirs.Min
	borrowedGroup := appWithUID("mine", "sneaky", mine.Min)
	borrowedGroup.Spec.SecurityContext.RunAsGroup = &gid
	if err := u.Validate(t.Context(), &Attributes{Operation: Create, Object: &borrowedGroup}); err == nil {
		t.Error("a gid from another namespace's block must be refused too")
	}

	// An id from the namespace's own block is exactly what is allowed.
	ok := appWithUID("mine", "honest", mine.Min+7)
	if err := u.Validate(t.Context(), &Attributes{Operation: Create, Object: &ok}); err != nil {
		t.Errorf("an id inside the namespace's own block must pass: %v", err)
	}
}

// TestNoBlockLeavesTheFloorInCharge: a namespace with no block annotation (a direct storage
// write, or one created before the allocator ran) must not wedge every workload in it — the
// compiled floor's sentinel stands in and nothing is confined.
func TestNoBlockLeavesTheFloorInCharge(t *testing.T) {
	u := uidAllocation{lister: fakeLister{namespaces: []corev1.Namespace{nsWithRange("plain", "")}}}
	app := corev1.Application{ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "plain"}}
	if err := u.Admit(t.Context(), &Attributes{Operation: Create, Object: &app}); err != nil {
		t.Fatalf("a namespace with no block must not fail admission: %v", err)
	}
	if app.Spec.SecurityContext != nil && app.Spec.SecurityContext.RunAsUser != nil {
		t.Error("with no block there is nothing to allocate from; the floor assigns the sentinel")
	}
	if err := u.Validate(t.Context(), &Attributes{Operation: Create, Object: &app}); err != nil {
		t.Errorf("with no block there is nothing to confine to: %v", err)
	}
}

// TestNamespaceSharesOneGroupSoAVolumeCanBeShared: distinct uids mean a uid can no longer be what
// lets two workloads use the same PersistentVolume. The namespace's group is what replaces it, so
// every workload in a namespace has to land on the same one — and workloads in another namespace
// must not, or the volume would be reachable across the tenancy boundary.
func TestNamespaceSharesOneGroupSoAVolumeCanBeShared(t *testing.T) {
	mine := corev1.IDRange{Min: corev1.WorkloadUIDBase, Size: corev1.WorkloadUIDBlock}
	theirs := corev1.IDRange{Min: corev1.WorkloadUIDBase + corev1.WorkloadUIDBlock, Size: corev1.WorkloadUIDBlock}
	u := uidAllocation{lister: fakeLister{namespaces: []corev1.Namespace{
		nsWithRange("mine", mine.String()),
		nsWithRange("theirs", theirs.String()),
	}}}

	group := func(ns, name string) int64 {
		app := corev1.Application{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
		if err := u.Admit(t.Context(), &Attributes{Operation: Create, Object: &app}); err != nil {
			t.Fatal(err)
		}
		return *app.Spec.SecurityContext.RunAsGroup
	}
	a, b := group("mine", "one"), group("mine", "two")
	if a != b {
		t.Errorf("two workloads in one namespace must share a group so they can share a volume, got %d and %d", a, b)
	}
	if other := group("theirs", "three"); other == a {
		t.Errorf("a different namespace must get a different group, both got %d", other)
	}

	// A group borrowed from another namespace's block is exactly how a tenant would reach that
	// tenant's volume data, so it is refused like any other borrowed id.
	gid := theirs.Min
	borrowed := appWithUID("mine", "thief", mine.Min)
	borrowed.Spec.SecurityContext.RunAsGroup = &gid
	if err := u.Validate(t.Context(), &Attributes{Operation: Create, Object: &borrowed}); err == nil {
		t.Error("a group from another namespace's block must be refused")
	}
}
