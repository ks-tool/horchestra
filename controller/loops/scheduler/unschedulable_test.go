package scheduler

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"
)

// TestUnschedulableSaysSoOnTheObject: a workload nothing can place is the one an operator goes
// looking for, and it used to be the one that said nothing — the reasons went to the
// controller's journal, which is not somewhere a kubectl user can read. From outside, a
// workload no node fits and one the scheduler has not reached yet were the same object.
func TestUnschedulableSaysSoOnTheObject(t *testing.T) {
	huge := app("huge", "", "8", "16Gi") // more than either node has
	c := &fakeCluster{
		apps:  []corev1.Application{huge},
		nodes: []corev1.Node{node("n1", "2", "4Gi", time.Second), node("n2", "2", "4Gi", time.Second)},
	}
	if got := run(t, c, Spread); len(got) != 0 {
		t.Fatalf("an app that fits nowhere was placed: %v", got)
	}

	st := c.statuses["huge"]
	if st.Phase != corev1.AppPhasePending {
		t.Errorf("phase = %q, want Pending", st.Phase)
	}
	// The shape a kubectl user already reads: how many nodes were considered, and why each
	// group of them said no.
	if !strings.HasPrefix(st.Message, "0/2 nodes are available:") {
		t.Errorf("message %q does not say how many nodes were considered", st.Message)
	}
	if !strings.Contains(st.Message, "2 ") {
		t.Errorf("message %q does not group the nodes that refused for the same reason", st.Message)
	}
}

// TestUnschedulableIsWrittenOnce: the scheduler retries every cycle, so a message rewritten each
// pass would be a write per pending app per cycle — forever, for an object nobody touched — and
// every one of them wakes the watchers.
func TestUnschedulableIsWrittenOnce(t *testing.T) {
	c := &fakeCluster{
		apps:  []corev1.Application{app("huge", "", "8", "16Gi")},
		nodes: []corev1.Node{node("n1", "2", "4Gi", time.Second)},
	}
	s := New(c, Config{})
	s.now = func() time.Time { return testNow }

	s.scheduleOnce(context.Background())
	if c.statusWrites != 1 {
		t.Fatalf("the first cycle wrote %d times, want 1", c.statusWrites)
	}
	for range 3 {
		s.scheduleOnce(context.Background())
	}
	if c.statusWrites != 1 {
		t.Errorf("the reason was rewritten %d more times while nothing changed", c.statusWrites-1)
	}
}

// TestPlacementClearsTheReason: the node takes over reporting once the app is placed, but only
// once it has something to send. In between, an operator would read a placed workload still
// carrying the reason it could not be placed.
func TestPlacementClearsTheReason(t *testing.T) {
	pending := app("web", "", "1", "1Gi")
	pending.Status = corev1.ApplicationStatus{
		Phase: corev1.AppPhasePending, Message: "0/1 nodes are available: 1 insufficient cpu",
	}
	c := &fakeCluster{
		apps:  []corev1.Application{pending},
		nodes: []corev1.Node{node("n1", "2", "4Gi", time.Second)},
	}
	if got := run(t, c, Spread); len(got) != 1 {
		t.Fatalf("the app was not placed: %v", got)
	}
	if msg := c.statuses["web"].Message; msg != "" {
		t.Errorf("a placed workload still carries %q", msg)
	}
}

// TestNoNodeFitsCountsReasons: one line per node is unreadable on a fleet and reshuffles between
// cycles; the counted form is neither, and it is the form kubectl users already know. Commonest
// reason first, then alphabetically — an ordering that changes between cycles would rewrite the
// object for no reason.
func TestNoNodeFitsCountsReasons(t *testing.T) {
	if got := noNodeFits(0, nil); got != "no node is registered" {
		t.Errorf("with no nodes at all: %q", got)
	}
	filtered := map[string]*framework.Status{
		"n1": framework.NewStatus(framework.Unschedulable, "insufficient cpu"),
		"n2": framework.NewStatus(framework.Unschedulable, "insufficient cpu"),
		"n3": framework.NewStatus(framework.Unschedulable, `runtimeClass "firecracker" not advertised`),
	}
	want := `0/3 nodes are available: 2 insufficient cpu, 1 runtimeClass "firecracker" not advertised`
	for range 8 { // map iteration is unordered; the summary must not be
		if got := noNodeFits(3, filtered); got != want {
			t.Fatalf("got  %s\nwant %s", got, want)
		}
	}
}
