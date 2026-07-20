package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var testNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func app(name, node, cpu, mem string) corev1.Application {
	a := corev1.Application{}
	a.Name = name
	a.Spec.NodeName = node
	if cpu != "" {
		a.Spec.Resources.Requests = corev1.ResourceAmounts{
			CPU:    resource.MustParse(cpu),
			Memory: resource.MustParse(mem),
		}
	}
	return a
}

func node(name string, capCPU, capMem string, hbAgo time.Duration) corev1.Node {
	n := corev1.Node{}
	n.Name = name
	n.Status.Ready = true
	n.Status.Heartbeat = metav1.NewTime(testNow.Add(-hbAgo))
	if capCPU != "" {
		n.Status.Capacity = corev1.ResourceAmounts{
			CPU:    resource.MustParse(capCPU),
			Memory: resource.MustParse(capMem),
		}
	}
	return n
}

type fakeCluster struct {
	apps      []corev1.Application
	nodes     []corev1.Node
	assigns   []string // "app->node" in call order
	assignErr map[string]error
}

func (f *fakeCluster) Applications(context.Context) ([]corev1.Application, error) { return f.apps, nil }
func (f *fakeCluster) Nodes(context.Context) ([]corev1.Node, error)               { return f.nodes, nil }
func (f *fakeCluster) Assign(_ context.Context, app, nodeName string) error {
	if err := f.assignErr[app]; err != nil {
		return err
	}
	f.assigns = append(f.assigns, app+"->"+nodeName)
	for i := range f.apps {
		if f.apps[i].Name == app {
			f.apps[i].Spec.NodeName = nodeName
		}
	}
	return nil
}

func run(t *testing.T, c *fakeCluster, policy Policy) []string {
	t.Helper()
	s := New(c, Config{Policy: policy})
	s.now = func() time.Time { return testNow }
	s.scheduleOnce(context.Background())
	return c.assigns
}

func TestAssignsPendingToReadyNode(t *testing.T) {
	c := &fakeCluster{
		apps:  []corev1.Application{app("web", "", "500m", "256Mi")},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second)},
	}
	if got := run(t, c, Spread); len(got) != 1 || got[0] != "web->n1" {
		t.Fatalf("assigns = %v, want [web->n1]", got)
	}
}

func TestAuthorPinnedAppIsIgnored(t *testing.T) {
	c := &fakeCluster{
		apps:  []corev1.Application{app("db", "n2", "500m", "256Mi")}, // nodeName set → pinned
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second)},
	}
	if got := run(t, c, Spread); len(got) != 0 {
		t.Fatalf("assigns = %v, want none (author-pinned)", got)
	}
}

func TestNoFitLeavesPending(t *testing.T) {
	c := &fakeCluster{
		apps:  []corev1.Application{app("big", "", "8", "1Gi")}, // 8 cpu > 4 cpu capacity
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second)},
	}
	if got := run(t, c, Spread); len(got) != 0 {
		t.Fatalf("assigns = %v, want none (does not fit)", got)
	}
}

func TestSpreadPicksLeastLoaded(t *testing.T) {
	c := &fakeCluster{
		apps: []corev1.Application{
			app("existing", "n2", "2", "4Gi"), // loads n2 to 50%
			app("web", "", "1", "1Gi"),
		},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second), node("n2", "4", "8Gi", time.Second)},
	}
	if got := run(t, c, Spread); len(got) != 1 || got[0] != "web->n1" {
		t.Fatalf("assigns = %v, want [web->n1] (spread to the empty node)", got)
	}
}

func TestBinpackPicksMostLoaded(t *testing.T) {
	c := &fakeCluster{
		apps: []corev1.Application{
			app("existing", "n2", "2", "4Gi"),
			app("web", "", "1", "1Gi"),
		},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second), node("n2", "4", "8Gi", time.Second)},
	}
	if got := run(t, c, Binpack); len(got) != 1 || got[0] != "web->n2" {
		t.Fatalf("assigns = %v, want [web->n2] (binpack onto the loaded node)", got)
	}
}

func TestSkipsUnschedulableNodes(t *testing.T) {
	notReady := node("down", "4", "8Gi", time.Second)
	notReady.Status.Ready = false
	stale := node("stale", "4", "8Gi", 10*time.Minute) // heartbeat too old
	noCap := node("fresh", "", "", time.Second)        // capacity not reported
	cordoned := node("cordon", "4", "8Gi", time.Second)
	cordoned.Spec.Unschedulable = true
	good := node("good", "4", "8Gi", time.Second)

	c := &fakeCluster{
		apps:  []corev1.Application{app("web", "", "500m", "256Mi")},
		nodes: []corev1.Node{notReady, stale, noCap, cordoned, good},
	}
	if got := run(t, c, Spread); len(got) != 1 || got[0] != "web->good" {
		t.Fatalf("assigns = %v, want [web->good] (all others unschedulable)", got)
	}
}

func TestSameCycleAccountsForEarlierPlacement(t *testing.T) {
	// A 3-cpu node and two 2-cpu apps: only the first fits; the second must see the
	// room already taken and stay pending.
	c := &fakeCluster{
		apps: []corev1.Application{
			app("a", "", "2", "1Gi"),
			app("b", "", "2", "1Gi"),
		},
		nodes: []corev1.Node{node("n1", "3", "8Gi", time.Second)},
	}
	got := run(t, c, Spread)
	if len(got) != 1 || got[0] != "a->n1" {
		t.Fatalf("assigns = %v, want only [a->n1] (b must not overcommit n1)", got)
	}
}

func TestAssignErrorLeavesPending(t *testing.T) {
	c := &fakeCluster{
		apps:      []corev1.Application{app("web", "", "500m", "256Mi")},
		nodes:     []corev1.Node{node("n1", "4", "8Gi", time.Second)},
		assignErr: map[string]error{"web": errors.New("rejected: over capacity")},
	}
	if got := run(t, c, Spread); len(got) != 0 {
		t.Fatalf("assigns = %v, want none (assign rejected)", got)
	}
}

func TestPendingOrderOldestFirst(t *testing.T) {
	older := app("older", "", "2", "1Gi")
	older.CreationTimestamp = metav1.NewTime(testNow.Add(-time.Hour))
	newer := app("newer", "", "2", "1Gi")
	newer.CreationTimestamp = metav1.NewTime(testNow)
	// 3-cpu node fits only one; the older app must win.
	c := &fakeCluster{
		apps:  []corev1.Application{newer, older}, // deliberately out of order
		nodes: []corev1.Node{node("n1", "3", "8Gi", time.Second)},
	}
	if got := run(t, c, Spread); len(got) != 1 || got[0] != "older->n1" {
		t.Fatalf("assigns = %v, want [older->n1] (oldest scheduled first)", got)
	}
}
