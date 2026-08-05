package framework

import (
	"context"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"k8s.io/apimachinery/pkg/api/resource"
)

// fakeHandle is a no-op Handle — the framework wiring tests don't exercise the writes.
type fakeHandle struct{ snap *Snapshot }

func (h fakeHandle) Snapshot() *Snapshot { return h.snap }
func (fakeHandle) Clock() time.Time      { return time.Time{} }
func (fakeHandle) PV(string, string) (corev1.PersistentVolume, bool) {
	return corev1.PersistentVolume{}, false
}
func (fakeHandle) CreatePV(context.Context, string, string, resource.Quantity) error { return nil }
func (fakeHandle) BindPV(context.Context, string, string, string) error              { return nil }
func (fakeHandle) BindApp(context.Context, string, string, string) error             { return nil }

// rejectNode filters out one named node.
type rejectNode struct{ bad string }

func (rejectNode) Name() string { return "rejectNode" }
func (p rejectNode) Filter(_ context.Context, _ *CycleState, _ *corev1.Application, n *NodeInfo) *Status {
	if n.Node.Name == p.bad {
		return NewStatus(Unschedulable, "rejected")
	}
	return nil
}

// constScore scores every node the same.
type constScore struct{ val int64 }

func (constScore) Name() string { return "constScore" }
func (p constScore) Score(_ context.Context, _ *CycleState, _ *corev1.Application, _ *NodeInfo) (int64, *Status) {
	return p.val, nil
}

// skipBinder always defers; recordBinder records the bind.
type skipBinder struct{}

func (skipBinder) Name() string { return "skipBinder" }
func (skipBinder) Bind(context.Context, *CycleState, *corev1.Application, string) *Status {
	return NewStatus(Skip, "not mine")
}

type recordBinder struct{ bound *string }

func (recordBinder) Name() string { return "recordBinder" }
func (p recordBinder) Bind(_ context.Context, _ *CycleState, app *corev1.Application, node string) *Status {
	*p.bound = app.Name + "->" + node
	return nil
}

func node(name string) *NodeInfo {
	n := corev1.Node{}
	n.Name = name
	return &NodeInfo{Node: n}
}

func mustBuild(t *testing.T, r Registry, p Profile) *Framework {
	t.Helper()
	fw, err := New(r, p, fakeHandle{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return fw
}

func TestFrameworkFilter(t *testing.T) {
	r := Registry{}
	r.Register("rejectNode", func(Handle) (Plugin, error) { return rejectNode{bad: "n2"}, nil })
	fw := mustBuild(t, r, Profile{Plugins: []string{"rejectNode"}})

	ctx, state, app := context.Background(), NewCycleState(), &corev1.Application{}
	if st := fw.RunFilter(ctx, state, app, node("n1")); !st.IsSuccess() {
		t.Fatalf("n1 should pass, got %v", st.Message())
	}
	if st := fw.RunFilter(ctx, state, app, node("n2")); st.IsSuccess() {
		t.Fatalf("n2 should be filtered out")
	}
}

func TestFrameworkScoreWeights(t *testing.T) {
	r := Registry{}
	r.Register("constScore", func(Handle) (Plugin, error) { return constScore{val: 10}, nil })
	fw := mustBuild(t, r, Profile{Plugins: []string{"constScore"}, ScoreWeights: map[string]int64{"constScore": 3}})

	scores, st := fw.RunScore(context.Background(), NewCycleState(), &corev1.Application{}, []*NodeInfo{node("n1")})
	if !st.IsSuccess() {
		t.Fatalf("score: %v", st.Message())
	}
	if scores["n1"] != 30 { // 10 * weight 3
		t.Fatalf("weighted score = %d, want 30", scores["n1"])
	}
}

func TestFrameworkBindSkipsToNext(t *testing.T) {
	var bound string
	r := Registry{}
	r.Register("skipBinder", func(Handle) (Plugin, error) { return skipBinder{}, nil })
	r.Register("recordBinder", func(Handle) (Plugin, error) { return recordBinder{bound: &bound}, nil })
	fw := mustBuild(t, r, Profile{Plugins: []string{"skipBinder", "recordBinder"}})

	app := &corev1.Application{}
	app.Name = "web"
	if st := fw.RunBind(context.Background(), NewCycleState(), app, "n1"); !st.IsSuccess() {
		t.Fatalf("bind: %v", st.Message())
	}
	if bound != "web->n1" {
		t.Fatalf("bound = %q, want web->n1 (skipBinder must defer to recordBinder)", bound)
	}
}

func TestFrameworkUnknownPlugin(t *testing.T) {
	if _, err := New(Registry{}, Profile{Plugins: []string{"missing"}}, fakeHandle{}); err == nil {
		t.Fatalf("want an error for an unregistered plugin")
	}
}

// byNameSort is a QueueSort plugin ordering apps by name.
type byNameSort struct{}

func (byNameSort) Name() string                       { return "byNameSort" }
func (byNameSort) Less(a, b *corev1.Application) bool { return a.Name < b.Name }

func appNamed(name string) corev1.Application {
	a := corev1.Application{}
	a.Name = name
	return a
}

func TestFrameworkQueueSort(t *testing.T) {
	r := Registry{}
	r.Register("byNameSort", func(Handle) (Plugin, error) { return byNameSort{}, nil })
	fw := mustBuild(t, r, Profile{Plugins: []string{"byNameSort"}})

	apps := []corev1.Application{appNamed("c"), appNamed("a"), appNamed("b")}
	fw.Sort(apps)
	if got := []string{apps[0].Name, apps[1].Name, apps[2].Name}; got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("sorted order = %v, want [a b c]", got)
	}
}

func TestFrameworkQueueSortNoop(t *testing.T) {
	// No QueueSort plugin: Sort must leave the order untouched.
	fw := mustBuild(t, Registry{}, Profile{})
	apps := []corev1.Application{appNamed("c"), appNamed("a")}
	fw.Sort(apps)
	if apps[0].Name != "c" || apps[1].Name != "a" {
		t.Fatalf("no-QueueSort Sort must not reorder, got %v", []string{apps[0].Name, apps[1].Name})
	}
}

func TestFrameworkQueueSortSingle(t *testing.T) {
	r := Registry{}
	r.Register("s1", func(Handle) (Plugin, error) { return byNameSort{}, nil })
	r.Register("s2", func(Handle) (Plugin, error) { return byNameSort{}, nil })
	if _, err := New(r, Profile{Plugins: []string{"s1", "s2"}}, fakeHandle{}); err == nil {
		t.Fatalf("want an error when two QueueSort plugins are enabled")
	}
}

func TestFrameworkPostFilterAndPermitNoop(t *testing.T) {
	fw := mustBuild(t, Registry{}, Profile{})
	ctx, state, app := context.Background(), NewCycleState(), &corev1.Application{}
	if _, st := fw.RunPostFilter(ctx, state, app, nil); st.IsSuccess() {
		t.Error("RunPostFilter with no plugin must not succeed (app stays unschedulable)")
	}
	if st := fw.RunPermit(ctx, state, app, "n1"); !st.IsSuccess() {
		t.Error("RunPermit with no plugin must succeed (no-op)")
	}
}
