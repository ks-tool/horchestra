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
	a.Spec.Placement.NodeName = node
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

func pv(name, node string) corev1.PersistentVolume {
	p := corev1.PersistentVolume{}
	p.Name = name
	p.Spec.Node = node
	return p
}

// withPV adds a named pv volume to an app.
func withPV(a corev1.Application, pvName string) corev1.Application {
	a.Spec.Volumes = append(a.Spec.Volumes, corev1.VolumeMount{
		Volume: corev1.VolumeSource{Type: corev1.VolumeTypePV, Name: pvName}, MountPath: "/data/" + pvName})
	return a
}

// withImplicitPV adds a pv volume with no name (its PV defaults to the app's name).
func withImplicitPV(a corev1.Application) corev1.Application {
	a.Spec.Volumes = append(a.Spec.Volumes, corev1.VolumeMount{
		Volume: corev1.VolumeSource{Type: corev1.VolumeTypePV}, MountPath: "/data"})
	return a
}

// withTmpfs adds a tmpfs volume (references no PV) to an app.
func withTmpfs(a corev1.Application) corev1.Application {
	a.Spec.Volumes = append(a.Spec.Volumes, corev1.VolumeMount{
		Volume: corev1.VolumeSource{Type: corev1.VolumeTypeTmpfs}, MountPath: "/run"})
	return a
}

type fakeCluster struct {
	apps         []corev1.Application
	nodes        []corev1.Node
	pvs          []corev1.PersistentVolume
	assigns      []string // "app->node" in call order
	volAssigns   []string // "pv->node" in call order
	created      []string // pv names created in call order
	assignErr    map[string]error
	volAssignErr map[string]error
	createErr    map[string]error
	// statuses is the last status written per app, so a test can read what the scheduler told
	// an operator about a workload it could not place.
	statuses map[string]corev1.ApplicationStatus
	// statusWrites counts every write: the scheduler retries each cycle, and a message
	// rewritten per pass would be a write per app forever.
	statusWrites int
}

func (f *fakeCluster) UpdateAppStatus(_ context.Context, app *corev1.Application) error {
	if f.statuses == nil {
		f.statuses = map[string]corev1.ApplicationStatus{}
	}
	f.statuses[app.Name] = app.Status
	f.statusWrites++
	for i := range f.apps {
		if f.apps[i].Name == app.Name {
			f.apps[i].Status = app.Status
		}
	}
	return nil
}

func (f *fakeCluster) Applications(context.Context) ([]corev1.Application, error) { return f.apps, nil }
func (f *fakeCluster) Nodes(context.Context) ([]corev1.Node, error)               { return f.nodes, nil }
func (f *fakeCluster) Volumes(context.Context) ([]corev1.PersistentVolume, error) { return f.pvs, nil }
func (f *fakeCluster) CreateVolume(_ context.Context, _, name string, _ resource.Quantity) error {
	if err := f.createErr[name]; err != nil {
		return err
	}
	f.created = append(f.created, name)
	f.pvs = append(f.pvs, pv(name, "")) // now exists, nodeless
	return nil
}
func (f *fakeCluster) Assign(_ context.Context, _, app, nodeName string) error {
	if err := f.assignErr[app]; err != nil {
		return err
	}
	f.assigns = append(f.assigns, app+"->"+nodeName)
	for i := range f.apps {
		if f.apps[i].Name == app {
			f.apps[i].Spec.Placement.NodeName = nodeName
		}
	}
	return nil
}

func (f *fakeCluster) AssignVolume(_ context.Context, _, pvName, nodeName string) error {
	if err := f.volAssignErr[pvName]; err != nil {
		return err
	}
	f.volAssigns = append(f.volAssigns, pvName+"->"+nodeName)
	for i := range f.pvs {
		if f.pvs[i].Name == pvName {
			f.pvs[i].Spec.Node = nodeName
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

func TestCoSchedulesNodelessVolume(t *testing.T) {
	c := &fakeCluster{
		apps:  []corev1.Application{withPV(app("db", "", "500m", "256Mi"), "pgdata")},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second)},
		pvs:   []corev1.PersistentVolume{pv("pgdata", "")}, // no node yet
	}
	if got := run(t, c, Spread); len(got) != 1 || got[0] != "db->n1" {
		t.Fatalf("assigns = %v, want [db->n1]", got)
	}
	if len(c.volAssigns) != 1 || c.volAssigns[0] != "pgdata->n1" {
		t.Fatalf("volAssigns = %v, want [pgdata->n1] (co-scheduled to the app's node)", c.volAssigns)
	}
}

func TestBoundVolumeConstrainsPlacement(t *testing.T) {
	// Two empty nodes: spread would pick n1 (name order), but the volume is backed on
	// n2, so the app must follow its data to n2.
	c := &fakeCluster{
		apps:  []corev1.Application{withPV(app("db", "", "1", "1Gi"), "pgdata")},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second), node("n2", "4", "8Gi", time.Second)},
		pvs:   []corev1.PersistentVolume{pv("pgdata", "n2")},
	}
	if got := run(t, c, Spread); len(got) != 1 || got[0] != "db->n2" {
		t.Fatalf("assigns = %v, want [db->n2] (volume-constrained, overriding spread)", got)
	}
	if len(c.volAssigns) != 0 {
		t.Fatalf("volAssigns = %v, want none (PV already bound)", c.volAssigns)
	}
}

func TestCoSchedulesVolumeForPinnedApp(t *testing.T) {
	// Author pinned the app to n1 but left the volume's node blank: the scheduler binds
	// the volume to the app's node without touching the app.
	c := &fakeCluster{
		apps:  []corev1.Application{withPV(app("db", "n1", "500m", "256Mi"), "pgdata")},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second)},
		pvs:   []corev1.PersistentVolume{pv("pgdata", "")},
	}
	if got := run(t, c, Spread); len(got) != 0 {
		t.Fatalf("assigns = %v, want none (app author-pinned)", got)
	}
	if len(c.volAssigns) != 1 || c.volAssigns[0] != "pgdata->n1" {
		t.Fatalf("volAssigns = %v, want [pgdata->n1] (co-scheduled to the pinned node)", c.volAssigns)
	}
}

func TestConflictingVolumesLeavePending(t *testing.T) {
	a := withPV(withPV(app("db", "", "500m", "256Mi"), "vol-a"), "vol-b")
	c := &fakeCluster{
		apps:  []corev1.Application{a},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second), node("n2", "4", "8Gi", time.Second)},
		pvs:   []corev1.PersistentVolume{pv("vol-a", "n1"), pv("vol-b", "n2")}, // two nodes
	}
	got := run(t, c, Spread)
	if len(got) != 0 || len(c.volAssigns) != 0 {
		t.Fatalf("assigns=%v volAssigns=%v, want none (mounts on conflicting nodes)", got, c.volAssigns)
	}
}

func TestImplicitlyCreatesNamedVolume(t *testing.T) {
	// The named pv does not exist yet: the scheduler creates it, then schedules the app
	// and co-schedules the fresh volume onto the chosen node — all in one cycle.
	c := &fakeCluster{
		apps:  []corev1.Application{withPV(app("db", "", "500m", "256Mi"), "pgdata")},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second)},
		pvs:   nil,
	}
	if got := run(t, c, Spread); len(got) != 1 || got[0] != "db->n1" {
		t.Fatalf("assigns = %v, want [db->n1]", got)
	}
	if len(c.created) != 1 || c.created[0] != "pgdata" {
		t.Fatalf("created = %v, want [pgdata] (implicitly provisioned)", c.created)
	}
	if len(c.volAssigns) != 1 || c.volAssigns[0] != "pgdata->n1" {
		t.Fatalf("volAssigns = %v, want [pgdata->n1] (co-scheduled after creation)", c.volAssigns)
	}
}

func TestImplicitVolumeDefaultsToAppName(t *testing.T) {
	// A pv volume with no name and no separate PersistentVolume — the postgres example's
	// shape. The PV is named after the Application, created, and co-scheduled.
	c := &fakeCluster{
		apps:  []corev1.Application{withImplicitPV(app("postgres", "", "500m", "256Mi"))},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second)},
	}
	if got := run(t, c, Spread); len(got) != 1 || got[0] != "postgres->n1" {
		t.Fatalf("assigns = %v, want [postgres->n1]", got)
	}
	if len(c.created) != 1 || c.created[0] != "postgres" {
		t.Fatalf("created = %v, want [postgres] (PV named after the app)", c.created)
	}
	if len(c.volAssigns) != 1 || c.volAssigns[0] != "postgres->n1" {
		t.Fatalf("volAssigns = %v, want [postgres->n1]", c.volAssigns)
	}
}

func TestBoundVolumeOnFullNodeLeavesPending(t *testing.T) {
	// The volume pins db to n1, but n1 is already full — db waits for n1 rather than
	// spilling onto the empty n2 (its data is on n1).
	c := &fakeCluster{
		apps: []corev1.Application{
			app("filler", "n1", "4", "8Gi"), // fills n1
			withPV(app("db", "", "1", "1Gi"), "pgdata"),
		},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second), node("n2", "4", "8Gi", time.Second)},
		pvs:   []corev1.PersistentVolume{pv("pgdata", "n1")},
	}
	if got := run(t, c, Spread); len(got) != 0 {
		t.Fatalf("assigns = %v, want none (db's volume pins it to the full n1)", got)
	}
}

func TestTmpfsMountDoesNotConstrain(t *testing.T) {
	c := &fakeCluster{
		apps:  []corev1.Application{withTmpfs(app("cache", "", "500m", "256Mi"))},
		nodes: []corev1.Node{node("n1", "4", "8Gi", time.Second)},
	}
	if got := run(t, c, Spread); len(got) != 1 || got[0] != "cache->n1" {
		t.Fatalf("assigns = %v, want [cache->n1] (tmpfs is not a PV)", got)
	}
	if len(c.volAssigns) != 0 {
		t.Fatalf("volAssigns = %v, want none (tmpfs references no PV)", c.volAssigns)
	}
}
