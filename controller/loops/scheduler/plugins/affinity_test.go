package plugins

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- test harness ---

type fakeHandle struct{ snap *framework.Snapshot }

func (h fakeHandle) Snapshot() *framework.Snapshot { return h.snap }
func (fakeHandle) Clock() time.Time                { return time.Time{} }
func (fakeHandle) PV(string, string) (corev1.PersistentVolume, bool) {
	return corev1.PersistentVolume{}, false
}
func (fakeHandle) CreatePV(context.Context, string, string, resource.Quantity) error { return nil }
func (fakeHandle) BindPV(context.Context, string, string, string) error              { return nil }
func (fakeHandle) BindApp(context.Context, string, string, string) error             { return nil }

// node builds a Node the way a live one exists: labels is the operator's spec.labels, and the
// derived set the controller stamps on every heartbeat is present because it always is. That is
// what makes topologyKey: horchestra.io/hostname work with nobody having typed it — before the
// derivation existed, no node carried the label and per-host anti-affinity matched nothing.
func node(name string, labels map[string]string) corev1.Node {
	n := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status:     corev1.NodeStatus{Platform: corev1.Platform{OS: "linux", Arch: "amd64"}},
	}
	n.Status.Labels = corev1.DerivedNodeLabels(&n)
	return n
}

func nodeInfo(name string, labels map[string]string, apps ...framework.PlacedApp) *framework.NodeInfo {
	return &framework.NodeInfo{Node: node(name, labels), Apps: apps}
}

func app(ns, name string, labels map[string]string, aff *corev1.Affinity) *corev1.Application {
	return &corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec:       corev1.ApplicationSpec{Placement: corev1.Placement{Affinity: aff}},
	}
}

func names(infos []*framework.NodeInfo) string {
	var out []string
	for _, ni := range infos {
		out = append(out, ni.Node.Name)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// --- Snapshot.Domain ---

func TestSnapshotDomain(t *testing.T) {
	n1 := nodeInfo("n1", map[string]string{"zone": "a"})
	n2 := nodeInfo("n2", map[string]string{"zone": "a"})
	n3 := nodeInfo("n3", map[string]string{"zone": "b"})
	s := framework.NewSnapshot([]*framework.NodeInfo{n1, n2, n3})

	if got := names(s.Domain("n1", corev1.LabelHostname)); got != "n1" {
		t.Errorf("per-host domain of n1 = %q, want n1", got)
	}
	if got := names(s.Domain("n1", "zone")); got != "n1,n2" {
		t.Errorf("zone domain of n1 = %q, want n1,n2", got)
	}
	if got := names(s.Domain("n1", "missing")); got != "n1" {
		t.Errorf("missing-key domain of n1 = %q, want n1 (singleton)", got)
	}
	if got := s.Domain("nope", corev1.LabelHostname); got != nil {
		t.Errorf("domain of an unknown node = %v, want nil", got)
	}
}

// TestNodeAffinityMatchesDerivedLabels: the labels the control plane derives from a node's own
// report are matchable by exactly the same rules as an operator's — an app whose image is not
// multi-arch pins itself with horchestra.io/arch and needs nobody to have labelled the fleet.
// A spec entry cannot shadow one: admission refuses that key, and if a Node stored before that
// refusal carries it, the derived value still wins here.
func TestNodeAffinityMatchesDerivedLabels(t *testing.T) {
	p := NewNodeAffinity()
	ctx, st := context.Background(), framework.NewCycleState()
	ni := nodeInfo("n1", map[string]string{"tier": "secure", corev1.LabelArch: "arm64"})

	fits := func(sel map[string]string) bool {
		return p.Filter(ctx, st, &corev1.Application{Spec: corev1.ApplicationSpec{Placement: corev1.Placement{NodeSelector: sel}}}, ni).IsSuccess()
	}
	if !fits(map[string]string{corev1.LabelArch: "amd64"}) {
		t.Error("a selector on the derived arch must match the reported one")
	}
	if fits(map[string]string{corev1.LabelArch: "arm64"}) {
		t.Error("a spec.labels entry shadowed the measured architecture")
	}
	if !fits(map[string]string{corev1.LabelOS: "linux", "tier": "secure"}) {
		t.Error("derived and operator labels must match together, as one set of keys")
	}
	if !fits(map[string]string{corev1.LabelHostname: "n1"}) {
		t.Error("the hostname label must be matchable without anyone having set it")
	}
}

// --- NodeAffinity ---

func TestNodeAffinityFilter(t *testing.T) {
	p := NewNodeAffinity()
	ctx, st := context.Background(), framework.NewCycleState()
	labels := map[string]string{"disktype": "ssd", "gpu": "true"}
	ni := nodeInfo("n1", labels)

	fits := func(a *corev1.Application) bool { return p.Filter(ctx, st, a, ni).IsSuccess() }

	if !fits(app("t", "a", nil, nil)) {
		t.Error("no constraints must fit")
	}
	if !fits(&corev1.Application{Spec: corev1.ApplicationSpec{Placement: corev1.Placement{NodeSelector: map[string]string{"disktype": "ssd"}}}}) {
		t.Error("matching nodeSelector must fit")
	}
	if fits(&corev1.Application{Spec: corev1.ApplicationSpec{Placement: corev1.Placement{NodeSelector: map[string]string{"disktype": "hdd"}}}}) {
		t.Error("non-matching nodeSelector must not fit")
	}
	req := func(r corev1.NodeSelector) *corev1.Affinity {
		return &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{Required: &r}}
	}
	cases := []struct {
		name string
		sel  corev1.NodeSelector
		fits bool
	}{
		{"matchLabels ok", corev1.NodeSelector{MatchLabels: map[string]string{"disktype": "ssd"}}, true},
		{"In ok", corev1.NodeSelector{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "disktype", Operator: corev1.NodeSelectorOpIn, Values: []string{"ssd", "nvme"}}}}, true},
		{"In miss", corev1.NodeSelector{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "disktype", Operator: corev1.NodeSelectorOpIn, Values: []string{"nvme"}}}}, false},
		{"NotIn ok", corev1.NodeSelector{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "disktype", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"hdd"}}}}, true},
		{"NotIn miss", corev1.NodeSelector{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "disktype", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"ssd"}}}}, false},
		{"Exists ok", corev1.NodeSelector{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "gpu", Operator: corev1.NodeSelectorOpExists}}}, true},
		{"Exists miss", corev1.NodeSelector{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "tpu", Operator: corev1.NodeSelectorOpExists}}}, false},
		{"DoesNotExist ok", corev1.NodeSelector{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "tpu", Operator: corev1.NodeSelectorOpDoesNotExist}}}, true},
		{"DoesNotExist miss", corev1.NodeSelector{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "gpu", Operator: corev1.NodeSelectorOpDoesNotExist}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if fits(app("t", "a", nil, req(tc.sel))) != tc.fits {
				t.Errorf("fits=%v, want %v", !tc.fits, tc.fits)
			}
		})
	}
}

func TestNodeAffinityScore(t *testing.T) {
	p := NewNodeAffinity()
	ctx, st := context.Background(), framework.NewCycleState()
	n1 := nodeInfo("n1", map[string]string{"tier": "gold"})
	n2 := nodeInfo("n2", map[string]string{"tier": "silver"})
	a := app("t", "a", nil, &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
		Preferred: []corev1.PreferredNodeTerm{{Weight: 10, Preference: corev1.NodeSelector{MatchLabels: map[string]string{"tier": "gold"}}}},
	}})
	if st2 := p.PreScore(ctx, st, a, []*framework.NodeInfo{n1, n2}); !st2.IsSuccess() {
		t.Fatalf("PreScore: %v", st2)
	}
	s1, _ := p.Score(ctx, st, a, n1)
	s2, _ := p.Score(ctx, st, a, n2)
	if s1 != framework.MaxNodeScore || s2 != 0 {
		t.Errorf("scores n1=%d n2=%d, want %d and 0 (preferred node ranks top)", s1, s2, framework.MaxNodeScore)
	}
}

// --- WorkloadAffinity ---

func placed(ns, name string, labels map[string]string, anti ...corev1.WorkloadAffinityTerm) framework.PlacedApp {
	return framework.PlacedApp{Namespace: ns, Name: name, Labels: labels, AntiAffinity: anti}
}

func term(sel map[string]string) corev1.WorkloadAffinityTerm {
	return corev1.WorkloadAffinityTerm{LabelSelector: sel, TopologyKey: corev1.LabelHostname}
}

func TestWorkloadAffinityRequiredColocate(t *testing.T) {
	ctx, st := context.Background(), framework.NewCycleState()
	// n1 hosts a db; n2 hosts nothing.
	n1 := nodeInfo("n1", nil, placed("team", "db", map[string]string{"app": "db"}))
	n2 := nodeInfo("n2", nil)
	p := NewWorkloadAffinity(fakeHandle{framework.NewSnapshot([]*framework.NodeInfo{n1, n2})})
	a := app("team", "web", map[string]string{"app": "web"}, &corev1.Affinity{
		WorkloadAffinity: &corev1.WorkloadAffinity{Required: []corev1.WorkloadAffinityTerm{term(map[string]string{"app": "db"})}},
	})
	if !p.Filter(ctx, st, a, n1).IsSuccess() {
		t.Error("must co-locate onto the node hosting db")
	}
	if p.Filter(ctx, st, a, n2).IsSuccess() {
		t.Error("must reject a node with no db in its host domain")
	}
}

func TestWorkloadAntiAffinityRequiredSpread(t *testing.T) {
	ctx, st := context.Background(), framework.NewCycleState()
	n1 := nodeInfo("n1", nil, placed("team", "web-0", map[string]string{"app": "web"}))
	n2 := nodeInfo("n2", nil)
	p := NewWorkloadAffinity(fakeHandle{framework.NewSnapshot([]*framework.NodeInfo{n1, n2})})
	a := app("team", "web-1", map[string]string{"app": "web"}, &corev1.Affinity{
		WorkloadAntiAffinity: &corev1.WorkloadAffinity{Required: []corev1.WorkloadAffinityTerm{term(map[string]string{"app": "web"})}},
	})
	if p.Filter(ctx, st, a, n1).IsSuccess() {
		t.Error("must not place a second web on the host already running one")
	}
	if !p.Filter(ctx, st, a, n2).IsSuccess() {
		t.Error("must place on the empty host")
	}
	// Cross-namespace peer must NOT count (same-namespace-only selectors).
	n1.Apps[0].Namespace = "other"
	if !p.Filter(ctx, st, a, n1).IsSuccess() {
		t.Error("a peer in another namespace must not trigger anti-affinity")
	}
}

func TestWorkloadAntiAffinitySymmetry(t *testing.T) {
	ctx, st := context.Background(), framework.NewCycleState()
	// A placed app B repels app=web on the host; the new app A (app=web) carries NO
	// affinity of its own — symmetry must still keep it off B's host.
	b := placed("team", "b", map[string]string{"app": "b"}, term(map[string]string{"app": "web"}))
	n1 := nodeInfo("n1", nil, b)
	n2 := nodeInfo("n2", nil)
	p := NewWorkloadAffinity(fakeHandle{framework.NewSnapshot([]*framework.NodeInfo{n1, n2})})
	a := app("team", "web", map[string]string{"app": "web"}, nil)
	if p.Filter(ctx, st, a, n1).IsSuccess() {
		t.Error("symmetry: must not place A where an already-placed B repels it")
	}
	if !p.Filter(ctx, st, a, n2).IsSuccess() {
		t.Error("A must fit a host B does not repel it on")
	}
}

func TestWorkloadAntiAffinitySymmetryKeylessNode(t *testing.T) {
	ctx, st := context.Background(), framework.NewCycleState()
	// B is placed on n1 with a required anti-affinity keyed on "zone" — a label NEITHER node
	// carries. A keyless node is its own singleton domain (Snapshot.Domain), so B still repels
	// app=web from its own node n1; the symmetry check must enforce that. The old hand-rolled
	// sameDomain returned false whenever the key was absent, silently skipping the check and
	// letting A land on n1 next to the app repelling it.
	zoneAnti := corev1.WorkloadAffinityTerm{LabelSelector: map[string]string{"app": "web"}, TopologyKey: "zone"}
	b := placed("team", "b", map[string]string{"app": "b"}, zoneAnti)
	n1 := nodeInfo("n1", nil, b) // no "zone" label
	n2 := nodeInfo("n2", nil)    // no "zone" label
	p := NewWorkloadAffinity(fakeHandle{framework.NewSnapshot([]*framework.NodeInfo{n1, n2})})
	a := app("team", "web", map[string]string{"app": "web"}, nil)

	if p.Filter(ctx, st, a, n1).IsSuccess() {
		t.Error("symmetry: B on the keyless node n1 must still repel app=web from n1 itself")
	}
	if !p.Filter(ctx, st, a, n2).IsSuccess() {
		t.Error("app=web must fit n2, which is outside B's singleton domain")
	}
}

func TestWorkloadAffinitySameCycleReserve(t *testing.T) {
	ctx, st := context.Background(), framework.NewCycleState()
	n1 := nodeInfo("n1", nil)
	n2 := nodeInfo("n2", nil)
	p := NewWorkloadAffinity(fakeHandle{framework.NewSnapshot([]*framework.NodeInfo{n1, n2})})
	anti := &corev1.Affinity{WorkloadAntiAffinity: &corev1.WorkloadAffinity{Required: []corev1.WorkloadAffinityTerm{term(map[string]string{"app": "web"})}}}
	first := app("team", "web-0", map[string]string{"app": "web"}, anti)
	second := app("team", "web-1", map[string]string{"app": "web"}, anti)

	if !p.Filter(ctx, st, second, n1).IsSuccess() {
		t.Fatal("precondition: n1 empty, second must fit")
	}
	// Place first on n1 this cycle → its presence must repel second from n1.
	p.Reserve(ctx, st, first, "n1")
	if p.Filter(ctx, st, second, n1).IsSuccess() {
		t.Error("same-cycle: after reserving web-0 on n1, web-1 must be repelled")
	}
	if !p.Filter(ctx, st, second, n2).IsSuccess() {
		t.Error("web-1 must still fit the empty n2")
	}
	// Rolling back the reservation restores feasibility.
	p.Unreserve(ctx, st, first, "n1")
	if !p.Filter(ctx, st, second, n1).IsSuccess() {
		t.Error("unreserve must restore n1 feasibility")
	}
}
