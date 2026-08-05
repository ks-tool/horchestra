package nodeserver

import (
	"context"
	"encoding/json"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	apischeme "github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/controller/internal/memory"
)

// fleet builds a control plane with two nodes that have reported addresses, which is the state
// every test here starts from: a workload's address means nothing without a node's.
func fleet(t *testing.T) *fakeController {
	t.Helper()
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	ctl := &fakeController{store: store, sch: sch}
	for name, ip := range map[string]string{nodeName: "10.0.0.1", "node-2": "10.0.0.2"} {
		mustCreateNode(t, ctl, name)
		reportNodeIP(t, ctl, name, ip)
	}
	return ctl
}

func reportNodeIP(t *testing.T, ctl *fakeController, name, ip string) {
	t.Helper()
	n := &corev1.Node{}
	n.APIVersion, n.Kind, n.Name = corev1.GroupVersion.String(), "Node", name
	n.Status = corev1.NodeStatus{IP: ip, Ready: true}
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.UpdateSubresource(context.Background(),
		corev1.GroupVersion.WithKind("Node"), "status", b, ""); err != nil {
		t.Fatalf("report the address of %s: %v", name, err)
	}
}

// isolated seeds a workload with a network of its own, optionally already wired at addr — which is
// a STATUS write, because an address becomes durable only once the node that wired it says so.
func isolated(t *testing.T, ctl *fakeController, name, node, service, addr string) {
	t.Helper()
	body := `{"metadata":{"name":"` + name + `"},"spec":{"image":"reg/` + name + `:v1","hostNetwork":false` +
		`,"ports":[{"name":"http","port":8080}],"serviceName":"` + service + `"` +
		`,"placement":{"nodeName":"` + node + `"}}}`
	obj, err := ctl.Create(context.Background(), corev1.GroupVersion.WithKind("Application"), []byte(body), "")
	if err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	if addr == "" {
		return
	}
	// The object as it was CREATED, so the report lands on it: a hand-built one carries no
	// namespace, uid or resourceVersion, and the write goes somewhere else entirely.
	app, ok := obj.(*corev1.Application)
	if !ok {
		t.Fatalf("seed %s: got %T", name, obj)
	}
	app.Status = corev1.ApplicationStatus{Phase: "Running", Address: addr}
	b, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.UpdateSubresource(context.Background(),
		corev1.GroupVersion.WithKind("Application"), "status", b, app.Namespace); err != nil {
		t.Fatalf("report the address of %s: %v", name, err)
	}
}

func mustCreateService(t *testing.T, ctl *fakeController, name, clusterIP string) {
	t.Helper()
	body := `{"metadata":{"name":"` + name + `"},"spec":{"clusterIP":"` + clusterIP + `"` +
		`,"ports":[{"port":80,"targetName":"http","protocol":"TCP"}]}}`
	if _, err := ctl.Create(context.Background(), corev1.GroupVersion.WithKind("Service"), []byte(body), ""); err != nil {
		t.Fatalf("seed service %s: %v", name, err)
	}
}

// TestEveryNodeLearnsWhereTheFleetsAddressesLive: applications are node-scoped in the push and
// deliberately are not here. A datapath forwarding a flat address range has to know where EVERY
// address lives — a node told only about its own workloads could reach nothing else — so this is
// where least exposure stops, and it stops on purpose.
func TestEveryNodeLearnsWhereTheFleetsAddressesLive(t *testing.T) {
	ctl := fleet(t)
	isolated(t, ctl, "elsewhere", "node-2", "", "10.244.0.7/32")

	ds, _, err := New(ctl).desiredState(context.Background(), nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if len(ds.Applications) != 0 {
		t.Fatalf("another node's application reached this node: %d", len(ds.Applications))
	}
	if len(ds.Routes) != 1 {
		t.Fatalf("routes = %d, want the one workload the fleet has", len(ds.Routes))
	}
	if got, want := ds.Routes[0].GetCidr(), "10.244.0.7/32"; got != want {
		t.Errorf("cidr = %q, want %q — an address is a host route, never a block", got, want)
	}
	if got, want := ds.Routes[0].GetNodeIp(), "10.0.0.2"; got != want {
		t.Errorf("node = %q, want %q", got, want)
	}
}

// TestAWorkloadWithNoAddressYetIsNotRouted: the address becomes real when the node that wired it
// reports it. Routing to one that was only chosen would send packets at a namespace that does not
// exist yet, on a node that may still refuse to start it.
func TestAWorkloadWithNoAddressYetIsNotRouted(t *testing.T) {
	ctl := fleet(t)
	isolated(t, ctl, "starting", "node-2", "", "")

	ds, _, err := New(ctl).desiredState(context.Background(), nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if len(ds.Routes) != 0 {
		t.Fatalf("routes = %d, want none until a node reports one", len(ds.Routes))
	}
}

// TestAClusterIPIsProgrammedFromItsMembers: the rule the datapath answers with is derived from the
// same objects the catalog is, and it fronts BOTH kinds of workload — an isolated one at its own
// address, a host-network one at its node's. That is what makes a ClusterIP work on a mixed fleet.
func TestAClusterIPIsProgrammedFromItsMembers(t *testing.T) {
	ctl := fleet(t)
	mustCreateService(t, ctl, "api", "10.96.0.10")
	isolated(t, ctl, "api-a", nodeName, "api", "10.244.0.3/32")
	// A host-network member: its address is its node's, and it never gets a route of its own.
	body := `{"metadata":{"name":"api-b"},"spec":{"image":"reg/api:v1","serviceName":"api"` +
		`,"ports":[{"name":"http","port":9000}],"placement":{"nodeName":"node-2"}}}`
	if _, err := ctl.Create(context.Background(), corev1.GroupVersion.WithKind("Application"), []byte(body), ""); err != nil {
		t.Fatalf("seed api-b: %v", err)
	}

	ds, _, err := New(ctl).desiredState(context.Background(), nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if len(ds.Services) != 1 {
		t.Fatalf("services = %d, want the one that has an address", len(ds.Services))
	}
	rule := ds.Services[0]
	if rule.GetClusterIp() != "10.96.0.10" || rule.GetPort() != 80 || rule.GetProtocol() != "TCP" {
		t.Errorf("rule = %s:%d/%s, want the service's own vocabulary", rule.GetClusterIp(), rule.GetPort(), rule.GetProtocol())
	}
	got := map[string]int32{}
	for _, b := range rule.GetBackends() {
		got[b.GetAddress()] = b.GetPort()
	}
	// The target port is the INSTANCE's, resolved by name — the whole point of targetName is that
	// two members listening on different ports are still one service.
	want := map[string]int32{"10.244.0.3": 8080, "10.0.0.2": 9000}
	if len(got) != len(want) {
		t.Fatalf("backends = %v, want %v", got, want)
	}
	for addr, port := range want {
		if got[addr] != port {
			t.Errorf("backend %s = %d, want %d", addr, got[addr], port)
		}
	}
}

// TestAServiceWithNoAddressIsNotProgrammed: a Service without a clusterIP is a catalog name and
// nothing for a datapath to answer. Programming it would need an address to key the rule by, and
// there is none.
func TestAServiceWithNoAddressIsNotProgrammed(t *testing.T) {
	ctl := fleet(t)
	mustCreateService(t, ctl, "named", "")
	isolated(t, ctl, "member", nodeName, "named", "10.244.0.4/32")

	ds, _, err := New(ctl).desiredState(context.Background(), nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if len(ds.Services) != 0 {
		t.Fatalf("services = %d, want none for a service with no address", len(ds.Services))
	}
}

// TestAnAddressAppearingRepushes is the one that matters for convergence. The push is deduplicated
// by a signature built from (kind, name, generation), and a STATUS write does not move a
// generation — that is deliberate, so a heartbeat does not wake every spec-watcher. But an address
// IS a status write, and it changes what every other node has to know. Without the addressing
// entering the signature on its own, node A would learn where node B's workload lives only on the
// five-minute sweep: five minutes of a ClusterIP answering nothing.
func TestAnAddressAppearingRepushes(t *testing.T) {
	ctl := fleet(t)
	isolated(t, ctl, "late", "node-2", "", "")

	_, before, err := New(ctl).desiredState(context.Background(), nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	isolated(t, ctl, "late2", "node-2", "", "10.244.0.9/32") // a second workload, wired
	_, after, err := New(ctl).desiredState(context.Background(), nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if before == after {
		t.Fatal("a new workload address left the signature unchanged: no node would be told about it")
	}
}

// TestTheReportedAddressIsNormalised names a bug the tests above had agreed with the code about,
// and that only a stand found: a node reports its address in CIDR form — the form it was pushed —
// so appending "/32" to it produced "10.244.0.1/32/32". netd refused the node's WHOLE forwarding
// state for it, every route and every service, and the only symptom was a ClusterIP that answered
// nothing.
func TestTheReportedAddressIsNormalised(t *testing.T) {
	for _, c := range []struct {
		reported, bare, route string
	}{
		{"10.244.0.1/32", "10.244.0.1", "10.244.0.1/32"}, // what a node actually sends
		{"10.244.0.1", "10.244.0.1", "10.244.0.1/32"},    // a bare address is the same fact
		{"", "", ""},                 // not wired yet
		{"10.244.0.1/32/32", "", ""}, // the bug itself, refused rather than passed on
		{"nonsense", "", ""},
	} {
		if got := bareAddress(c.reported); got != c.bare {
			t.Errorf("bareAddress(%q) = %q, want %q", c.reported, got, c.bare)
		}
		if got := hostRoute(c.reported); got != c.route {
			t.Errorf("hostRoute(%q) = %q, want %q", c.reported, got, c.route)
		}
	}
}
