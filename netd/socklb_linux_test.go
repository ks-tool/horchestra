//go:build linux

package netd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	netdapi "github.com/ks-tool/horchestra/api/netd"

	"github.com/cilium/ebpf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestTheObjectAndTheCodeAgree guards the seam nothing else can: the map layouts live in C and are
// written from Go by byte offset, and the object is COMMITTED — so a change to a struct in
// socklb.bpf.c that is rebuilt without updating the constants here would produce keys the kernel
// accepts and the program never matches. Every ClusterIP would simply stop answering, with no
// error anywhere. This test needs no privileges: it reads the object, which is the artefact under
// suspicion.
func TestTheObjectAndTheCodeAgree(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(socklbELF))
	if err != nil {
		t.Fatalf("the embedded datapath does not parse: %v", err)
	}
	for _, name := range []string{"horc_connect4", "horc_sendmsg4"} {
		p := spec.Programs[name]
		if p == nil {
			t.Fatalf("the embedded datapath has no %s: rebuild it with `make bpf`", name)
		}
		if p.Type != ebpf.CGroupSockAddr {
			t.Errorf("%s is a %s, want a cgroup sock_addr program", name, p.Type)
		}
	}
	for _, m := range []struct {
		name             string
		keySize, valSize uint32
	}{
		{"horc_services", svcKeySize, svcValSize},
		{"horc_backends", backendKeySize, backendValSize},
	} {
		spec := spec.Maps[m.name]
		if spec == nil {
			t.Fatalf("the embedded datapath has no %s map", m.name)
		}
		if spec.KeySize != m.keySize || spec.ValueSize != m.valSize {
			t.Errorf("%s is keyed %d/%d, this code writes %d/%d — the layouts have diverged",
				m.name, spec.KeySize, spec.ValueSize, m.keySize, m.valSize)
		}
	}
}

// datapath loads the real thing or skips. The skip is the honest outcome on a workstation and in
// the unprivileged linux test container: loading BPF is gated on capabilities in the INITIAL user
// namespace, which is exactly the reason netd exists as a separate privileged process.
func datapath(t *testing.T) *SockLB {
	t.Helper()
	dp, err := LoadSockLB("/sys/fs/cgroup", testPinDir(t))
	if err != nil {
		t.Skipf("no datapath here: %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	return dp
}

// TestAClusterIPIsRewrittenAtConnect is the whole point of the datapath, tested the only way that
// means anything: a real listener on a real port, a service programmed at an address that exists
// nowhere on this machine and that nothing routes, and a dial to it that arrives anyway.
//
// If the rewrite did not happen the dial fails — there is no route to 10.99.0.1 and nothing
// listening on it — so this cannot pass by accident.
func TestAClusterIPIsRewrittenAtConnect(t *testing.T) {
	dp := datapath(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	backendPort := int32(ln.Addr().(*net.TCPAddr).Port)

	if err := dp.Services([]*netdapi.ServiceRule{{
		ClusterIp: "10.99.0.1", Port: 80, Protocol: "TCP",
		Backends: []*netdapi.Backend{{Address: "127.0.0.1", Port: backendPort}},
	}}); err != nil {
		t.Fatalf("program the service: %v", err)
	}

	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
		accepted <- err
	}()

	conn, err := net.DialTimeout("tcp", "10.99.0.1:80", 3*time.Second)
	if err != nil {
		t.Fatalf("dial the ClusterIP: %v (nothing rewrote it to the backend)", err)
	}
	defer func() { _ = conn.Close() }()
	// The consequence of rewriting at connect: the socket's peer IS the backend. Asserted rather
	// than worked around — a workload that needs the ClusterIP back needs a getpeername4 program,
	// which is not written.
	if got := conn.RemoteAddr().String(); got != fmt.Sprintf("127.0.0.1:%d", backendPort) {
		t.Errorf("peer = %s, want the backend", got)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the connection never reached the backend")
	}
}

// TestAServiceThatIsGoneStopsAnswering: the table is a REPLACE, so a service left out of a later
// call must not keep answering — the failure this prevents is a ClusterIP that outlives the
// Service, sending traffic to a workload nobody has any record of routing to.
func TestAServiceThatIsGoneStopsAnswering(t *testing.T) {
	dp := datapath(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := int32(ln.Addr().(*net.TCPAddr).Port)

	rules := []*netdapi.ServiceRule{{
		ClusterIp: "10.99.0.2", Port: 8080, Protocol: "TCP",
		Backends: []*netdapi.Backend{{Address: "127.0.0.1", Port: port}},
	}}
	if err := dp.Services(rules); err != nil {
		t.Fatalf("program: %v", err)
	}
	if err := dp.Services(nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	// Both maps, not just the one that is looked up first: a backend entry outliving its service
	// is a leak that fills a fixed-size map, and nothing would report it.
	for _, m := range []*ebpf.Map{dp.services, dp.backends} {
		if n := count(t, m); n != 0 {
			t.Errorf("%d entries left after clearing the table", n)
		}
	}

	// A dial now has nothing to rewrite it, so it must fail rather than reach the old backend.
	conn, err := net.DialTimeout("tcp", "10.99.0.2:8080", time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("the ClusterIP still answers after the service was removed")
	}
}

// TestABackendSetShrinksWithoutABlackHole: while a service is being narrowed, the count in the map
// must never name an entry that is not there — an index that resolves to nothing is a connect(2)
// to a live ClusterIP that fails. The check is the invariant itself, read back from the kernel.
func TestABackendSetShrinksWithoutABlackHole(t *testing.T) {
	dp := datapath(t)

	backends := func(n int) []*netdapi.Backend {
		out := make([]*netdapi.Backend, 0, n)
		for i := range n {
			out = append(out, &netdapi.Backend{Address: fmt.Sprintf("10.244.0.%d", i+1), Port: 80})
		}
		return out
	}
	rule := func(n int) []*netdapi.ServiceRule {
		return []*netdapi.ServiceRule{{ClusterIp: "10.99.0.3", Port: 80, Protocol: "TCP", Backends: backends(n)}}
	}
	for _, n := range []int{4, 1, 3, 0} {
		if err := dp.Services(rule(n)); err != nil {
			t.Fatalf("program %d backends: %v", n, err)
		}
		if got := count(t, dp.backends); got != n {
			t.Errorf("%d backend entries for a service of %d: the map holds what the count does not name", got, n)
		}
		var val [svcValSize]byte
		key := serviceKey(mustAddr(t, "10.99.0.3"), 80, 6)
		if err := dp.services.Lookup(key[:], &val); err != nil {
			t.Fatalf("the service is not in the table: %v", err)
		}
	}
}

// TestAMalformedRuleTouchesNothing: the table is validated whole before the first map write, so a
// caller that sends one bad rule does not get half a service table — which would be worse than the
// error, because half a table looks converged.
func TestAMalformedRuleTouchesNothing(t *testing.T) {
	dp := datapath(t)

	err := dp.Services([]*netdapi.ServiceRule{
		{ClusterIp: "10.99.0.4", Port: 80, Protocol: "TCP", Backends: []*netdapi.Backend{{Address: "10.244.0.1", Port: 80}}},
		{ClusterIp: "not-an-address", Port: 80, Protocol: "TCP"},
	})
	if err == nil {
		t.Fatal("a rule with no address was accepted")
	}
	if n := count(t, dp.services); n != 0 {
		t.Errorf("%d services written from a request that was refused", n)
	}
}

// TestTheDatapathIsRefusedNotFaked: a node with no datapath must refuse to program services rather
// than accept them, or the control plane records a converged node whose ClusterIPs answer nothing.
func TestTheDatapathIsRefusedNotFaked(t *testing.T) {
	h := &Handler{Version: "test", Link: &VethLinker{}, DatapathReason: "measured: this kernel has no BTF"}
	c := serve(t, h, uint32(os.Getuid()))

	_, err := c.ProgramServices(context.Background(), &netdapi.ProgramServicesRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ProgramServices with no datapath = %v, want FailedPrecondition", err)
	}
	if !bytes.Contains([]byte(status.Convert(err).Message()), []byte("no BTF")) {
		t.Errorf("the refusal does not carry why: %v", err)
	}
	st, err := c.Status(context.Background(), &netdapi.StatusRequest{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.GetDatapath() {
		t.Error("a node with no datapath reports one")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	ip, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ip
}

func count(t *testing.T, m *ebpf.Map) int {
	t.Helper()
	var (
		n    int
		k    [backendKeySize]byte
		v    [backendValSize]byte
		iter = m.Iterate()
	)
	// The buffers are the larger of the two layouts; a map with smaller entries fills the prefix.
	key, val := k[:m.KeySize()], v[:m.ValueSize()]
	for iter.Next(&key, &val) {
		n++
	}
	if err := iter.Err(); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("iterate: %v", err)
	}
	return n
}
