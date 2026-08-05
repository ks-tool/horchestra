//go:build linux

package netd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	netdapi "github.com/ks-tool/horchestra/api/netd"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// serve starts a helper on a socket in the test's own directory and returns a client for it.
// allowUID is what the helper will admit — the point of the parameter is that a test can be a peer
// the helper refuses without needing a second user.
func serve(t *testing.T, handler netdapi.NetdServiceServer, allowUID uint32) netdapi.NetdServiceClient {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "netd.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := NewServer(handler, allowUID, zerolog.Nop())
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return netdapi.NewNetdServiceClient(conn)
}

func handler(t *testing.T) *Handler {
	t.Helper()
	return &Handler{Version: "test"}
}

// wiring is a helper that can actually wire, for the tests that need one.
func wiring(t *testing.T) *Handler {
	t.Helper()
	return &Handler{Version: "test", Link: &VethLinker{}}
}

// heldNetns starts a process in a network namespace of its own and returns its pid — the state the
// sandbox is in when it asks to be wired, and the only handle this helper accepts.
func heldNetns(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot unshare a user+network namespace here: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd.Process.Pid
}

// TestOnlyTheAgentIsAnswered: the socket's mode is one operator edit away from being wrong, so the
// helper asks the KERNEL who is calling instead of trusting the directory. SO_PEERCRED is recorded
// at connect() and cannot be changed afterwards by the peer — not by exec, not by dropping
// privilege — which is why this is the credential and not a token the peer presents.
func TestOnlyTheAgentIsAnswered(t *testing.T) {
	// The test process is its own peer, so admitting a uid it does not have is how "somebody
	// else" is expressed without a second user.
	other := uint32(os.Getuid()) + 1
	c := serve(t, handler(t), other)

	_, err := c.Status(context.Background(), &netdapi.StatusRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Status as a foreign uid = %v, want PermissionDenied", err)
	}
}

// TestTheAgentIsAnswered is the other half: the same call from the uid the helper was told to
// serve goes through, so the refusal above is about identity and not about the call.
func TestTheAgentIsAnswered(t *testing.T) {
	c := serve(t, handler(t), uint32(os.Getuid()))

	st, err := c.Status(context.Background(), &netdapi.StatusRequest{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.GetVersion() != "test" {
		t.Errorf("version = %q, want the helper's build", st.GetVersion())
	}
	// No link layer yet, so the honest answer is that this node cannot give a workload a network.
	if st.GetRoutedNetwork() || st.GetDatapath() {
		t.Errorf("status = %+v, want both false while nothing can address a namespace", st)
	}
	if st.GetReason() == "" {
		t.Error("a false capability with no reason is a fact an operator cannot act on")
	}
}

// TestIsolationIsRefusedRatherThanFaked: a namespace with no address is not a weaker network, it is
// a workload that cannot reach anything — including the control plane that would tell anyone about
// it. Refusing is what keeps the agent on the host network until the link layer lands.
func TestIsolationIsRefusedRatherThanFaked(t *testing.T) {
	c := serve(t, handler(t), uint32(os.Getuid()))

	_, err := c.SetupWorkloadNetwork(context.Background(), &netdapi.SetupWorkloadNetworkRequest{
		Workload: &netdapi.Workload{Id: "u1", Namespace: "team-a", Name: "api", Address: "10.244.0.7/24"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("SetupWorkloadNetwork with no link layer = %v, want FailedPrecondition", err)
	}
}

// TestAWorkloadIdCannotEscapeTheDirectory: the id reaches a path join inside a root process and
// arrives over a socket, so it is checked where it lands rather than where it was minted.
func TestAWorkloadIdCannotEscapeTheDirectory(t *testing.T) {
	c := serve(t, wiring(t), uint32(os.Getuid()))

	// A pid that names no process, or names one that is not a workload of this caller, is refused
	// where it is READ. The check is what makes a pid safe to accept at all: without it, naming a
	// pid would be a way to ask a root process to reach into any namespace on the machine.
	for _, pid := range []int32{0, 1, -1} {
		_, err := c.SetupWorkloadNetwork(context.Background(), &netdapi.SetupWorkloadNetworkRequest{
			Workload: &netdapi.Workload{Id: "u1", Address: "10.244.7.9/32", Gateway: "10.244.0.1"},
			NetnsPid: pid,
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("SetupWorkloadNetwork(pid=%d) = %v, want InvalidArgument", pid, err)
		}
	}
}

// TestGCIsTotalAndSurvivesAnEmptyNode: the keep list is the whole authority, and a node running
// nothing is an ordinary state rather than a reason to refuse. What GC reclaims is this helper's
// OWN state — the host-side interfaces — because the namespaces belong to the agent.
func TestGCIsTotalAndSurvivesAnEmptyNode(t *testing.T) {
	c := serve(t, wiring(t), uint32(os.Getuid()))

	if _, err := c.GC(context.Background(), &netdapi.GCRequest{Keep: nil}); err != nil {
		t.Fatalf("GC on a node with no workloads: %v", err)
	}
}

// TestNoDatapathSaysSo: an agent that believed its services were programmed would report a
// converged node whose ClusterIPs answer nothing.
func TestNoDatapathSaysSo(t *testing.T) {
	c := serve(t, handler(t), uint32(os.Getuid()))

	_, err := c.ProgramServices(context.Background(), &netdapi.ProgramServicesRequest{
		Services: []*netdapi.ServiceRule{{ClusterIp: "10.243.0.1", Port: 80}},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("ProgramServices with no datapath = %v, want FailedPrecondition", err)
	}
}

// TestAVethPairIsWiredAndReclaimed is the link layer against a real kernel: create a namespace,
// wire it, and check from INSIDE that the workload has an address, a default route and a live
// loopback — the three things whose absence looks like a hung application rather than a missing
// feature. Root only, so `make test-linux` (which is not) skips it and a privileged run does not.
func TestAVethPairIsWiredAndReclaimed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("wiring a veth pair needs root")
	}
	c := serve(t, wiring(t), uint32(os.Getuid()))
	wl := &netdapi.Workload{
		Id: "u-link-1", Namespace: "team-a", Name: "api",
		Address: "10.244.7.9/32", Gateway: "10.244.0.1", Mtu: 1450,
	}
	pid := heldNetns(t)

	resp, err := c.SetupWorkloadNetwork(context.Background(), &netdapi.SetupWorkloadNetworkRequest{
		Workload: wl, NetnsPid: int32(pid),
	})
	if err != nil {
		t.Fatalf("SetupWorkloadNetwork: %v", err)
	}
	host := resp.GetHostInterface()
	if host == "" {
		t.Fatal("no host interface reported: an operator has nothing to find the link by")
	}
	if _, err := net.InterfaceByName(host); err != nil {
		t.Fatalf("host side %s: %v", host, err)
	}

	ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.Close() }()
	if err := withNetns(int(ns.Fd()), func() error {
		eth, err := net.InterfaceByName(WorkloadInterface)
		if err != nil {
			return fmt.Errorf("%s: %w", WorkloadInterface, err)
		}
		if eth.Flags&net.FlagUp == 0 {
			return errors.New("eth0 is down")
		}
		if eth.MTU != 1450 {
			return fmt.Errorf("mtu = %d, want the one asked for", eth.MTU)
		}
		addrs, err := eth.Addrs()
		if err != nil {
			return err
		}
		var found bool
		for _, a := range addrs {
			if a.String() == "10.244.7.9/32" {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("addresses = %v, want the leased one", addrs)
		}
		lo, err := net.InterfaceByName("lo")
		if err != nil || lo.Flags&net.FlagUp == 0 {
			return fmt.Errorf("loopback is not up (%v): an image whose lo is down breaks in ways nobody debugs quickly", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("inside the namespace: %v", err)
	}

	// Idempotent: the agent converges the same workload on every push.
	if _, err := c.SetupWorkloadNetwork(context.Background(), &netdapi.SetupWorkloadNetworkRequest{
		Workload: wl, NetnsPid: int32(pid),
	}); err != nil {
		t.Fatalf("second SetupWorkloadNetwork: %v", err)
	}

	if _, err := c.TeardownWorkloadNetwork(context.Background(), &netdapi.TeardownWorkloadNetworkRequest{Id: wl.GetId()}); err != nil {
		t.Fatalf("TeardownWorkloadNetwork: %v", err)
	}
	if _, err := net.InterfaceByName(host); err == nil {
		t.Errorf("the host side %s survived teardown", host)
	}
}

// TestTheKernelIsAskedNotGuessed: the datapath's support is answered by loading a program, not by
// comparing versions — a version says what was merged, not what this build enabled, what lockdown
// allows or which capability this helper holds, and all three fail later as the same symptom: a
// ClusterIP that silently answers nothing.
//
// It asserts only that the probe REACHES an answer and explains a negative one, because the answer
// itself is the host's: a kernel without BTF is a legitimate no.
func TestTheKernelIsAskedNotGuessed(t *testing.T) {
	ok, why := datapathSupport()
	if !ok && why == "" {
		t.Fatal("the datapath is unsupported and the probe says nothing about why — unactionable")
	}
	if ok && why != "" {
		t.Errorf("supported, yet a reason was given: %q", why)
	}
}
