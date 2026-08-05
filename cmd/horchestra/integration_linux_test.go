//go:build linux

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ks-tool/horchestra/agent/network"
	netdapi "github.com/ks-tool/horchestra/api/netd"
	"github.com/ks-tool/horchestra/netd"

	"github.com/rs/zerolog"
)

// TestBothHalves wires one workload end to end: the agent creates and pins the namespace, the
// helper reaches in and gives it a veth, an address and a route, and the workload's side is checked
// from inside.
//
// It is the test that proves the ownership split, which is the kernel's and not a preference:
// joining a network namespace needs CAP_SYS_ADMIN in the user namespace that OWNS it, so a
// namespace made by root can never be entered by the unprivileged sandbox that has to run in it —
// measured separately, EPERM. Here both halves run as root because a test cannot hold two
// identities at once; what this checks is that the halves agree about who creates what.
func TestBothHalves(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("wiring a veth pair needs root")
	}
	sock := filepath.Join(t.TempDir(), "netd.sock")
	l, err := netd.Listen(sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := netd.NewServer(&netd.Handler{Version: "test", Link: &netd.VethLinker{}},
		uint32(os.Getuid()), zerolog.Nop())
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)

	agent := &network.Netd{Path: sock}
	t.Cleanup(func() { _ = agent.Close() })

	st, err := agent.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.GetRoutedNetwork() {
		t.Fatalf("routedNetwork = false (%s): the helper holds the capabilities here", st.GetReason())
	}
	if st.GetDatapath() {
		t.Error("datapath = true with no eBPF loaded: an agent would report ClusterIPs that answer nothing")
	}

	wl := &netdapi.Workload{
		Id: "u-both-1", Namespace: "team-a", Name: "api",
		Address: "10.244.9.4/32", Gateway: "10.244.0.1", Mtu: 1450,
	}
	// A stand-in for the sandbox: a process that has unshared a network namespace and waits, which
	// is exactly the state the real one is in when it asks for its wiring.
	sandbox := newSandbox(t)
	wired, err := agent.Setup(context.Background(), wl, sandbox.pid)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if wired.HostInterface == "" {
		t.Fatalf("setup = %+v, want the interface an operator can find the workload by", wired)
	}
	if _, err := net.InterfaceByName(wired.HostInterface); err != nil {
		t.Fatalf("host side %s: %v", wired.HostInterface, err)
	}
	if err := insideNetns(sandbox.netnsPath(), func() error {
		eth, err := net.InterfaceByName("eth0")
		if err != nil {
			return err
		}
		addrs, err := eth.Addrs()
		if err != nil {
			return err
		}
		for _, a := range addrs {
			if a.String() == "10.244.9.4/32" {
				return nil
			}
		}
		return fmt.Errorf("addresses = %v, want the leased one", addrs)
	}); err != nil {
		t.Fatalf("inside the workload's namespace: %v", err)
	}

	// Converging the same workload again is what the agent does on every push.
	if _, err := agent.Setup(context.Background(), wl, sandbox.pid); err != nil {
		t.Fatalf("second Setup: %v", err)
	}

	// GC is total: a workload the agent no longer names loses both halves — the helper's interface
	// and the agent's own pinned namespace.
	if err := agent.GC(context.Background(), []string{}); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := net.InterfaceByName(wired.HostInterface); err == nil {
		t.Errorf("the host side %s survived a GC that named nothing", wired.HostInterface)
	}
	// The namespace is not the agent's to reclaim and never was: it goes when the workload does.
	sandbox.stop()
}

// TestAnAgentWiresOnlyItsOwnWorkloads: a pid is safe to accept only because ownership is checked
// against the kernel's answer about the caller. Without it, naming a pid would be a way to ask a
// root process to reach into any namespace on the machine.
func TestAnAgentWiresOnlyItsOwnWorkloads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the helper")
	}
	sock := filepath.Join(t.TempDir(), "netd.sock")
	l, err := netd.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	// The helper is told to serve a uid this process does not have, so its own pid is "somebody
	// else's" from the helper's point of view — the shape of the attack without a second user.
	srv := netd.NewServer(&netd.Handler{Version: "test", Link: &netd.VethLinker{}},
		uint32(os.Getuid())+1, zerolog.Nop())
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)

	agent := &network.Netd{Path: sock}
	t.Cleanup(func() { _ = agent.Close() })
	if _, err := agent.Setup(context.Background(), &netdapi.Workload{
		Id: "u-foreign", Address: "10.244.9.5/32", Gateway: "10.244.0.1",
	}, os.Getpid()); err == nil {
		t.Fatal("a foreign caller wired a namespace")
	}
}
