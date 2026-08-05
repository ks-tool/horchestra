//go:build linux

package netd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netdapi "github.com/ks-tool/horchestra/api/netd"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestTheForwarderObjectAndTheCodeAgree is the socket balancer's layout test, for the other object:
// the workloads map is written from Go by byte offset, so a struct changed in fwd.bpf.c and rebuilt
// without changing the constants here would produce entries the program reads as something else —
// an ifindex read out of a MAC, and packets delivered to whatever interface that names.
func TestTheForwarderObjectAndTheCodeAgree(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(fwdELF))
	if err != nil {
		t.Fatalf("the embedded forwarder does not parse: %v", err)
	}
	p := spec.Programs["horc_forward"]
	if p == nil {
		t.Fatal("the embedded forwarder has no horc_forward: rebuild it with `make bpf`")
	}
	if p.Type != ebpf.SchedCLS {
		t.Errorf("horc_forward is a %s, want a tc program", p.Type)
	}
	workloads := spec.Maps["horc_workloads"]
	if workloads == nil {
		t.Fatal("the embedded forwarder has no horc_workloads map")
	}
	if workloads.KeySize != workloadKeySize || workloads.ValueSize != workloadValSize {
		t.Errorf("horc_workloads is keyed %d/%d, this code writes %d/%d — the layouts have diverged",
			workloads.KeySize, workloads.ValueSize, workloadKeySize, workloadValSize)
	}
}

// TestAWorkloadReachesAWorkloadOnAnotherNode is the forwarding datapath, tested against a real
// second node rather than against the map it just wrote.
//
// The topology is two network namespaces and one veth between them: this container's namespace is
// node A, "nodeB" is the other node, and a third namespace holds a workload wired by the real
// VethLinker. Node B answers on 10.244.0.2 — an address that exists in no route on node A, in no
// route on the veth, and nowhere but the workloads map. If the program did not look it up, redirect it
// and deliver the reply back into the workload's namespace, the dial below could not complete.
func TestAWorkloadReachesAWorkloadOnAnotherNode(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("this builds a network topology: it needs the node's own privileges, which is what netd has")
	}
	// Forwarding OFF, which is the state of a node nothing has configured — and what makes this
	// test prove the datapath rather than the kernel. Without it the reply could come back through
	// ordinary routing (the host route to the workload exists), and the delivery branch would go
	// untested while looking tested.
	noForwarding(t)

	nodeB := netnsOf(t, heldNetns(t))
	workload := netnsOf(t, heldNetns(t))

	// The workload's side is wired by the code that wires it in production, so what is tested is
	// the pair netd actually makes: /32, link-local gateway, onlink default route.
	// A prefix of two, not the production three: a name is 15 bytes and the digest takes twelve.
	linker := &VethLinker{HostPrefix: "ht"}
	t.Cleanup(func() { _ = linker.Reclaim(context.Background(), nil) })
	wiring, err := linker.Attach(context.Background(), &netdapi.Workload{
		Id: "workload-a", Address: "10.244.0.1/32", Gateway: "169.254.1.1",
	}, workload.Name())
	if err != nil {
		t.Fatalf("wire the workload: %v", err)
	}

	// The underlay: what two nodes reach each other over.
	const uplink = "hortest0"
	if err := createVeth(uplink, "uplink", int(nodeB.Fd()), 0); err != nil {
		t.Fatalf("create the node link: %v", err)
	}
	t.Cleanup(func() { _ = linker.deleteLink(uplink) })
	if err := ifconfig(uplink, "192.168.99.1/24"); err != nil {
		t.Fatalf("address the node link: %v", err)
	}
	if err := withNetns(int(nodeB.Fd()), func() error {
		if err := ifconfig("uplink", "192.168.99.2/24"); err != nil {
			return err
		}
		// The far workload's address lives on node B's loopback: it is the node that answers for
		// it, which is exactly the shape of a node holding a workload.
		if err := ifconfig("lo", "10.244.0.2/32"); err != nil {
			return err
		}
		return routeVia("uplink", "10.244.0.1/32", "192.168.99.1")
	}); err != nil {
		t.Fatalf("configure the other node: %v", err)
	}

	fw, err := LoadForwarder(uplink, testPinDir(t), OverlayNone)
	if err != nil {
		t.Skipf("no forwarding datapath here: %v", err)
	}
	t.Cleanup(func() { _ = fw.Close() })

	if err := fw.Attach(wiring.Interface); err != nil {
		t.Fatalf("attach the datapath to the workload's interface: %v", err)
	}
	if err := fw.Local(wiring.Address, wiring.Index); err != nil {
		t.Fatalf("record the local workload: %v", err)
	}
	if err := fw.Routes([]*netdapi.Route{{Cidr: "10.244.0.2/32", NodeIp: "192.168.99.2"}}); err != nil {
		t.Fatalf("program the route: %v", err)
	}

	// A listener on the far node, and a dial from inside the workload's namespace. Both sockets are
	// created in their own namespace and used from anywhere afterwards — a socket belongs to the
	// namespace it was made in, not to the thread that uses it.
	var ln net.Listener
	if err := withNetns(int(nodeB.Fd()), func() error {
		var err error
		ln, err = net.Listen("tcp", "10.244.0.2:9099")
		return err
	}); err != nil {
		t.Fatalf("listen on the other node: %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan error, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
			accepted <- nil
		}
	}()

	dial := func(what string) {
		t.Helper()
		var conn net.Conn
		if err := withNetns(int(workload.Fd()), func() error {
			var err error
			conn, err = net.DialTimeout("tcp", "10.244.0.2:9099", 5*time.Second)
			return err
		}); err != nil {
			t.Fatalf("dial the other node's workload %s: %v (nothing forwarded it)", what, err)
		}
		_ = conn.Close()
		select {
		case <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatalf("the connection never arrived at the other node %s", what)
		}
	}
	dial("with the helper running")

	// AND NOW THE HELPER DIES. Close drops every descriptor this process holds — which is what
	// process death does — and the pins keep the programs attached and the table populated. If they
	// did not, this second dial would fail exactly like the first would have without a datapath: the
	// address is in no route on either node.
	//
	// This is the difference between a degradation and an outage, and it is the whole reason the
	// objects are pinned rather than rebuilt on the next start.
	if err := fw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	dial("with the helper gone")
}

// TestARouteToThisNodeIsNotStored: the control plane sends every node the whole cluster, so a node
// receives its own workloads back. Storing one would point the datapath at the uplink for an
// address that is one veth away — a packet sent out to come back in, or dropped by whatever is
// between. The local entry the wiring wrote must survive the push untouched.
func TestARouteToThisNodeIsNotStored(t *testing.T) {
	fw := forwarder(t)

	if err := fw.Local(netip.MustParseAddr("10.244.0.1"), 42); err != nil {
		t.Fatalf("record the local workload: %v", err)
	}
	mine, err := hostAddresses()
	if err != nil || len(mine) == 0 {
		t.Fatalf("this host has no addresses to be reached at: %v", err)
	}
	var self netip.Addr
	for a := range mine {
		if a.Is4() && !a.IsLoopback() {
			self = a
			break
		}
	}
	if !self.IsValid() {
		t.Skip("this host has no non-loopback IPv4 address to claim as its own")
	}

	if err := fw.Routes([]*netdapi.Route{
		{Cidr: "10.244.0.1/32", NodeIp: self.String()},   // this node, the long way round
		{Cidr: "10.244.0.9/32", NodeIp: "192.168.199.9"}, // somewhere else
	}); err != nil {
		t.Fatalf("program routes: %v", err)
	}

	var val [workloadValSize]byte
	key := netip.MustParseAddr("10.244.0.1").As4()
	if err := fw.workloads.Lookup(key[:], &val); err != nil {
		t.Fatalf("the local workload is gone from the table: %v", err)
	}
	if node := val[workloadNode : workloadNode+4]; !bytes.Equal(node, []byte{0, 0, 0, 0}) {
		t.Errorf("the local workload now lives on %v: a route to this node was stored", node)
	}
}

// TestOnlyHostRoutesAreAccepted: the addresses are one flat range with no per-node slice, so a
// prefix is a claim this design does not make — and one accepted into an address-keyed map would
// simply never match, leaving a workload unreachable with nothing logged anywhere.
func TestOnlyHostRoutesAreAccepted(t *testing.T) {
	fw := forwarder(t)

	err := fw.Routes([]*netdapi.Route{{Cidr: "10.244.1.0/24", NodeIp: "192.168.199.9"}})
	if err == nil {
		t.Fatal("a /24 was accepted as a workload address")
	}
	if n := entryCount(t, fw); n != 0 {
		t.Errorf("%d entries written from a request that was refused", n)
	}
}

// testPinDir gives each test its own pin root, mounting a bpf filesystem if this environment has
// none. A TEST may mount one; netd must not (see preparePinDir), and the difference is not a
// double standard: a test owns the container it runs in, while netd runs in a mount namespace
// systemd gave it, where a mount of its own would die with the process it was meant to outlive.
func testPinDir(t *testing.T) string {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err != nil || st.Type != unix.BPF_FS_MAGIC {
		if err := unix.Mount("bpffs", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
			t.Skipf("no bpf filesystem here and none can be mounted: %v", err)
		}
	}
	dir := filepath.Join("/sys/fs/bpf", "horctest-"+strings.ReplaceAll(t.Name(), "/", "-"))
	// Removing a pin file unpins the object, so this is also what stops a test leaving programs
	// attached to interfaces it deleted.
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func forwarder(t *testing.T) *Forwarder {
	t.Helper()
	fw, err := LoadForwarder(uplinkForTest(t), testPinDir(t), OverlayNone)
	if err != nil {
		t.Skipf("no forwarding datapath here: %v", err)
	}
	t.Cleanup(func() { _ = fw.Close() })
	return fw
}

// uplinkForTest names an interface that exists rather than relying on this container having a
// default route.
func uplinkForTest(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
			return i.Name
		}
	}
	t.Skip("this host has no interface to attach to")
	return ""
}

func entryCount(t *testing.T, fw *Forwarder) int {
	t.Helper()
	keys, err := fw.entries(func([workloadKeySize]byte, [workloadValSize]byte) bool { return true })
	if err != nil {
		t.Fatalf("read the table: %v", err)
	}
	return len(keys)
}

// noForwarding turns IP forwarding off for the duration, and restores it. The sysctl belongs to the
// network namespace, so this reaches no further than the container the test runs in.
func noForwarding(t *testing.T) {
	t.Helper()
	const path = "/proc/sys/net/ipv4/ip_forward"
	was, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cannot read %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Skipf("cannot turn forwarding off: %v", err)
	}
	t.Cleanup(func() { _ = os.WriteFile(path, was, 0o644) })
}

// netnsOf opens a process's network namespace and keeps it open for the test.
func netnsOf(t *testing.T, pid int) *os.File {
	t.Helper()
	f, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		t.Fatalf("open the namespace of %d: %v", pid, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// ifconfig brings an interface up with an address, in whatever namespace the caller is in.
func ifconfig(name, cidr string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	dev, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	if err := linkUp(c, dev.Index); err != nil {
		return err
	}
	return addAddress(c, dev.Index, p)
}

// routeVia adds a route through a gateway on an interface, in the caller's namespace.
func routeVia(iface, cidr, gw string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	via, err := netip.ParseAddr(gw)
	if err != nil {
		return err
	}
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	attrs := attr(unix.RTA_DST, addrBytes(p.Addr()))
	attrs = append(attrs, attr(unix.RTA_GATEWAY, addrBytes(via))...)
	attrs = append(attrs, attrU32(unix.RTA_OIF, uint32(dev.Index))...)
	_, err = c.do(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		rtMsg(addrFamily(p.Addr()), uint8(p.Bits()), unix.RT_SCOPE_UNIVERSE, 0), attrs)
	return err
}

// TestARestartRestoresTheLocalTable is the bug a stand found and no test had: the attachments are
// not the only thing a helper loses when it exits.
//
// A workload's own entry is written by SetupWorkloadNetwork, which runs once, when the workload
// starts — never again for one that is already running — and the control plane's push deliberately
// leaves the local half alone. So a helper that came back and only re-attached its programs had an
// empty local table and a node that had quietly stopped delivering to its own workloads, while
// reporting a loaded datapath. What restores it is the /32 host route, which is the record of which
// address lives behind which veth and outlives every process here.
func TestARestartRestoresTheLocalTable(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("this wires a real veth: it needs the node's own privileges, which is what netd has")
	}
	workload := netnsOf(t, heldNetns(t))
	linker := &VethLinker{HostPrefix: "hr"}
	t.Cleanup(func() { _ = linker.Reclaim(context.Background(), nil) })

	wiring, err := linker.Attach(context.Background(), &netdapi.Workload{
		Id: "restarted", Address: "10.244.7.7/32", Gateway: "169.254.1.1",
	}, workload.Name())
	if err != nil {
		t.Fatalf("wire the workload: %v", err)
	}

	// A HELPER THAT RESTARTED: a fresh forwarder, with none of the previous one's state, told
	// nothing about the workload that is already running.
	fw, err := LoadForwarder(uplinkForTest(t), testPinDir(t), OverlayNone)
	if err != nil {
		t.Skipf("no forwarding datapath here: %v", err)
	}
	t.Cleanup(func() { _ = fw.Close() })
	if n := entryCount(t, fw); n != 0 {
		t.Fatalf("a fresh forwarder already holds %d entries", n)
	}

	h := &Handler{Version: "test", Link: linker, Forward: fw}
	if err := h.Rewire(); err != nil {
		t.Fatalf("rewire: %v", err)
	}

	var val [workloadValSize]byte
	key := wiring.Address.As4()
	if err := fw.workloads.Lookup(key[:], &val); err != nil {
		t.Fatalf("%s is not in the table after a restart: %v", wiring.Address, err)
	}
	if got := binary.NativeEndian.Uint32(val[workloadIfindex : workloadIfindex+4]); got != uint32(wiring.Index) {
		t.Errorf("restored behind ifindex %d, want %d", got, wiring.Index)
	}
	if node := binary.NativeEndian.Uint32(val[workloadNode : workloadNode+4]); node != 0 {
		t.Errorf("restored as living on node %d, want this one", node)
	}
}

// TestASecondHelperAdoptsRatherThanReattaches: with the datapath pinned, a netd that starts while
// its predecessor's programs are still attached must take them over — not add a second copy to the
// same hook, and not detach and re-attach, which would be a window in which the interface delivers
// nothing. The table it finds is the one that has been in use the whole time.
func TestASecondHelperAdoptsRatherThanReattaches(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("this wires a real veth: it needs the node's own privileges, which is what netd has")
	}
	workload := netnsOf(t, heldNetns(t))
	linker := &VethLinker{HostPrefix: "ha"}
	t.Cleanup(func() { _ = linker.Reclaim(context.Background(), nil) })
	wiring, err := linker.Attach(context.Background(), &netdapi.Workload{
		Id: "adopted", Address: "10.244.8.8/32", Gateway: "169.254.1.1",
	}, workload.Name())
	if err != nil {
		t.Fatalf("wire the workload: %v", err)
	}

	pins := testPinDir(t)
	first, err := LoadForwarder(uplinkForTest(t), pins, OverlayNone)
	if err != nil {
		t.Skipf("no forwarding datapath here: %v", err)
	}
	if err := first.Attach(wiring.Interface); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := first.Local(wiring.Address, wiring.Index); err != nil {
		t.Fatalf("record the local workload: %v", err)
	}
	if err := first.Close(); err != nil { // the helper dies with everything still attached
		t.Fatalf("close: %v", err)
	}

	second, err := LoadForwarder(uplinkForTest(t), pins, OverlayNone)
	if err != nil {
		t.Fatalf("the second helper could not load over the first's pins: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	// The table was never rewritten by this process, and the entry is still there: the map it opened
	// IS the one the first helper filled.
	var val [workloadValSize]byte
	key := wiring.Address.As4()
	if err := second.workloads.Lookup(key[:], &val); err != nil {
		t.Fatalf("%s is gone from the adopted table: %v", wiring.Address, err)
	}
	if got := binary.NativeEndian.Uint32(val[workloadIfindex : workloadIfindex+4]); got != uint32(wiring.Index) {
		t.Errorf("adopted entry points at ifindex %d, want %d", got, wiring.Index)
	}
	if err := second.Attach(wiring.Interface); err != nil {
		t.Fatalf("adopt the attachment: %v", err)
	}
}

// TestTheOverlayIsOneDeviceAndOneFlag: the encapsulated mode is one collect-metadata device and one
// bit per entry — no peer list, no forwarding database, no per-node configuration. A node joining
// the cluster needs nothing set up here, which is the same property the address table already has.
//
// The three things asserted are the three that would each silently half-work: the device exists and
// is up, a remote entry names the TUNNEL rather than the uplink (naming the uplink would send the
// frame out unencapsulated, which is precisely what a cloud fabric drops), and the workload MTU
// comes down by what the encapsulation will take.
func TestTheOverlayIsOneDeviceAndOneFlag(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("this creates a tunnel device: it needs the node's own privileges, which is what netd has")
	}
	fw, err := LoadForwarder(uplinkForTest(t), testPinDir(t), OverlayVXLAN)
	if err != nil {
		t.Skipf("no forwarding datapath here: %v", err)
	}
	t.Cleanup(func() {
		_ = fw.Close()
		_ = (&VethLinker{}).deleteLink(tunnels[OverlayVXLAN].name)
	})

	dev, err := net.InterfaceByName(tunnels[OverlayVXLAN].name)
	if err != nil {
		t.Fatalf("the tunnel device was not created: %v", err)
	}
	if dev.Flags&net.FlagUp == 0 {
		t.Error("the tunnel device is down: nothing would leave through it")
	}
	if got := fw.Overlay(); got != OverlayVXLAN {
		t.Errorf("overlay = %q, want %q", got, OverlayVXLAN)
	}

	if err := fw.Routes([]*netdapi.Route{{Cidr: "10.244.5.5/32", NodeIp: "192.168.77.7"}}); err != nil {
		t.Fatalf("program a remote route: %v", err)
	}
	var val [workloadValSize]byte
	key := netip.MustParseAddr("10.244.5.5").As4()
	if err := fw.workloads.Lookup(key[:], &val); err != nil {
		t.Fatalf("the route is not in the table: %v", err)
	}
	if flags := binary.NativeEndian.Uint32(val[workloadFlags : workloadFlags+4]); flags != workloadTunnel {
		t.Errorf("flags = %d, want the entry marked as tunnelled", flags)
	}
	if idx := binary.NativeEndian.Uint32(val[workloadIfindex : workloadIfindex+4]); idx != uint32(dev.Index) {
		t.Errorf("the entry leaves by ifindex %d, want the tunnel's %d", idx, dev.Index)
	}

	// The uplink's MTU minus the encapsulation, whatever was asked for.
	uplink, err := net.InterfaceByName(fw.uplink)
	if err != nil {
		t.Fatalf("uplink: %v", err)
	}
	// Computed from the uplink this environment actually has, not from an assumed 1500: the first
	// version of this assertion hard-coded the shape of a LAN and failed on a container whose uplink
	// carries 65535.
	cap := int32(uplink.MTU - tunnels[OverlayVXLAN].overhead)
	if got := fw.WorkloadMTU(0); got != cap {
		t.Errorf("an unset MTU became %d, want the cap %d", got, cap)
	}
	if got := fw.WorkloadMTU(cap + 1000); got != cap {
		t.Errorf("an oversized MTU became %d, want it capped to %d", got, cap)
	}
	if got := fw.WorkloadMTU(cap - 100); got != cap-100 {
		t.Errorf("a workload asking for less than the cap got %d", got)
	}
}

// TestAReattachedInterfaceGetsTheProgram is the bug pinning introduced and the stand found: a pin
// outlives the device it was made for, and a workload's interface NAME is stable across restarts
// (it is a digest of the workload id) while its index is not.
//
// So a workload that restarts comes back with a new veth under the old name — and a helper that
// adopted the pin on the strength of the name alone left that veth with no program attached, while
// everything looked healthy: the pin was there and Status said the datapath was loaded. The packets
// were simply never redirected.
func TestAReattachedInterfaceGetsTheProgram(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("this wires a real veth: it needs the node's own privileges, which is what netd has")
	}
	pins := testPinDir(t)
	fw, err := LoadForwarder(uplinkForTest(t), pins, OverlayNone)
	if err != nil {
		t.Skipf("no forwarding datapath here: %v", err)
	}
	t.Cleanup(func() { _ = fw.Close() })

	linker := &VethLinker{HostPrefix: "hb"}
	t.Cleanup(func() { _ = linker.Reclaim(context.Background(), nil) })
	wl := &netdapi.Workload{Id: "restarter", Address: "10.244.9.9/32", Gateway: "169.254.1.1"}

	first := netnsOf(t, heldNetns(t))
	w1, err := linker.Attach(context.Background(), wl, first.Name())
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	if err := fw.Attach(w1.Interface); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// THE RESTART: the namespace goes, and a veth dies with its peer. The name is the same on the
	// way back; the index is not.
	if err := linker.Detach(context.Background(), wl.GetId()); err != nil {
		t.Fatalf("tear down: %v", err)
	}
	second := netnsOf(t, heldNetns(t))
	w2, err := linker.Attach(context.Background(), wl, second.Name())
	if err != nil {
		t.Fatalf("re-wire: %v", err)
	}
	if w2.Interface != w1.Interface {
		t.Fatalf("the interface was renamed (%s -> %s): this test is about the name staying the same",
			w1.Interface, w2.Interface)
	}
	if w2.Index == w1.Index {
		t.Skip("the kernel reused the index: nothing to distinguish here")
	}

	// NOTHING tells the forwarder the old device is gone — which is the real sequence: a workload
	// that crashes and restarts is re-Setup, never torn down, so both the pin and this process's own
	// bookkeeping still name an interface that no longer exists.
	if err := fw.Attach(w2.Interface); err != nil {
		t.Fatalf("attach after the restart: %v", err)
	}
	if got := attachedTo(fw.links[w2.Interface]); got != w2.Index {
		t.Fatalf("the program is attached to ifindex %d, but the interface is now %d: "+
			"this workload's packets would never be redirected", got, w2.Index)
	}
}

// TestTheL3OverlayCarriesIPAndNotFrames: ipip differs from vxlan in the one way that reaches the
// datapath — the tunnel carries IP, so the entries have to say so and the tunnel's ingress needs the
// program that starts at the IP header rather than fourteen bytes later. Both are asserted here
// because getting either wrong produces a tunnel that looks configured and drops everything.
func TestTheL3OverlayCarriesIPAndNotFrames(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("this creates a tunnel device: it needs the node's own privileges, which is what netd has")
	}
	// Deliberately NOT a skip on any error: this test skipped on a malformed netlink attribute once,
	// and the failure reached a stand instead. A kernel that cannot load BPF at all is the only
	// thing worth stepping around here.
	fw, err := LoadForwarder(uplinkForTest(t), testPinDir(t), OverlayIPIP)
	if err != nil {
		if ok, _ := datapathSupport(); !ok {
			t.Skipf("this kernel cannot run the datapath: %v", err)
		}
		t.Fatalf("the ipip overlay did not load: %v", err)
	}
	t.Cleanup(func() {
		_ = fw.Close()
		_ = (&VethLinker{}).deleteLink(tunnels[OverlayIPIP].name)
	})

	dev, err := net.InterfaceByName(tunnels[OverlayIPIP].name)
	if err != nil {
		t.Fatalf("the tunnel device was not created: %v", err)
	}
	if dev.Flags&net.FlagUp == 0 {
		t.Error("the tunnel device is down")
	}
	if got := fw.Overlay(); got != OverlayIPIP {
		t.Errorf("overlay = %q, want %q", got, OverlayIPIP)
	}
	// An L3 device has no ethernet address at all, which is exactly why its ingress needs the other
	// program.
	if len(dev.HardwareAddr) != 0 {
		t.Errorf("the tunnel has an ethernet address %s: it is not an L3 device", dev.HardwareAddr)
	}
	if fw.programFor(fw.tunnel) != fw.progL3 {
		t.Error("the tunnel got the frame-parsing program: it would read the IP header as MAC addresses")
	}
	if fw.programFor(fw.uplink) != fw.prog {
		t.Error("the uplink got the L3 program: it carries frames")
	}

	if err := fw.Routes([]*netdapi.Route{{Cidr: "10.244.6.6/32", NodeIp: "192.168.77.7"}}); err != nil {
		t.Fatalf("program a remote route: %v", err)
	}
	var val [workloadValSize]byte
	key := netip.MustParseAddr("10.244.6.6").As4()
	if err := fw.workloads.Lookup(key[:], &val); err != nil {
		t.Fatalf("the route is not in the table: %v", err)
	}
	if flags := binary.NativeEndian.Uint32(val[workloadFlags : workloadFlags+4]); flags != workloadTunnel {
		t.Errorf("flags = %d, want the entry marked as tunnelled", flags)
	}
	// 20 bytes against vxlan's 50 — the whole reason for this mode.
	uplink, err := net.InterfaceByName(fw.uplink)
	if err != nil {
		t.Fatalf("uplink: %v", err)
	}
	if got, want := fw.WorkloadMTU(0), int32(uplink.MTU-tunnels[OverlayIPIP].overhead); got != want {
		t.Errorf("MTU = %d, want %d", got, want)
	}
}

// TestAnAddressOfAGoneWorkloadIsReclaimed: a workload torn down while netd was not running leaves
// its address in the table with an ifindex nothing owns any more. Rewire cannot restore it (there is
// no interface to read it from) and the agent's GC cannot name it (the workload is gone from every
// keep-list), so without a sweep it stays — and the kernel reuses interface indices.
func TestAnAddressOfAGoneWorkloadIsReclaimed(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("this loads the datapath: it needs the node's own privileges, which is what netd has")
	}
	fw := forwarder(t)

	live, err := net.InterfaceByName(fw.uplink)
	if err != nil {
		t.Fatalf("uplink: %v", err)
	}
	if err := fw.Local(netip.MustParseAddr("10.244.4.1"), live.Index); err != nil {
		t.Fatalf("record a live workload: %v", err)
	}
	// The one left behind: an index no interface has.
	if err := fw.Local(netip.MustParseAddr("10.244.4.2"), 999999); err != nil {
		t.Fatalf("record the stale one: %v", err)
	}

	if err := fw.ReclaimLocal(map[int]struct{}{live.Index: {}}); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	kept := netip.MustParseAddr("10.244.4.1").As4()
	var val [workloadValSize]byte
	if err := fw.workloads.Lookup(kept[:], &val); err != nil {
		t.Errorf("the live workload was swept too: %v", err)
	}
	gone := netip.MustParseAddr("10.244.4.2").As4()
	if err := fw.workloads.Lookup(gone[:], &val); err == nil {
		t.Error("the address of a workload this node no longer has is still in the table")
	}
}
