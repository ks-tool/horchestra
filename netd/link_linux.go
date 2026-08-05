//go:build linux

package netd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"

	netdapi "github.com/ks-tool/horchestra/api/netd"

	"golang.org/x/sys/unix"
)

// WorkloadInterface is what the workload's side of the pair is called inside its own namespace. It is
// `eth0` because that is what every image, health check and piece of documentation in the world
// assumes, and a namespace is a fresh naming space where nothing else wants the name.
const WorkloadInterface = "eth0"

// networkMAC is the ethernet address of EVERY interface in this network: both ends of every veth
// pair, and the tunnel device. `02:00` — locally administered and unicast — followed by the four
// bytes of the gateway's link-local address.
//
// One address, and that is the point. A workload always sends to its gateway's MAC, so making the
// gateway's MAC also the workload's means every frame in this network is addressed to exactly the
// device it arrives at — always, by construction. PACKET_OTHERHOST, which is a drop that happens
// before IP and reports nothing, stops being possible; and the datapath's local delivery stops
// having to rewrite the destination on every packet, because there is nothing left to correct.
//
// It is safe here and would not be on a bridge: each pair is its own point-to-point segment, there
// is no learning, no ARP (the neighbour entry is pinned) and nobody to collide with. It replaced a
// per-workload address derived from the workload's own — which worked, and which the program had to
// reconstruct for every packet it delivered.
var networkMAC = net.HardwareAddr{0x02, 0x00, 0xa9, 0xfe, 0x01, 0x01}

// tunnelMAC is the one address in this network that is deliberately DIFFERENT, and the reason is a
// loop guard in the kernel's VXLAN receive path: a decapsulated frame whose inner SOURCE address
// equals the receiving device's own is dropped as an echo. Every frame here is sent by a workload,
// so its source is networkMAC — and a tunnel device carrying networkMAC therefore discarded every
// packet that arrived through it.
//
// Measured, and it cost an hour: encapsulated packets left one node and arrived at the other's
// uplink with the right VNI and port, and never surfaced on its tunnel device. Changing this one
// byte by hand made the traffic flow immediately.
//
// Nothing needs the tunnel to share the address: a frame arriving through it is redirected into a
// workload's veth by the datapath before the host stack would ever check who it was addressed to.
var tunnelMAC = net.HardwareAddr{0x02, 0x00, 0xa9, 0xfe, 0x01, 0x02}

// VethLinker gives a network namespace an address and a way out: a veth pair with one end in the
// namespace and one on the host, an address on the workload's side, and routes on both.
//
// The shape is point-to-point, not a bridge. Each workload gets its own pair and its own /32 route
// on the host, so there is no shared L2 segment for one workload to ARP-spoof another on, no bridge
// whose STP/forwarding state is one more thing to be wrong, and no ordering problem when several
// workloads are set up at once. The cost is one route per workload, which is what a routing table
// is for.
//
// The default route inside is ONLINK. The workload address is a /32 with no subnet on the wire, so the
// gateway is not "reachable" in the kernel's usual sense; onlink says "trust me, it is on this
// link", which is exactly true of a point-to-point pair and is what CNI's own ptp plugin does.
type VethLinker struct {
	// HostPrefix names the host-side interfaces. Kept short because a Linux interface name is 15
	// bytes and the workload's id has to fit beside it.
	HostPrefix string
}

// HostInterface is the host-side interface for a workload: a prefix plus the first bytes of a digest of
// its id. A digest rather than the id itself because the id is a UUID (36 characters) and the
// kernel allows 15 — and rather than a counter because a counter is state, and this helper keeps
// none: the same workload must get the same name after a restart, computed and not remembered.
func (v *VethLinker) HostInterface(id string) string {
	sum := sha256.Sum256([]byte(id))
	return v.prefix() + hex.EncodeToString(sum[:6])
}

func (v *VethLinker) prefix() string {
	if v.HostPrefix != "" {
		return v.HostPrefix
	}
	return "hor"
}

// Attach wires one namespace. It is idempotent because the agent is level-driven: the host-side
// interface existing IS the record that the pair was made, and everything after it is re-applied
// with EEXIST treated as success.
func (v *VethLinker) Attach(_ context.Context, workload *netdapi.Workload, netnsPath string) (Wiring, error) {
	addr, err := netip.ParsePrefix(workload.GetAddress())
	if err != nil {
		return Wiring{}, fmt.Errorf("workload address %q: %w", workload.GetAddress(), err)
	}
	gw, err := netip.ParseAddr(workload.GetGateway())
	if err != nil {
		return Wiring{}, fmt.Errorf("gateway %q: %w", workload.GetGateway(), err)
	}
	if addr.Addr().Is4() != gw.Is4() {
		return Wiring{}, fmt.Errorf("workload address %s and gateway %s are different families", addr, gw)
	}
	host := v.HostInterface(workload.GetId())

	ns, err := os.Open(netnsPath)
	if err != nil {
		return Wiring{}, fmt.Errorf("open netns %s: %w", netnsPath, err)
	}
	defer func() { _ = ns.Close() }()

	if _, err := net.InterfaceByName(host); err != nil {
		// Both MACs are set AT CREATION rather than afterwards: a link that exists for a moment with
		// the kernel's random address is a moment in which the namespace could learn the wrong one.
		if err := createVeth(host, WorkloadInterface, int(ns.Fd()), int(workload.GetMtu())); err != nil {
			return Wiring{}, fmt.Errorf("create veth %s: %w", host, err)
		}
	}
	if err := v.configureHost(host, addr.Addr(), gw); err != nil {
		return Wiring{}, err
	}
	dev, err := net.InterfaceByName(host)
	if err != nil {
		return Wiring{}, fmt.Errorf("host interface %s: %w", host, err)
	}
	// The workload's side is configured from INSIDE its namespace, on a thread that goes there and comes
	// back. It is the only way: netlink talks to the namespace of the calling thread, and there is
	// no per-message "do this over there".
	return Wiring{Interface: host, Index: dev.Index, Address: addr.Addr()},
		withNetns(int(ns.Fd()), func() error {
			return configureWorkload(addr, gw, int(workload.GetMtu()))
		})
}

// Interfaces is everything this linker has wired, read back out of the kernel: the interface, its
// index, and the address behind it. It is what lets the datapath be rebuilt after a restart without
// a record of what was wired — the interfaces and the host routes ARE the record.
//
// The ADDRESS is the part that matters here, and it is recovered from the /32 host route this
// linker installed pointing at that interface. Nothing else on the node knows it: a workload's
// address is chosen by the control plane, delivered in a push, and handed to netd once, at wiring
// time. Without reading it back, a helper that restarted could re-attach its programs and still not
// know which address lives behind which veth — which is a node that has stopped delivering to its
// own workloads while reporting a loaded datapath.
func (v *VethLinker) Interfaces() ([]Wiring, error) {
	names, err := hostInterfaces(v.prefix())
	if err != nil {
		return nil, err
	}
	routed, err := hostRouteAddresses()
	if err != nil {
		return nil, err
	}
	out := make([]Wiring, 0, len(names))
	for _, name := range names {
		dev, err := net.InterfaceByName(name)
		if err != nil {
			continue // it went away between the listing and here: the next pass will not see it
		}
		// An interface with no route is half-wired — an Attach that failed between the pair and the
		// route. It is still named, so the datapath is put back on it, but nothing is claimed about
		// an address that was never installed.
		out = append(out, Wiring{Interface: name, Index: dev.Index, Address: routed[name]})
	}
	return out, nil
}

// hostRouteAddresses maps each interface to the single address routed to it, read from
// /proc/net/route rather than asked over netlink: it is a table the kernel already renders, and a
// route DUMP parser would be a second netlink message shape to keep correct for one lookup.
//
// Only /32 destinations count — that is the shape routeToWorkload installs, one host route per
// workload, and a wider prefix on one of these interfaces would be somebody else's doing.
func hostRouteAddresses() (map[string]netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := map[string]netip.Addr{}
	s := bufio.NewScanner(f)
	s.Scan() // the header
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 8 || fields[7] != "FFFFFFFF" {
			continue
		}
		// The destination is the 32-bit value the kernel prints in host order, so its little-endian
		// bytes are the address itself.
		v, err := strconv.ParseUint(fields[1], 16, 32)
		if err != nil {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		out[fields[0]] = netip.AddrFrom4(b)
	}
	return out, s.Err()
}

// configureHost brings the host end up and routes the workload's address to it — a /32 (or /128) with
// link scope, which is what makes the node reach exactly this workload and nothing else through
// this interface.
func (v *VethLinker) configureHost(host string, workload, gw netip.Addr) error {
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	iface, err := net.InterfaceByName(host)
	if err != nil {
		return fmt.Errorf("host interface %s: %w", host, err)
	}
	if err := linkUp(c, iface.Index); err != nil {
		return fmt.Errorf("bring %s up: %w", host, err)
	}
	// The gateway address goes ON the host end. The workload's default route is onlink, so it ARPs
	// for the gateway on eth0 — and an address nobody on the link owns is an ARP that goes
	// unanswered and a namespace that reaches nothing.
	//
	// It is the SAME address on every pair and on every node, because it is link-local and never
	// leaves the pair: each veth is its own point-to-point link, so there is no conflict to have.
	// That is what makes a per-node range unnecessary — a workload's address says nothing about
	// where it runs, and nothing has to be renumbered when it moves.
	if err := addAddress(c, iface.Index, netip.PrefixFrom(gw, gw.BitLen())); err != nil {
		return fmt.Errorf("gateway %s on %s: %w", gw, host, err)
	}
	if err := routeToWorkload(c, iface.Index, workload); err != nil {
		return fmt.Errorf("route %s to %s: %w", workload, host, err)
	}
	// And the workload pinned in the HOST's neighbour table, the mirror of the entry inside the
	// namespace. Both directions now know the other's address without asking, which removes ARP from
	// this network entirely — and is load-bearing rather than tidy: an L3 tunnel delivers by handing
	// the packet to the neighbouring subsystem, and an address that has to be resolved first is a
	// packet dropped while it is. Measured: with an empty neighbour table every decapsulated packet
	// was discarded, while the tunnel's own counters showed them arriving.
	if err := addNeighbour(c, iface.Index, workload, networkMAC); err != nil {
		return fmt.Errorf("pin %s on %s: %w", workload, host, err)
	}
	return nil
}

// configureWorkload runs INSIDE the workload's namespace: loopback up (an image whose lo is down breaks
// in ways nobody debugs quickly), the address on eth0, the gateway's address pinned in the
// neighbour table, and a default route out through it.
func configureWorkload(addr netip.Prefix, gw netip.Addr, mtu int) error {
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	if lo, err := net.InterfaceByName("lo"); err == nil {
		if err := linkUp(c, lo.Index); err != nil {
			return fmt.Errorf("bring lo up: %w", err)
		}
	}
	iface, err := net.InterfaceByName(WorkloadInterface)
	if err != nil {
		return fmt.Errorf("workload interface: %w", err)
	}
	if mtu > 0 {
		if err := setMTU(c, iface.Index, mtu); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
	}
	if err := linkUp(c, iface.Index); err != nil {
		return fmt.Errorf("bring %s up: %w", WorkloadInterface, err)
	}
	if err := addAddress(c, iface.Index, addr); err != nil {
		return fmt.Errorf("address %s: %w", addr, err)
	}
	// The gateway is PINNED rather than ARPed for. Its address is link-local and its MAC is derived
	// from it, so both sides know it without asking — and what asking used to cost was a round trip
	// on the first packet and a failure nobody can trace: an ARP that goes unanswered (a host end
	// that lost its address, an interface that is not up) hangs the workload's first connection with
	// no error, no ICMP and nothing in any log.
	//
	// ARP stays ENABLED on the interface: the node's own traffic to this workload is routed by the
	// kernel and resolves the workload's address the ordinary way. What is removed is the workload
	// having to ask, not its ability to answer.
	if err := addNeighbour(c, iface.Index, gw, networkMAC); err != nil {
		return fmt.Errorf("pin the gateway %s: %w", gw, err)
	}
	if err := defaultRoute(c, iface.Index, gw); err != nil {
		return fmt.Errorf("default route via %s: %w", gw, err)
	}
	return nil
}

// Detach removes the host end. The workload end dies with it — a veth pair is one object with two names
// — and everything inside the namespace goes when the namespace does, so there is no inventory to
// walk here.
func (v *VethLinker) Detach(_ context.Context, id string) error {
	return v.deleteLink(v.HostInterface(id))
}

// Reclaim removes the host-side end of every workload the agent no longer names.
//
// The interfaces ARE the record — there is no file to consult, and none to disagree with reality.
// The keep list is turned into the names those workloads WOULD have, and anything else carrying
// this helper's prefix is a leftover: a workload that went away while the helper was down, or one
// whose teardown never got an answer.
func (v *VethLinker) Reclaim(ctx context.Context, keep []string) error {
	wanted := make(map[string]struct{}, len(keep))
	for _, id := range keep {
		wanted[v.HostInterface(id)] = struct{}{}
	}
	present, err := hostInterfaces(v.prefix())
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range present {
		if _, ok := wanted[name]; ok {
			continue
		}
		if err := v.deleteLink(name); err != nil {
			errs = append(errs, fmt.Errorf("reclaim %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// deleteLink removes one interface by name. A pair is one object with two names, so the peer
// inside the namespace goes with it — and the namespace itself is the agent's to reclaim.
func (v *VethLinker) deleteLink(name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil // already gone: teardown is idempotent because reconcile repeats
	}
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_, err = c.do(unix.RTM_DELLINK, 0, ifInfomsg(int32(iface.Index), 0, 0), nil)
	if err != nil && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}

// createVeth makes the pair with the peer placed directly into the target namespace by descriptor.
// Placing it at CREATION rather than moving it afterwards means the workload's interface never
// exists in the host's namespace at all — there is no window in which another process could see or
// rename it.
func createVeth(hostName, peerName string, nsFD, mtu int) error {
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	var peer []byte
	peer = append(peer, ifInfomsg(0, 0, 0)...) // the peer's own header, then its attributes
	peer = append(peer, attrString(unix.IFLA_IFNAME, peerName)...)
	peer = append(peer, attr(unix.IFLA_ADDRESS, networkMAC)...)
	peer = append(peer, attrU32(unix.IFLA_NET_NS_FD, uint32(nsFD))...)
	if mtu > 0 {
		peer = append(peer, attrU32(unix.IFLA_MTU, uint32(mtu))...)
	}

	attrs := attrString(unix.IFLA_IFNAME, hostName)
	attrs = append(attrs, attr(unix.IFLA_ADDRESS, networkMAC)...)
	if mtu > 0 {
		attrs = append(attrs, attrU32(unix.IFLA_MTU, uint32(mtu))...)
	}
	attrs = append(attrs, attrNested(unix.IFLA_LINKINFO,
		attrString(unix.IFLA_INFO_KIND, "veth"),
		attrNested(unix.IFLA_INFO_DATA, attrNested(vethInfoPeer, peer)),
	)...)

	_, err = c.do(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, ifInfomsg(0, 0, 0), attrs)
	if errors.Is(err, unix.EEXIST) {
		return nil // another pass won the race; the pair is what matters, not who made it
	}
	return err
}

func linkUp(c *nlConn, index int) error {
	_, err := c.do(unix.RTM_NEWLINK, 0, ifInfomsg(int32(index), unix.IFF_UP, unix.IFF_UP), nil)
	return err
}

func setMTU(c *nlConn, index, mtu int) error {
	_, err := c.do(unix.RTM_NEWLINK, 0, ifInfomsg(int32(index), 0, 0), attrU32(unix.IFLA_MTU, uint32(mtu)))
	return err
}

// addAddress puts the address on the interface. An address that is already there is not an error:
// the agent converges the same workload repeatedly, and a second pass must not turn a healthy
// namespace into a failure.
func addAddress(c *nlConn, index int, p netip.Prefix) error {
	a := p.Addr()
	attrs := attr(unix.IFA_LOCAL, addrBytes(a))
	attrs = append(attrs, attr(unix.IFA_ADDRESS, addrBytes(a))...)
	_, err := c.do(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		ifAddrmsg(addrFamily(a), uint8(p.Bits()), uint32(index)), attrs)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

// defaultRoute sends everything out through the gateway, ONLINK because on a point-to-point pair
// the gateway is on the link by construction and the kernel has no subnet to infer that from.
func defaultRoute(c *nlConn, index int, gw netip.Addr) error {
	attrs := attr(unix.RTA_GATEWAY, addrBytes(gw))
	attrs = append(attrs, attrU32(unix.RTA_OIF, uint32(index))...)
	_, err := c.do(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		rtMsg(addrFamily(gw), 0, unix.RT_SCOPE_UNIVERSE, unix.RTNH_F_ONLINK), attrs)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

// routeToWorkload is the host's half: a host route for exactly this workload's address out of exactly
// its interface. Link scope, because the workload address is directly attached to that veth.
func routeToWorkload(c *nlConn, index int, workload netip.Addr) error {
	bits := uint8(32)
	if !workload.Is4() {
		bits = 128
	}
	attrs := attr(unix.RTA_DST, addrBytes(workload))
	attrs = append(attrs, attrU32(unix.RTA_OIF, uint32(index))...)
	_, err := c.do(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		rtMsg(addrFamily(workload), bits, unix.RT_SCOPE_LINK, 0), attrs)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

// withNetns runs fn inside the namespace named by fd, on a thread of its own.
//
// setns moves the calling THREAD, so the work is pinned to one — and the thread is never unlocked
// on the failure path: if the return trip fails, the thread is in the wrong namespace forever, and
// letting the goroutine exit while locked makes the Go runtime discard it instead of handing a
// poisoned thread back to the pool. The same reasoning as createNetns, for the same syscall.
func withNetns(fd int, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		origin, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			done <- fmt.Errorf("read this thread's netns: %w", err)
			return
		}
		defer func() { _ = origin.Close() }()

		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("enter netns: %w", err)
			return
		}
		callErr := fn()
		if err := unix.Setns(int(origin.Fd()), unix.CLONE_NEWNET); err != nil {
			// The work is done either way; what is lost is this thread, which the runtime
			// discards because the goroutine exits still locked to it.
			done <- callErr
			return
		}
		runtime.UnlockOSThread()
		done <- callErr
	}()
	return <-done
}
