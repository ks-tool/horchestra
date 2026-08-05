//go:build linux

package netd

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	netdapi "github.com/ks-tool/horchestra/api/netd"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed bpf/fwd.bpf.o
var fwdELF []byte

// Forwarder is the loaded forwarding datapath: one program, one map, and the interfaces it is
// attached to.
//
// All of it is PINNED (see pin_linux.go), which is what makes this helper's death a degradation
// instead of an outage: the attachments and the table are held by the filesystem, so packets keep
// moving while netd is not running. Closing a Forwarder therefore tears NOTHING down — it drops this
// process's descriptors and leaves the datapath where it is. What removes an attachment is a
// workload going away (Detach) or a startup sweep finding an interface that no longer exists.
//
// The consequence is that startup ADOPTS rather than rebuilds: an existing pin is loaded and pointed
// at the newly loaded program, which also makes an upgrade of netd a program swap under a live
// attachment rather than a gap.
type Forwarder struct {
	coll        *ebpf.Collection
	prog        *ebpf.Program
	progL3      *ebpf.Program
	workloads   *ebpf.Map
	uplink      string
	uplinkIndex int
	uplinkMTU   int
	pinDir      string
	// tunnel is the device remote traffic is encapsulated into, empty in native mode. When it is
	// set it — and not the uplink — is what a remote entry names.
	tunnel      string
	tunnelIndex int
	tunnelL3    bool
	overhead    int

	mu    sync.Mutex
	links map[string]link.Link
}

// The workloads map layout, mirrored from bpf/fwd.bpf.c. Byte offsets rather than a marshalled struct,
// for the reason the service table gives: the address is network order and the ifindex is host
// order, and one endianness cannot express both.
//
// ifindex means the same thing in both kinds of entry — the interface a packet for this address
// leaves by — which is the workload's veth when it is here and the node's uplink when it is not.
// There is no MAC: it is derived from the address by both ends (see macFor).
const (
	workloadKeySize = 4  // __be32 workload address
	workloadValSize = 12 // __be32 node, u32 ifindex, u32 flags
	workloadNode    = 0
	workloadIfindex = 4
	workloadFlags   = 8
)

// workloadTunnel mirrors HORC_TUNNEL: the interface in the entry is the tunnel device, so the packet
// is encapsulated toward the node rather than addressed to it at L2. Whether that tunnel carries IP
// or ethernet needs no bit here — the kernel strips the link-layer header on the way into a device
// that has none, and the receive side is a different program chosen when it is attached.
const workloadTunnel = 1

// LoadForwarder loads the datapath and attaches it to the node's uplink, which is where packets
// from other nodes arrive. An empty uplink is auto-detected from the default route: the interface a
// node reaches the rest of the cluster through is the interface it reaches everything through, and
// asking an operator to name it is asking them to keep it correct forever.
func LoadForwarder(uplink, pinDir, overlay string) (*Forwarder, error) {
	if ok, reason := datapathSupport(); !ok {
		return nil, errors.New(reason)
	}
	if err := preparePinDir(pinDir); err != nil {
		return nil, err
	}
	if uplink == "" {
		var err error
		if uplink, err = defaultRouteInterface(); err != nil {
			return nil, fmt.Errorf("find this node's uplink: %w (name it with --uplink)", err)
		}
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(fwdELF))
	if err != nil {
		return nil, fmt.Errorf("read the embedded forwarder: %w", err)
	}
	coll, err := loadPinned(spec, filepath.Join(pinDir, pinMaps))
	if err != nil {
		return nil, fmt.Errorf("load the forwarder: %w", err)
	}
	f := &Forwarder{
		coll:      coll,
		prog:      coll.Programs["horc_forward"],
		progL3:    coll.Programs["horc_forward_l3"],
		workloads: coll.Maps["horc_workloads"],
		uplink:    uplink,
		pinDir:    pinDir,
		links:     map[string]link.Link{},
	}
	if f.prog == nil || f.progL3 == nil || f.workloads == nil {
		coll.Close()
		return nil, errors.New("the embedded forwarder has no program or no workloads map: it was built from other sources than this tree")
	}
	dev, err := net.InterfaceByName(uplink)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("uplink %s: %w", uplink, err)
	}
	f.uplinkIndex, f.uplinkMTU = dev.Index, dev.MTU
	if err := f.attach(uplink); err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach to the uplink %s: %w", uplink, err)
	}
	// The tunnel is a second ingress, not a second datapath: the same program runs on it, and a
	// decapsulated frame takes the same local-delivery branch as one off a workload's veth.
	if overlay != "" && overlay != OverlayNone {
		t, ok := tunnels[overlay]
		if !ok {
			coll.Close()
			return nil, fmt.Errorf("overlay %q is none, %s or %s", overlay, OverlayVXLAN, OverlayIPIP)
		}
		idx, err := ensureTunnel(t)
		if err != nil {
			coll.Close()
			return nil, err
		}
		f.tunnel, f.tunnelIndex, f.tunnelL3, f.overhead = t.name, idx, t.l3, t.overhead
		if err := f.attach(t.name); err != nil {
			coll.Close()
			return nil, fmt.Errorf("attach to the tunnel %s: %w", t.name, err)
		}
	}
	return f, nil
}

// programFor picks which half of the datapath an interface gets. Everything carries frames except an
// L3 tunnel, whose packets arrive with no ethernet header at all — a program that parsed one there
// would read the IP header as MAC addresses.
func (f *Forwarder) programFor(iface string) *ebpf.Program {
	if f.tunnelL3 && iface == f.tunnel {
		return f.progL3
	}
	return f.prog
}

// WorkloadMTU caps what a workload may be given to what its packets can actually carry. The node is
// the only thing that knows both numbers — its own uplink's MTU and whether an overlay is in force —
// so it is the node that subtracts, rather than a control plane guessing on its behalf.
func (f *Forwarder) WorkloadMTU(requested int32) int32 {
	if f.tunnel == "" || f.uplinkMTU == 0 {
		return requested
	}
	maxMtu := int32(f.uplinkMTU - f.overhead)
	if requested == 0 || requested > maxMtu {
		return maxMtu
	}
	return requested
}

// Overlay is the mode in force, for whoever has to report it.
func (f *Forwarder) Overlay() string {
	if f.tunnel == "" {
		return OverlayNone
	}
	if f.tunnelL3 {
		return OverlayIPIP
	}
	return OverlayVXLAN
}

// Attach puts the datapath on one workload's host-side interface — the point every packet a
// workload sends passes through. Idempotent: the agent converges the same workload repeatedly, and
// a second attach would be a second copy of the program on the same hook.
func (f *Forwarder) Attach(iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attach(iface)
}

func (f *Forwarder) attach(iface string) error {
	if f.links == nil {
		f.links = map[string]link.Link{}
	}
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	// Already attached, and to THIS interface: nothing to do. The index is checked and not just the
	// name for the reason spelled out below — within one process, too, since the agent converges the
	// same workload repeatedly and a restart replaces the device under the name.
	if l, ok := f.links[iface]; ok {
		if attachedTo(l) == dev.Index {
			return nil
		}
		_ = l.Close()
		delete(f.links, iface)
	}
	// An existing pin is the attachment a previous netd left running. It is ADOPTED and pointed at
	// this process's program rather than replaced: replacing means detaching, and detaching means a
	// window in which this interface delivers nothing.
	//
	// But only if it still names THIS interface. A pin outlives the device it was made for, and an
	// interface name here is a digest of the workload's id — stable across restarts — while its
	// index is not: a workload that restarts gets a new namespace, its veth dies with the old one
	// and is created again under the same name with a new index. Adopting on the strength of the
	// name alone left the new veth with no program at all, and nothing looked wrong: the pin was
	// there, Status said the datapath was loaded, and packets from that workload were simply never
	// redirected. Found on a stand, where a workload had restarted a few times.
	if l, err := link.LoadPinnedLink(f.linkPin(iface), nil); err == nil {
		if attachedTo(l) == dev.Index {
			if err := l.Update(f.programFor(iface)); err != nil {
				_ = l.Close()
				return fmt.Errorf("adopt the attachment on %s: %w", iface, err)
			}
			f.links[iface] = l
			return nil
		}
		_ = l.Unpin()
		_ = l.Close()
	}
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: dev.Index,
		Program:   f.programFor(iface),
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return err
	}
	if err := l.Pin(f.linkPin(iface)); err != nil {
		_ = l.Close()
		return fmt.Errorf("pin the attachment on %s: %w", iface, err)
	}
	f.links[iface] = l
	return nil
}

// attachedTo is the interface index a link is attached to, or 0 if it cannot be asked — which is
// treated as "not this one", so an unreadable pin is replaced rather than trusted.
func attachedTo(l link.Link) int {
	info, err := l.Info()
	if err != nil {
		return 0
	}
	tcx := info.TCX()
	if tcx == nil {
		return 0
	}
	return int(tcx.Ifindex)
}

func (f *Forwarder) linkPin(iface string) string {
	return filepath.Join(f.pinDir, pinFwdLinks, iface)
}

// Detach takes the datapath off an interface for good: the pin goes too, because a workload that is
// gone is not a degradation to preserve. It is the only thing besides the startup sweep that does —
// everything else here leaves the datapath running.
func (f *Forwarder) Detach(iface string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unpin(iface)
}

// unpin removes an attachment whether or not this process is the one holding it: after a restart the
// pin exists and the descriptor does not, and a workload torn down in that state must still be
// taken off the datapath.
func (f *Forwarder) unpin(iface string) {
	l, ok := f.links[iface]
	if ok {
		delete(f.links, iface)
	} else {
		var err error
		if l, err = link.LoadPinnedLink(f.linkPin(iface), nil); err != nil {
			return // never attached, or already gone
		}
	}
	_ = l.Unpin()
	_ = l.Close()
}

// ReclaimLocal removes the address entries of workloads this node no longer has.
//
// The local half of the table is written by Setup and removed by Teardown or GC — all of which go
// through this helper. A workload torn down while it was NOT RUNNING leaves an entry nothing later
// finds: the interface is gone, so Rewire never restores it, and the agent's GC sweeps by workload
// id, which that workload no longer has. Seen live as an address pointing at an ifindex that had not
// existed for an hour. The kernel reuses interface indices, so left alone that entry eventually
// delivers somebody's packets into the wrong veth.
func (f *Forwarder) ReclaimLocal(keep map[int]struct{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	stale, err := f.entries(func(_ [workloadKeySize]byte, val [workloadValSize]byte) bool {
		if binary.NativeEndian.Uint32(val[workloadNode:workloadNode+4]) != 0 {
			return false // remote, and the push owns those wholesale
		}
		idx := int(binary.NativeEndian.Uint32(val[workloadIfindex : workloadIfindex+4]))
		_, live := keep[idx]
		return !live
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, key := range stale {
		if err := f.workloads.Delete(key[:]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", netip.AddrFrom4(key), err))
		}
	}
	return errors.Join(errs...)
}

// ReclaimPins removes attachments left behind for interfaces this node no longer has. It is the
// price of pinning, paid where the rest of the reclaim is: a pin outlives the process, so a workload
// torn down while netd was DOWN leaves one with nothing behind it.
func (f *Forwarder) ReclaimPins(keep []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	wanted := make(map[string]struct{}, len(keep)+1)
	for _, name := range keep {
		wanted[name] = struct{}{}
	}
	wanted[f.uplink] = struct{}{} // the node's own, which no workload keeps alive
	if f.tunnel != "" {
		wanted[f.tunnel] = struct{}{}
	}
	pins, err := os.ReadDir(filepath.Join(f.pinDir, pinFwdLinks))
	if err != nil {
		return err
	}
	for _, p := range pins {
		if _, ok := wanted[p.Name()]; ok {
			continue
		}
		f.unpin(p.Name())
	}
	return nil
}

// Close drops this process's descriptors and TEARS NOTHING DOWN. The programs stay attached and the
// table keeps its contents, which is the whole point of pinning them: netd exiting — gracefully or
// not — must not take the node's networking with it.
func (f *Forwarder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, l := range f.links {
		_ = l.Close()
		delete(f.links, name)
	}
	if f.coll != nil {
		f.coll.Close()
		f.coll = nil
	}
	return nil
}

// Local records that an address lives HERE, behind this interface. It is written where the wiring
// happens rather than pushed from the control plane, because it is the only place that knows: the
// control plane knows which node holds an address, and the node knows which veth.
//
// It carries no MAC. Delivery still needs one, but every interface in this network carries `02:00`
// followed by its address, so the program derives it from the key rather than being told.
func (f *Forwarder) Local(addr netip.Addr, ifindex int) error {
	if !addr.Is4() {
		return fmt.Errorf("%s is not IPv4: this datapath forwards IPv4 only", addr)
	}
	key := addr.As4()
	var val [workloadValSize]byte
	binary.NativeEndian.PutUint32(val[workloadIfindex:workloadIfindex+4], uint32(ifindex))
	return f.workloads.Update(key[:], val[:], ebpf.UpdateAny)
}

// Forget removes every local entry pointing at an interface. Keyed by INTERFACE and not by address
// because a teardown names a workload and the address it had is exactly what is no longer known —
// the map is read to find it, which is the same rule the rest of this helper follows: what exists
// is the record.
func (f *Forwarder) Forget(ifindex int) error {
	stale, err := f.entries(func(_ [workloadKeySize]byte, val [workloadValSize]byte) bool {
		// Local entries only: a remote one carries the UPLINK's ifindex, and this must never be
		// able to sweep the whole cluster off the node because one veth went away.
		return binary.NativeEndian.Uint32(val[workloadNode:workloadNode+4]) == 0 &&
			binary.NativeEndian.Uint32(val[workloadIfindex:workloadIfindex+4]) == uint32(ifindex)
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, key := range stale {
		if err := f.workloads.Delete(key[:]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Routes replaces the table's REMOTE half: which other node holds which address. The local half is
// left alone — it is written by Setup, which is the only thing that knows an interface, and a push
// that overwrote it would take every workload on this node off the network until the next wiring.
//
// A route naming THIS node is dropped rather than stored. The control plane sends the whole cluster
// to every node, so a node receives its own workloads back; storing them would point the datapath
// at the uplink for an address that is one veth away — a packet sent to itself.
func (f *Forwarder) Routes(routes []*netdapi.Route) error {
	mine, err := hostAddresses()
	if err != nil {
		return err
	}
	want := make(map[[workloadKeySize]byte]netip.Addr, len(routes))
	for _, r := range routes {
		addr, err := singleAddress(r.GetCidr())
		if err != nil {
			return fmt.Errorf("route %q: %w", r.GetCidr(), err)
		}
		if r.GetNodeIp() == "" {
			continue // this node's own, and the wiring already recorded it
		}
		node, err := netip.ParseAddr(r.GetNodeIp())
		if err != nil {
			return fmt.Errorf("route %s: node %q: %w", r.GetCidr(), r.GetNodeIp(), err)
		}
		if !node.Is4() {
			return fmt.Errorf("route %s: node %s is not IPv4", r.GetCidr(), node)
		}
		if _, ok := mine[node]; ok {
			continue
		}
		want[addr.As4()] = node
	}
	if uint32(len(want)) > f.workloads.MaxEntries() {
		return fmt.Errorf("%d workload addresses exceed the datapath's capacity of %d", len(want), f.workloads.MaxEntries())
	}

	var errs []error
	for key, node := range want {
		var val [workloadValSize]byte
		n := node.As4()
		copy(val[workloadNode:workloadNode+4], n[:])
		// The egress interface and the mode, written per entry rather than kept in a config map the
		// program would have to read on every packet: they are the same answer for every remote
		// address, and one lookup is already being made. The program cannot work this out itself —
		// see the note on struct workload in the C for why bpf_fib_lookup is unavailable here.
		egress, flags := f.uplinkIndex, uint32(0)
		if f.tunnel != "" {
			egress, flags = f.tunnelIndex, uint32(workloadTunnel)
		}
		binary.NativeEndian.PutUint32(val[workloadIfindex:workloadIfindex+4], uint32(egress))
		binary.NativeEndian.PutUint32(val[workloadFlags:workloadFlags+4], flags)
		if err := f.workloads.Update(key[:], val[:], ebpf.UpdateAny); err != nil {
			errs = append(errs, fmt.Errorf("route %s: %w", netip.AddrFrom4(key), err))
		}
	}
	stale, err := f.entries(func(key [workloadKeySize]byte, val [workloadValSize]byte) bool {
		if binary.NativeEndian.Uint32(val[workloadNode:workloadNode+4]) == 0 {
			return false // local, and not this call's to remove
		}
		_, ok := want[key]
		return !ok
	})
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, key := range stale {
		if err := f.workloads.Delete(key[:]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("remove route %s: %w", netip.AddrFrom4(key), err))
		}
	}
	return errors.Join(errs...)
}

// entries collects the keys matching a predicate. Collected and not deleted in place: a hash map
// iterated while it is being deleted from may skip entries the kernel moved, and a skipped entry
// here is an address that keeps being forwarded somewhere it no longer lives.
func (f *Forwarder) entries(match func(key [workloadKeySize]byte, val [workloadValSize]byte) bool) ([][workloadKeySize]byte, error) {
	var (
		out  [][workloadKeySize]byte
		key  [workloadKeySize]byte
		val  [workloadValSize]byte
		iter = f.workloads.Iterate()
	)
	for iter.Next(&key, &val) {
		if match(key, val) {
			out = append(out, key)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("read the address table: %w", err)
	}
	return out, nil
}

// singleAddress refuses anything but a host route. The addresses are one flat range with no
// per-node slice, so what a node learns is where ONE address lives; a prefix would be a claim that
// a whole block sits behind one node, which is the arrangement this design exists to avoid.
func singleAddress(cidr string) (netip.Addr, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		addr, aerr := netip.ParseAddr(cidr)
		if aerr != nil {
			return netip.Addr{}, err
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	if !p.Addr().Is4() {
		return netip.Addr{}, errors.New("not IPv4: this datapath forwards IPv4 only")
	}
	if p.Bits() != 32 {
		return netip.Addr{}, fmt.Errorf("is a /%d: a workload address is a host route, never a block", p.Bits())
	}
	return p.Addr(), nil
}

// hostAddresses is every address this node answers on, for recognising a route back to itself.
func hostAddresses() (map[netip.Addr]struct{}, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]struct{}, len(addrs))
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out[ip.Unmap()] = struct{}{}
			}
		}
	}
	return out, nil
}

// defaultRouteInterface is the interface carrying the default route, read from /proc/net/route
// rather than asked over netlink: it is one line of text the kernel already renders, and a route
// DUMP parser would be a second netlink message shape to keep correct for one string.
func defaultRouteInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	s := bufio.NewScanner(f)
	s.Scan() // the header
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 4 {
			continue
		}
		// Destination 0 with the "up" and "gateway" flags: the default route.
		if fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x0002 == 0 { // RTF_GATEWAY
			continue
		}
		return fields[0], nil
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", errors.New("this node has no default route")
}
