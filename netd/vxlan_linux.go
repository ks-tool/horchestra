//go:build linux

package netd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Overlay modes. Native is the default and the right one wherever the underlay carries the workload
// range — one L2 segment, or a fabric the addresses are published into. VXLAN is for everywhere
// else, which on measurement includes every cloud network: a virtual switch drops a frame whose
// destination is not an address it knows, silently, so a workload address native-routed toward
// another node never arrives (verified with tcpdump on the receiving node: zero packets).
const (
	OverlayNone  = "none"
	OverlayVXLAN = "vxlan"
	OverlayIPIP  = "ipip"
)

// tunnelKind is what a mode needs: a device of some kind, the bytes it costs, and whether it
// carries IP or ethernet. The last one decides the shape of the datapath on both sides — an L3
// tunnel takes the frame's header off on the way in and hands delivery to the neighbouring
// subsystem on the way out — so it is a property of the mode rather than a second flag beside it.
type tunnelKind struct {
	name     string
	kind     string
	overhead int
	l3       bool
}

// The two tunnels. VXLAN is UDP, so it crosses anything that carries UDP, hashes across a
// multipath underlay by source port, and is decoded by every tool an operator already has. IPIP is
// smaller and, MEASURED on this fleet's fabric, faster: 1520 Mbit/s against VXLAN's 1125 node to
// node, a third more, which is not the 30 bytes of header — it is the UDP checksum and segmentation
// work that IP-in-IP does not do. What it does not have is a key (so no second network later),
// IPv6, or any way for a multipath fabric to spread it.
var tunnels = map[string]tunnelKind{
	OverlayVXLAN: {name: "hvx0", kind: "vxlan", overhead: 50},
	OverlayIPIP:  {name: "hip0", kind: "ipip", overhead: 20, l3: true},
}

// IFLA_IPTUN_COLLECT_METADATA is not in x/sys/unix (it lives in linux/if_tunnel.h, not in the
// netlink headers that package generates from), so it is spelled out with its position in the enum
// — read off the kernel's own header rather than remembered.
const iptunCollectMetadata = 19

// Tunnel device names deliberately do NOT start with the veth linker's prefix: everything named
// `hor*` is a workload's host-side end, and the reclaim deletes any of those the agent no longer
// names.

// vxlanPort is the assigned VXLAN port. It must be reachable BETWEEN NODES for the overlay to work,
// and it is worth saying plainly that nothing in the product can enforce that or check it: a
// firewall that drops it produces a datapath that reports itself healthy and delivers nothing
// cross-node. It is also the reason the tunnel is unauthenticated — anything that can send to this
// port can inject a frame with any inner address straight into the workload network, so it belongs
// open to node addresses and to nothing else.
const vxlanPort = 4789

// vxlanVNI is the one network identifier this datapath uses. There is one workload network per
// cluster, so there is one VNI; the device is in collect-metadata mode, where the VNI travels per
// packet rather than being a property of the device, and a second one would be a second network to
// have an opinion about.
const vxlanVNI = 1

// ensureTunnel creates the node's tunnel device if it is not there and brings it up, returning its
// index. The device of the OTHER mode is removed, so switching modes cannot leave two tunnels on a
// node with one of them quietly attached to the datapath.
//
// COLLECT_METADATA is the whole reason this is one device and not one per peer: the remote node's
// address rides with each packet (the BPF program sets it from the table it has just read), so the
// device holds no peer list, no forwarding database and no per-node configuration. A node joining
// the cluster needs nothing configured here — which is exactly the property the address table
// already has, kept.
func ensureTunnel(t tunnelKind) (int, error) {
	for mode, other := range tunnels {
		if mode != t.kindMode() {
			_ = (&VethLinker{}).deleteLink(other.name)
		}
	}
	if dev, err := net.InterfaceByName(t.name); err == nil {
		return dev.Index, tunnelReady(dev.Index, t)
	}
	c, err := dialNetlink()
	if err != nil {
		return 0, err
	}
	defer func() { _ = c.Close() }()

	attrs := attrString(unix.IFLA_IFNAME, t.name)
	if !t.l3 {
		attrs = append(attrs, attr(unix.IFLA_ADDRESS, tunnelMAC)...)
	}
	attrs = append(attrs, attrNested(unix.IFLA_LINKINFO,
		attrString(unix.IFLA_INFO_KIND, t.kind),
		attrNested(unix.IFLA_INFO_DATA, t.data()),
	)...)

	_, err = c.do(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, ifInfomsg(0, 0, 0), attrs)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return 0, fmt.Errorf("create the tunnel device %s: %w", t.name, err)
	}
	dev, err := net.InterfaceByName(t.name)
	if err != nil {
		return 0, fmt.Errorf("tunnel device %s: %w", t.name, err)
	}
	return dev.Index, tunnelReady(dev.Index, t)
}

// data is the kind-specific half of the link message.
func (t tunnelKind) data() []byte {
	if t.l3 {
		// A FLAG attribute: its presence IS the value, so the payload must be empty. Sending the
		// one byte vxlan's equivalent takes gets the whole message rejected with ERANGE, which
		// reads as "your kernel cannot do this" and is not that at all.
		return attr(iptunCollectMetadata, nil)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], vxlanPort) // __be16, unlike every other attribute here
	data := attr(unix.IFLA_VXLAN_COLLECT_METADATA, []byte{1})
	data = append(data, attr(unix.IFLA_VXLAN_LEARNING, []byte{0})...)
	return append(data, attr(unix.IFLA_VXLAN_PORT, port[:])...)
}

func (t tunnelKind) kindMode() string {
	if t.l3 {
		return OverlayIPIP
	}
	return OverlayVXLAN
}

// tunnelReady brings the device up and, for an ethernet one, asserts its address — see tunnelMAC for
// why that must not be the network's. An L3 tunnel has no address to assert.
func tunnelReady(index int, t tunnelKind) error {
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if !t.l3 {
		if err := setMAC(c, index, tunnelMAC); err != nil {
			return fmt.Errorf("set the tunnel's address: %w", err)
		}
	}
	return linkUp(c, index)
}

// The overhead each mode costs is in its tunnelKind above, and it is subtracted from a workload's
// MTU — because the alternative is a workload that learns the difference from a TLS handshake that
// hangs, which is the one failure mode of an overlay everybody meets exactly once.
