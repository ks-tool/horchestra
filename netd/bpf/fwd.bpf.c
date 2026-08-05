// SPDX-License-Identifier: GPL-2.0
//
// fwd — where a workload address lives, answered from a map instead of from the route table.
//
// The addresses are ONE flat range for the whole cluster, not a slice per node. That is the entire
// reason this program exists: with per-node ranges a node needs one route per node and the kernel's
// table is enough, but a range that is not carved cannot be summarised, so "which node holds
// 10.244.0.9" is a question about an ADDRESS and not about a prefix. A map answers it in one lookup
// at any cluster size, holds no state beyond the answer, and is what a route reflector can later
// publish per address (that half is not here).
//
// The same program serves both directions, attached at the ingress of each workload's host-side
// veth and at the ingress of the node's uplink:
//
//	from a workload, to a workload here      -> straight into the target's veth
//	from a workload, to a workload elsewhere -> out toward the node that holds it
//	from the uplink, to a workload here      -> straight into its veth
//	anything else                            -> untouched, the kernel decides
//
// Delivering by REDIRECT rather than by letting the kernel route is what keeps this independent of
// the host's configuration: no ip_forward, no rp_filter exemption on the uplink (a packet from a
// remote workload has no route back, so a strict reverse-path check drops it), and no per-workload
// kernel route on any node but the one that holds it.
//
// Known deviation: the TTL is not decremented. A packet forwarded to another node arrives with the
// hop count it left with. It matters only while two nodes disagree about who holds an address —
// each would send it to the other — and that window is one push of the map long.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

char _license[] SEC("license") = "GPL";

// workload is one entry of the table: where an address lives. `node` is the node holding it (0 for
// this one) and `ifindex` is the interface a packet for it LEAVES BY — one field with one meaning in
// both cases, the workload's own veth when it is here and the node's uplink when it is not.
//
// There is no MAC here, and there is nothing to write one for either: every interface in this
// network — both ends of every veth pair and the tunnel device — carries the SAME ethernet address,
// so a frame is addressed to whatever device it arrives at by construction. That removed a field
// from this entry and, later, the destination rewrite from every delivered packet.
//
// Userspace supplies the ifindex — the workload's veth when the address is here, the uplink or the
// tunnel when it is not — and the reason is worth stating precisely, because it changed.
//
// It was first done this way because bpf_fib_lookup, the helper that would answer "which way to
// that node", is gpl_only and these objects declared a licence that forbade it. They declare GPL
// now, and the helper STILL cannot be used: measured on a live kernel, it answers
// BPF_FIB_LKUP_RET_FWD_DISABLED (5), because bpf_ipv4_fib_lookup checks IN_DEV_FORWARD on the
// interface it is asked about — before the OUTPUT branch and regardless of it. This datapath
// deliberately runs with forwarding OFF, since delivery is by redirect precisely so the host's
// configuration cannot decide it. So the helper is unavailable to this design as long as that
// decision stands, and the cost is the honest one: the node's egress is whatever netd was told
// (--uplink, or the default route), which is one interface rather than a route table.
struct workload {
	__u32 node;
	__u32 ifindex;
	__u32 flags;
};

// HORC_TUNNEL says the interface above is the node's tunnel device rather than its uplink, so the
// packet is encapsulated toward the node instead of being addressed to it at L2. It is per ENTRY
// and not a global mode because that is where it costs nothing: the lookup has already happened.
#define HORC_TUNNEL 1u


// One network identifier for one workload network. The device is in collect-metadata mode, so this
// travels with the packet rather than being a property of the device.
#define HORC_VNI 1

// One entry per workload in the cluster, on every node. Fixed at load time because a BPF map cannot
// grow: the userspace side refuses an update past this rather than letting the kernel drop the
// entries that lost the race.
#define MAX_WORKLOADS 65536

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // __be32 workload address
	__type(value, struct workload);
	__uint(max_entries, MAX_WORKLOADS);
} horc_workloads SEC(".maps");

SEC("tc")
int horc_forward(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	// A miss is the common case and must stay cheap: everything a node says to the LAN, to the
	// internet and to itself lands here, and none of it is a workload address.
	__u32 dst = ip->daddr;
	struct workload *wl = bpf_map_lookup_elem(&horc_workloads, &dst);
	if (!wl)
		return TC_ACT_OK;

	if (wl->node == 0) {
		if (wl->ifindex == 0 || skb->ifindex == wl->ifindex)
			return TC_ACT_OK; // nowhere to deliver into, or already on its way in

		// Nothing to correct. Every interface in this network carries the same ethernet address, so
		// a frame is already addressed to the device it is about to arrive at — and the destination
		// rewrite this used to do on every delivered packet has no work left to do.
		//
		// Egress of the host-side veth IS ingress of the namespace: this is the delivery.
		return bpf_redirect(wl->ifindex, 0);
	}

	// Elsewhere, and there are two ways to get there.
	if (wl->flags & HORC_TUNNEL) {
		if (wl->ifindex == 0 || skb->ifindex == wl->ifindex)
			return TC_ACT_OK;
		// Encapsulated toward the node: the frame goes inside a UDP packet addressed to the node's
		// own address, which is an address the underlay knows and will carry. That is the whole
		// point — a cloud fabric drops a workload address outright, and drops it silently.
		//
		// remote_ipv4 is in HOST byte order while everything else in this program is network order:
		// the helper converts it on the way in. Getting that backwards sends every packet to a
		// mirrored address, which looks exactly like a routing problem.
		// Nothing is stripped here for an L3 tunnel, and the first version of this did strip: the
		// kernel already does it. bpf_redirect to a device with no link-layer header takes the
		// __bpf_redirect_no_mac path, which pulls the mac header itself — while BPF_ADJ_ROOM_MAC
		// adjusts the room BETWEEN L2 and L3 rather than removing the header, so doing both left a
		// mangled packet that the tunnel counted as transmitted and the wire never saw.
		struct bpf_tunnel_key key = {};
		key.remote_ipv4 = bpf_ntohl(wl->node);
		key.tunnel_id = HORC_VNI;
		key.tunnel_ttl = 64; // zero here is a packet the outer stack drops immediately
		if (bpf_skb_set_tunnel_key(skb, &key, sizeof(key), BPF_F_ZERO_CSUM_TX) < 0)
			return TC_ACT_OK;
		return bpf_redirect(wl->ifindex, 0);
	}

	// Natively: out of the uplink, addressed to the NODE and not to the workload. The L2 header is
	// filled by the neighbouring subsystem, which is also what queues an ARP if the node has not
	// been spoken to yet — dropping it here instead would make the first connection to every node
	// fail exactly once, which is the kind of flake nobody ever traces back.
	//
	// The nexthop is the node itself, so the nodes must be neighbours: one L2 segment, or an
	// underlay that routes their addresses directly. Anywhere else, that is what the tunnel above is
	// for.
	if (wl->ifindex == 0 || skb->ifindex == wl->ifindex)
		return TC_ACT_OK;
	struct bpf_redir_neigh nh = {};
	nh.nh_family = AF_INET;
	nh.ipv4_nh = wl->node;
	return bpf_redirect_neigh(wl->ifindex, &nh, sizeof(nh), 0);
}

// horc_forward_l3 is the receive half of an L3 tunnel, and it exists because a packet arriving there
// has no ethernet header at all: the device is ARPHRD_NONE, so this program starts at the IP header
// where the other one starts fourteen bytes later.
//
// Delivery hands the frame to the NEIGHBOURING subsystem rather than building the header here. The
// kernel already knows the workload's address on that veth — it is one ARP away and normally
// cached — and asking it is both shorter than assembling a header and correct if the address ever
// stops being derivable.
SEC("tc")
int horc_forward_l3(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct iphdr *ip = data;

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	__u32 dst = ip->daddr;
	struct workload *wl = bpf_map_lookup_elem(&horc_workloads, &dst);
	// Only local delivery belongs here. A packet that came out of the tunnel addressed to somewhere
	// else is not this node's to forward on — it would be a loop through the fabric.
	if (!wl || wl->node != 0 || wl->ifindex == 0)
		return TC_ACT_OK;

	// Straight onto the peer's ingress, which is the one delivery that needs no link-layer header
	// at all: the packet is re-injected inside the namespace with the protocol it already carries,
	// rather than being transmitted out of an ethernet device that would demand a frame.
	//
	// bpf_redirect_neigh was tried first and does not work here — measured, not assumed: it returns
	// TC_ACT_REDIRECT and the kernel then drops the packet inside __bpf_redirect_neigh itself
	// (skb:kfree_skb, protocol=2048), with the neighbour PERMANENT on the right device and the
	// device up. Building a frame for a device whose packets never had one is the wrong shape.
	return bpf_redirect_peer(wl->ifindex, 0);
}
