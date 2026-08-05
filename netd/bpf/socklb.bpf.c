// SPDX-License-Identifier: GPL-2.0
//
// socklb — the service load balancer, done at the socket instead of on the packet.
//
// A ClusterIP is not an address anything answers on: nothing owns it, no interface carries it, no
// ARP resolves it. Something has to turn it into a backend, and the choice is WHERE. The packet
// route (netfilter/DNAT, or a tc program) rewrites the address after it has been built, which means
// every reply has to be rewritten back, which means state: a conntrack entry per flow, per node,
// that must be kept, aged and looked up on both directions of every packet.
//
// This does it one layer earlier. A connect(2) to a ClusterIP is rewritten in the kernel before the
// socket has a peer, so the socket is opened to the BACKEND: the packets that follow are ordinary
// packets to a real address, the replies come back to the address that sent them, and there is no
// return path to translate and no per-flow state to hold anywhere. What is held is the service
// table itself — a map of what exists, not a map of what is happening.
//
// The consequence to know: a workload that calls getpeername(2) sees the backend, not the ClusterIP
// it dialled. This is inherent to rewriting at connect time, and the fix (a reverse map consulted
// from a cgroup/getpeername4 program) is a later slice; nothing in horchestra depends on it today.
//
// These objects are GPL-2.0 — a deliberate dual-licence for the datapath alone, and the reason is
// the VERIFIER: helpers marked gpl_only in the kernel's helper table are refused outright unless the
// program declares a GPL-compatible licence. That refusal already cost this datapath one design
// decision (bpf_fib_lookup) and one debugging session (bpf_trace_printk cannot be called at all
// under a non-GPL string). Declaring GPL here buys the whole helper table; the rest of the tree is
// unaffected.
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

// svc_key is what a connect(2) is looked up by. Every field is in NETWORK byte order except the
// protocol, so the userspace side stores exactly what the kernel will present here and no
// conversion happens on the datapath.
//
// pad is explicit and zeroed on purpose: a hash map compares KEYS BYTE-WISE, so a byte the compiler
// chose to leave uninitialised is a lookup that misses at random.
struct svc_key {
	__u32 address;
	__u16 port;
	__u8 protocol;
	__u8 pad;
};

// svc_val is the number of backends registered for the service, and only that. The backends
// themselves live in a second map keyed by (service, index): one map would mean a value big enough
// for the largest imaginable backend set, allocated for every service that has one backend.
//
// Keeping it separate is also what makes an update safe without stopping the datapath: userspace
// writes every entry BEFORE the count that names it and removes the ones it no longer names AFTER,
// so the count is never higher than the entries present, and the index this program picks always
// resolves.
struct svc_val {
	__u32 backends;
};

struct backend_key {
	struct svc_key service;
	__u16 index;
	__u16 pad;
};

struct backend {
	__u32 address;
	__u16 port;
	__u16 pad;
};

// The sizes are fixed at load time — a BPF map cannot grow — so they are a declared limit rather
// than a guess to revisit: a cluster past them gets a service that does not answer, which is why
// the userspace side refuses the update instead of letting the kernel drop it.
#define MAX_SERVICES 4096
#define MAX_BACKENDS 65536

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct svc_key);
	__type(value, struct svc_val);
	__uint(max_entries, MAX_SERVICES);
} horc_services SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct backend_key);
	__type(value, struct backend);
	__uint(max_entries, MAX_BACKENDS);
} horc_backends SEC(".maps");

// rewrite is the whole program: look the destination up, pick a backend, replace the destination.
// A miss returns the address untouched, which is the case that must stay cheap — every connect(2)
// made by every process in the attached cgroup comes through here, and almost none of them are to a
// ClusterIP.
//
// The pick is random rather than round-robin because a counter in a map is shared mutable state
// across every CPU on the node, and its cost (a contended atomic on the connect path) buys an
// even spread nobody measures. Random is even in aggregate and needs nothing remembered.
static __always_inline int rewrite(struct bpf_sock_addr *ctx)
{
	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return 1;

	struct svc_key key = {};
	key.address = ctx->user_ip4;
	// user_port is a 4-byte field holding a 2-byte port in network byte order: the port is the
	// LOW half, and the kernel wants it written back the same way.
	key.port = (__u16)ctx->user_port;
	key.protocol = (__u8)ctx->protocol;

	struct svc_val *svc = bpf_map_lookup_elem(&horc_services, &key);
	if (!svc || svc->backends == 0)
		return 1;

	struct backend_key bk = {};
	bk.service = key;
	bk.index = (__u16)(bpf_get_prandom_u32() % svc->backends);

	struct backend *be = bpf_map_lookup_elem(&horc_backends, &bk);
	if (!be)
		return 1; // a shrinking service, mid-update: the ClusterIP is better than a black hole

	ctx->user_ip4 = be->address;
	ctx->user_port = (__u32)be->port;
	return 1;
}

// connect4 covers TCP and connected UDP: the address is chosen once, at connect(2).
SEC("cgroup/connect4")
int horc_connect4(struct bpf_sock_addr *ctx)
{
	return rewrite(ctx);
}

// sendmsg4 covers UDP that never connects — sendto(2) carries the destination per datagram, so it
// never passes through connect4 at all. Without this a UDP service answers for some clients and not
// others, which is the kind of half-working nobody debugs quickly.
SEC("cgroup/sendmsg4")
int horc_sendmsg4(struct bpf_sock_addr *ctx)
{
	return rewrite(ctx);
}
