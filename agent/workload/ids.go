package workload

import corev1 "github.com/ks-tool/horchestra/api/core/v1"

// Slots is how many ids at the TOP of the node's subordinate range carry workload identities.
// The rest of the range carries the image's own file ownership, which the unpacker spread across
// it and the sandbox must still be able to read.
const Slots = 4096

// HostID is the node-visible id a workload's in-namespace id maps to.
//
// The container-side id is private to each sandbox — every workload may believe it is 1000000000 —
// but /proc/<pid>/root and every file on the node are checked against the HOST id, so mapping two
// workloads onto one host id would hand back exactly the cross-tenant reach the per-namespace
// allocation exists to remove. The range is finite, so this is a hash rather than a bijection:
// two workloads collide when their allocated ids are congruent modulo Slots, and widening
// /etc/subuid and Slots together is what raises that ceiling.
func HostID(sub corev1.IDRange, id int64) int64 {
	slots := min(int64(Slots), sub.Size/2)
	return sub.Min + (sub.Size - slots) + floorMod(id, slots)
}

// AgentID is the same identity as the AGENT addresses it — the number it must chown a file to for
// the workload to own it.
//
// The agent runs in its own user namespace mapping in-ns 1..N onto the subordinate range, so a
// host id is that range's offset plus one. That map is written by this code, not discovered, which
// is what makes the arithmetic sound: HostID and AgentID are two views of one mapping, and a file
// the agent chowns to AgentID(x) is a file the workload with in-ns id x owns.
//
// It is also why chowning to the workload's IN-NAMESPACE id fails: the agent's namespace has no
// such id (an allocated 1000000000 is far outside a 65536-wide range), which the kernel reports as
// EINVAL rather than EPERM.
func AgentID(sub corev1.IDRange, id int64) int64 {
	return HostID(sub, id) - sub.Min + 1
}

// floorMod is n mod m with a non-negative result, so a negative id can never index below the slot
// region.
func floorMod(n, m int64) int64 {
	if m <= 0 {
		return 0
	}
	r := n % m
	if r < 0 {
		r += m
	}
	return r
}
