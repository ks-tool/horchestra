package workload

import (
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// fedoraRange is the subordinate range a real node has (/etc/subuid `pirate:524288:65536`), so the
// numbers below are the ones measured on it rather than invented for the test.
var fedoraRange = corev1.IDRange{Min: 524288, Size: 65536}

// TestHostIDMatchesTheMeasuredMap pins the arithmetic against a live reading: on fedora-01 a
// workload allocated in-namespace id 1000000000 runs as host uid 588288, per its own
// /proc/<pid>/uid_map. If this changes, every file the agent gave that workload becomes
// unreachable to it.
func TestHostIDMatchesTheMeasuredMap(t *testing.T) {
	if got := HostID(fedoraRange, 1_000_000_000); got != 588288 {
		t.Errorf("HostID = %d, want 588288 (the id the kernel showed for that workload)", got)
	}
	// The agent's own namespace maps 1..N onto the same range, so it addresses that identity one
	// past the offset. 588288 - 524288 + 1.
	if got := AgentID(fedoraRange, 1_000_000_000); got != 64001 {
		t.Errorf("AgentID = %d, want 64001", got)
	}
}

// TestWorkloadIDsStayInTheSlotRegion: the ids the agent hands out must land in the region reserved
// for workload identities, never in the part of the range carrying image file ownership — a
// workload whose id collided with a layer's owner would own files it never wrote.
func TestWorkloadIDsStayInTheSlotRegion(t *testing.T) {
	shared := fedoraRange.Min + fedoraRange.Size - Slots
	for _, id := range []int64{0, 1, 65532, 1_000_000_000, 1_000_004_096, -7} {
		host := HostID(fedoraRange, id)
		if host < shared || host >= fedoraRange.Min+fedoraRange.Size {
			t.Errorf("HostID(%d) = %d, outside the slot region [%d,%d)", id, host, shared, fedoraRange.Min+fedoraRange.Size)
		}
		if a := AgentID(fedoraRange, id); a < 1 || a > fedoraRange.Size {
			t.Errorf("AgentID(%d) = %d, outside the agent's own map [1,%d]", id, a, fedoraRange.Size)
		}
	}
}

// TestCollisionIsModularAndDocumented: two workloads congruent modulo the slot count share a host
// id. That is the known ceiling of a finite range, and the test exists so it is a decision rather
// than a surprise.
func TestCollisionIsModularAndDocumented(t *testing.T) {
	if HostID(fedoraRange, 1_000_000_000) != HostID(fedoraRange, 1_000_000_000+Slots) {
		t.Error("ids a slot-count apart must collide; if they no longer do, the ceiling moved and the doc is stale")
	}
	if HostID(fedoraRange, 1_000_000_000) == HostID(fedoraRange, 1_000_000_001) {
		t.Error("adjacent ids must not collide")
	}
}
