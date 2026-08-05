package workload

import "time"

// Usage is what one workload actually consumed, as its runtime can measure it. It is the
// cAdvisor-shaped half of monitoring — the resources the sandbox used — and says nothing
// about what the application thinks of itself, which is its own /metrics and a different
// problem.
//
// Every counter is CUMULATIVE since the workload started, and deliberately so: a rate would
// bake the node's sampling interval into the number, and the reader — Prometheus, or an
// operator comparing two samples — is the one who knows over what window it wants one.
//
// The Runtime measures it because only the runtime knows how: a shared-kernel workload is a
// cgroup, a microVM is a hypervisor's accounting, and neither answer is available to the
// reconciler.
type Usage struct {
	// CPUUsec is CPU time consumed; CPUThrottledUsec is how long the workload was held back
	// by its own quota — the number that says a limit is biting, which usage alone never
	// shows.
	CPUUsec          int64
	CPUThrottledUsec int64
	// MemoryBytes is current consumption; MemoryPeakBytes the high-water mark since start,
	// which is what a request SHOULD have been and what current usage cannot tell you.
	MemoryBytes     int64
	MemoryPeakBytes int64
	PIDs            int64
	// OOMKills is the kernel's own count. A workload that was OOM-killed and restarted looks
	// perfectly healthy afterwards; this is the only thing that remembers it happened.
	OOMKills int64
	// At is when the sample was taken, so a reader can tell a fresh number from one left by a
	// node that stopped reporting.
	At time.Time
}
