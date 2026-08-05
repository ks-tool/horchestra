package v1

import (
	"fmt"
	"strconv"
	"strings"
)

// The range a runAsUser/runAsGroup may occupy. The kernel's uid_t/gid_t are 32-bit
// unsigned, and the whole no-root floor is expressed as "not zero" — so a value outside
// this range is not merely invalid, it is a floor bypass: setresuid(2) receives the id in
// a 64-bit register but the kernel reads it as uid_t, so 2^32 truncates to 0 and the
// workload execs as root inside its user namespace (which is the agent's own host uid).
// 2^32-1 is (uid_t)-1, the "no change"/nobody sentinel the kernel and shadow-utils reserve,
// and is excluded for the same reason.
const (
	MinRunAsID int64 = 1
	MaxRunAsID int64 = 1<<32 - 2 // 4294967294

	// DefaultRunAsID is the sentinel the compiled floor falls back to when nothing else assigned
	// an id — the conventional "nonroot" account (distroless/nonroot, Kubernetes' 65532). It is
	// only a floor: in a cluster with the uid allocator running, every workload gets a distinct
	// id out of its namespace's block instead, and this value is never reached.
	DefaultRunAsID int64 = 65532
)

// The host uid/gid space is carved into one private block per namespace, the OpenShift model:
// a workload's id is unpredictable to the image that runs under it, and — the point — no two
// tenants ever share one. A shared id is not a cosmetic issue: workloads on a node run in the
// host PID namespace, so one uid means /proc/<pid>/root reaches the other tenant's rootfs,
// volumes and materialized secrets.
//
// The base sits above every id a distribution hands out and below the subuid ranges the
// rootless runtime maps, so a block collides with neither. 65536 ids per namespace is enough
// that an id is never recycled while data owned by it survives.
const (
	WorkloadUIDBase  int64 = 1_000_000_000
	WorkloadUIDBlock int64 = 65536
)

// UIDRangeAnnotation carries a namespace's block on the Namespace object, in OpenShift's
// "<min>/<size>" spelling. It is an annotation rather than a spec field because the block is
// assigned by the control plane, not declared by whoever creates the namespace.
const UIDRangeAnnotation = "horchestra.io/uid-range"

// IDRange is a half-open block of host ids, [Min, Min+Size). It carries both blocks the system
// reserves: a namespace's workload ids, and the /etc/sub{u,g}id range the rootless runtime maps.
type IDRange struct {
	Min  int64
	Size int64
}

// Contains reports whether id falls inside the block.
func (r IDRange) Contains(id int64) bool { return id >= r.Min && id < r.Min+r.Size }

// IsZero reports an unallocated range.
func (r IDRange) IsZero() bool { return r.Min == 0 && r.Size == 0 }

// String renders the annotation form, "<min>/<size>".
func (r IDRange) String() string { return fmt.Sprintf("%d/%d", r.Min, r.Size) }

// ParseIDRange reads the annotation form. It refuses a block that is empty or that reaches
// outside the usable id space, so a hand-edited annotation cannot hand a workload id 0 or an
// id that truncates in uid_t.
func ParseIDRange(s string) (IDRange, error) {
	minStr, sizeStr, ok := strings.Cut(s, "/")
	if !ok {
		return IDRange{}, fmt.Errorf("uid range %q: want \"<min>/<size>\"", s)
	}
	min, err := strconv.ParseInt(minStr, 10, 64)
	if err != nil {
		return IDRange{}, fmt.Errorf("uid range %q: bad min: %w", s, err)
	}
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return IDRange{}, fmt.Errorf("uid range %q: bad size: %w", s, err)
	}
	if size <= 0 {
		return IDRange{}, fmt.Errorf("uid range %q: size must be positive", s)
	}
	if min < MinRunAsID || min+size-1 > MaxRunAsID {
		return IDRange{}, fmt.Errorf("uid range %q: outside the usable id space (%d..%d)", s, MinRunAsID, MaxRunAsID)
	}
	return IDRange{Min: min, Size: size}, nil
}

// ValidRunAsID rejects an id that is not a usable non-root uid/gid. It is enforced at
// admission and re-checked on the node before the privilege drop, because the two guards
// defend different attackers: admission stops the manifest, the node guard stops a
// storage-direct write or a bug in the push path.
func ValidRunAsID(what string, id int64) error {
	switch {
	case id == 0:
		return fmt.Errorf("%s: the no-root floor forbids id 0", what)
	case id < MinRunAsID || id > MaxRunAsID:
		return fmt.Errorf("%s %d is out of range (%d..%d): a value outside the kernel's uid_t truncates to a different id",
			what, id, MinRunAsID, MaxRunAsID)
	}
	return nil
}

// MaxReportedCPU / MaxReportedMemory bound what a node may claim for itself in status.Capacity.
//
// Capacity is self-reported over the credential-less node stream and is then believed by the
// scheduler's Filter and Score, and by the admission capacity check — which reads the same
// number, so it can never contradict a lying node. An unbounded value makes one compromised node
// certificate a placement oracle: utilization rounds to zero, the node wins every scoring cycle
// in every namespace, and every Application placed on it is pushed there together with the
// plaintext Secrets it references. A ceiling does not make the number trustworthy, it makes it
// unable to dominate; the operator-declared machine size that would make it trustworthy belongs
// in Node.Spec and is not built yet.
const (
	MaxReportedCPU    int64 = 4096
	MaxReportedMemory int64 = 64 << 40 // 64 TiB
)
