//go:build linux

package sandbox

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// rlimitResources maps a config key to its RLIMIT_ constant. The keys are systemd's Limit*
// names without the prefix, so an operator moving a limit between a unit and a config does not
// have to translate it.
var rlimitResources = map[string]int{
	"AS":         unix.RLIMIT_AS,
	"CORE":       unix.RLIMIT_CORE,
	"CPU":        unix.RLIMIT_CPU,
	"DATA":       unix.RLIMIT_DATA,
	"FSIZE":      unix.RLIMIT_FSIZE,
	"LOCKS":      unix.RLIMIT_LOCKS,
	"MEMLOCK":    unix.RLIMIT_MEMLOCK,
	"MSGQUEUE":   unix.RLIMIT_MSGQUEUE,
	"NICE":       unix.RLIMIT_NICE,
	"NOFILE":     unix.RLIMIT_NOFILE,
	"NPROC":      unix.RLIMIT_NPROC,
	"RSS":        unix.RLIMIT_RSS,
	"RTPRIO":     unix.RLIMIT_RTPRIO,
	"RTTIME":     unix.RLIMIT_RTTIME,
	"SIGPENDING": unix.RLIMIT_SIGPENDING,
	"STACK":      unix.RLIMIT_STACK,
}

// rlimitInfinity is RLIM_INFINITY, spelled as a word in the config because the number it stands
// for (2^64-1) is unreadable and easy to mistype into something finite.
const rlimitInfinity = "infinity"

// validateRlimits checks every limit against what this process may actually set. Raising a HARD
// limit takes CAP_SYS_RESOURCE in the INITIAL user namespace, which a rootless sandbox does not
// have however much the namespace it created says otherwise — so a config asking for more than
// it inherited is refused here, naming the unit directive that would grant it, rather than
// failing with EPERM from inside the trampoline.
func validateRlimits(limits map[string]Rlimit) error {
	for _, name := range slices.Sorted(maps.Keys(limits)) {
		res, ok := rlimitResources[name]
		if !ok {
			return fmt.Errorf("unknown rlimit %q (known: %s)", name,
				strings.Join(slices.Sorted(maps.Keys(rlimitResources)), " "))
		}
		l := limits[name]
		if l.Soft > l.Hard {
			return fmt.Errorf("rlimit %s: soft %s exceeds hard %s", name, l.Soft, l.Hard)
		}
		var cur unix.Rlimit
		if err := unix.Getrlimit(res, &cur); err != nil {
			return fmt.Errorf("rlimit %s: %w", name, err)
		}
		if uint64(l.Hard) > cur.Max {
			return fmt.Errorf("rlimit %s: hard %s exceeds the inherited hard limit %d, which only "+
				"the caller can raise (Limit%s= on the unit)", name, l.Hard, cur.Max, name)
		}
	}
	return nil
}

// applyRlimits sets the configured limits on this process, which execve then preserves. They
// bound the workload where a cgroup cannot: a cgroup limit is shared by everything in it, while
// these are per-process.
//
// RLIMIT_NPROC is the exception worth knowing: the kernel counts it per REAL uid, and the
// sandbox maps the workload onto the invoking user — so it bounds that user's processes across
// the host, not this sandbox's. TasksMax on the unit is the per-workload bound.
func applyRlimits(limits map[string]Rlimit) error {
	for _, name := range slices.Sorted(maps.Keys(limits)) {
		l := limits[name]
		rl := unix.Rlimit{Cur: uint64(l.Soft), Max: uint64(l.Hard)}
		if err := unix.Setrlimit(rlimitResources[name], &rl); err != nil {
			return fmt.Errorf("setrlimit %s (%s:%s): %w", name, l.Soft, l.Hard, err)
		}
	}
	return nil
}
