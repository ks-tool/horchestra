//go:build linux

package userns

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ks-tool/horchestra/agent/workload"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
)

// cgroupRoot is where the unified hierarchy is mounted. cgroup v2 only: v1 spread these
// numbers across per-controller trees with different names and no delegation story worth
// having, and this runtime already requires a systemd new enough that v2 is what it gets.
const cgroupRoot = "/sys/fs/cgroup"

// Metrics reads the workload's cgroup — which is the whole of what cAdvisor would do here,
// minus the container discovery this runtime does not need: the unit is known, so systemd is
// asked for its ControlGroup and the numbers are four file reads underneath it.
//
// No privilege is involved. The workloads are systemd --user units, and the user session has
// cpu, memory and pids delegated to it, so the agent reads its own subtree as itself. What
// delegation does NOT include is io, so per-workload disk accounting is absent rather than
// wrong — it would need a privilege this agent is designed not to hold.
func (r *Runtime) Metrics(ctx context.Context, id string) (workload.Usage, error) {
	unit := r.UnitName(id)
	var cg string
	if err := withUserConn(ctx, func(c *sddbus.Conn) error {
		// The SERVICE interface, not the unit's. ControlGroup lives on
		// org.freedesktop.systemd1.Service, so asking for it as a unit property answers
		// nothing — which `systemctl show` hides, because it merges every interface into one
		// listing and made this look like it should work.
		p, err := c.GetUnitTypePropertyContext(ctx, unit, "Service", "ControlGroup")
		if err != nil || p == nil {
			return fmt.Errorf("control group of %s: %w", unit, err)
		}
		cg, _ = p.Value.Value().(string)
		return nil
	}); err != nil {
		return workload.Usage{}, err
	}
	// systemd answers "/" for a unit it knows but is not running, and "" for one it does not
	// know. Either way there is no cgroup to read and no sample to take.
	if cg == "" || cg == "/" {
		return workload.Usage{}, fmt.Errorf("%s is not running: no cgroup to measure", unit)
	}
	return readCgroup(filepath.Join(cgroupRoot, cg))
}

// readCgroup collects the counters from one cgroup directory.
//
// Each file is best-effort: a kernel or a delegation that does not offer one leaves its
// fields zero rather than failing the sample, because a partial answer about a running
// workload is worth more than none. The directory itself missing IS an error — that means
// the workload is gone, and reporting zeros for it would look like a workload using nothing.
func readCgroup(dir string) (workload.Usage, error) {
	if _, err := os.Stat(dir); err != nil {
		return workload.Usage{}, fmt.Errorf("cgroup %s: %w", dir, err)
	}
	u := workload.Usage{At: time.Now()}
	for key, val := range keyedFile(filepath.Join(dir, "cpu.stat")) {
		switch key {
		case "usage_usec":
			u.CPUUsec = val
		case "throttled_usec":
			u.CPUThrottledUsec = val
		}
	}
	u.MemoryBytes = singleValue(filepath.Join(dir, "memory.current"))
	u.MemoryPeakBytes = singleValue(filepath.Join(dir, "memory.peak"))
	u.PIDs = singleValue(filepath.Join(dir, "pids.current"))
	for key, val := range keyedFile(filepath.Join(dir, "memory.events")) {
		if key == "oom_kill" {
			u.OOMKills = val
		}
	}
	return u, nil
}

// singleValue reads a cgroup file holding one number. "max" — the spelling of "no limit" —
// and anything unparseable read as zero.
func singleValue(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// keyedFile reads the "<key> <value>" per line shape cpu.stat and memory.events use.
func keyedFile(path string) map[string]int64 {
	out := map[string]int64{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, rest, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
			out[key] = n
		}
	}
	return out
}
