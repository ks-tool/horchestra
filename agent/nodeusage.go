package agent

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ks-tool/horchestra/agent/workload"
)

// nodeUsage is what the MACHINE is consuming — not the sum of its workloads, which would miss
// the system, the agent itself and anything else on the host, and so would be the wrong
// number to hold a capacity against.
//
// Read from /proc rather than from cgroup arithmetic, because "the whole node" is exactly
// what /proc/stat and /proc/meminfo answer, and both are readable by anyone. Off linux they
// are absent and every field stays zero, which the caller reports as no sample rather than as
// an idle machine.
func nodeUsage() (workload.Usage, bool) {
	busy, ok := cpuBusyUsec()
	if !ok {
		return workload.Usage{}, false
	}
	used, total, ok := memoryUsedBytes()
	if !ok {
		return workload.Usage{}, false
	}
	return workload.Usage{
		CPUUsec:         busy,
		MemoryBytes:     used,
		MemoryPeakBytes: total, // the machine's total, so a reader has both halves of the ratio
		At:              time.Now(),
	}, true
}

// cpuBusyUsec is cumulative non-idle CPU time across every core, in microseconds.
//
// Everything except idle and iowait counts as busy — the same split top(1) and every node
// exporter use. iowait is excluded deliberately: a core waiting on disk is not a core doing
// work, and counting it would report a machine as saturated when it is merely blocked.
func cpuBusyUsec() (int64, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue // the aggregate line only; per-core lines are "cpu0", "cpu1", ...
		}
		var busy int64
		for i, v := range fields[1:] {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			// user nice system idle iowait irq softirq steal guest guest_nice
			if i == 3 || i == 4 {
				continue // idle, iowait
			}
			busy += n
		}
		// The kernel reports these in USER_HZ, which is 100 on every architecture Linux
		// supports in practice; one tick is therefore 10000 microseconds.
		return busy * 10000, true
	}
	return 0, false
}

// memoryUsedBytes is what the machine has in use and what it has in total. Used is derived
// from MemAvailable rather than from MemFree: free memory excludes the page cache, which the
// kernel will hand back on demand, so MemFree reports a healthy machine as nearly full.
func memoryUsedBytes() (used, total int64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer func() { _ = f.Close() }()
	var available int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, rest, found := strings.Cut(sc.Text(), ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		kb, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			total = kb * 1024
		case "MemAvailable":
			available = kb * 1024
		}
	}
	if total <= 0 || available <= 0 {
		return 0, 0, false
	}
	return total - available, total, true
}
