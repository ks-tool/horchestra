//go:build linux

package agent

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/api/resource"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// nodeCapacity measures the compute resource this node offers — logical CPUs and
// total RAM — reduced by any -config limit, and reads its OS identity. CPU is a
// whole-core quantity, memory a byte quantity. Probes are best-effort — a failure
// leaves that field zero. Allocation is derived by the reconciler from running
// apps, not measured here.
func nodeCapacity(limits corev1.ResourceAmounts) (corev1.ResourceAmounts, string) {
	cpu := *resource.NewQuantity(int64(runtime.NumCPU()), resource.DecimalSI)
	mem := *resource.NewQuantity(memTotalBytes(), resource.BinarySI)
	return corev1.ResourceAmounts{
		CPU:    capped(cpu, limits.CPU),
		Memory: capped(mem, limits.Memory),
	}, osIdentity()
}

// memTotalBytes returns MemTotal from /proc/meminfo in bytes.
func memTotalBytes() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok || key != "MemTotal" {
			continue
		}
		// The value is in kB, e.g. "MemTotal:  16333312 kB".
		kb, _ := strconv.ParseInt(strings.Fields(strings.TrimSpace(rest))[0], 10, 64)
		return kb * 1024
	}
	return 0
}

// osIdentity is the distro pretty name (from /etc/os-release) with the kernel
// release and CPU architecture, e.g. "Ubuntu 24.04.2 LTS (6.8.0-85-generic,
// amd64)". Missing pieces are omitted.
func osIdentity() string {
	pretty := osReleasePrettyName()
	detail := runtime.GOARCH
	if kernel := kernelRelease(); kernel != "" {
		detail = kernel + ", " + runtime.GOARCH
	}
	if pretty != "" {
		return pretty + " (" + detail + ")"
	}
	return detail
}

func osReleasePrettyName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}
