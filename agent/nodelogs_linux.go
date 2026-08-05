//go:build linux

package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ks-tool/horchestra/api/utils"
)

// agentUnitLogs tails THIS agent's own unit journal. It is what the controller's
// nodes/<name>/log route streams, and it is deliberately the agent's unit rather than the host
// journal: the host journal carries every workload's output on the node, so serving it would hand
// over in one call what pods/log serves one workload at a time with a permission check on each.
//
// The first argument is ignored — it names a workload for the runtime's Logs, and there is no
// workload here. The signature matches so the two are interchangeable at the one call site.
func agentUnitLogs(ctx context.Context, _ string, follow bool, tail int64) (io.ReadCloser, error) {
	unit, err := ownUnit()
	if err != nil {
		return nil, err
	}
	// Selected by field match on the unit, not `--user-unit`, for the same reason the workload
	// path does it: --merge spans whichever journal files hold the entries, and the field match
	// carries no implicit _UID for the caller.
	args := []string{"--merge", "_SYSTEMD_USER_UNIT=" + unit, "-o", "short-iso", "--no-pager"}
	if tail > 0 {
		args = append(args, "-n", strconv.FormatInt(tail, 10))
	}
	if follow {
		args = append(args, "-f")
	}
	return utils.StartReader(exec.CommandContext(ctx, "journalctl", args...))
}

// ownUnit is the systemd unit this process runs under, read from its own cgroup path — whose last
// component is the unit for a systemd-managed process.
//
// The cgroup and not INVOCATION_ID, which systemd also sets: an invocation id selects the CURRENT
// run only, and an operator asking a node for its agent's logs is usually asking precisely because
// the agent has been restarting.
func ownUnit() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("read own cgroup: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		path := line[strings.LastIndex(line, ":")+1:]
		unit := ""
		for _, seg := range strings.Split(path, "/") {
			if strings.HasSuffix(seg, ".service") {
				unit = seg // the innermost .service is the unit; outer ones are slices
			}
		}
		if unit != "" {
			return unit, nil
		}
	}
	return "", fmt.Errorf("this process is not running under a systemd unit, so it has no unit journal")
}
