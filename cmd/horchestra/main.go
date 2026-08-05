//go:build linux

// Command horchestra is the NODE binary: the agent reconcile daemon, its purge helper, the
// privileged network helper (netd) and the workload trampoline (sandbox), in one file.
//
// One file because the three are one deployment. They are always copied to a node together, they
// must always be the same build — the agent writes a unit that ExecStarts the trampoline, and it
// speaks a typed protocol to the helper — and three files gave three chances to be half-upgraded.
//
// One file is NOT one process, and that distinction is the whole design:
//
//	agent    an unprivileged `systemd --user` unit, holding no capability at all
//	netd     a root SYSTEM unit, holding exactly CAP_NET_ADMIN/NET_RAW/SYS_ADMIN/SYS_PTRACE/BPF
//	sandbox  the ExecStart of each workload's transient unit, which drops to the workload's id
//
// systemd draws those lines, and it drew them when these were separate binaries too. What is
// genuinely given up is the compiler's refusal: nothing now stops agent code importing netd's, so
// the module boundary (netd/ is its own module) is what has to hold that line.
//
// The control plane is NOT here, and that is why the trampoline can be. `horchestra-controller` is
// its own binary, so a workload's supervisor path no longer execs anything that serves clients,
// holds the store, or carries the PKI.
package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ks-tool/horchestra/cmd/internal/root"

	"github.com/spf13/cobra"
)

// version is stamped by the build; netd reports it back to an agent in Status.
var version = "dev"

// aliasPrefix is what an argv[0] alias is named with: `horchestra-agent` runs `horchestra agent`.
// The symlinks are shipped beside the binary so a unit file, a habit or a script written against
// the old three-binary layout keeps working, and so `ps` still shows which role a process is.
const aliasPrefix = "horchestra-"

func main() {
	rootCmd := &cobra.Command{
		Use:   "horchestra",
		Short: "horchestra node: the agent, the network helper and the workload sandbox",
	}
	rootCmd.AddCommand(agentCmd(), netdCmd(version), sandboxCmd())

	// argv[0] dispatch. Only a name that resolves to a real subcommand is honoured — anything
	// else falls through to the ordinary parse, so a binary renamed for some unrelated reason
	// still behaves like itself instead of failing on a subcommand nobody typed.
	if role, ok := strings.CutPrefix(filepath.Base(os.Args[0]), aliasPrefix); ok {
		for _, c := range rootCmd.Commands() {
			if c.Name() == role {
				rootCmd.SetArgs(append([]string{role}, os.Args[1:]...))
				break
			}
		}
	}
	root.Run(rootCmd)
}
