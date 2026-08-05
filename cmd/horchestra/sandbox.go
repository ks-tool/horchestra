//go:build linux

// sandbox — the `horchestra sandbox` command: the workload trampoline systemd --user ExecStarts for
// every rootless workload.
//
// It is a thin front over the ./sandbox MODULE, which is where the mechanism lives. The sandbox is
// not part of the agent and never was — it runs as the workload's parent, in the bare host context,
// supervised by systemd rather than by the agent. Sharing a file with the agent is a deployment
// decision (one build for a node's three roles); sharing an implementation was an accident of
// history, and it is over.
package main

import (
	"fmt"
	"os"

	sandboxmod "github.com/ks-tool/horchestra/sandbox"

	"github.com/spf13/cobra"
)

// sandboxCmd builds the `sandbox` command.
func sandboxCmd() *cobra.Command {
	var configPath, configSum string
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "run a workload inside its sandbox (the ExecStart of every rootless workload unit)",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			// Both required. A config accepted without its digest is a config anything running as
			// this user can rewrite between two starts, and the workload that comes back would be
			// theirs under the application's name.
			if configPath == "" || configSum == "" {
				die(2, "--config and --config-sha256 are both required")
			}
			cfg, err := sandboxmod.LoadConfig(configPath, sandboxmod.WithDigest(configSum))
			if err != nil {
				die(2, "%v", err)
			}
			if err := sandboxmod.Run(cfg); err != nil {
				die(3, "%v", err)
			}
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&configPath, "config", "", "path to the sandbox config JSON the agent wrote")
	fs.StringVar(&configSum, "config-sha256", "", "sha256 of that config, as the agent rendered it")
	return cmd
}

// die reports on stderr — which systemd captures into the workload's journal, the only place an
// operator will look — and exits with code.
func die(code int, format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "sandbox: "+format+"\n", args...)
	os.Exit(code)
}
