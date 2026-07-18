// Command horchestra is the horchestra control-plane + node-agent binary, built in
// one of three modes by build tag:
//
//   - default        the monolith: BOTH roles in one binary. On linux that is the
//     controller, the agent reconcile daemon, purge, and install
//     for either role; off-linux it is controller-only.
//   - controlleronly the control plane alone (`go build -tags controlleronly`),
//     which builds on ANY OS — handy for local control-plane dev.
//   - agentonly      the node role alone (`go build -tags agentonly`), linux only.
//
// The monolith works because the agent (gRPC client) and the apiserver (gRPC
// server) import ONE shared generated transport package, api/pb, so node.proto is
// registered once. Two per-module copies would register the same file/service/
// message names twice in protobuf's global registry and panic at init — which is
// why there is a single api/pb, not an agent/nodeapi + apiserver/nodeapi pair.
//
// Platform: the control plane builds cross-platform; the node role is linux only
// (systemd over D-Bus, overlay rootfs via pkg/systemd/units and pkg/oci, behind a
// linux tag), so any off-linux build is controller-only. node-tool deploys the
// chosen binary and installs the role's systemd unit.
package main

import (
	hlog "github.com/ks-tool/horchestra/pkg/log"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	logLevel  string
	logPretty bool
)

var rootCmd = &cobra.Command{
	Use:           "horchestra",
	Short:         "horchestra control-plane and node-agent",
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(*cobra.Command, []string) {
		hlog.Setup(logLevel, logPretty)
	},
}

// fatal aborts the process with err when it is non-null — the commands are
// fail-fast, so each step logs and exits rather than unwinding an error.
func fatal(err error, msg string) {
	if err != nil {
		log.Fatal().Err(err).Msg(msg)
	}
}

func main() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	rootCmd.PersistentFlags().BoolVar(&logPretty, "log-pretty", false, "human-readable console log output")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("horchestra")
	}
}
