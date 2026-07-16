// Command horchestra is the single control-plane + node-agent binary. The same
// executable runs the controller (`horchestra controller`) and the per-node
// reconcile daemon (`horchestra agent`), installs either as a systemd unit
// (`horchestra install controller|agent`) and garbage-collects node images
// (`horchestra purge`); node-tool deploys it to both roles from one artifact
// (deploy-controller / deploy).
//
// Build matrix. The `controller` command builds cross-platform (handy for local
// control-plane dev); `agent`/`install`/`purge` are linux only, because the agent
// drives systemd over D-Bus and mounts overlay rootfs — so an off-linux build
// yields a controller-only binary and a linux build the full monolith. The
// `agent` build tag strips the controller (its run command and its
// `install controller` subcommand) for a node-only binary that never links the
// control-plane: `go build -tags agent` on linux.
package main

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "horchestra",
	Short:         "horchestra control-plane and node-agent",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func main() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("horchestra")
	}
}
