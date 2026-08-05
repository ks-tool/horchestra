// Package rootcli is the shared entrypoint plumbing for the horchestra binaries: the common
// --log-level/--log-pretty flags, log setup, and a fail-fast Execute.
package root

import (
	hlog "github.com/ks-tool/horchestra/pkg/log"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// Run makes cmd the process root — it adds the shared logging flags, wires log setup into the
// persistent pre-run, disables the completion subcommand, and executes, aborting on error.
func Run(cmd *cobra.Command) {
	var level string
	var pretty bool

	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.CompletionOptions.DisableDefaultCmd = true

	cmd.PersistentFlags().StringVar(&level, "log-level", "info", "log level: debug, info, warn, error")
	cmd.PersistentFlags().BoolVar(&pretty, "log-pretty", false, "human-readable console log output")

	prev := cmd.PersistentPreRun
	cmd.PersistentPreRun = func(c *cobra.Command, args []string) {
		hlog.Setup(level, pretty)
		if prev != nil {
			prev(c, args)
		}
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg(cmd.Name())
	}
}
