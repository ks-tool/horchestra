//go:build linux && !agentonly

package main

import (
	"os"

	"github.com/ks-tool/horchestra/pkg/systemd"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	installCmd.AddCommand(installControllerCmd())
}

// installControllerCmd writes the controller's systemd unit (ExecStart=horchestra
// controller <flags>) and — unless --enable=false — enables and (re)starts it over
// D-Bus. The flags below are baked into ExecStart so the served controller runs
// with the same auth-config, database and address; anything more (authorizer,
// admin groups, …) goes through a --config YAML.
func installControllerCmd() *cobra.Command {
	var (
		unitPath, authConfig, configFile, db, addr string
		enable                                     bool
	)
	cmd := &cobra.Command{
		Use:   "controller",
		Short: "install and start the controller as a systemd unit",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			self, err := os.Executable()
			fatal(err, "resolve executable")

			// Bake the flags that shape the served controller into ExecStart, skipping
			// the unset ones.
			execStart := []string{self, "controller"}
			for _, f := range []struct{ name, val string }{
				{"--config", configFile}, {"--auth-config", authConfig}, {"--db", db}, {"--addr", addr},
			} {
				if len(f.val) > 0 {
					execStart = append(execStart, f.name, f.val)
				}
			}

			rendered, err := systemd.Unit{
				Description: "horchestra controller",
				ExecStart:   execStart,
				Restart:     "on-failure",
			}.Render()
			fatal(err, "render unit")
			fatal(os.WriteFile(unitPath, []byte(rendered), 0o644), "write unit "+unitPath)
			log.Info().Str("path", unitPath).Msg("installed controller unit")

			if !enable {
				return
			}
			fatal(systemd.EnableAndRestart(unitPath), "enable controller")
			log.Info().Msg("controller enabled and started")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&unitPath, "unit", "/etc/systemd/system/horchestra-controller.service", "path to write the systemd unit")
	fs.StringVar(&authConfig, "auth-config", "", "controller.conf bundling the serving cert/key, CA and address (from node-tool init)")
	fs.StringVar(&configFile, "config", "", "controller YAML config file")
	fs.StringVar(&db, "db", "/var/lib/horchestra/controller.db", "BoltDB path")
	fs.StringVar(&addr, "addr", "", "listen address (overrides the address from --auth-config)")
	fs.BoolVar(&enable, "enable", true, "enable and start the service via systemd")
	return cmd
}
