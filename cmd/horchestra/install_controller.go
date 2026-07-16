//go:build linux && !agent

package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"ks-tool.dev/horchestra/pkg/systemd"
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
		RunE: func(_ *cobra.Command, _ []string) error {
			self, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolve executable: %w", err)
			}
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
			if err != nil {
				return fmt.Errorf("render unit: %w", err)
			}
			if err := os.WriteFile(unitPath, []byte(rendered), 0o644); err != nil {
				return fmt.Errorf("write unit %s: %w", unitPath, err)
			}
			log.Info().Str("path", unitPath).Msg("installed controller unit")
			if !enable {
				return nil
			}
			if err := systemd.EnableAndRestart(unitPath); err != nil {
				return fmt.Errorf("enable controller: %w", err)
			}
			log.Info().Msg("controller enabled and started")
			return nil
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
