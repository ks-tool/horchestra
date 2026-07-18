//go:build linux && !controlleronly

package main

import (
	"os"

	"github.com/ks-tool/horchestra/agent"
	"github.com/ks-tool/horchestra/pkg/systemd"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	installCmd.AddCommand(installAgentCmd())
}

// installAgentCmd writes the node-agent's systemd unit and, unless --enable=false,
// enables and starts it via systemd (D-Bus). The agent arguments are resolved and
// validated here so a bad controller URL fails fast at install time rather than on
// every reconcile.
func installAgentCmd() *cobra.Command {
	var (
		unitPath, authConfig, configFile, controller, cert, key, ca string
		enable                                                      bool
	)
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "install and start the node-agent as a systemd unit",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			// Resolve the controller URL for validation and the `agent` arguments to
			// bake into the unit — from node.conf when given, otherwise the flags.
			var runArgs []string
			var controllerURL string
			if len(authConfig) > 0 {
				cfg, err := agent.LoadAuthConfig(authConfig)
				fatal(err, "load auth config "+authConfig)
				controllerURL = cfg.Host
				runArgs = []string{"agent", "--auth-config", authConfig}
			} else {
				controllerURL = controller
				runArgs = []string{"agent", "--controller", controller, "--cert", cert, "--key", key, "--ca", ca}
			}
			if len(configFile) > 0 {
				_, err := agent.LoadNodeConfig(configFile)
				fatal(err, "load node config "+configFile)
				runArgs = append(runArgs, "--config", configFile)
			}

			// Fail fast on a bad controller URL — at install time, not on every reconcile.
			normalized, err := agent.NormalizeControllerURL(controllerURL)
			fatal(err, "invalid controller URL "+controllerURL)
			if agent.IsLoopbackHost(normalized) {
				log.Warn().Str("controller", normalized).
					Msg("controller URL is loopback; a remote node cannot reach the controller here — pass the controller's reachable address")
			}

			self, err := os.Executable()
			fatal(err, "resolve executable")
			rendered, err := systemd.Unit{
				Description: "horchestra node-agent",
				ExecStart:   append([]string{self}, runArgs...),
				Restart:     "on-failure",
			}.Render()
			fatal(err, "render unit")
			fatal(os.WriteFile(unitPath, []byte(rendered), 0o644), "write unit "+unitPath)
			log.Info().Str("path", unitPath).Msg("installed node-agent unit")

			if !enable {
				return
			}
			fatal(systemd.EnableAndRestart(unitPath), "enable node-agent")
			log.Info().Msg("node-agent enabled and started")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&unitPath, "unit", "/etc/systemd/system/horchestra-agent.service", "path to write the systemd unit")
	fs.StringVar(&authConfig, "auth-config", "", "node.conf bundling the client cert/key, CA and controller URL (from node-tool deploy)")
	fs.StringVar(&configFile, "config", "", "node-agent config file (resource limits)")
	fs.StringVar(&controller, "controller", "https://127.0.0.1:8443", "controller API URL (ignored when --auth-config is set)")
	fs.StringVar(&cert, "cert", "/etc/horchestra/node.crt", "client certificate for mTLS")
	fs.StringVar(&key, "key", "/etc/horchestra/node.key", "client private key")
	fs.StringVar(&ca, "ca", "/etc/horchestra/ca.crt", "CA that verifies the controller")
	fs.BoolVar(&enable, "enable", true, "enable and start the service via systemd")
	return cmd
}
