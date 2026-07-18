// Command node-tool is horchestra's PKI and SSH deployment tool: it creates the
// CA and kubeconfigs (init), issues client certificates and kubeconfigs (cert,
// kubeconfig), and installs the agent or controller on a host over SSH from one
// binary (deploy, deploy-controller). Each subcommand lives in its own file.
package main

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:           "node-tool",
		Short:         "horchestra PKI and SSH deployment tool",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(initCmd(), certCmd(), kubeconfigCmd(), deployCmd(), deployControllerCmd())

	if err := root.Execute(); err != nil {
		log.Fatal().Err(err).Msg("node-tool")
	}
}
