// Command node-tool is horchestra's PKI and deployment tool: it creates the CA and kubeconfigs
// (init), issues client certificates and kubeconfigs (cert, kubeconfig), and installs a whole
// fleet over SSH from one declarative file (apply). Each subcommand lives in its own file.
//
// The split between the two halves is deliberate. PKI is a lifecycle — a CA is created once and
// certificates are issued against it over years — so it stays imperative. A fleet is a STATE, so it
// is described rather than commanded: `apply -f` reads what the fleet should be and makes it so,
// which is the same relationship the rest of horchestra has with its own objects.
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
	root.AddCommand(initCmd(), certCmd(), kubeconfigCmd(), applyCmd())

	if err := root.Execute(); err != nil {
		log.Fatal().Err(err).Msg("node-tool")
	}
}
