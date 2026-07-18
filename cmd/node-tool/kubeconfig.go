package main

import (
	"os"
	"path/filepath"

	"github.com/ks-tool/horchestra/pkg/pki"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

// kubeconfigCmd issues a client certificate and emits a self-contained kubeconfig
// (CA, client certificate and key embedded) for reaching the controller with
// kubectl. The CN becomes the request identity and --group the request groups.
func kubeconfigCmd() *cobra.Command {
	var dir, group, server, name, out string
	cmd := &cobra.Command{
		Use:   "kubeconfig <cn>",
		Short: "issue a certificate and emit a kubeconfig for kubectl",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			cn := args[0]

			ca, err := pki.LoadCA(read(filepath.Join(dir, "ca.crt")), read(filepath.Join(dir, "ca.key")))
			fatal(err, "load CA")
			cert, key, err := ca.IssueClient(cn, splitGroups(group))
			fatal(err, "issue certificate")

			data, err := clientcmd.Write(newKubeconfig(name, cn, server, ca.CertPEM(), cert, key))
			fatal(err, "marshal kubeconfig")

			if len(out) == 0 {
				_, _ = os.Stdout.Write(data)
				return
			}
			write(out, data, 0o600) // contains the client private key
			log.Info().Str("cn", cn).Str("out", out).Msg("wrote kubeconfig")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "pki-dir", "pki", "PKI directory")
	fs.StringVar(&group, "group", "", "comma-separated groups (certificate Organization)")
	fs.StringVar(&server, "server", "https://127.0.0.1:8443", "controller API URL")
	fs.StringVar(&name, "name", "horchestra", "cluster and context name")
	fs.StringVar(&out, "out", "", "output file (defaults to stdout)")
	return cmd
}
