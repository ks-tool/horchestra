package main

import (
	"net"
	"os"
	"path/filepath"

	"github.com/ks-tool/horchestra/pkg/pki"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// initCmd creates the local CA and the controller server certificate, then bundles
// them into controller.conf and admin.conf.
func initCmd() *cobra.Command {
	var (
		dir   string
		hosts []string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "create the CA plus controller.conf and admin.conf",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			if len(hosts) == 0 {
				hosts = []string{"127.0.0.1", "localhost"}
			}

			// CA + serving certificate.
			ca, err := pki.NewCA()
			fatal(err, "create CA")
			caKey, err := ca.KeyPEM()
			fatal(err, "CA key")
			srvCert, srvKey, err := ca.IssueServer(hosts)
			fatal(err, "issue server certificate")

			// Write the raw PKI material.
			fatal(os.MkdirAll(dir, 0o755), "create pki dir")
			write(filepath.Join(dir, "ca.crt"), ca.CertPEM(), 0o644)
			write(filepath.Join(dir, "ca.key"), caKey, 0o600)
			write(filepath.Join(dir, "server.crt"), srvCert, 0o644)
			write(filepath.Join(dir, "server.key"), srvKey, 0o600)

			// Bundle it into kubeconfigs, the way `kubeadm init` emits admin.conf:
			// controller.conf carries the serving identity to launch the controller
			// from a single file; admin.conf is the cluster-admin client config for
			// kubectl. Both point at the first --host.
			server := "https://" + net.JoinHostPort(hosts[0], "8443")
			writeKubeconfig(filepath.Join(dir, "controller.conf"),
				newKubeconfig("horchestra", "controller", server, ca.CertPEM(), srvCert, srvKey))

			adminCert, adminKey, err := ca.IssueClient("admin", []string{"system:masters"})
			fatal(err, "issue admin certificate")
			writeKubeconfig(filepath.Join(dir, "admin.conf"),
				newKubeconfig("horchestra", "admin", server, ca.CertPEM(), adminCert, adminKey))

			log.Info().Str("dir", dir).Strs("hosts", hosts).Msg("PKI initialized; wrote controller.conf and admin.conf")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "pki-dir", "pki", "directory to write the PKI into")
	fs.StringArrayVar(&hosts, "host", nil, "controller host (IP or DNS) for the server certificate SAN; repeatable")
	return cmd
}
