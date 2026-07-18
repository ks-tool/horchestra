package main

import (
	"net"
	"path/filepath"

	"github.com/ks-tool/horchestra/pkg/pki"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

// deployControllerCmd issues a controller serving certificate for addr, writes
// controller.conf (and refreshes admin.conf so kubectl reaches the new address),
// then installs the controller on the host over SSH — the control-plane analogue of
// deploy. The CA must already exist (run `node-tool init` first).
func deployControllerCmd() *cobra.Command {
	var (
		dir, binary, db, user, sshKey, sudoPass string
		sudo, adminConf                         bool
	)
	cmd := &cobra.Command{
		Use:   "deploy-controller <addr>",
		Short: "install the controller (horchestra) on a host over SSH",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			addr := args[0]
			if user != "root" && !cmd.Flags().Changed("sudo") {
				sudo = true
				log.Info().Str("user", user).Msg("non-root SSH user; elevating remote steps with sudo")
			}

			// Serving certificate valid for the deploy address (plus loopback, so
			// kubectl and health checks work locally on the host) + controller.conf.
			ca, err := pki.LoadCA(read(filepath.Join(dir, "ca.crt")), read(filepath.Join(dir, "ca.key")))
			fatal(err, "load CA (run 'node-tool init' first)")
			srvCert, srvKey, err := ca.IssueServer([]string{addr, "127.0.0.1", "localhost"})
			fatal(err, "issue server certificate")
			server := "https://" + net.JoinHostPort(addr, "8443")
			controllerConf, err := clientcmd.Write(newKubeconfig("horchestra", "controller", server, ca.CertPEM(), srvCert, srvKey))
			fatal(err, "marshal controller.conf")

			// Refresh admin.conf locally so kubectl targets this address, unless
			// disabled (e.g. to keep an admin.conf for a different controller).
			if adminConf {
				adminCert, adminKey, err := ca.IssueClient("admin", []string{"system:masters"})
				fatal(err, "issue admin certificate")
				writeKubeconfig(filepath.Join(dir, "admin.conf"),
					newKubeconfig("horchestra", "admin", server, ca.CertPEM(), adminCert, adminKey))
			}

			// Copy the binary + controller.conf and install the controller over SSH.
			// Bind all interfaces (--addr :8443) while the certificate/URL advertise addr.
			r := connect(user, addr, sshKey, sudo, sudoPass)
			defer r.close()
			r.put(read(binary), "/usr/local/bin/horchestra", "0755")
			r.put(controllerConf, "/etc/horchestra/controller.conf", "0600") // embeds the serving key
			r.sudoRun("/usr/local/bin/horchestra install controller --auth-config /etc/horchestra/controller.conf --db " + db + " --addr :8443")
			log.Info().Str("controller", addr).Msg("controller deployed")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "pki-dir", "pki", "PKI directory")
	fs.StringVar(&binary, "binary", "horchestra", "path to the horchestra binary to copy")
	fs.StringVar(&db, "db", "/var/lib/horchestra/controller.db", "controller BoltDB path on the host")
	fs.StringVar(&user, "user", "root", "SSH user")
	fs.StringVar(&sshKey, "ssh-key", "", "SSH private key (defaults to ~/.ssh/id_ed25519 or id_rsa, then ssh-agent)")
	fs.BoolVar(&sudo, "sudo", false, "elevate remote install steps with sudo (auto-enabled when --user is not root)")
	fs.StringVar(&sudoPass, "sudo-pass", "", "sudo password (skips the interactive prompt; or set HORCHESTRA_SUDO_PASS)")
	fs.BoolVar(&adminConf, "admin-conf", true, "rewrite <pki-dir>/admin.conf to target this controller address (set false to keep the existing one)")
	return cmd
}
