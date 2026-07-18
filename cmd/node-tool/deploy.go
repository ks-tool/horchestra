package main

import (
	"net"
	"path/filepath"

	"github.com/ks-tool/horchestra/agent"
	"github.com/ks-tool/horchestra/pkg/pki"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

// deployCmd issues a node client certificate and installs the agent on the node
// over an in-process SSH connection (no scp/ssh binaries required).
func deployCmd() *cobra.Command {
	var (
		dir, binary, controller, node, user, sshKey, sudoPass string
		sudo                                                  bool
	)
	cmd := &cobra.Command{
		Use:   "deploy <node-addr>",
		Short: "install the node-agent (horchestra) on a node over SSH",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			addr := args[0]

			// The node name is the certificate CN — its identity, the Node it may
			// write (NodeRestriction), and the auth-config user. A non-root SSH user
			// can't write /usr/local/bin or register a unit, so auto-enable sudo.
			nodeName := node
			if len(nodeName) == 0 {
				nodeName = addr
			}
			if user != "root" && !cmd.Flags().Changed("sudo") {
				sudo = true
				log.Info().Str("user", user).Msg("non-root SSH user; elevating remote steps with sudo")
			}

			// Resolve and canonicalize the controller URL baked into node.conf.
			if len(controller) == 0 {
				controller = autoController(addr)
			}
			controllerURL, err := agent.NormalizeControllerURL(controller)
			fatal(err, "invalid --controller")
			if agent.IsLoopbackHost(controllerURL) {
				log.Warn().Str("controller", controllerURL).
					Msg("controller URL is loopback; the node will not be able to reach the controller — pass its reachable address")
			}

			// node.conf bundles the node's client identity, the CA and the controller
			// URL — the node-side analogue of controller.conf/admin.conf.
			ca, err := pki.LoadCA(read(filepath.Join(dir, "ca.crt")), read(filepath.Join(dir, "ca.key")))
			fatal(err, "load CA")
			nodeCert, nodeKey, err := ca.IssueClient(nodeName, []string{"system:nodes"})
			fatal(err, "issue node certificate")
			nodeConf, err := clientcmd.Write(newKubeconfig("horchestra", nodeName, controllerURL, ca.CertPEM(), nodeCert, nodeKey))
			fatal(err, "marshal node.conf")

			// Copy the binary + node.conf and install the agent over SSH.
			r := connect(user, addr, sshKey, sudo, sudoPass)
			defer r.close()
			r.put(read(binary), "/usr/local/bin/horchestra", "0755")
			r.put(nodeConf, "/etc/horchestra/node.conf", "0600") // embeds the node private key
			r.sudoRun("/usr/local/bin/horchestra install agent --auth-config /etc/horchestra/node.conf")
			log.Info().Str("node", nodeName).Msg("agent deployed")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "pki-dir", "pki", "PKI directory")
	fs.StringVar(&binary, "binary", "horchestra", "path to the horchestra binary to copy")
	fs.StringVar(&controller, "controller", "", "controller API URL")
	fs.StringVar(&node, "node", "", "node name — the certificate CN and identity (defaults to the address)")
	fs.StringVar(&user, "user", "root", "SSH user")
	fs.StringVar(&sshKey, "ssh-key", "", "SSH private key (defaults to ~/.ssh/id_ed25519 or id_rsa, then ssh-agent)")
	fs.BoolVar(&sudo, "sudo", false, "elevate remote install steps with sudo (auto-enabled when --user is not root)")
	fs.StringVar(&sudoPass, "sudo-pass", "", "sudo password (skips the interactive prompt; or set HORCHESTRA_SUDO_PASS)")
	return cmd
}

// autoController picks the controller URL the node should call back on when
// --controller is omitted: the local source address toward the node, port 8443. It
// warns when that address is in a different subnet than the node (a VPN/tunnel
// source the node likely cannot route back to).
func autoController(nodeAddr string) string {
	ip := localAddr(nodeAddr)
	if len(ip) == 0 {
		log.Fatal().Msg("could not determine local address; pass --controller")
	}
	if !sameSubnet(ip, nodeAddr) {
		log.Warn().Str("controller", ip).Str("node", nodeAddr).
			Msg("auto-selected controller address is in a different subnet than the node (e.g. a VPN/tunnel address); the node may be unable to route back to it — pass --controller with a reachable address")
	}
	url := "https://" + net.JoinHostPort(ip, "8443")
	log.Info().Str("controller", url).Msg("defaulting controller to local address")
	return url
}

// localAddr returns the local IP that would be used to reach target — the address
// the node can reach the controller back on.
func localAddr(target string) string {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	conn, err := net.Dial("udp", net.JoinHostPort(host, "443"))
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// sameSubnet reports whether the node's address shares a subnet with the local
// interface that owns localIP. It errs toward "same" (no warning) on uncertainty.
func sameSubnet(localIP, nodeAddr string) bool {
	host := nodeAddr
	if h, _, err := net.SplitHostPort(nodeAddr); err == nil {
		host = h
	}
	lip, nip := net.ParseIP(localIP), net.ParseIP(host)
	if lip == nil || nip == nil {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(lip) {
			return ipnet.Contains(nip)
		}
	}
	return true
}
