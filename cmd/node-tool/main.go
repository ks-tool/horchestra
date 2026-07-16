package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"ks-tool.dev/horchestra/pkg/agent"
	"ks-tool.dev/horchestra/pkg/kubeconfig"
	"ks-tool.dev/horchestra/pkg/pki"
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

// initCmd creates the local CA and the controller server certificate, then
// bundles them into controller.conf and admin.conf.
func initCmd() *cobra.Command {
	var (
		dir   string
		hosts []string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "create the CA plus controller.conf and admin.conf",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if len(hosts) == 0 {
				hosts = []string{"127.0.0.1", "localhost"}
			}
			ca, err := pki.NewCA()
			if err != nil {
				return fmt.Errorf("create CA: %w", err)
			}
			caKey, err := ca.KeyPEM()
			if err != nil {
				return fmt.Errorf("CA key: %w", err)
			}
			srvCert, srvKey, err := ca.IssueServer(hosts)
			if err != nil {
				return fmt.Errorf("issue server certificate: %w", err)
			}

			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create pki dir: %w", err)
			}
			write(filepath.Join(dir, "ca.crt"), ca.CertPEM(), 0o644)
			write(filepath.Join(dir, "ca.key"), caKey, 0o600)
			write(filepath.Join(dir, "server.crt"), srvCert, 0o644)
			write(filepath.Join(dir, "server.key"), srvKey, 0o600)

			// Bundle the TLS material into kubeconfigs, the way `kubeadm init` emits
			// admin.conf: controller.conf carries the serving identity to launch the
			// controller from a single file; admin.conf is the cluster-admin client
			// config for kubectl. Both point at the first --host.
			server := "https://" + net.JoinHostPort(hosts[0], "8443")
			writeKubeconfig(filepath.Join(dir, "controller.conf"),
				kubeconfig.New("horchestra", "controller", server, ca.CertPEM(), srvCert, srvKey))
			adminCert, adminKey, err := ca.IssueClient("admin", []string{"system:masters"})
			if err != nil {
				return fmt.Errorf("issue admin certificate: %w", err)
			}
			writeKubeconfig(filepath.Join(dir, "admin.conf"),
				kubeconfig.New("horchestra", "admin", server, ca.CertPEM(), adminCert, adminKey))

			log.Info().Str("dir", dir).Strs("hosts", hosts).
				Msg("PKI initialized; wrote controller.conf and admin.conf")
			return nil
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "pki-dir", "pki", "directory to write the PKI into")
	fs.StringArrayVar(&hosts, "host", nil, "controller host (IP or DNS) for the server certificate SAN; repeatable")
	return cmd
}

// certCmd issues a client certificate signed by the local CA.
func certCmd() *cobra.Command {
	var dir, group, out string
	cmd := &cobra.Command{
		Use:   "cert <cn>",
		Short: "issue a client certificate signed by the CA",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cn := args[0]
			prefix := out
			if len(prefix) == 0 {
				prefix = cn
			}
			ca, err := pki.LoadCA(read(filepath.Join(dir, "ca.crt")), read(filepath.Join(dir, "ca.key")))
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}
			var groups []string
			if len(group) > 0 {
				groups = strings.Split(group, ",")
			}
			cert, key, err := ca.IssueClient(cn, groups)
			if err != nil {
				return fmt.Errorf("issue certificate: %w", err)
			}
			write(prefix+".crt", cert, 0o644)
			write(prefix+".key", key, 0o600)
			log.Info().Str("cn", cn).Str("out", prefix).Msg("issued client certificate")
			return nil
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "pki-dir", "pki", "PKI directory")
	fs.StringVar(&group, "group", "", "comma-separated groups (certificate Organization)")
	fs.StringVar(&out, "out", "", "output path prefix (writes <out>.crt and <out>.key; defaults to the CN)")
	return cmd
}

// kubeconfigCmd issues a client certificate and emits a self-contained kubeconfig
// (CA, client certificate and key embedded) for reaching the controller with
// kubectl. The CN becomes the request identity and --group the request groups
// (e.g. system:masters for admin access).
func kubeconfigCmd() *cobra.Command {
	var dir, group, server, name, out string
	cmd := &cobra.Command{
		Use:   "kubeconfig <cn>",
		Short: "issue a certificate and emit a kubeconfig for kubectl",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cn := args[0]
			ca, err := pki.LoadCA(read(filepath.Join(dir, "ca.crt")), read(filepath.Join(dir, "ca.key")))
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}
			var groups []string
			if len(group) > 0 {
				groups = strings.Split(group, ",")
			}
			cert, key, err := ca.IssueClient(cn, groups)
			if err != nil {
				return fmt.Errorf("issue certificate: %w", err)
			}
			kc := kubeconfig.New(name, cn, server, ca.CertPEM(), cert, key)
			data, err := kc.Marshal()
			if err != nil {
				return fmt.Errorf("marshal kubeconfig: %w", err)
			}
			if len(out) == 0 {
				_, _ = os.Stdout.Write(data)
				return nil
			}
			write(out, data, 0o600) // contains the client private key
			log.Info().Str("cn", cn).Str("out", out).Msg("wrote kubeconfig")
			return nil
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
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			// The node name is the certificate CN: it is the node's identity, the Node
			// object it may write (NodeRestriction), and the auth-config user. Default
			// it to the address when --node is omitted.
			nodeName := node
			if len(nodeName) == 0 {
				nodeName = addr
			}
			// A non-root SSH user cannot write /usr/local/bin or /etc/horchestra, nor
			// register the systemd unit — auto-enable sudo unless it was set explicitly.
			if user != "root" && !cmd.Flags().Changed("sudo") {
				sudo = true
				log.Info().Str("user", user).Msg("non-root SSH user; elevating remote steps with sudo")
			}
			if len(controller) == 0 {
				ip := localAddr(addr)
				if len(ip) == 0 {
					return fmt.Errorf("could not determine local address; pass --controller")
				}
				if !sameSubnet(ip, addr) {
					log.Warn().Str("controller", ip).Str("node", addr).
						Msg("auto-selected controller address is in a different subnet than the node (e.g. a VPN/tunnel address); the node may be unable to route back to it — pass --controller with an address reachable from the node")
				}
				controller = "https://" + net.JoinHostPort(ip, "8443")
				log.Info().Str("controller", controller).Msg("defaulting controller to local address")
			}
			// Canonicalize the controller URL before it is embedded in node.conf so the
			// node never receives a scheme-less address that fails at reconcile time.
			controllerURL, err := agent.NormalizeControllerURL(controller)
			if err != nil {
				return fmt.Errorf("invalid --controller: %w", err)
			}
			if agent.IsLoopbackHost(controllerURL) {
				log.Warn().Str("controller", controllerURL).
					Msg("controller URL is loopback; the node will not be able to reach the controller — pass its reachable address")
			}

			ca, err := pki.LoadCA(read(filepath.Join(dir, "ca.crt")), read(filepath.Join(dir, "ca.key")))
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}
			nodeCert, nodeKey, err := ca.IssueClient(nodeName, []string{"system:nodes"})
			if err != nil {
				return fmt.Errorf("issue node certificate: %w", err)
			}
			// node.conf bundles the node's client identity, the CA and the controller
			// URL into one file — the node-side analogue of controller.conf/admin.conf.
			// The node-agent reads everything it needs from it (see agent.LoadAuthConfig).
			nodeConf, err := kubeconfig.New("horchestra", nodeName, controllerURL, ca.CertPEM(), nodeCert, nodeKey).Marshal()
			if err != nil {
				return fmt.Errorf("marshal node.conf: %w", err)
			}

			client, err := dialSSH(user, addr, sshKey)
			if err != nil {
				return fmt.Errorf("ssh connect: %w", err)
			}
			defer func() { _ = client.Close() }()
			r := &remote{client: client, sudo: sudo}
			if sudo {
				r.pass = sudoPassword(r, sudoPass)
			}

			r.put(read(binary), "/usr/local/bin/horchestra", "0755")
			r.put(nodeConf, "/etc/horchestra/node.conf", "0600") // embeds the node private key
			r.sudoRun("/usr/local/bin/horchestra install agent --auth-config /etc/horchestra/node.conf")
			log.Info().Str("node", nodeName).Msg("agent deployed")
			return nil
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

// deployControllerCmd issues a controller serving certificate for addr, writes
// controller.conf (and refreshes admin.conf so kubectl reaches the new address),
// then installs the controller on the host over SSH — the control-plane analogue
// of deploy, from the same horchestra binary. The CA must already exist (run
// `node-tool init` first).
func deployControllerCmd() *cobra.Command {
	var (
		dir, binary, db, user, sshKey, sudoPass string
		sudo, adminConf                         bool
	)
	cmd := &cobra.Command{
		Use:   "deploy-controller <addr>",
		Short: "install the controller (horchestra) on a host over SSH",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			if user != "root" && !cmd.Flags().Changed("sudo") {
				sudo = true
				log.Info().Str("user", user).Msg("non-root SSH user; elevating remote steps with sudo")
			}

			ca, err := pki.LoadCA(read(filepath.Join(dir, "ca.crt")), read(filepath.Join(dir, "ca.key")))
			if err != nil {
				return fmt.Errorf("load CA (run 'node-tool init' first): %w", err)
			}
			// Serving certificate valid for the deploy address (plus loopback, so
			// kubectl and health checks work locally on the host).
			srvCert, srvKey, err := ca.IssueServer([]string{addr, "127.0.0.1", "localhost"})
			if err != nil {
				return fmt.Errorf("issue server certificate: %w", err)
			}
			server := "https://" + net.JoinHostPort(addr, "8443")
			controllerConf, err := kubeconfig.New("horchestra", "controller", server, ca.CertPEM(), srvCert, srvKey).Marshal()
			if err != nil {
				return fmt.Errorf("marshal controller.conf: %w", err)
			}
			// Refresh admin.conf locally so kubectl targets the freshly deployed
			// address, unless disabled (e.g. to preserve an admin.conf for a different
			// controller).
			if adminConf {
				adminCert, adminKey, err := ca.IssueClient("admin", []string{"system:masters"})
				if err != nil {
					return fmt.Errorf("issue admin certificate: %w", err)
				}
				writeKubeconfig(filepath.Join(dir, "admin.conf"),
					kubeconfig.New("horchestra", "admin", server, ca.CertPEM(), adminCert, adminKey))
			}

			client, err := dialSSH(user, addr, sshKey)
			if err != nil {
				return fmt.Errorf("ssh connect: %w", err)
			}
			defer func() { _ = client.Close() }()
			r := &remote{client: client, sudo: sudo}
			if sudo {
				r.pass = sudoPassword(r, sudoPass)
			}

			r.put(read(binary), "/usr/local/bin/horchestra", "0755")
			r.put(controllerConf, "/etc/horchestra/controller.conf", "0600") // embeds the serving key
			// Bind all interfaces (--addr :8443) while the certificate/URL advertise addr.
			r.sudoRun("/usr/local/bin/horchestra install controller --auth-config /etc/horchestra/controller.conf --db " + db + " --addr :8443")
			log.Info().Str("controller", addr).Msg("controller deployed")
			return nil
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
	fs.BoolVar(&adminConf, "admin-conf", true, "rewrite <pki-dir>/admin.conf to target this controller address (set false to keep the existing one, e.g. with multiple controllers)")
	return cmd
}

// localAddr returns the local IP that would be used to reach target — the
// address the node can reach the controller back on.
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
// interface that owns localIP. A different subnet — the classic case being a
// VPN/tunnel source address auto-selected as the controller — usually means the
// node has no route back. It errs toward "same" (no warning) when either address
// is not a plain IP or the owning interface can't be found, so it never nags on
// uncertainty.
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

func dialSSH(user, addr, keyPath string) (*ssh.Client, error) {
	auths, err := sshAuth(keyPath)
	if err != nil {
		return nil, err
	}
	host := addr
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "22")
	}
	return ssh.Dial("tcp", host, &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
}

func sshAuth(keyPath string) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod
	paths := []string{keyPath}
	if len(keyPath) == 0 {
		home, _ := os.UserHomeDir()
		paths = []string{filepath.Join(home, ".ssh", "id_ed25519"), filepath.Join(home, ".ssh", "id_rsa")}
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if signer, err := ssh.ParsePrivateKey(data); err == nil {
			auths = append(auths, ssh.PublicKeys(signer))
			break
		}
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); len(sock) > 0 {
		if conn, err := net.Dial("unix", sock); err == nil {
			auths = append(auths, ssh.PublicKeysCallback(sshagent.NewClient(conn).Signers))
		}
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("no SSH authentication available (provide --ssh-key or run ssh-agent)")
	}
	return auths, nil
}

// remote runs the privileged install steps on a node over SSH, elevating with
// sudo when the login user is not root. All steps are fail-fast (log.Fatal).
type remote struct {
	client *ssh.Client
	sudo   bool
	pass   string // sudo password; empty selects passwordless sudo (sudo -n)
}

// exec runs cmd on the node, feeding stdin (may be nil) and streaming output.
func (r *remote) exec(cmd string, stdin io.Reader) error {
	sess, err := r.client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = sess.Close() }()
	sess.Stdin = stdin
	sess.Stdout, sess.Stderr = os.Stdout, os.Stderr
	return sess.Run(cmd)
}

// elevate wraps cmd with sudo when enabled. Password sudo consumes the password
// from stdin (-S), so it replaces any caller stdin — only safe for commands that
// carry no other stdin payload (put stages file bytes separately for that case).
func (r *remote) elevate(cmd string, stdin io.Reader) (string, io.Reader) {
	switch {
	case !r.sudo:
		return cmd, stdin
	case r.pass == "":
		return "sudo -n " + cmd, stdin
	default:
		return "sudo -S -p '' " + cmd, strings.NewReader(r.pass + "\n")
	}
}

// sudoRun runs a command, elevating it when sudo is enabled.
func (r *remote) sudoRun(cmd string) {
	c, stdin := r.elevate(cmd, nil)
	if err := r.exec(c, stdin); err != nil {
		log.Fatal().Err(err).Msg("remote command")
	}
}

// put streams data to dest with the given octal mode via `install`, elevating
// via sudo when needed.
func (r *remote) put(data []byte, dest, mode string) {
	install := "install -D -m" + mode + " "
	if r.sudo && r.pass != "" {
		// Password sudo can't share stdin between the password line and the file
		// bytes, so stage the file as the login user, then move it into place
		// with sudo and delete the (world-unreadable) stage.
		stage := ".horchestra-stage/" + filepath.Base(dest)
		if err := r.exec(install+"/dev/stdin "+stage, bytes.NewReader(data)); err != nil {
			log.Fatal().Err(err).Str("remote", stage).Msg("upload")
		}
		c, stdin := r.elevate(install+stage+" "+dest+" && rm -f "+stage, nil)
		if err := r.exec(c, stdin); err != nil {
			log.Fatal().Err(err).Str("remote", dest).Msg("upload")
		}
		return
	}
	// No sudo, or passwordless sudo (-n does not read stdin): the file streams
	// straight into install on the remote.
	c, _ := r.elevate(install+"/dev/stdin "+dest, nil)
	if err := r.exec(c, bytes.NewReader(data)); err != nil {
		log.Fatal().Err(err).Str("remote", dest).Msg("upload")
	}
}

// sudoPassword resolves the sudo password: the --sudo-pass flag if given, then
// HORCHESTRA_SUDO_PASS. With neither, it probes the remote — if sudo there is
// passwordless no password is needed (so CI stays non-interactive) — and only
// prompts, on a terminal, when a password is actually required. An empty result
// selects passwordless sudo.
func sudoPassword(r *remote, flagVal string) string {
	if len(flagVal) > 0 {
		return flagVal
	}
	if p, ok := os.LookupEnv("HORCHESTRA_SUDO_PASS"); ok {
		return p
	}
	if r.nopasswdSudo() {
		log.Info().Msg("remote sudo is passwordless; no password needed")
		return ""
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		log.Warn().Msg("remote sudo needs a password but no terminal to prompt and no --sudo-pass/HORCHESTRA_SUDO_PASS set")
		return ""
	}
	_, _ = fmt.Fprint(os.Stderr, "[sudo] password for remote user: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(b), "\r\n")
}

// nopasswdSudo reports whether the remote user may run sudo without a password.
// `sudo -n true` is non-interactive: it succeeds under NOPASSWD and fails (never
// prompting) when a password would be required.
func (r *remote) nopasswdSudo() bool {
	sess, err := r.client.NewSession()
	if err != nil {
		return false
	}
	defer func() { _ = sess.Close() }()
	return sess.Run("sudo -n true") == nil
}

func write(path string, data []byte, mode os.FileMode) {
	if err := os.WriteFile(path, data, mode); err != nil {
		log.Fatal().Err(err).Str("path", path).Msg("write")
	}
}

func read(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal().Err(err).Str("path", path).Msg("read")
	}
	return data
}

// writeKubeconfig marshals kc and writes it 0600 (it embeds a private key).
func writeKubeconfig(path string, kc *kubeconfig.Config) {
	data, err := kc.Marshal()
	if err != nil {
		log.Fatal().Err(err).Str("path", path).Msg("marshal kubeconfig")
	}
	write(path, data, 0o600)
}
