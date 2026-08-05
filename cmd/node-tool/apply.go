package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/ks-tool/horchestra/agent"
	"github.com/ks-tool/horchestra/api/pki"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

// applyCmd installs a whole fleet from one file.
//
// It replaces `deploy` and `deploy-controller`, which took the same information as two dozen flags
// spread over two commands run in an order nothing enforced. The flags were not merely verbose:
// they were re-typed on every run, so the fleet's actual shape lived in an operator's shell history
// and drifted between the person who deployed it and the person repairing it later. A file is the
// thing both of them read, and it is the thing that can be committed, reviewed and diffed.
//
// The one input that is NOT in the file is the sudo password — a secret does not belong in a
// document whose whole purpose is to be checked in.
func applyCmd() *cobra.Command {
	var file, sudoPass, local string
	cmd := &cobra.Command{
		Use:   "apply -f <file>",
		Short: "install a fleet from one file: certificates, binaries and units",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			fleet, err := loadFleet(file)
			fatal(err, "read "+file)

			// The ON-HOST half, which the operator's half invokes over SSH after uploading
			// this same file. It is the same command because it is the same act: `install`
			// used to be a second command with its own flags, and the two agreed about paths
			// only because one of them built the other's command line.
			if local != "" {
				applyLocal(fleet, local)
				return
			}
			// Checked here rather than in the loader, and checked for the WHOLE fleet before
			// the first connection: an operator who forgot to build learns which binaries are
			// missing once, instead of one host into the apply.
			fatal(fleet.checkBinaries(), "binaries")

			// Loaded ONCE, here, for two reasons. It is the fleet's single signing identity, so
			// re-reading it per host would let a key swapped mid-apply sign half a fleet with a
			// different CA. And it is the first thing a first-time operator gets wrong: without
			// this the failure is a bare "no such file" from somewhere inside the third step.
			ca, err := loadFleetCA(fleet.Controller.Spec.PKIDir)
			fatal(err, "certificate authority")

			// The controller goes first, and not because an agent needs it up: the agent dials
			// inside a retry loop and tolerates a controller that is not there yet. It goes
			// first because its ADDRESS is what every node.conf is written against, and because
			// the CA has to have issued its serving certificate before anything else is signed.
			controllerURL := fleet.Node.Spec.Controller
			if n, ok := fleet.controllerNode(); ok {
				applyController(fleet, ca, n, sudoPass)
				if controllerURL == "" {
					// Read from the file rather than guessed. The retired `deploy` had to
					// infer this from whichever local interface routed toward the node, which
					// is how a VPN address ended up baked into a fleet's node.conf.
					controllerURL = controllerURLFor(n.Addr, fleet.Controller.Spec.Addr)
				}
			}
			normalized, err := agent.NormalizeControllerURL(controllerURL)
			fatal(err, "controller URL "+controllerURL)
			if agent.IsLoopbackHost(normalized) {
				log.Warn().Str("controller", normalized).
					Msg("the controller URL is loopback; no node will reach it — give the controller a reachable addr")
			}

			for _, n := range fleet.Inventory.Nodes {
				if n.Role == roleAgent {
					applyAgent(fleet, ca, n, normalized, sudoPass)
				}
			}
			log.Info().Int("nodes", len(fleet.Inventory.Nodes)).Str("controller", normalized).Msg("fleet applied")
		},
	}
	fs := cmd.Flags()
	fs.StringVarP(&file, "filename", "f", "", "the fleet description (required)")
	fatal(cmd.MarkFlagRequired("filename"), "filename")
	fs.StringVar(&sudoPass, "sudo-pass", "", "sudo password (skips the interactive prompt; or set HORCHESTRA_SUDO_PASS) — deliberately not a config field")
	fs.StringVar(&local, "local", "", "install THIS host's entry here instead of reaching out over SSH (the address naming it in the inventory); linux only, and normally invoked by the operator's own apply")
	return cmd
}

// controllerURLFor builds the URL nodes call, from the host's address in the inventory and the port
// the controller was told to bind. Taking the port from the bind address rather than hardcoding
// 8443 is what keeps a fleet that moved the port from having to say so twice.
func controllerURLFor(addr, bind string) string {
	port := "8443"
	if _, p, err := net.SplitHostPort(bind); err == nil && p != "" {
		port = p
	}
	return "https://" + net.JoinHostPort(addr, port)
}

// loadFleetCA reads the CA the whole fleet is signed against, naming the fix when it is not there —
// a fleet applied before `node-tool init` is the ordinary first mistake, and "no such file" is not
// an answer to it.
func loadFleetCA(pkiDir string) (*pki.CA, error) {
	crt, key := filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")
	for _, p := range []string{crt, key} {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("%s is missing: create the fleet's CA with `node-tool init --pki-dir %s` first", p, pkiDir)
		}
	}
	return pki.LoadCA(read(crt), read(key))
}

// applyController issues the control plane's serving identity and installs it on its host.
func applyController(f *Fleet, ca *pki.CA, n InventoryNode, sudoPass string) {
	spec := f.Controller.Spec
	runtime, err := roleRuntime(n)
	fatal(err, n.Addr)

	// The serving certificate covers the inventory address plus loopback, so kubectl and health
	// checks work on the host itself.
	srvCert, srvKey, err := ca.IssueServer([]string{n.Addr, "127.0.0.1", "localhost"})
	fatal(err, "issue the serving certificate")
	server := controllerURLFor(n.Addr, spec.Addr)
	controllerConf, err := clientcmd.Write(newKubeconfig("horchestra", "controller", server, ca.CertPEM(), srvCert, srvKey))
	fatal(err, "marshal controller.conf")

	// Refresh admin.conf locally so kubectl targets this controller.
	if spec.AdminConf != nil && *spec.AdminConf {
		fatal(ensurePrivateDir(spec.PKIDir), "pki dir")
		adminCert, adminKey, err := ca.IssueClient("admin", []string{"system:masters"}, adminCertTTL)
		fatal(err, "issue the admin certificate")
		writeKubeconfig(filepath.Join(spec.PKIDir, "admin.conf"),
			newKubeconfig("horchestra", "admin", server, ca.CertPEM(), adminCert, adminKey))
	}

	r := connect(f.sshOptions(n, sudoPass))
	defer r.close()
	shipBinaries(r, n)
	r.put(f.Source, hostConfigFile, "0644")
	r.put(controllerConf, hostControllerConf, "0600") // embeds the serving key

	mode, err := spec.signerMode()
	fatal(err, "node-certificate signer")
	switch mode {
	case signerLocal:
		// The operator chose to sign here: the CA signs node CSRs on the host, so it goes there.
		r.put(ca.CertPEM(), hostClusterCACrt, "0644")
		r.put(read(spec.ClusterCAKey), hostClusterCAKey, "0600")
	case signerVault:
		// No signing key goes anywhere — only the credential the controller proves itself with.
		// The cluster CA still does, because the controller has to verify the chain it is handed
		// back, and that is a certificate rather than a key.
		r.put(ca.CertPEM(), hostClusterCACrt, "0644")
		r.put(read(spec.VaultPKI.Cert), hostVaultCert, "0644")
		r.put(read(spec.VaultPKI.Key), hostVaultKey, "0600")
		if spec.VaultPKI.CABundle != "" {
			r.put(read(spec.VaultPKI.CABundle), hostVaultCA, "0644")
		}
	}

	// The controller is a hardened SYSTEM unit running as a dedicated account, so its whole
	// install needs root — one elevated call, and nothing left to pass but which host this is.
	r.sudoRun(localApply(n.Addr))
	log.Info().Str("host", n.Addr).Str("url", server).Str("runtime", remoteBin(runtime)).Msg("controller installed")
}

// localApply is the command the operator's half runs on a host: the same binary, the same file,
// the same subcommand. What used to be an `install` command line assembled here — a dozen flags
// whose values had to match what the file said — is now one address.
func localApply(addr string) string {
	return hostBinDir + "/" + binNodeTool + " apply -f " + hostConfigFile + " --local " + addr
}

// applyAgent issues a node's client identity and installs the agent — and the network helper, when
// the host was given one.
func applyAgent(f *Fleet, ca *pki.CA, n InventoryNode, controllerURL, sudoPass string) {
	ssh := f.sshFor(n)
	runtime, err := roleRuntime(n)
	fatal(err, n.Addr)

	// The agent is unprivileged by construction and runs on the SSH user's own systemd manager.
	// A root login installs it on ROOT's manager: it works, and it hands the agent exactly the
	// privilege the whole design gives up.
	if ssh.User == "root" {
		log.Warn().Str("host", n.Addr).
			Msg("deploying over a root SSH login: the agent will run on root's systemd --user manager — give the inventory an unprivileged ssh.user for the intended shape")
	}

	// node.conf bundles the node's client identity, the CA and the controller URL. The CN is the
	// node's whole identity: which apps, status writes and Secrets it may reach, on both sides.
	nodeCert, nodeKey, err := ca.IssueClient(n.Name, []string{"system:nodes"}, pki.DefaultClientTTL)
	fatal(err, "issue the node certificate for "+n.Name)
	nodeConf, err := clientcmd.Write(newKubeconfig("horchestra", n.Name, controllerURL, ca.CertPEM(), nodeCert, nodeKey))
	fatal(err, "marshal node.conf")

	r := connect(f.sshOptions(n, sudoPass))
	defer r.close()
	shipBinaries(r, n)
	r.put(f.Source, hostConfigFile, "0644")
	// Owned by the user the agent runs as, not by root: it embeds the node's private key, so
	// 0600 is right — and 0600 root:root is a credential the agent cannot open.
	r.putOwned(nodeConf, hostNodeConf, "0600", ssh.User)

	// Journal access, granted BEFORE the agent's user manager starts — that ordering is the
	// point, not a detail. See grantJournalAccess.
	if ssh.User != "root" {
		if err := r.exec(grantJournalAccess(r, ssh.User), nil); err != nil {
			log.Warn().Err(err).Str("group", journalGroup).Str("user", ssh.User).
				Msg("could not grant journal access; `kubectl logs` will be empty until it is granted and the user manager restarted")
		}
	}

	// Two calls, at two privileges, and the split is load-bearing rather than tidy.
	//
	// NOT elevated: the agent's is a `systemd --user` unit belonging to the user it runs as.
	// Under sudo it would land in root's unit directory and be enabled on root's manager — an
	// agent installed for the wrong user, which is a thing that has actually happened here.
	r.run(localApply(n.Addr))
	if n.Netd {
		// Elevated: the helper IS a system unit, and it exists to hold the capabilities the
		// agent must not have.
		r.sudoRun(localApply(n.Addr))
	}
	log.Info().Str("host", n.Addr).Str("node", n.Name).Str("user", ssh.User).Str("runtime", remoteBin(runtime)).Msg("agent installed")
}

// shipBinaries copies what the host was given, plus the two that are structural rather than chosen.
//
// node-tool is one: it is what performs the install on the far side, so a file that had to name it
// would be naming the tool to itself. horchestra-sandbox is the other: every workload's unit
// ExecStarts it and the agent refuses to start without it, so an inventory that could omit it would
// be an inventory that can describe a node that cannot run anything. Both are taken from beside the
// role's runtime, which is where `make` puts them — and both are logged, because a file that says
// what lands on a host should not be quietly wrong about it.
func shipBinaries(r *remote, n InventoryNode) {
	runtime, err := roleRuntime(n)
	fatal(err, n.Addr)
	for _, b := range n.Binaries {
		r.put(read(b), remoteBin(b), "0755")
	}
	r.put(nodeToolFor(runtime), hostBinDir+"/"+binNodeTool, "0755")
	log.Info().Str("host", n.Addr).Str("binary", binNodeTool).Msg("shipping the installer alongside what the inventory listed")

	if n.Role != roleAgent {
		return
	}
	// The argv[0] aliases. They are SYMLINKS and not copies: the node's three roles are one build,
	// and three files was three chances to be half-upgraded — which is the reason they were merged.
	// Made here rather than shipped because there is nothing to ship; `horchestra-agent` IS
	// `horchestra`, dispatching on the name it was invoked by.
	links := make([]string, 0, len(nodeAliases))
	for _, role := range nodeAliases {
		links = append(links, "ln -sfn "+binNode+" "+hostBinDir+"/"+binNode+"-"+role)
	}
	r.sudoRun("sh -c " + shellQuote(strings.Join(links, "; ")))
	log.Info().Str("host", n.Addr).Strs("aliases", nodeAliases).Msg("linked the node binary's roles beside it")
}

// remoteBin is where a local binary lands on the host: /usr/local/bin, under its own basename.
func remoteBin(local string) string {
	return "/usr/local/bin/" + filepath.Base(local)
}

// sshOptions turns a host's resolved connection settings into what connect takes.
func (f *Fleet) sshOptions(n InventoryNode, sudoPass string) sshOptions {
	s := f.sshFor(n)
	sudo := s.sudoEnabled()
	if sudo && s.User != "root" && s.Sudo == nil {
		log.Info().Str("host", n.Addr).Str("user", s.User).Msg("non-root SSH user; elevating the remote steps that need it")
	}
	return sshOptions{
		user: s.User, addr: n.Addr, keyPath: s.Key, hostKey: s.HostKey,
		acceptNew: s.AcceptNew, sudo: sudo, sudoPass: sudoPass,
	}
}

// sudoEnabled resolves the three-state setting: an explicit choice wins, and the default is "on
// unless the login is root", since a non-root user can write neither /usr/local/bin nor a system
// unit.
func (spec SSHSpec) sudoEnabled() bool {
	if spec.Sudo != nil {
		return *spec.Sudo
	}
	return spec.User != "root"
}
