package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/ks-tool/horchestra/api/features"
	"github.com/ks-tool/horchestra/api/pki"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"sigs.k8s.io/yaml"
)

// fleetFileName is what init writes the fleet description as, and what apply reads by default. It
// is a fixed name rather than a flag because the file is the fleet's identity: one per fleet, in
// the directory the operator works from, beside the pki/ it signs against.
const fleetFileName = "node-tool.yaml"

// initCmd creates the local CA plus controller.conf and admin.conf, and writes the fleet
// description that `apply` reads.
//
// The PKI mode is asked for HERE, at the earliest point, rather than at apply time. How node
// certificates get signed is a security decision with three genuinely different answers, and the
// tool refuses to pick one — so the choice may as well be made when the CA it concerns is created,
// while the operator is thinking about exactly that.
func initCmd() *cobra.Command {
	var (
		dir, vaultPKI             string
		controller, agents, hosts []string
		localPKI                  bool
		gateFlags                 []gateFlag
	)
	cmd := &cobra.Command{
		Use:   "init --local-pki | --vault-pki <server>",
		Short: "create the CA, controller.conf and admin.conf, and write " + fleetFileName,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			// Which of the two was chosen is enforced by cobra's flag groups below — one is
			// required, and both together are refused.

			// One control plane, said here rather than at apply time: --controller is repeatable
			// (pflag keeps every value), and a fleet named with two of them is a fleet whose
			// operator expects something this does not do yet.
			if len(controller) > 1 {
				log.Fatal().Msg("HA not supported yet")
			}
			ctrl := ""
			if len(controller) > 0 {
				ctrl = controller[0]
			}

			// The controller's address belongs in the serving certificate whether or not it was
			// also passed as a --host: an operator who named the controller once should not have
			// to name it twice, and a certificate missing that SAN fails at the first kubectl.
			if ctrl != "" {
				hosts = append([]string{ctrl}, hosts...)
			}
			if len(hosts) == 0 {
				hosts = []string{"127.0.0.1", "localhost"}
			}
			for _, extra := range []string{"127.0.0.1", "localhost"} {
				if !slices.Contains(hosts, extra) {
					hosts = append(hosts, extra)
				}
			}

			// CA + serving certificate.
			ca, err := pki.NewCA()
			fatal(err, "create CA")
			caKey, err := ca.KeyPEM()
			fatal(err, "CA key")
			srvCert, srvKey, err := ca.IssueServer(hosts)
			fatal(err, "issue server certificate")

			// Write the raw PKI material.
			fatal(ensurePrivateDir(dir), "create pki dir")
			write(filepath.Join(dir, "ca.crt"), ca.CertPEM(), 0o644)
			write(filepath.Join(dir, "ca.key"), caKey, 0o600)
			write(filepath.Join(dir, "server.crt"), srvCert, 0o644)
			write(filepath.Join(dir, "server.key"), srvKey, 0o600)

			// Bundle it into kubeconfigs, the way `kubeadm init` emits admin.conf:
			// controller.conf carries the serving identity to launch the controller from a
			// single file; admin.conf is the cluster-admin client config for kubectl. Both
			// point at the first host, which is the controller when one was named.
			server := "https://" + net.JoinHostPort(hosts[0], "8443")
			writeKubeconfig(filepath.Join(dir, "controller.conf"),
				newKubeconfig("horchestra", "controller", server, ca.CertPEM(), srvCert, srvKey))

			adminCert, adminKey, err := ca.IssueClient("admin", []string{"system:masters"}, adminCertTTL)
			fatal(err, "issue admin certificate")
			writeKubeconfig(filepath.Join(dir, "admin.conf"),
				newKubeconfig("horchestra", "admin", server, ca.CertPEM(), adminCert, adminKey))

			log.Info().Str("dir", dir).Strs("hosts", hosts).Msg("PKI initialized; wrote controller.conf and admin.conf")

			// The fleet description. REFUSED rather than overwritten if it exists: the PKI above
			// is generated material and regenerating it is an operator's own doing, but this file
			// is the one thing here they WROTE, and clobbering an edited inventory to re-emit a
			// scaffold would be the worst trade in the command.
			if _, err := os.Stat(fleetFileName); err == nil {
				log.Warn().Str("file", fleetFileName).
					Msg("already exists and was left alone; delete it if you want a fresh scaffold")
				return
			}
			scaffold, err := fleetScaffold(scaffoldOptions{
				pkiDir:       dir,
				vaultServer:  vaultPKI,
				featureGates: resolveGates(cmd.Flags(), gateFlags, len(vaultPKI) > 0),
				controller:   ctrl,
				agents:       agents,
			})
			fatal(err, "render "+fleetFileName)
			write(fleetFileName, scaffold, 0o644)
			log.Info().Str("file", fleetFileName).Msg("wrote the fleet description")
			if len(controller) == 0 || len(agents) == 0 {
				log.Info().Msg("no hosts named: fill in the Inventory before `node-tool apply -f " + fleetFileName + "`")
			}
			if len(vaultPKI) > 0 {
				log.Info().Msg("Vault signing needs vaultPKI.role and the controller's own client credential (cert/key) before applying; " +
					"add vaultPKI.adminRole too if `node-tool kubeconfig` is to issue operator certificates through the same engine")
			}
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "pki-dir", "pki", "directory to write the PKI into")
	fs.StringArrayVar(&hosts, "host", nil, "extra controller host (IP or DNS) for the server certificate SAN; repeatable")
	fs.BoolVar(&localPKI, "local-pki", false,
		"the controller signs node rotation CSRs itself, with the CA key uploaded to its host: nodes renew automatically, and a controller compromise discloses the CA")
	fs.StringVar(&vaultPKI, "vault-pki", "",
		"sign node CSRs through this Vault/OpenBao server instead (e.g. https://vault:8200), so the controller holds no signing key at all: renewal then stops while Vault is unreachable")
	fs.StringArrayVar(&controller, "controller", nil, "address of the host that will run the control plane; also a SAN of the serving certificate (one: HA is not supported yet)")
	fs.StringArrayVar(&agents, "agent", nil, "address of a host that will run workloads; repeatable")
	gateFlags = registerGateFlags(fs)

	// The signing decision is cobra's to enforce, not this command's to re-check: one of the two
	// is required and the pair is exclusive, which is exactly what flag groups say. Hand-rolling
	// it meant the rule lived in a switch that --help could not see.
	cmd.MarkFlagsMutuallyExclusive("local-pki", "vault-pki")
	cmd.MarkFlagsOneRequired("local-pki", "vault-pki")
	return cmd
}

// gateFlag is one generated feature-gate flag: the gate it turns on, the flag name it answers to,
// and where its value lands.
type gateFlag struct {
	feature features.Feature
	name    string
	value   *bool
}

// registerGateFlags gives every gate this build knows its own flag, named by kebab-casing the
// gate's own name — VaultStaticRoles becomes --vault-static-roles.
//
// GENERATED rather than listed, and that is the point: a gate added to the registry gets a flag
// without anyone remembering to add one here, a gate removed loses its flag in the same commit
// instead of leaving one that sets something nothing reads, and its --help text is the registry's
// own sentence rather than a second description that can disagree with it. A mistyped gate is
// caught by cobra as an unknown flag, before the CA is created.
func registerGateFlags(fs *pflag.FlagSet) []gateFlag {
	names := features.Names()
	out := make([]gateFlag, 0, len(names))
	for _, name := range names {
		f := features.Feature(name)
		spec, ok := features.Describe(f)
		if !ok {
			continue
		}
		g := gateFlag{feature: f, name: kebabCase(name), value: new(bool)}
		fs.BoolVar(g.value, g.name, spec.Default, spec.Doc+" ("+spec.Stage+")")
		out = append(out, g)
	}
	return out
}

// resolveGates renders the gates the fleet's controller will run with, in its own --feature-gates
// form. Only a flag the operator actually CHANGED is written down: a gate left at the registry's
// default belongs in the registry, not restated in every fleet file, where it would go stale the
// day the default moved.
func resolveGates(fs *pflag.FlagSet, flags []gateFlag, vault bool) string {
	gates := features.Gates{}
	if vault {
		// Signing through Vault and signing WITHOUT a human approving each CSR are separate
		// decisions, and an operator who stood up an engine to sign is asking for the first.
		// Still theirs to refuse: an explicit --auto-node-cert-rotation=false below wins.
		gates[features.AutoNodeCertRotation] = true
	}
	for _, g := range flags {
		if fs.Changed(g.name) {
			gates[g.feature] = *g.value
		}
	}
	return gates.String()
}

// kebabCase turns a gate's name into its flag: VaultStaticRoles → vault-static-roles. Every gate
// this build knows is ordinary CamelCase; an acronym would come out letter-by-letter, which is a
// reason to keep naming them that way rather than to complicate this.
func kebabCase(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// scaffoldOptions is what init knows when it writes the fleet description. A struct rather than
// five positional strings: the last two are both addresses, and a call site that swapped them would
// compile and deploy the control plane to a worker.
type scaffoldOptions struct {
	pkiDir       string
	vaultServer  string
	featureGates string
	controller   string
	agents       []string
}

// fleetScaffold builds the fleet description and marshals it from the very types apply reads back,
// so the file init writes and the file apply parses cannot describe different things. A field
// renamed in the Go type changes both ends at once, which hand-written YAML could not promise.
func fleetScaffold(o scaffoldOptions) ([]byte, error) {
	pkiDir, vaultServer, controller, agents := o.pkiDir, o.vaultServer, o.controller, o.agents
	meta := TypeMeta{APIVersion: toolAPIVersion, Kind: "ControllerConfig"}
	cc := ControllerConfig{
		TypeMeta: meta,
		Spec: ControllerSpec{
			PKIDir:  pkiDir,
			Addr:    ":8443",
			Storage: "bolt:/var/lib/horchestra/controller.db",
		},
	}
	cc.Spec.FeatureGates = o.featureGates
	if len(vaultServer) > 0 {
		// The role and the client credential are fields init cannot know, so they go out empty
		// and the loader refuses the file until they are filled in — which is better than a
		// plausible default that signs with the wrong authority.
		cc.Spec.VaultPKI = &VaultPKISpec{Server: vaultServer, Mount: "pki_int"}
	} else {
		cc.Spec.ClusterCAKey = filepath.Join(pkiDir, "ca.key")
	}

	nc := NodeConfig{
		TypeMeta: TypeMeta{APIVersion: toolAPIVersion, Kind: "NodeConfig"},
		Spec:     NodeSpec{Heartbeat: "5s", Netd: NetdSpec{Overlay: "none"}},
	}

	inv := Inventory{
		TypeMeta: TypeMeta{APIVersion: toolAPIVersion, Kind: "Inventory"},
		SSH:      SSHSpec{User: "root"},
		Nodes:    []InventoryNode{},
	}
	if len(controller) > 0 {
		inv.Nodes = append(inv.Nodes, InventoryNode{
			Addr: controller, Role: roleController,
			Binaries: []string{"./bin/" + binControllerRole},
		})
	}
	for _, a := range agents {
		// One binary: the node's agent, network helper and workload sandbox are one build, and
		// node-tool makes the argv[0] aliases beside it on the host. `netd: true` asks for the
		// privileged helper — an isolated workload needs it, a host-network fleet does not, and an
		// operator who wants the latter deletes one line rather than discovering it was needed.
		inv.Nodes = append(inv.Nodes, InventoryNode{
			Addr: a, Role: roleAgent, Netd: true,
			Binaries: []string{"./bin/" + binNode},
		})
	}

	var out [][]byte
	for _, doc := range []any{cc, nc, inv} {
		b, err := yaml.Marshal(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return bytes.Join(out, []byte("---\n")), nil
}
