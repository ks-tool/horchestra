package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// toolAPIVersion is the only apiVersion this tool reads, and it is CHECKED rather than ignored: a
// document written against a version that does not exist is a mistake worth refusing, and a tool
// that shrugs at the field will one day apply half a file it did not understand.
const toolAPIVersion = "node-tool.horchestra.io/v1"

// The roles a host can hold. There are two and there is no third — a host either runs the control
// plane or runs workloads. The monolith is a development convenience, not a fleet role, so it has
// no name here.
const (
	roleController = "controller"
	roleAgent      = "agent"
)

// Binary basenames the tool recognises. The inventory names PATHS, and what a path means is decided
// by its basename rather than by its position in the list: a list whose meaning depends on order is
// a list an operator can silently get wrong by reformatting it.
const (
	binControllerRole = "horchestra-controller"
	binNode           = "horchestra"
	binNodeTool       = "node-tool"
)

// nodeAliases are the argv[0] symlinks node-tool makes beside the node binary. They are not
// separate programs and are never shipped — `horchestra-agent` IS `horchestra`, which dispatches on
// the name it was invoked by. They exist so a unit's ExecStart, a `ps` line and an operator's habit
// still say which role a process is.
var nodeAliases = []string{"agent", "netd", "sandbox"}

// Where things land on a host. BOTH sides of apply read these — the operator's, which uploads, and
// the host's, which installs — so the two cannot disagree about a path. They did disagree while
// they were separate commands passing strings on a command line, and the only thing keeping them
// aligned was that one of them built the other's arguments.
const (
	hostBinDir         = "/usr/local/bin"
	hostConfigFile     = "/etc/horchestra/node-tool.yaml"
	hostControllerConf = "/etc/horchestra/controller.conf"
	hostNodeConf       = "/etc/horchestra/node.conf"
	hostClusterCACrt   = "/etc/horchestra/cluster-ca.crt"
	hostClusterCAKey   = "/etc/horchestra/cluster-ca.key"
	hostVaultCert      = "/etc/horchestra/vault-client.crt"
	hostVaultKey       = "/etc/horchestra/vault-client.key"
	hostVaultCA        = "/etc/horchestra/vault-ca.crt"
)

// How a node's certificate gets renewed. There are three answers and no default, because the
// controller either holds the CA key, holds a credential to something that signs on its behalf, or
// holds nothing and cannot rotate at all — and each is a different thing to be true about a fleet.
const (
	signerLocal   = "clusterCAKey"
	signerVault   = "vaultPKI"
	signerOffline = "offlineCA"
)

// TypeMeta is the apiVersion/kind pair every document carries. It is read on its own first, so a
// document can be routed to its type before anything tries to decode it as one.
type TypeMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// ControllerConfig is what a controller host gets. There is one per file and it applies to every
// host holding the role — which is the point of splitting it from the inventory: the role's
// configuration is written once instead of repeated beside each address that happens to hold it.
type ControllerConfig struct {
	TypeMeta `json:",inline"`
	Spec     ControllerSpec `json:"spec"`
}

// ControllerSpec is the controller's whole configuration. Every field here was a flag on the
// retired `deploy-controller`, and moving them into a file is not only ergonomics: a flag set is
// re-typed on every run and drifts between the operator who deployed on Tuesday and the one
// repairing it on Friday, while a file is the thing both of them read.
type ControllerSpec struct {
	// PKIDir is the LOCAL directory holding the CA this fleet is signed by — the tool reads it
	// here and never uploads the key unless ClusterCAKey says to. Created by `node-tool init`.
	PKIDir string `json:"pkiDir,omitempty"`
	// Addr is what the controller binds. The serving certificate advertises the inventory
	// address instead, so binding every interface is normal and is the default.
	Addr string `json:"addr,omitempty"`
	// Storage is the backend DSN on the host (bolt:<absolute path>).
	Storage string `json:"storage,omitempty"`
	// RoutedCIDR is the one range the whole fleet takes workload addresses from. It reaches a
	// node in the desired-state push, so the controller is the only place that needs to know it,
	// and that is why it is here and not in NodeSpec.
	RoutedCIDR string `json:"routedCIDR,omitempty"`
	// ClusterCAKey is the CA private key to UPLOAD so the controller can sign node rotation
	// CSRs. Exactly one of this and OfflineCA must be set: node certificates expire, and which
	// way that is handled is a decision an operator has to make rather than inherit from a
	// default that quietly picked one.
	ClusterCAKey string `json:"clusterCAKey,omitempty"`
	// OfflineCA declines rotation and keeps the CA key off the host. Node certificates then
	// expire at their TTL and are reissued by hand.
	OfflineCA bool `json:"offlineCA,omitempty"`
	// VaultPKI signs node CSRs through a Vault/OpenBao PKI engine instead of a local CA key. It
	// is the third signing mode and the only one where the controller holds NO signing key at
	// all — which is the whole point of it, and why it cannot be combined with ClusterCAKey.
	VaultPKI *VaultPKISpec `json:"vaultPKI,omitempty"`
	// FeatureGates opts the deployment into named capabilities that are off by default, as the
	// controller's own `--feature-gates` takes them (`A=true,B=true`). Rotation through Vault
	// still needs `AutoNodeCertRotation=true` to sign without an operator approving each CSR:
	// the signer and the decision to use it automatically are separate choices.
	FeatureGates string `json:"featureGates,omitempty"`
	// AdminConf rewrites <pkiDir>/admin.conf to target this controller. A pointer because the
	// default is true and "false" has to be expressible.
	AdminConf *bool `json:"adminConf,omitempty"`
}

// VaultPKISpec points the controller at a PKI engine that signs for it.
//
// Cert, Key and CABundle are LOCAL paths — the operator's copies — and apply uploads them, the way
// it uploads the CA key in the local-signer mode. The controller authenticates to Vault as ITSELF
// (cert auth), so it needs its own credential there; that credential is not the serving certificate
// from controller.conf, which Vault refuses for lacking ClientAuth.
type VaultPKISpec struct {
	// Server is the Vault/OpenBao address. Its presence is what selects this mode.
	Server string `json:"server"`
	// Mount is the PKI engine mount (default pki_int).
	Mount string `json:"mount,omitempty"`
	// Role is the PKI role node certificates are issued under. Required — and it must pin
	// `organization` to system:nodes rather than allowing sign-verbatim, or the engine would
	// issue whatever group a CSR asked for and the node authorizer would believe it.
	Role string `json:"role"`
	// Cert and Key are the controller's own client credential for Vault's cert auth method.
	Cert string `json:"cert"`
	Key  string `json:"key"`
	// CABundle verifies the Vault server's certificate. Empty trusts the host's roots.
	CABundle string `json:"caBundle,omitempty"`
	// AuthPath is the cert auth method mount (default cert); AuthRole the named role to log in
	// against.
	AuthPath string `json:"authPath,omitempty"`
	AuthRole string `json:"authRole,omitempty"`
	// SelfRole is the PKI role the controller renews its OWN client credential under before it
	// expires. Empty means that credential is renewed out of band — which is a decision, since
	// nothing else will notice it expiring until signing stops.
	SelfRole string `json:"selfRole,omitempty"`
	// AdminRole is the PKI role an OPERATOR's kubeconfig is issued under — a third role, and it
	// has to be: Role pins organization to system:nodes and SelfRole issues a credential with no
	// group at all, so neither can produce the system:masters certificate a human needs. Empty
	// means `node-tool kubeconfig` has nothing to sign with in this mode and says so.
	AdminRole string `json:"adminRole,omitempty"`
}

// validate refuses a Vault configuration that cannot work, naming the field rather than letting the
// controller discover it at startup on a host the operator is no longer looking at.
func (v *VaultPKISpec) validate() error {
	switch {
	case v.Role == "":
		return errors.New("vaultPKI.role is required: it is the PKI role node certificates are issued under, and it must pin organization to system:nodes")
	case v.Cert == "" || v.Key == "":
		return errors.New("vaultPKI.cert and vaultPKI.key are required: the controller authenticates to Vault as itself")
	}
	return nil
}

// NodeConfig is what every agent host gets — one document for the whole fleet, for the same reason
// the controller has one. Anything that genuinely differs per host belongs in the inventory beside
// the address it differs for.
type NodeConfig struct {
	TypeMeta `json:",inline"`
	Spec     NodeSpec `json:"spec"`
}

// NodeSpec is the agent's configuration.
type NodeSpec struct {
	// Controller is the URL nodes call back on. Empty is the ordinary case and it is not a
	// guess: the inventory names the controller host, so the address is READ from the file
	// rather than inferred from whichever local interface happened to route toward the node —
	// which is what the retired `deploy` had to do, and what made a VPN address end up baked
	// into a fleet's node.conf.
	Controller string `json:"controller,omitempty"`
	// StateDir is the agent's state directory, baked into the unit.
	StateDir string `json:"stateDir,omitempty"`
	// Heartbeat is the status report interval, baked into the unit (e.g. 5s).
	Heartbeat string `json:"heartbeat,omitempty"`
	// Netd configures the privileged network helper. It does NOT decide whether the helper is
	// installed — listing horchestra-netd among a host's binaries does, so the decision to put a
	// privileged process on a node stays a thing an operator typed out per host.
	Netd NetdSpec `json:"netd,omitzero"`
}

// NetdSpec is the network helper's configuration.
type NetdSpec struct {
	// Uplink is the interface the node reaches other nodes by. Empty lets the helper take the
	// interface its default route uses.
	Uplink string `json:"uplink,omitempty"`
	// Overlay is how another node is REACHED: none (the underlay carries workload addresses),
	// vxlan or ipip. It is a property of the routed network rather than a second axis, and
	// `none` is not usable on a cloud VPC — measured: a fabric there drops natively-routed
	// workload addresses outright.
	Overlay string `json:"overlay,omitempty"`
}

func (spec NetdSpec) IsZero() bool {
	return len(spec.Uplink) == 0 && len(spec.Overlay) == 0
}

// Inventory is which host holds which role, and what lands on it. It is the only document that
// repeats per host, because it is the only one whose content genuinely differs per host.
type Inventory struct {
	TypeMeta `json:",inline"`
	// SSH is how every host is reached unless the host overrides it.
	SSH SSHSpec `json:"ssh,omitzero"`
	// Nodes is the fleet.
	Nodes []InventoryNode `json:"nodes"`
}

// InventoryNode is one host.
type InventoryNode struct {
	// Addr is the host's address — how the tool reaches it, and what the controller's serving
	// certificate or the node's URL is written for.
	Addr string `json:"addr"`
	// Role is controller or agent.
	Role string `json:"role"`
	// Binaries are the LOCAL paths to ship, named by their basenames: `horchestra-controller` on
	// the control plane, `horchestra` on a node. One file per host, because the node's three roles
	// — agent, network helper, workload sandbox — are one build; node-tool makes the argv[0]
	// aliases beside it. node-tool itself is shipped without being listed, since it is what
	// performs the install on the far side.
	Binaries []string `json:"binaries"`
	// Netd asks for the privileged network helper on THIS host. It is per-host and not a fleet
	// setting because putting a root process on a node is a decision worth typing out: an isolated
	// workload needs it and a host-network fleet does not. It used to be expressed by listing the
	// helper's binary, which stopped being possible when it stopped being a binary.
	Netd bool `json:"netd,omitempty"`
	// Name is the node's identity: its certificate CN, which is what gates the apps, the status
	// writes and the Secrets it may reach. Defaults to Addr, which is what the retired `deploy`
	// did — and naming it here is the better shape, since an address is a thing that moves.
	Name string `json:"name,omitempty"`
	// SSH overrides the fleet-wide connection settings for this host alone.
	SSH *SSHSpec `json:"ssh,omitempty"`
}

// SSHSpec is how a host is reached. There is deliberately no password field of any kind: a sudo
// password belongs in the environment or in a prompt, never in a file that gets committed.
type SSHSpec struct {
	User string `json:"user,omitempty"`
	// Key is the private key path. Empty falls back to ~/.ssh/id_ed25519, id_rsa, then the agent.
	Key string `json:"key,omitempty"`
	// HostKey pins the host's key (a known_hosts line, or a SHA256:... fingerprint), verified
	// instead of trust-on-first-use.
	HostKey string `json:"hostKey,omitempty"`
	// AcceptNew pins an unknown host key without prompting. A CHANGED key is still refused.
	AcceptNew bool `json:"acceptNew,omitempty"`
	// Sudo elevates the remote steps that need it. A pointer because it defaults to "on unless
	// the user is root", and an operator has to be able to say no to that.
	Sudo *bool `json:"sudo,omitempty"`
}

func (spec SSHSpec) IsZero() bool {
	return len(spec.User) == 0 && len(spec.Key) == 0 && len(spec.HostKey) == 0 && !spec.AcceptNew && spec.Sudo == nil
}

// Fleet is one file, decoded: the role configurations and the inventory binding them to hosts.
type Fleet struct {
	Controller ControllerConfig
	Node       NodeConfig
	Inventory  Inventory
	// Source is the file verbatim. It is uploaded to each host, so the on-host half of apply
	// reads the SAME bytes the operator did rather than a command line reassembled from them —
	// and so a node carries the description that produced it, which is what makes it
	// re-convergeable without the operator's working tree.
	Source []byte
}

// loadFleet reads and validates a fleet description. Everything it can refuse, it refuses HERE —
// before a single connection is opened — because the alternative is a half-applied fleet: three
// hosts in, a typo in the fourth, and now the operator has to work out which of them changed.
func loadFleet(path string) (*Fleet, error) {
	docs, err := yamlDocuments(path)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("%s holds no documents", path)
	}

	var f Fleet
	if f.Source, err = os.ReadFile(path); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, doc := range docs {
		var tm TypeMeta
		if err := yaml.Unmarshal(doc, &tm); err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		if tm.APIVersion != toolAPIVersion {
			return nil, fmt.Errorf("document %d: apiVersion %q, want %q", i+1, tm.APIVersion, toolAPIVersion)
		}
		if seen[tm.Kind] {
			return nil, fmt.Errorf("document %d: a second %s — one file describes one fleet", i+1, tm.Kind)
		}
		seen[tm.Kind] = true

		// Strict: an unknown field is a refusal and not a shrug. A misspelled key that decodes
		// to nothing is the worst outcome available — the tool reports success and the setting
		// the operator wrote was never applied.
		switch tm.Kind {
		case "ControllerConfig":
			err = yaml.UnmarshalStrict(doc, &f.Controller)
		case "NodeConfig":
			err = yaml.UnmarshalStrict(doc, &f.Node)
		case "Inventory":
			err = yaml.UnmarshalStrict(doc, &f.Inventory)
		default:
			return nil, fmt.Errorf("document %d: unknown kind %q", i+1, tm.Kind)
		}
		if err != nil {
			return nil, fmt.Errorf("document %d (%s): %w", i+1, tm.Kind, err)
		}
	}
	if !seen["Inventory"] {
		return nil, errors.New("no Inventory: the file describes configuration but names no host to apply it to")
	}
	f.applyDefaults()
	return &f, f.validate(seen)
}

// yamlDocuments splits a multi-document file, skipping a comment-only tail. It matches what
// examples_test.go does for manifests, and for the same reason: `---` followed by comments is a
// separating line an operator wrote, not a document with no kind.
func yamlDocuments(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	r := utilyaml.NewYAMLReader(bufio.NewReader(f))
	var docs [][]byte
	for {
		doc, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return docs, nil
			}
			return nil, err
		}
		if len(bytes.TrimSpace(stripYAMLComments(doc))) == 0 {
			continue
		}
		docs = append(docs, doc)
	}
}

// stripYAMLComments removes whole-line comments so a comment-only document is not read as one.
func stripYAMLComments(doc []byte) []byte {
	var out bytes.Buffer
	for line := range bytes.SplitSeq(doc, []byte("\n")) {
		if t := bytes.TrimSpace(line); len(t) == 0 || t[0] == '#' {
			continue
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// applyDefaults fills what an operator should not have to type. The values are the ones the retired
// flags defaulted to, so a file that says only what is specific to the fleet behaves as before.
func (f *Fleet) applyDefaults() {
	c := &f.Controller.Spec
	if c.PKIDir == "" {
		c.PKIDir = "pki"
	}
	if c.Addr == "" {
		c.Addr = ":8443"
	}
	if c.Storage == "" {
		c.Storage = "bolt:/var/lib/horchestra/controller.db"
	}
	if c.AdminConf == nil {
		yes := true
		c.AdminConf = &yes
	}
	if f.Inventory.SSH.User == "" {
		f.Inventory.SSH.User = "root"
	}
	for i := range f.Inventory.Nodes {
		n := &f.Inventory.Nodes[i]
		if n.Name == "" {
			n.Name = n.Addr
		}
	}
}

// validate refuses a fleet that cannot be applied. seen says which documents the file carried, so a
// missing role configuration is named as missing rather than silently applied as an empty one.
func (f *Fleet) validate(seen map[string]bool) error {
	if len(f.Inventory.Nodes) == 0 {
		return errors.New("Inventory names no nodes")
	}

	var controllers, agents int
	addrs := map[string]bool{}
	for i, n := range f.Inventory.Nodes {
		where := fmt.Sprintf("nodes[%d]", i)
		if n.Addr == "" {
			return fmt.Errorf("%s: no addr", where)
		}
		if addrs[n.Addr] {
			return fmt.Errorf("%s: %s is listed twice", where, n.Addr)
		}
		addrs[n.Addr] = true

		switch n.Role {
		case roleController:
			controllers++
		case roleAgent:
			agents++
		default:
			return fmt.Errorf("%s (%s): role %q is neither %s nor %s", where, n.Addr, n.Role, roleController, roleAgent)
		}
		if len(n.Binaries) == 0 {
			return fmt.Errorf("%s (%s): no binaries — a host with nothing to run is not a deployment", where, n.Addr)
		}
		if _, err := roleRuntime(n); err != nil {
			return fmt.Errorf("%s (%s): %w", where, n.Addr, err)
		}
		if n.Role == roleController && n.Netd {
			return fmt.Errorf("%s (%s): the network helper belongs on a node that runs workloads, not on the controller", where, n.Addr)
		}
	}

	// One controller. Leader election is not built, so a second one is two control planes
	// sharing an inventory and disagreeing about a fleet, which is worse than not starting.
	if controllers > 1 {
		return fmt.Errorf("%d hosts hold the controller role: there is no leader election yet, so exactly one may", controllers)
	}
	if controllers == 1 && !seen["ControllerConfig"] {
		return errors.New("a host holds the controller role but the file carries no ControllerConfig")
	}
	if agents > 0 && !seen["NodeConfig"] {
		return errors.New("hosts hold the agent role but the file carries no NodeConfig")
	}
	if controllers == 0 && f.Node.Spec.Controller == "" {
		return errors.New("no controller in the inventory and no spec.controller in NodeConfig: the agents would have nothing to call")
	}

	if controllers == 1 {
		if _, err := f.Controller.Spec.signerMode(); err != nil {
			return err
		}
	}
	switch f.Node.Spec.Netd.Overlay {
	case "", "none", "vxlan", "ipip":
	default:
		return fmt.Errorf("netd.overlay %q: one of none, vxlan, ipip", f.Node.Spec.Netd.Overlay)
	}
	return nil
}

// localFiles are the operator-side files the fleet names besides the binaries: the CA key when the
// controller signs, or the Vault client credential when Vault does. They are uploaded, so a missing
// one is an apply that dies partway rather than at the start.
func (f *Fleet) localFiles() []string {
	spec := f.Controller.Spec
	var out []string
	if spec.ClusterCAKey != "" {
		out = append(out, spec.ClusterCAKey)
	}
	if v := spec.VaultPKI; v != nil && v.Server != "" {
		out = append(out, v.Cert, v.Key)
		if v.CABundle != "" {
			out = append(out, v.CABundle)
		}
	}
	return out
}

// checkBinaries reports every file the inventory names that is not there — all of them, not the
// first, because an operator fixing a build should learn about all four missing binaries at once
// rather than one `apply` at a time.
//
// It is deliberately NOT part of loadFleet: parsing a description and checking a working tree are
// different questions, and only the second needs a build to have happened. That separation is what
// lets a canonical example be validated by a test that never compiles anything.
func (f *Fleet) checkBinaries() error {
	var missing []string
	for _, n := range f.Inventory.Nodes {
		for _, b := range n.Binaries {
			if _, err := os.Stat(b); err != nil {
				missing = append(missing, fmt.Sprintf("%s (%s)", b, n.Addr))
			}
		}
	}
	for _, p := range f.localFiles() {
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("named by the file but not present: %s", strings.Join(missing, ", "))
	}
	return nil
}

// signerMode resolves how node certificates get signed, refusing both zero choices and two.
//
// It has no default on purpose. Without a signer the controller marks a rotation CSR Approved with
// no certificate behind it; with the CA key on the host, a controller compromise discloses the CA;
// through Vault, the fleet gains a dependency that must be reachable for a node to renew. Those are
// not interchangeable, and a tool that picked one would be making the security decision quietly.
func (spec ControllerSpec) signerMode() (string, error) {
	var chosen []string
	if spec.ClusterCAKey != "" {
		chosen = append(chosen, signerLocal)
	}
	if spec.VaultPKI != nil && spec.VaultPKI.Server != "" {
		chosen = append(chosen, signerVault)
	}
	if spec.OfflineCA {
		chosen = append(chosen, signerOffline)
	}

	switch len(chosen) {
	case 1:
	case 0:
		return "", errors.New("pick how node certificates are signed — there is no default: " +
			"`clusterCAKey: <path>` uploads the CA key so the controller signs rotation CSRs itself (nodes renew automatically, but a controller compromise then discloses the CA); " +
			"`vaultPKI: {server, role, cert, key}` signs through a Vault/OpenBao PKI engine, so the controller holds no signing key at all; " +
			"or `offlineCA: true` keeps the key off the host entirely, accepting that node certificates cannot rotate and expire at their TTL")
	default:
		return "", fmt.Errorf("%s are mutually exclusive: node certificates have one signer, and the point of %s is that no signing key is held on the host",
			strings.Join(chosen, " and "), signerVault)
	}
	if chosen[0] == signerVault {
		if err := spec.VaultPKI.validate(); err != nil {
			return "", err
		}
	}
	return chosen[0], nil
}

// node finds an inventory entry by address — how a host, running the on-host half of apply, learns
// which entry describes it.
func (f *Fleet) node(addr string) (InventoryNode, bool) {
	for _, n := range f.Inventory.Nodes {
		if n.Addr == addr {
			return n, true
		}
	}
	return InventoryNode{}, false
}

// controllerNode returns the host holding the control plane, if the inventory has one.
func (f *Fleet) controllerNode() (InventoryNode, bool) {
	for _, n := range f.Inventory.Nodes {
		if n.Role == roleController {
			return n, true
		}
	}
	return InventoryNode{}, false
}

// sshFor resolves a host's connection settings: the fleet's, with the host's own on top.
func (f *Fleet) sshFor(n InventoryNode) SSHSpec {
	s := f.Inventory.SSH
	if n.SSH == nil {
		return s
	}
	o := *n.SSH
	if o.User != "" {
		s.User = o.User
	}
	if o.Key != "" {
		s.Key = o.Key
	}
	if o.HostKey != "" {
		s.HostKey = o.HostKey
	}
	if o.AcceptNew {
		s.AcceptNew = true
	}
	if o.Sudo != nil {
		s.Sudo = o.Sudo
	}
	return s
}

// roleRuntime picks the binary the host's unit will ExecStart, by basename. The split binary is
// preferred and the monolith is accepted, because a single-host stand legitimately runs it.
func roleRuntime(n InventoryNode) (string, error) {
	want := binNode
	if n.Role == roleController {
		want = binControllerRole
	}
	if p, ok := binaryNamed(n, want); ok {
		return p, nil
	}
	return "", fmt.Errorf("no %s among the binaries: nothing for the unit to run", want)
}

// binaryNamed finds a listed binary by basename.
func binaryNamed(n InventoryNode, name string) (string, bool) {
	for _, b := range n.Binaries {
		if filepath.Base(b) == name {
			return b, true
		}
	}
	return "", false
}
