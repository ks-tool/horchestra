package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fleetFile writes a fleet description into a temp dir, creating any binaries it names so the
// loader's existence check has something to find. It returns the path to the file.
func fleetFile(t *testing.T, body string, binaries ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, b := range binaries {
		p := filepath.Join(dir, b)
		if err := os.WriteFile(p, []byte("#!/bin/true\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "fleet.yaml")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(body, "@DIR@", dir)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const threeHostFleet = `apiVersion: node-tool.horchestra.io/v1
kind: ControllerConfig
spec:
  offlineCA: true
---
apiVersion: node-tool.horchestra.io/v1
kind: NodeConfig
spec:
  netd:
    overlay: ipip
---
apiVersion: node-tool.horchestra.io/v1
kind: Inventory
ssh:
  user: ks-tool
nodes:
  - addr: 10.92.16.121
    role: controller
    binaries:
      - @DIR@/horchestra-controller
  - addr: 10.92.16.17
    role: agent
    netd: true
    binaries:
      - @DIR@/horchestra
  - addr: 10.92.16.188
    role: agent
    binaries:
      - @DIR@/horchestra
`

// TestAFleetIsOneFile is the shape the tool exists for: three documents, one of them repeating per
// host and two of them not. It also pins the defaults, because a file that says only what is
// specific to the fleet has to still describe a working one.
func TestAFleetIsOneFile(t *testing.T) {
	path := fleetFile(t, threeHostFleet, "horchestra-controller", "horchestra", "node-tool")
	f, err := loadFleet(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if got := len(f.Inventory.Nodes); got != 3 {
		t.Fatalf("nodes = %d, want 3", got)
	}
	c, ok := f.controllerNode()
	if !ok || c.Addr != "10.92.16.121" {
		t.Fatalf("controller node = %v (%v)", c, ok)
	}
	// Unset fields take the values the retired flags defaulted to.
	if f.Controller.Spec.Addr != ":8443" || f.Controller.Spec.PKIDir != "pki" {
		t.Errorf("controller defaults = %+v", f.Controller.Spec)
	}
	if f.Controller.Spec.AdminConf == nil || !*f.Controller.Spec.AdminConf {
		t.Error("adminConf should default to true")
	}
	// A node's identity defaults to its address, and the fleet's ssh user reaches every host.
	if f.Inventory.Nodes[1].Name != "10.92.16.17" {
		t.Errorf("name = %q, want the address", f.Inventory.Nodes[1].Name)
	}
	if got := f.sshFor(f.Inventory.Nodes[1]); got.User != "ks-tool" {
		t.Errorf("ssh user = %q, want ks-tool", got.User)
	}
	// The controller URL is READ from the inventory, not guessed from a local interface.
	if got := controllerURLFor(c.Addr, f.Controller.Spec.Addr); got != "https://10.92.16.121:8443" {
		t.Errorf("controller URL = %q", got)
	}
	// The runtime is chosen by basename, and netd's presence in the list is what asks for the
	// helper — so an agent that was given one is distinguishable from one that was not.
	rt, err := roleRuntime(f.Inventory.Nodes[0])
	if err != nil || filepath.Base(rt) != binControllerRole {
		t.Errorf("controller runtime = %q (%v)", rt, err)
	}
	// The helper is asked for per host, and the second agent deliberately does not.
	if !f.Inventory.Nodes[1].Netd || f.Inventory.Nodes[2].Netd {
		t.Errorf("netd opt-in = %v / %v, want true / false", f.Inventory.Nodes[1].Netd, f.Inventory.Nodes[2].Netd)
	}
}

// TestAnUnknownFieldIsRefused: a misspelled key that decodes to nothing is the worst outcome
// available — the tool reports success and the setting the operator wrote was never applied.
//
// The limit of this is worth knowing rather than discovering: decoding goes through encoding/json,
// which matches field names CASE-INSENSITIVELY, so `offlineCa` is accepted as `offlineCA`. Strict
// decoding catches a key that does not exist, not a key spelled with different capitals.
func TestAnUnknownFieldIsRefused(t *testing.T) {
	body := strings.Replace(threeHostFleet, "  offlineCA: true", "  offlineCA: true\n  storag: bolt:/tmp/x.db", 1)
	_, err := loadFleet(fleetFile(t, body, "horchestra-controller", "horchestra"))
	if err == nil {
		t.Fatal("a misspelled field was accepted")
	}
	if !strings.Contains(err.Error(), "storag") {
		t.Errorf("the error should name the field, got: %v", err)
	}

	// The case-insensitive half, pinned so a future decoder swap has to notice it changed.
	body = strings.Replace(threeHostFleet, "  offlineCA: true", "  offlineca: true", 1)
	if _, err := loadFleet(fleetFile(t, body, "horchestra-controller", "horchestra")); err != nil {
		t.Errorf("a case variant should still decode (encoding/json matches case-insensitively): %v", err)
	}
}

// TestTheFileIsRefusedBeforeAnythingIsTouched covers what the loader exists to prevent: a fleet
// half-applied because the fourth host had a typo the tool only reached after connecting to three.
func TestTheFileIsRefusedBeforeAnythingIsTouched(t *testing.T) {
	bins := []string{"horchestra-controller", "horchestra"}
	for _, tc := range []struct{ name, edit, replace, want string }{
		{"an unknown apiVersion", "node-tool.horchestra.io/v1", "node-tool.horchestra.io/v2", "apiVersion"},
		{"an unknown kind", "kind: NodeConfig", "kind: NodeConfiguration", "unknown kind"},
		{"an unknown role", "role: agent", "role: worker", "neither"},
		{"an unknown overlay", "overlay: ipip", "overlay: geneve", "overlay"},
		{"a host with no binaries", "      - @DIR@/horchestra-controller", "", "no binaries"},
		{
			// A well-formed second controller, binary and all — otherwise the per-host runtime
			// check fires first and the rule under test is never reached.
			"a second controller",
			"  - addr: 10.92.16.17\n    role: agent\n    netd: true\n    binaries:\n      - @DIR@/horchestra",
			"  - addr: 10.92.16.17\n    role: controller\n    binaries:\n      - @DIR@/horchestra-controller",
			"leader election",
		},
		{"a duplicate host", "addr: 10.92.16.188", "addr: 10.92.16.17", "twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Replace(threeHostFleet, tc.edit, tc.replace, 1)
			_, err := loadFleet(fleetFile(t, body, bins...))
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestTheRotationChoiceHasNoDefault: node certificates expire, and which way that is handled is a
// decision an operator makes rather than inherits. An empty ControllerConfig is therefore refused,
// which is the same rule the retired flags enforced.
func TestTheRotationChoiceHasNoDefault(t *testing.T) {
	body := strings.Replace(threeHostFleet, "  offlineCA: true", "  {}", 1)
	_, err := loadFleet(fleetFile(t, body, "horchestra-controller", "horchestra"))
	if err == nil || !strings.Contains(err.Error(), "rotation") {
		t.Fatalf("an unstated rotation mode should be refused, got: %v", err)
	}
}

// TestACommentOnlySpecIsAnEmptySpec: `spec:` followed by nothing but a comment is what an operator
// writes while filling a file in, and it must read as "no fields set" rather than as a parse error.
func TestACommentOnlySpecIsAnEmptySpec(t *testing.T) {
	body := strings.Replace(threeHostFleet, "  netd:\n    overlay: ipip", "  #", 1)
	f, err := loadFleet(fleetFile(t, body, "horchestra-controller", "horchestra"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if f.Node.Spec != (NodeSpec{}) {
		t.Errorf("spec = %+v, want the zero value", f.Node.Spec)
	}
}

// TestTheDocumentedExampleIsTheRealShape keeps testdata/node-tool.yaml honest. It is the file an
// operator copies, so a field renamed in the Go types has to break it here rather than on a stand —
// which is exactly what examples/ does for the API manifests.
//
// It checks structure only: the binaries it names are build outputs, and requiring a build to
// validate a document would make the example unverifiable in a clean tree.
func TestTheDocumentedExampleIsTheRealShape(t *testing.T) {
	f, err := loadFleet(filepath.Join("testdata", "node-tool.yaml"))
	if err != nil {
		t.Fatalf("the documented example does not load: %v", err)
	}
	// An example that parsed to nothing would keep passing after a rename, so assert it actually
	// carries the settings it exists to document.
	if f.Controller.Spec.RoutedCIDR == "" || f.Controller.Spec.ClusterCAKey == "" {
		t.Errorf("controller spec parsed to %+v", f.Controller.Spec)
	}
	if f.Node.Spec.Netd.Overlay != "ipip" || f.Node.Spec.Heartbeat == "" {
		t.Errorf("node spec parsed to %+v", f.Node.Spec)
	}
	if len(f.Inventory.Nodes) != 3 || f.Inventory.SSH.User != "ks-tool" {
		t.Errorf("inventory parsed to %+v", f.Inventory)
	}
	// The example names build outputs, so a clean tree has none of them — which is the whole
	// reason the check is not part of loading.
	if err := f.checkBinaries(); err == nil {
		t.Log("binaries present: this tree has been built")
	}
}

// TestTheVaultExampleIsTheRealShape is the second documented file: the same fleet with the
// controller holding no signing key at all. It exists as a file rather than a comment because the
// Vault mode has required fields, and a commented block nothing decodes cannot go stale loudly.
func TestTheVaultExampleIsTheRealShape(t *testing.T) {
	f, err := loadFleet(filepath.Join("testdata", "node-tool-vault.yaml"))
	if err != nil {
		t.Fatalf("the documented Vault example does not load: %v", err)
	}
	mode, err := f.Controller.Spec.signerMode()
	if err != nil || mode != signerVault {
		t.Fatalf("signer = %q (%v), want %q", mode, err, signerVault)
	}
	v := f.Controller.Spec.VaultPKI
	if v.Mount == "" || v.Role == "" || v.Cert == "" || v.Key == "" || v.SelfRole == "" {
		t.Errorf("the example parsed to %+v — it exists to document these fields", v)
	}
	// The gate is a separate decision from the signer, and the example documents both.
	if !strings.Contains(f.Controller.Spec.FeatureGates, "AutoNodeCertRotation") {
		t.Errorf("featureGates = %q", f.Controller.Spec.FeatureGates)
	}
	// The Vault client credential is uploaded like the CA key is, so it has to be checked for
	// like the CA key is — a missing one must not surface halfway through an apply.
	files := f.localFiles()
	if len(files) != 3 {
		t.Errorf("localFiles = %v, want the client cert, its key and the CA bundle", files)
	}
}

// TestMissingBinariesAreAllNamedAtOnce: an operator who forgot to build should learn about every
// missing file in one go, not one apply at a time.
func TestMissingBinariesAreAllNamedAtOnce(t *testing.T) {
	f, err := loadFleet(fleetFile(t, threeHostFleet, "horchestra-controller"))
	if err != nil {
		t.Fatal(err)
	}
	err = f.checkBinaries()
	if err == nil {
		t.Fatal("missing binaries were accepted")
	}
	if !strings.Contains(err.Error(), binNode) {
		t.Errorf("the error should name every missing binary, got: %v", err)
	}
	if strings.Contains(err.Error(), binControllerRole+" ") {
		t.Errorf("the one binary that exists should not be reported missing: %v", err)
	}
}

// TestSudoFollowsTheLogin: a non-root login cannot write /usr/local/bin or register a unit, so
// elevation is on by default — and an operator who says otherwise is obeyed.
func TestSudoFollowsTheLogin(t *testing.T) {
	no := false
	for _, tc := range []struct {
		spec SSHSpec
		want bool
	}{
		{SSHSpec{User: "root"}, false},
		{SSHSpec{User: "ks-tool"}, true},
		{SSHSpec{User: "ks-tool", Sudo: &no}, false},
	} {
		if got := tc.spec.sudoEnabled(); got != tc.want {
			t.Errorf("%+v: sudo = %v, want %v", tc.spec, got, tc.want)
		}
	}
}
