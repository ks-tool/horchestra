package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ks-tool/horchestra/api/features"

	"github.com/spf13/pflag"
)

// loadScaffold writes a generated fleet description to a temp file and puts it through the REAL
// loader. Marshalling from the same types apply reads back is what makes the two ends agree; this
// round trip is what proves the file is a document and not just a struct that happened to encode.
func loadScaffold(t *testing.T, body []byte) (*Fleet, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), fleetFileName)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return loadFleet(path)
}

// TestTheLocalScaffoldIsApplyable: with both roles named, what init writes must be a file apply can
// run — not a template that needs editing first.
func TestTheLocalScaffoldIsApplyable(t *testing.T) {
	body, err := fleetScaffold(scaffoldOptions{pkiDir: "pki", controller: "10.0.0.1", agents: []string{"10.0.0.2", "10.0.0.3"}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := loadScaffold(t, body)
	if err != nil {
		t.Fatalf("the generated file does not load: %v\n%s", err, body)
	}

	mode, err := f.Controller.Spec.signerMode()
	if err != nil || mode != signerLocal {
		t.Fatalf("signer = %q (%v), want %q", mode, err, signerLocal)
	}
	if f.Controller.Spec.ClusterCAKey != filepath.Join("pki", "ca.key") {
		t.Errorf("clusterCAKey = %q", f.Controller.Spec.ClusterCAKey)
	}
	if len(f.Inventory.Nodes) != 3 {
		t.Fatalf("nodes = %d, want the controller and two agents", len(f.Inventory.Nodes))
	}
	c, ok := f.controllerNode()
	if !ok || c.Addr != "10.0.0.1" {
		t.Errorf("controller node = %+v (%v)", c, ok)
	}
	// One binary per node, and the helper asked for by a field rather than by a second file.
	if len(f.Inventory.Nodes[1].Binaries) != 1 || !f.Inventory.Nodes[1].Netd {
		t.Errorf("agent = %+v", f.Inventory.Nodes[1])
	}
}

// TestTheVaultScaffoldRefusesUntilItIsComplete: Vault mode has fields init cannot know — the role,
// and the controller's own client credential — so they go out empty and the loader must name the
// missing one rather than accept a configuration that cannot sign.
func TestTheVaultScaffoldRefusesUntilItIsComplete(t *testing.T) {
	body, err := fleetScaffold(scaffoldOptions{pkiDir: "pki", vaultServer: "https://vault:8200", featureGates: "AutoNodeCertRotation=true", controller: "10.0.0.1", agents: []string{"10.0.0.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadScaffold(t, body); err == nil {
		t.Fatalf("an incomplete Vault scaffold was accepted:\n%s", body)
	} else if !strings.Contains(err.Error(), "role") {
		t.Errorf("the refusal should name the field to fill in, got: %v", err)
	}

	// The server is what init DID know, and the two modes must never both appear: a signing key
	// beside Vault would make the guarantee false while the file still claimed it.
	if !strings.Contains(string(body), "https://vault:8200") {
		t.Errorf("the scaffold lost the server it was given:\n%s", body)
	}
	if strings.Contains(string(body), "clusterCAKey") {
		t.Errorf("the Vault scaffold also offers a local signing key:\n%s", body)
	}

	// Filling in what the refusals asked for produces a file that loads.
	completed := strings.NewReplacer(
		`role: ""`, "role: nodes",
		`cert: ""`, "cert: pki/vault-client.crt",
		`key: ""`, "key: pki/vault-client.key",
	).Replace(string(body))
	f, err := loadScaffold(t, []byte(completed))
	if err != nil {
		t.Fatalf("the completed Vault scaffold does not load: %v\n%s", err, completed)
	}
	if mode, _ := f.Controller.Spec.signerMode(); mode != signerVault {
		t.Errorf("signer = %q, want %q", mode, signerVault)
	}
	// The gate is a separate decision from the signer, and init makes it because rotation that
	// waits for a human is not what an operator asking for Vault is usually after.
	if !strings.Contains(f.Controller.Spec.FeatureGates, "AutoNodeCertRotation") {
		t.Errorf("featureGates = %q", f.Controller.Spec.FeatureGates)
	}
}

// TestEveryGateGetsItsOwnFlag: the flags are generated from the registry, so a gate added there
// gets one without anyone remembering — and the names it generates have to be the ones an operator
// would guess. It also pins the direction of the derivation: the registry is the source, and this
// list is the assertion, so removing a gate makes this fail rather than leaving a dead flag.
func TestEveryGateGetsItsOwnFlag(t *testing.T) {
	fs := pflag.NewFlagSet("init", pflag.ContinueOnError)
	flags := registerGateFlags(fs)
	if len(flags) != len(features.Names()) {
		t.Fatalf("%d flags for %d gates", len(flags), len(features.Names()))
	}
	for _, want := range []string{
		"--vault-static-roles", "--auto-node-cert-rotation", "--vault-dynamic-secrets", "--node-logs",
	} {
		if fs.Lookup(strings.TrimPrefix(want, "--")) == nil {
			t.Errorf("no %s flag; this build has %v", want, features.Names())
		}
	}

	// Only a gate the operator actually CHANGED is written down: one left at the registry's
	// default belongs in the registry, not restated in every fleet file where it would go stale
	// the day the default moved.
	if got := resolveGates(fs, flags, false); got != "" {
		t.Errorf("untouched flags produced %q, want nothing", got)
	}
	if err := fs.Parse([]string{"--node-logs", "--vault-static-roles=false"}); err != nil {
		t.Fatal(err)
	}
	if got := resolveGates(fs, flags, false); got != "NodeLogs=true,VaultStaticRoles=false" {
		t.Errorf("resolveGates = %q", got)
	}

	// Vault turns rotation on, and the operator can still say no — an explicit flag wins over
	// what the mode assumed.
	if got := resolveGates(fs, flags, true); !strings.Contains(got, "AutoNodeCertRotation=true") {
		t.Errorf("vault mode did not enable rotation: %q", got)
	}
	if err := fs.Parse([]string{"--auto-node-cert-rotation=false"}); err != nil {
		t.Fatal(err)
	}
	if got := resolveGates(fs, flags, true); !strings.Contains(got, "AutoNodeCertRotation=false") {
		t.Errorf("an explicit refusal was overridden by the vault default: %q", got)
	}
}

func TestKebabCase(t *testing.T) {
	for in, want := range map[string]string{
		"VaultStaticRoles":     "vault-static-roles",
		"AutoNodeCertRotation": "auto-node-cert-rotation",
		"NodeLogs":             "node-logs",
		"VaultDynamicSecrets":  "vault-dynamic-secrets",
	} {
		if got := kebabCase(in); got != want {
			t.Errorf("kebabCase(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAnUnnamedHostYieldsAnEmptyInventory: --controller/--agent are optional, so a scaffold without
// them is still a valid document — and apply must refuse it by saying what is missing rather than
// deploying to an address nobody typed.
func TestAnUnnamedHostYieldsAnEmptyInventory(t *testing.T) {
	body, err := fleetScaffold(scaffoldOptions{pkiDir: "pki"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadScaffold(t, body)
	if err == nil {
		t.Fatalf("a scaffold with no hosts was accepted:\n%s", body)
	}
	if !strings.Contains(err.Error(), "names no nodes") {
		t.Errorf("the refusal should say the inventory is empty, got: %v", err)
	}
}
