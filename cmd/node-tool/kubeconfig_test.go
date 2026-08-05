package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFleet puts a fleet description where a test can point -f at it.
func writeFleet(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), fleetFileName)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestTheFleetDecidesWhoSigns: which authority issues an operator's certificate is a property of
// the fleet, not a flag on the command. A fleet with a local CA key signs with it; one that says
// vaultPKI has no key on disk to sign with, and asking the operator to remember which is which is
// how a certificate ends up issued by an authority the fleet retired.
func TestTheFleetDecidesWhoSigns(t *testing.T) {
	// No fleet file at all — a CA created before one existed. Local signing, as before.
	if got := vaultSigningSpec(filepath.Join(t.TempDir(), "absent.yaml")); got != nil {
		t.Errorf("a missing fleet file should mean local signing, got %+v", got)
	}

	local, err := fleetScaffold(scaffoldOptions{pkiDir: "pki", controller: "10.0.0.1", agents: []string{"10.0.0.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := vaultSigningSpec(writeFleet(t, local)); got != nil {
		t.Errorf("a local-CA fleet should not sign through Vault, got %+v", got)
	}

	vault, err := fleetScaffold(scaffoldOptions{
		pkiDir: "pki", vaultServer: "https://vault:8200",
		controller: "10.0.0.1", agents: []string{"10.0.0.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	complete := strings.NewReplacer(
		`role: ""`, "role: nodes",
		`cert: ""`, "cert: pki/vault-client.crt",
		`key: ""`, "key: pki/vault-client.key",
	).Replace(string(vault))
	spec := vaultSigningSpec(writeFleet(t, []byte(complete)))
	if spec == nil {
		t.Fatal("a vaultPKI fleet should sign through Vault")
	}
	if spec.Server != "https://vault:8200" {
		t.Errorf("spec = %+v", spec)
	}
}

// TestAnOperatorCertificateNeedsItsOwnRole: vaultPKI.role pins organization to system:nodes and
// selfRole issues a credential with no group, so neither can produce what a human needs. The
// refusal has to say that rather than let Vault reject the request with its own vocabulary.
func TestAnOperatorCertificateNeedsItsOwnRole(t *testing.T) {
	base := &VaultPKISpec{Server: "https://vault:8200", Role: "nodes", Cert: "c.crt", Key: "c.key"}

	_, _, err := vaultClientCert(base, "", "admin", []string{"system:masters"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "adminRole") {
		t.Fatalf("an unset adminRole should be refused by name, got: %v", err)
	}

	// A group is required, because the role pins the Organization and this is the value that
	// has to match it — signing with none would mean not checking.
	withRole := *base
	withRole.AdminRole = "operators"
	if _, _, err := vaultClientCert(&withRole, "", "admin", nil, time.Hour); err == nil || !strings.Contains(err.Error(), "--group") {
		t.Fatalf("a missing group should be refused, got: %v", err)
	}

	// --vault-role stands in for an unset adminRole, so a one-off certificate needs no edit to
	// the fleet file. It gets far enough to read the credential, which is the next thing wrong.
	if _, _, err := vaultClientCert(base, "operators", "admin", []string{"system:masters"}, time.Hour); err == nil ||
		strings.Contains(err.Error(), "adminRole") {
		t.Fatalf("--vault-role should override the fleet's role, got: %v", err)
	}
}

func TestVaultRoleForPrefersTheOverride(t *testing.T) {
	v := &VaultPKISpec{AdminRole: "operators"}
	if got := vaultRoleFor(v, ""); got != "operators" {
		t.Errorf("vaultRoleFor = %q, want the fleet's adminRole", got)
	}
	if got := vaultRoleFor(v, "one-off"); got != "one-off" {
		t.Errorf("vaultRoleFor = %q, want the override", got)
	}
}
