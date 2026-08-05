package vaultpki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

// TestLiveVaultPKI drives a REAL Vault/OpenBao PKI engine. It is skipped unless the
// environment names one, so `go test ./...` stays hermetic, and it is cross-compiled and run
// on a host that has one when the wire shape needs proving.
//
// What only a real server can answer: that `pki_int/sign/<role>` takes and returns the fields
// this client assumes, and — the load-bearing one — that a role with `organization=` actually
// OVERRIDES the Organization a CSR asks for rather than merging or ignoring it. The whole
// no-escalation guarantee rests on that being true of the server, and a fake asserting it
// would only be asserting what this code already believes.
//
//	VAULTPKI_ADDR   https://127.0.0.1:8200
//	VAULTPKI_CA     path to the server's CA bundle
//	VAULTPKI_CERT   the controller's client certificate (cert auth)
//	VAULTPKI_KEY    its private key
//	VAULTPKI_MOUNT  engine mount (default pki_int)
//	VAULTPKI_ROLE   the role (default nodes)
func TestLiveVaultPKI(t *testing.T) {
	addr := os.Getenv("VAULTPKI_ADDR")
	if addr == "" {
		t.Skip("VAULTPKI_ADDR is unset: this test needs a real Vault/OpenBao PKI engine")
	}
	read := func(env string) []byte {
		b, err := os.ReadFile(os.Getenv(env))
		if err != nil {
			t.Fatalf("%s: %v", env, err)
		}
		return b
	}
	cfg := Config{
		Server:   addr,
		Mount:    envOr("VAULTPKI_MOUNT", "pki_int"),
		Role:     envOr("VAULTPKI_ROLE", "nodes"),
		CABundle: read("VAULTPKI_CA"),
		CertPEM:  read("VAULTPKI_CERT"),
		KeyPEM:   read("VAULTPKI_KEY"),
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// A node asking for a group it has no right to. The role must overrule it; if the server
	// merged or honoured it instead, verifyIssued fails the signing and this test says so.
	certPEM, err := s.SignCSR(nodeCSR(t, "live-node-1", []string{"system:masters"}), []string{"system:nodes"}, time.Hour)
	if err != nil {
		t.Fatalf("sign through the live engine: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("issued: CN=%q O=%v notAfter=%s issuer=%q",
		cert.Subject.CommonName, cert.Subject.Organization, cert.NotAfter.Format(time.RFC3339), cert.Issuer.CommonName)
	if cert.Subject.CommonName != "live-node-1" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "system:nodes" {
		t.Errorf("organization = %v — the role did not pin it", cert.Subject.Organization)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
