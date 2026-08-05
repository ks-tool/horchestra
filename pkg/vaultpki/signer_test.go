package vaultpki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ks-tool/horchestra/api/pki"
)

// fakeVaultPKI is a PKI engine that issues whatever its issue func returns, so a test can
// hand back the certificate a MISCONFIGURED role would and see it refused.
type fakeVaultPKI struct {
	srv *httptest.Server
	// ca is the INTERMEDIATE that issues, root the self-signed CA above it — the shape a real
	// pki_int has, and the reason a leaf alone does not authenticate anywhere.
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	root   *x509.Certificate
	logins int
	signs  int
	// issue builds the certificate template from the parsed CSR; nil is the correct role.
	issue func(csr *x509.CertificateRequest) *x509.Certificate
	// chainOut is what the engine reports as ca_chain; nil is the truthful one.
	chainOut []string
}

// caTemplate is a CA certificate template; both the root and the intermediate are one.
func caTemplate(cn string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
}

func newFakeVaultPKI(t *testing.T) *fakeVaultPKI {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := caTemplate("horchestra-ca", 1)
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate("pki_int", 2), root, &caKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeVaultPKI{ca: ca, caKey: caKey, root: root}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/cert/login", func(w http.ResponseWriter, r *http.Request) {
		// Cert auth means the CLIENT CERTIFICATE is the credential; no certificate, no token.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["no client certificate"]}`))
			return
		}
		f.logins++
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok-1"}})
	})
	mux.HandleFunc("POST /v1/pki_int/sign/nodes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		var body struct {
			CSR string `json:"csr"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		block, _ := pem.Decode([]byte(body.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.signs++
		leaf := f.correctLeaf(csr)
		if f.issue != nil {
			leaf = f.issue(csr)
		}
		pub := csr.PublicKey
		if leaf.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm && leaf.PublicKey != nil {
			pub = leaf.PublicKey
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, pub, f.caKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		chain := f.chainOut
		if chain == nil {
			chain = []string{certPEM(f.ca), certPEM(f.root)}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			"ca_chain":    chain,
		}})
	})
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// correctLeaf is what a role with `organization=system:nodes` issues.
func (f *fakeVaultPKI) correctLeaf(csr *x509.CertificateRequest) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: csr.Subject.CommonName, Organization: []string{"system:nodes"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func (f *fakeVaultPKI) signer(t *testing.T) *Signer {
	t.Helper()
	cert := f.srv.TLS.Certificates[0]
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	s, err := New(Config{
		Server: f.srv.URL, Mount: "pki_int", Role: "nodes",
		CABundle: caPEM, CertPEM: certPEM, KeyPEM: keyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// nodeCSR is a node asking for a certificate, optionally claiming an Organization it has no
// right to — which is exactly what a real CSR can carry, since the node writes it.
func nodeCSR(t *testing.T, cn string, org []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn, Organization: org},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestSignThroughVault is the happy path: the controller logs in with its own certificate,
// the engine issues, and the result carries the groups the caller asked for.
func TestSignThroughVault(t *testing.T) {
	f := newFakeVaultPKI(t)
	s := f.signer(t)

	certPEM, err := s.SignCSR(nodeCSR(t, "node-1", nil), []string{"system:nodes"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "node-1" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "system:nodes" {
		t.Errorf("organization = %v", cert.Subject.Organization)
	}
	if f.logins != 1 || f.signs != 1 {
		t.Errorf("logins=%d signs=%d", f.logins, f.signs)
	}
}

// TestIssuedChainCarriesTheIntermediates: what this returns is what the CSR's status carries
// and what the node writes into its credential verbatim. A PKI engine signs under an
// intermediate, so a bare leaf builds no path at a peer holding only the root — the handshake
// fails with "unknown ca" and the node drops out of the fleet at the moment it renews. The
// root itself is dropped: it is what the peer's trust store already is.
func TestIssuedChainCarriesTheIntermediates(t *testing.T) {
	f := newFakeVaultPKI(t)
	bundle, err := f.signer(t).SignCSR(nodeCSR(t, "node-1", nil), []string{"system:nodes"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var certs []*x509.Certificate
	for rest := bundle; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	if len(certs) != 2 {
		t.Fatalf("bundle holds %d certificates, want the leaf and its issuer", len(certs))
	}
	if certs[0].Subject.CommonName != "node-1" {
		t.Errorf("first certificate is %q, and a leaf-first bundle is what a TLS stack reads",
			certs[0].Subject.CommonName)
	}
	if certs[1].Subject.CommonName != "pki_int" {
		t.Errorf("second certificate is %q, want the issuing intermediate", certs[1].Subject.CommonName)
	}

	// The point of carrying it: a verifier trusting only the ROOT can now build the path.
	roots := x509.NewCertPool()
	roots.AddCert(f.root)
	inter := x509.NewCertPool()
	inter.AddCert(certs[1])
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("the bundle does not verify against the root alone: %v", err)
	}
}

// TestChainThatDoesNotIssueIsRefused: an unordered or unrelated ca_chain builds no path at the
// far end, and finding that out at a node's next handshake is finding it out too late.
func TestChainThatDoesNotIssueIsRefused(t *testing.T) {
	f := newFakeVaultPKI(t)
	other := newFakeVaultPKI(t) // a CA that issued nothing here
	f.chainOut = []string{certPEM(other.ca)}

	_, err := f.signer(t).SignCSR(nodeCSR(t, "node-1", nil), []string{"system:nodes"}, time.Hour)
	if err == nil {
		t.Fatal("a chain that does not issue the certificate was accepted")
	}
	if !strings.Contains(err.Error(), "ca_chain") {
		t.Errorf("error %q does not say the chain is the problem", err)
	}
}

// TestIssuedCertificateIsVerified is the reason this package exists rather than a bare HTTP
// call. The local signer guarantees the Organization by BUILDING the subject; here that
// guarantee lives in a role definition on another machine, so every way the role could be
// wrong — or changed — has to fail the signing instead of issuing something nobody checked.
func TestIssuedCertificateIsVerified(t *testing.T) {
	cases := []struct {
		name  string
		issue func(csr *x509.CertificateRequest) *x509.Certificate
		want  string
	}{{
		// sign-verbatim, or a role that does not pin organization: the CSR's own subject is
		// passed through, so a node that asked for system:masters is handed it. This is the
		// escalation the whole design refuses, and the reason the docs say never verbatim.
		name: "the role did not pin the organization",
		issue: func(csr *x509.CertificateRequest) *x509.Certificate {
			return &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      csr.Subject, // verbatim
				NotAfter:     time.Now().Add(time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
		},
		want: "organization",
	}, {
		name: "the certificate names a different node",
		issue: func(*x509.CertificateRequest) *x509.Certificate {
			return &x509.Certificate{
				SerialNumber: big.NewInt(3),
				Subject:      pkix.Name{CommonName: "node-2", Organization: []string{"system:nodes"}},
				NotAfter:     time.Now().Add(time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
		},
		want: "not the requested",
	}, {
		name: "the certificate is a CA",
		issue: func(csr *x509.CertificateRequest) *x509.Certificate {
			return &x509.Certificate{
				SerialNumber:          big.NewInt(4),
				Subject:               pkix.Name{CommonName: csr.Subject.CommonName, Organization: []string{"system:nodes"}},
				NotAfter:              time.Now().Add(time.Hour),
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
		},
		want: "CA certificate",
	}, {
		name: "the certificate cannot authenticate a client",
		issue: func(csr *x509.CertificateRequest) *x509.Certificate {
			return &x509.Certificate{
				SerialNumber: big.NewInt(5),
				Subject:      pkix.Name{CommonName: csr.Subject.CommonName, Organization: []string{"system:nodes"}},
				NotAfter:     time.Now().Add(time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
		},
		want: "client authentication",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeVaultPKI(t)
			f.issue = tc.issue
			_, err := f.signer(t).SignCSR(nodeCSR(t, "node-1", []string{"system:masters"}), []string{"system:nodes"}, time.Hour)
			if err == nil {
				t.Fatal("the issued certificate was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestSignedForADifferentKey: a certificate issued for someone else's public key
// authenticates whoever holds the matching private key, not the node that asked.
func TestSignedForADifferentKey(t *testing.T) {
	f := newFakeVaultPKI(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.issue = func(csr *x509.CertificateRequest) *x509.Certificate {
		leaf := f.correctLeaf(csr)
		leaf.PublicKey = &other.PublicKey
		return leaf
	}
	if _, err := f.signer(t).SignCSR(nodeCSR(t, "node-1", nil), []string{"system:nodes"}, time.Hour); err == nil ||
		!strings.Contains(err.Error(), "different public key") {
		t.Fatalf("want a public-key mismatch refusal, got %v", err)
	}
}

// TestUnsignedCSRIsRefused: the CN and public key the issued certificate is verified against
// come out of the CSR, so an unverified CSR would mean checking against an unproven claim.
func TestUnsignedCSRIsRefused(t *testing.T) {
	f := newFakeVaultPKI(t)
	csrPEM := nodeCSR(t, "node-1", nil)
	block, _ := pem.Decode(csrPEM)
	block.Bytes[len(block.Bytes)-1] ^= 0xff // break the signature
	tampered := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: block.Bytes})

	if _, err := f.signer(t).SignCSR(tampered, []string{"system:nodes"}, time.Hour); err == nil {
		t.Fatal("a CSR with a broken signature was signed")
	}
	if f.signs != 0 {
		t.Error("the CSR reached Vault before its signature was checked")
	}
}

// TestNewRefusesAnUnusableConfiguration: the controller must fail at startup, not at the
// first node rotation — by then the operator is not watching and a node is stuck.
func TestNewRefusesAnUnusableConfiguration(t *testing.T) {
	for _, cfg := range []Config{
		{Role: "nodes"},                           // no server
		{Server: "https://v:8200"},                // no role
		{Server: "https://v:8200", Role: "nodes"}, // no credential
		{Server: "https://v:8200", Role: "nodes", CertPEM: []byte("not a pem"), KeyPEM: []byte("nor this")},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) was accepted", cfg)
		}
	}
}

// TestSelfRenewReplacesTheCredentialWithANewKey: the hand-bootstrapped certificate is meant
// to be a ONE-TIME step, so the controller renews it through the same engine it signs node
// certificates with — and with a fresh key, because a renewal that keeps the key leaves
// whoever once copied it a credential that never stops working.
func TestSelfRenewReplacesTheCredentialWithANewKey(t *testing.T) {
	f := newFakeVaultPKI(t)
	f.issue = func(csr *x509.CertificateRequest) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(99),
			Subject:      pkix.Name{CommonName: csr.Subject.CommonName}, // the self role pins no O
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(2 * time.Hour),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "ctl.pem"), filepath.Join(dir, "ctl.key")

	// Bootstrap: a credential for "horchestra-controller" written by hand.
	ca, err := pki.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueClient("horchestra-controller", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	s, err := New(Config{
		Server: f.srv.URL, Mount: "pki_int", Role: "nodes", SelfRole: "nodes",
		CABundle: caPEM, CertPEM: certPEM, KeyPEM: keyPEM, CertFile: certFile, KeyFile: keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}

	before, err := pemLeaf(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.renewSelf(context.Background(), before); err != nil {
		t.Fatalf("renewSelf: %v", err)
	}

	// Written to disk, so a restart comes back on the new credential rather than the old one.
	onDisk, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	after, err := pemLeaf(onDisk)
	if err != nil {
		t.Fatal(err)
	}
	if after.Subject.CommonName != "horchestra-controller" {
		t.Errorf("renewed CN = %q — the identity must not change", after.Subject.CommonName)
	}
	if !after.NotAfter.After(before.NotAfter) {
		t.Errorf("renewed NotAfter %v is not later than %v", after.NotAfter, before.NotAfter)
	}
	if after.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(before.PublicKey) {
		t.Error("the renewal reused the old key: a copied key would then never stop working")
	}
	// And in memory, so the next request already uses it.
	live, err := s.currentLeaf()
	if err != nil || !live.Equal(after) {
		t.Errorf("the signer is still presenting the old credential (%v)", err)
	}
}

// TestSelfRenewIsOffWithoutARole: an operator who has not named a self role renews out of
// band, and the loop must return rather than spin.
func TestSelfRenewIsOffWithoutARole(t *testing.T) {
	f := newFakeVaultPKI(t)
	s := f.signer(t) // no SelfRole
	done := make(chan struct{})
	go func() { defer close(done); s.SelfRenew(context.Background()) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SelfRenew did not return with no self role configured")
	}
}
