// Package vaultpki signs node CSRs through a Vault/OpenBao PKI engine, so the controller
// holds no CA private key at all. It is a nodecsr.Signer, the same seam *pki.CA fills when
// the key IS local — the approval loop does not know which one it is talking to.
//
// What moves is the key, NOT the invariant. The local signer guarantees a node's certificate
// carries exactly the groups the caller asked for, by building the Subject itself; that
// guarantee is what stands between a node and a certificate saying O=system:masters, and
// pki.TestSignCSR exists to pin it. Signing through Vault would put that guarantee in a role
// definition on another machine, where this code cannot see it and an operator can change it
// — so the certificate Vault returns is VERIFIED here before it is handed back, against the
// CSR it was issued for and the groups that were asked for. A misconfigured role fails the
// signing rather than issuing a certificate nobody checked.
//
// This is also why the engine is addressed as pki/sign/<role> and never sign-verbatim:
// verbatim passes the CSR's own subject through, which is precisely the escalation the
// local signer refuses.
package vaultpki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// bodyLimit caps a Vault response, matching the agent-side client.
const bodyLimit = 2 << 20

// Config is what the controller needs to sign through a Vault PKI engine.
type Config struct {
	// Server is the Vault/OpenBao base URL, e.g. https://vault.example:8200.
	Server string
	// Mount is the PKI engine mount (e.g. "pki_int").
	Mount string
	// Role is the PKI role node certificates are issued under. The role — not this code and
	// not the CSR — decides the issued Organization, so it must pin organization to the
	// node group; SignCSR verifies that it did.
	Role string
	// CABundle verifies Vault's serving certificate (PEM). Empty means the system roots.
	CABundle []byte
	// AuthPath is the cert auth method's mount ("cert" by default) and AuthRole the named
	// cert role to log in against (optional).
	AuthPath, AuthRole string
	// CertPEM/KeyPEM are the controller's own client credential: the identity Vault's cert
	// auth method knows it by. Bootstrapped once by hand, and renewed by the controller
	// itself thereafter.
	CertPEM, KeyPEM []byte
	// CertFile/KeyFile are where that credential lives, so a renewal can write it back;
	// SelfRole is the PKI role it is renewed under — a role of its own, because the node role
	// pins organization=system:nodes and the controller is not a node. Empty SelfRole leaves
	// the credential for an operator to renew out of band.
	CertFile, KeyFile, SelfRole string
}

// Signer issues certificates by asking Vault to. It holds no CA key.
type Signer struct {
	cfg    Config
	client *http.Client

	mu   sync.RWMutex
	pair tls.Certificate
}

// New builds the signer and proves it can be used: the credential must parse and the
// configuration must name an engine and a role. It does NOT reach Vault — a control plane
// that refuses to start because Vault is briefly unreachable would turn a dependency on the
// rotation path into a dependency on booting at all.
func New(cfg Config) (*Signer, error) {
	if cfg.Server == "" || cfg.Role == "" {
		return nil, fmt.Errorf("vaultpki: server and role are required")
	}
	if cfg.Mount == "" {
		cfg.Mount = "pki_int"
	}
	if cfg.AuthPath == "" {
		cfg.AuthPath = "cert"
	}
	pair, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("vaultpki: controller client credential: %w", err)
	}
	s := &Signer{cfg: cfg, pair: pair}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, GetClientCertificate: s.clientCert}
	if len(cfg.CABundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CABundle) {
			return nil, fmt.Errorf("vaultpki: caBundle holds no certificate")
		}
		tlsCfg.RootCAs = pool
	}
	s.client = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	return s, nil
}

// clientCert hands the current credential to the TLS handshake. It is read under the lock so
// a rotation that swaps it mid-flight cannot be seen half-applied.
func (s *Signer) clientCert(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pair := s.pair
	return &pair, nil
}

// SignCSR asks Vault for the certificate and verifies what comes back. groups is the
// Organization the caller requires; a certificate carrying anything else is refused rather
// than returned, because the caller's whole authorization model reads that field.
func (s *Signer) SignCSR(csrPEM []byte, groups []string, ttl time.Duration) ([]byte, error) {
	return s.signWithRole(context.Background(), s.cfg.Role, csrPEM, groups, ttl)
}

// signWithRole is the shared request: the node role issues node certificates, and the
// self role the controller's own credential. Both answers are verified the same way.
func (s *Signer) signWithRole(ctx context.Context, role string, csrPEM []byte, groups []string, ttl time.Duration) ([]byte, error) {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	token, err := s.login(ctx)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]any{
		"csr":         string(csrPEM),
		"common_name": csr.Subject.CommonName,
		"ttl":         fmt.Sprintf("%ds", int(ttl.Seconds())),
	})
	if err != nil {
		return nil, err
	}
	url := strings.TrimSuffix(s.cfg.Server, "/") + "/v1/" + strings.Trim(s.cfg.Mount, "/") + "/sign/" + role
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	var payload struct {
		Data struct {
			Certificate string   `json:"certificate"`
			CAChain     []string `json:"ca_chain"`
		} `json:"data"`
	}
	if err := s.do(req, &payload); err != nil {
		return nil, fmt.Errorf("vaultpki: sign: %w", err)
	}
	bundle, err := chain(payload.Data.Certificate, payload.Data.CAChain)
	if err != nil {
		return nil, fmt.Errorf("vaultpki: %w", err)
	}
	if err := verifyIssued(bundle, csr, groups); err != nil {
		return nil, fmt.Errorf("vaultpki: %w", err)
	}
	return bundle, nil
}

// chain returns the leaf followed by the intermediates that issued it.
//
// The intermediates are the difference between a certificate that authenticates and one that
// does not. A local CA signs node certificates directly, so the leaf alone verifies against
// the cluster CA every peer already holds; a PKI engine signs them under an INTERMEDIATE, and
// a peer holding only the root cannot build the path from a bare leaf — the handshake fails
// with "unknown ca" and the node drops out of the fleet at the moment it renews. Whatever this
// returns is what the CSR's status carries and what the node writes into its credential
// verbatim, so the chain has to be in here or it exists nowhere.
//
// The root is dropped: it is what the peer's trust store already is, and sending a copy asks
// every verifier to consider a certificate that decides nothing.
func chain(leafPEM string, caChain []string) ([]byte, error) {
	leaf, err := parseCertPEM(leafPEM)
	if err != nil {
		return nil, fmt.Errorf("the response is not a PEM certificate: %w", err)
	}
	out := append([]byte(nil), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})...)
	prev := leaf
	for _, p := range caChain {
		ca, err := parseCertPEM(p)
		if err != nil {
			return nil, fmt.Errorf("the ca_chain holds something that is not a certificate: %w", err)
		}
		if bytes.Equal(ca.Raw, leaf.Raw) || isSelfSigned(ca) {
			continue // the leaf repeated, or the root the peer already trusts
		}
		// Each link must actually issue the one before it. An unordered or unrelated bundle
		// would build no path at the far end, and finding that out at a node's next handshake
		// is finding it out too late.
		if err := prev.CheckSignatureFrom(ca); err != nil {
			return nil, fmt.Errorf("the ca_chain does not issue the certificate it came with: %w", err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
		prev = ca
	}
	return out, nil
}

func parseCertPEM(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("not a PEM CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}

// verifyIssued holds Vault to what was asked for. Every check here is a guarantee the local
// signer gets for free by constructing the certificate itself, and each one is a way a role
// definition on another machine could quietly hand back something else.
//
// bundle is what chain built — leaf first, then the intermediates. Everything below is about
// the LEAF: the intermediates carry no identity and were already checked to issue it.
func verifyIssued(bundle []byte, csr *x509.CertificateRequest, groups []string) error {
	block, _ := pem.Decode(bundle)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("the response is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse the issued certificate: %w", err)
	}
	// The groups ARE the authorization. A role that does not pin organization would pass the
	// CSR's own through, which is how a node asks for system:masters and is told yes.
	got := slices.Clone(cert.Subject.Organization)
	want := slices.Clone(groups)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("the issued certificate carries organization %v, not %v — pin `organization` on the PKI role", cert.Subject.Organization, groups)
	}
	// The CN is the node's identity everywhere else in this system, so it may not be
	// rewritten between the request and the certificate.
	if cert.Subject.CommonName != csr.Subject.CommonName {
		return fmt.Errorf("the issued certificate names %q, not the requested %q", cert.Subject.CommonName, csr.Subject.CommonName)
	}
	// A certificate for a DIFFERENT key authenticates whoever holds that key, not the node
	// that asked. Every stdlib public key implements Equal; one that does not is unknown to
	// this build and fails closed.
	pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(csr.PublicKey) {
		return fmt.Errorf("the issued certificate is for a different public key than the CSR")
	}
	if cert.IsCA {
		return fmt.Errorf("the issued certificate is a CA certificate")
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("the issued certificate is not valid for client authentication")
	}
	return nil
}

// login authenticates with the controller's own client certificate — the same cert auth
// method the nodes use, so a deployment configures one trust relationship, not two.
func (s *Signer) login(ctx context.Context) (string, error) {
	body := map[string]string{}
	if s.cfg.AuthRole != "" {
		body["name"] = s.cfg.AuthRole
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	url := strings.TrimSuffix(s.cfg.Server, "/") + "/v1/auth/" + strings.Trim(s.cfg.AuthPath, "/") + "/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	var payload struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := s.do(req, &payload); err != nil {
		return "", fmt.Errorf("vaultpki: cert login: %w", err)
	}
	if payload.Auth.ClientToken == "" {
		return "", fmt.Errorf("vaultpki: cert login: no client token in the response")
	}
	return payload.Auth.ClientToken, nil
}

func (s *Signer) do(req *http.Request, out any) error {
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		excerpt := strings.TrimSpace(string(body))
		if len(excerpt) > 256 {
			excerpt = excerpt[:256]
		}
		return fmt.Errorf("%s: %s", resp.Status, excerpt)
	}
	return json.Unmarshal(body, out)
}

func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("vaultpki: not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vaultpki: parse CSR: %w", err)
	}
	// Checked HERE as well as by Vault: the CN and public key this code verifies the issued
	// certificate against come out of the CSR, so an unverified CSR would be checking the
	// certificate against a claim nobody proved.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("vaultpki: CSR signature: %w", err)
	}
	return csr, nil
}
