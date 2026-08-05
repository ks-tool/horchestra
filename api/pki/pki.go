package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "horchestra-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: encode("CERTIFICATE", der)}, nil
}

func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

func (ca *CA) CertPEM() []byte { return ca.certPEM }

func (ca *CA) KeyPEM() ([]byte, error) { return keyPEM(ca.key) }

// IssueServer issues a server certificate whose SANs cover the given hosts
// (IPs and DNS names).
func (ca *CA) IssueServer(hosts []string) (certPEM, keyPEM []byte, err error) {
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: firstOr(hosts, "horchestra-controller")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return ca.issue(tmpl)
}

// DefaultClientTTL is the client-certificate lifetime issued when the caller has no
// stronger opinion. It matches controller/loops/nodecsr's defaultTTL (~90 days) so an
// initial node-tool-issued credential rotates on the same cadence the rotation loop
// assumes; a short TTL plus rotation is the only revocation lever (there is no CRL).
const DefaultClientTTL = 90 * 24 * time.Hour

// IssueClient issues a client certificate with the given common name (the node
// identity), organization values (groups) and lifetime.
func (ca *CA) IssueClient(cn string, groups []string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	if ttl <= 0 {
		return nil, nil, fmt.Errorf("pki: client certificate TTL must be positive, got %v", ttl)
	}
	return ca.issue(&x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn, Organization: groups},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

// GenerateCSR creates a fresh ECDSA P-256 private key and a PKCS#10 certificate signing
// request for the common name cn (the node name). The private key never leaves the caller —
// only the returned CSR is sent to the controller for signing. Used by a node to enroll and to
// rotate its certificate.
func GenerateCSR(cn string) (csrPEM, privPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	privPEM, err = keyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return encode("CERTIFICATE REQUEST", der), privPEM, nil
}

// SignCSR signs an external certificate signing request as a short-lived client certificate.
// The CN is taken from the CSR, but the Organization (groups) is set by the CALLER — never the
// CSR — so a requester cannot self-assign a privileged group (the approval loop decides the
// groups, e.g. exactly system:nodes). The requester's private key never leaves its box; only
// the CSR's public key is signed. ttl bounds the lifetime — a short TTL plus rotation is the
// only revocation lever (there is no CRL).
func (ca *CA) SignCSR(csrPEM []byte, groups []string, ttl time.Duration) (certPEM []byte, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("pki: not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: csr.Subject.CommonName, Organization: groups},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return encode("CERTIFICATE", der), nil
}

func (ca *CA) issue(tmpl *x509.Certificate) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	kp, err := keyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return encode("CERTIFICATE", der), kp, nil
}

func keyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return encode("EC PRIVATE KEY", der), nil
}

func encode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

func firstOr(s []string, def string) string {
	if len(s) > 0 {
		return s[0]
	}
	return def
}
