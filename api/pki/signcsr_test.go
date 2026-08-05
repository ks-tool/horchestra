package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func TestSignCSR(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	// A node key + CSR that (maliciously) requests O=system:masters.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "node1", Organization: []string{"system:masters"}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, err := ca.SignCSR(csrPEM, []string{"system:nodes"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "node1" {
		t.Errorf("CN = %q, want node1 (from the CSR)", cert.Subject.CommonName)
	}
	// The caller's groups win — the CSR's requested system:masters must be dropped.
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "system:nodes" {
		t.Errorf("O = %v, want [system:nodes] (the CSR's requested groups must be ignored)", cert.Subject.Organization)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want client-auth", cert.ExtKeyUsage)
	}
	if cert.NotAfter.After(time.Now().Add(2 * time.Hour)) {
		t.Errorf("NotAfter = %v, want bounded by the 1h ttl", cert.NotAfter)
	}
	// The signed public key must be the node's own.
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("the signed certificate must carry the CSR's public key")
	}
	if _, err := ca.SignCSR([]byte("not a pem"), nil, time.Hour); err == nil {
		t.Error("a non-PEM input must be rejected")
	}
}
