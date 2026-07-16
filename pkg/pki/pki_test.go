package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestIssueClient(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	certPEM, keyPEM, err := ca.IssueClient("node1", []string{"system:nodes"})
	if err != nil {
		t.Fatalf("issue client: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("key pair: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cert.Subject.CommonName != "node1" {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("append CA")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSaveLoadAndServer(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	loaded, err := LoadCA(ca.CertPEM(), keyPEM)
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}
	certPEM, srvKeyPEM, err := loaded.IssueServer([]string{"127.0.0.1", "controller.local"})
	if err != nil {
		t.Fatalf("issue server: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, srvKeyPEM); err != nil {
		t.Fatalf("server key pair: %v", err)
	}
}
