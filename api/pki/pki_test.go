package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestIssueClient(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	certPEM, keyPEM, err := ca.IssueClient("node1", []string{"system:nodes"}, DefaultClientTTL)
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
	want := time.Now().Add(DefaultClientTTL)
	if d := cert.NotAfter.Sub(want); d < -time.Hour || d > time.Hour {
		t.Fatalf("NotAfter = %v, want ~%v (the ttl parameter must bound the lifetime)", cert.NotAfter, want)
	}
}

func TestIssueClientRejectsNonPositiveTTL(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	if _, _, err := ca.IssueClient("node1", nil, 0); err == nil {
		t.Fatal("a zero TTL must be rejected")
	}
	if _, _, err := ca.IssueClient("node1", nil, -time.Hour); err == nil {
		t.Fatal("a negative TTL must be rejected")
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
