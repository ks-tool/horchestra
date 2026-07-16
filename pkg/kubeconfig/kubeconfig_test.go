package kubeconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	ca := []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")
	cert := []byte("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n")
	key := []byte("-----BEGIN EC PRIVATE KEY-----\nkey\n-----END EC PRIVATE KEY-----\n")

	data, err := New("horchestra", "controller", "https://10.0.0.1:8443", ca, cert, key).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "kc.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cluster, user, err := loaded.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cluster.Server != "https://10.0.0.1:8443" {
		t.Errorf("server = %q", cluster.Server)
	}
	if !bytes.Equal(cluster.CertificateAuthorityData, ca) {
		t.Errorf("CA did not round-trip")
	}
	if !bytes.Equal(user.ClientCertificateData, cert) || !bytes.Equal(user.ClientKeyData, key) {
		t.Errorf("cert/key did not round-trip")
	}
}

func TestCurrentMissing(t *testing.T) {
	c := &Config{CurrentContext: "nope"}
	if _, _, err := c.Current(); err == nil {
		t.Fatal("want error for missing current-context")
	}
}
