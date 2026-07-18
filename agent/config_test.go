package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestNormalizeControllerURL(t *testing.T) {
	ok := map[string]string{
		"127.0.0.1":                  "https://127.0.0.1:8443", // the bug: bare IP, no scheme
		"10.0.0.5:8443":              "https://10.0.0.5:8443",  // host:port, no scheme
		"https://ctrl.example:8443":  "https://ctrl.example:8443",
		"https://ctrl.example":       "https://ctrl.example:8443", // default port
		"http://10.0.0.5:9000":       "http://10.0.0.5:9000",
		"https://10.0.0.5:8443/":     "https://10.0.0.5:8443", // path stripped
		"  https://10.0.0.5:8443  ":  "https://10.0.0.5:8443", // trimmed
		"[2001:db8::1]:8443":         "https://[2001:db8::1]:8443",
		"https://[2001:db8::1]:8443": "https://[2001:db8::1]:8443",
	}
	for in, want := range ok {
		got, err := NormalizeControllerURL(in)
		if err != nil {
			t.Errorf("NormalizeControllerURL(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeControllerURL(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"", "   ", "ftp://10.0.0.5", "https://"} {
		if got, err := NormalizeControllerURL(bad); err == nil {
			t.Errorf("NormalizeControllerURL(%q) = %q, want error", bad, got)
		}
	}
}

func TestLoadAuthConfig(t *testing.T) {
	server := "https://10.0.0.5:8443"
	cert := []byte("-----BEGIN CERTIFICATE-----\nnode-cert\n-----END CERTIFICATE-----\n")
	key := []byte("-----BEGIN PRIVATE KEY-----\nnode-key\n-----END PRIVATE KEY-----\n")
	ca := []byte("-----BEGIN CERTIFICATE-----\nca-cert\n-----END CERTIFICATE-----\n")

	kc := clientcmdapi.NewConfig()
	kc.Clusters["horchestra"] = &clientcmdapi.Cluster{Server: server, CertificateAuthorityData: ca}
	kc.AuthInfos["node-a"] = &clientcmdapi.AuthInfo{ClientCertificateData: cert, ClientKeyData: key}
	kc.Contexts["horchestra"] = &clientcmdapi.Context{Cluster: "horchestra", AuthInfo: "node-a"}
	kc.CurrentContext = "horchestra"
	data, err := clientcmd.Write(*kc)
	if err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	path := filepath.Join(t.TempDir(), "node.conf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadAuthConfig(path)
	if err != nil {
		t.Fatalf("LoadAuthConfig: %v", err)
	}
	if cfg.Host != server {
		t.Errorf("Host = %q, want %q", cfg.Host, server)
	}
	if !bytes.Equal(cfg.TLSClientConfig.CertData, cert) {
		t.Errorf("CertData = %q, want %q", cfg.TLSClientConfig.CertData, cert)
	}
	if !bytes.Equal(cfg.TLSClientConfig.KeyData, key) {
		t.Errorf("KeyData = %q, want %q", cfg.TLSClientConfig.KeyData, key)
	}
	if !bytes.Equal(cfg.TLSClientConfig.CAData, ca) {
		t.Errorf("CAData = %q, want %q", cfg.TLSClientConfig.CAData, ca)
	}

	if _, err := LoadAuthConfig(filepath.Join(t.TempDir(), "missing.conf")); err == nil {
		t.Error("LoadAuthConfig(missing) = nil error, want error")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"https://127.0.0.1:8443", "https://localhost:8443", "http://[::1]:8443"}
	for _, u := range loopback {
		if !IsLoopbackHost(u) {
			t.Errorf("IsLoopbackHost(%q) = false, want true", u)
		}
	}
	for _, u := range []string{"https://10.0.0.5:8443", "https://ctrl.example:8443"} {
		if IsLoopbackHost(u) {
			t.Errorf("IsLoopbackHost(%q) = true, want false", u)
		}
	}
}
