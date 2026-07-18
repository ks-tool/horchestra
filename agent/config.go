package agent

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DefaultControllerPort is assumed when a controller URL omits an explicit port.
const DefaultControllerPort = "8443"

// NormalizeControllerURL canonicalizes a controller address into the base URL the
// agent connects to. A missing scheme defaults to https and a missing port to
// DefaultControllerPort, so "10.0.0.5" and "10.0.0.5:8443" both resolve to
// "https://10.0.0.5:8443". Anything that is not a valid http(s) origin is
// rejected here rather than surfacing later as an opaque connection error.
func NormalizeControllerURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("controller URL is empty")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s // bare host/IP, e.g. "10.0.0.5" or "10.0.0.5:8443"
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("parse controller URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("controller URL %q: scheme must be http or https, got %q", raw, u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("controller URL %q has no host", raw)
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), DefaultControllerPort)
	}
	return u.Scheme + "://" + u.Host, nil
}

// IsLoopbackHost reports whether a controller URL points at loopback. A node
// reaching the controller on loopback is almost always a misconfiguration (the
// controller runs on a different host), so callers warn on it.
func IsLoopbackHost(controllerURL string) bool {
	u, err := url.Parse(controllerURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// LoadAuthConfig reads node.conf — the node's kubeconfig (the --auth-config file) —
// into a REST client config: the controller URL (cluster server), the client
// certificate/key and the CA. It is client-go's standard loader, so a node is
// configured from an ordinary kubeconfig, the same way any Kubernetes client is.
func LoadAuthConfig(path string) (*rest.Config, error) {
	return clientcmd.BuildConfigFromFlags("", path)
}

// RESTConfig builds a REST client config from discrete mTLS material and a
// controller URL — the alternative to LoadAuthConfig when the node's
// certificate/key/CA are supplied as separate files rather than a kubeconfig.
func RESTConfig(host string, certPEM, keyPEM, caPEM []byte) *rest.Config {
	return &rest.Config{
		Host: host,
		TLSClientConfig: rest.TLSClientConfig{
			CertData: certPEM,
			KeyData:  keyPEM,
			CAData:   caPEM,
		},
	}
}

// clientCertPEM returns the PEM-encoded client certificate from a REST config,
// reading the file form when the config references a path rather than inline data.
// Empty when the config carries no client certificate (e.g. token auth).
func clientCertPEM(cfg *rest.Config) ([]byte, error) {
	if len(cfg.TLSClientConfig.CertData) > 0 {
		return cfg.TLSClientConfig.CertData, nil
	}
	if cfg.TLSClientConfig.CertFile != "" {
		return os.ReadFile(cfg.TLSClientConfig.CertFile)
	}
	return nil, nil
}

// certCN returns the CommonName of a PEM-encoded certificate (the node identity).
func certCN(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("invalid certificate PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return c.Subject.CommonName, nil
}
