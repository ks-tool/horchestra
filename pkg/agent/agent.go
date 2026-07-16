package agent

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/kubeconfig"
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

// App is a desired application, projected from an Application pushed by the
// controller.
type App struct {
	Name            string
	Node            string
	Image           string
	Command         []string
	Args            []string
	Requests        v1.ResourceAmounts
	Limits          v1.ResourceAmounts
	Env             map[string]string
	RestartPolicy   string
	SecurityContext *v1.SecurityContext
	VolumeMounts    []v1.VolumeMount
}

// appFromV1 projects a decoded Application into the reconciler's App form.
func appFromV1(it v1.Application) App {
	return App{
		Name:            it.Name,
		Node:            it.Spec.NodeName,
		Image:           it.Spec.Image,
		Command:         it.Spec.Command,
		Args:            it.Spec.Args,
		Requests:        it.Spec.Resources.Requests,
		Limits:          it.Spec.Resources.Limits,
		Env:             it.Spec.Env,
		RestartPolicy:   it.Spec.RestartPolicy,
		SecurityContext: it.Spec.SecurityContext,
		VolumeMounts:    it.Spec.VolumeMounts,
	}
}

// appsForNode keys the applications pinned to node by name. spec.node pins each
// application to exactly one node (one app = one node), so a node runs only the
// applications naming it; the rest belong to other nodes.
func appsForNode(apps []App, node string) map[string]App {
	want := make(map[string]App, len(apps))
	for _, a := range apps {
		if a.Node == node {
			want[a.Name] = a
		}
	}
	return want
}

// effectiveRequests are the resources this app reserves on its node.
func (a App) effectiveRequests() v1.ResourceAmounts {
	return v1.ResourceRequirements{Requests: a.Requests, Limits: a.Limits}.EffectiveRequests()
}

// NodeCredentials is the mTLS client material and controller endpoint a node
// agent needs to reach the controller — the contents of a node.conf.
type NodeCredentials struct {
	Controller string
	CertPEM    []byte
	KeyPEM     []byte
	CAPEM      []byte
}

// LoadAuthConfig reads node.conf — the node's kubeconfig (the --auth-config file)
// — resolving the controller URL from the cluster server, the client
// certificate/key from the user, and the CA from the cluster. It mirrors how the
// controller loads its own kubeconfig (see pkg/config), so a node is configured
// from a single bundle.
func LoadAuthConfig(path string) (NodeCredentials, error) {
	kc, err := kubeconfig.Load(path)
	if err != nil {
		return NodeCredentials{}, err
	}
	cluster, user, err := kc.Current()
	if err != nil {
		return NodeCredentials{}, err
	}
	return NodeCredentials{
		Controller: cluster.Server,
		CertPEM:    user.ClientCertificateData,
		KeyPEM:     user.ClientKeyData,
		CAPEM:      cluster.CertificateAuthorityData,
	}, nil
}

// nodeIP returns this node's source IP toward the controller — the address it
// reaches the control plane on, reported as the node's IP. A UDP "connect" sends
// no packets; it just resolves the route and yields the local address. Empty if
// it cannot be determined.
func nodeIP(controller string) string {
	u, err := url.Parse(controller)
	if err != nil {
		return ""
	}
	host, port := u.Hostname(), u.Port()
	if len(port) == 0 {
		port = "443"
	}
	conn, err := net.Dial("udp", net.JoinHostPort(host, port))
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
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
