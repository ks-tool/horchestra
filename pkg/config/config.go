package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/ks-tool/horchestra/api/features"
	"github.com/ks-tool/horchestra/pkg/vaultpki"

	"github.com/spf13/pflag"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// DefaultNodeReadyTimeout is how long a node's heartbeat may age before it reads NotReady.
	DefaultNodeReadyTimeout = 45 * time.Second
	// DefaultStorage is the built-in storage DSN: an embedded BoltDB in the working directory.
	DefaultStorage = "bolt:horchestra.db"
)

// Config is the controller configuration: the flag-bound fields, plus the material Complete
// resolves from them (the serving TLS config, the client CA, the node-join signer CA and the
// parsed ready timeout). The resolved fields are valid only after Complete and are not serialized.
type Config struct {
	Addr             string `json:"addr"`
	Storage          string `json:"storage"`
	TLSCert          string `json:"tlsCert"`
	TLSKey           string `json:"tlsKey"`
	TLSCA            string `json:"tlsCA"`
	ClusterCA        string `json:"clusterCA"`
	ClusterCAKey     string `json:"clusterCAKey"`
	AuthConfig       string `json:"authConfig"`
	NodeReadyTimeout string `json:"nodeReadyTimeout"`
	NodeCertTTL      string `json:"nodeCertTTL"`
	// JWTSigningKey is the PEM EC P-256 key the controller signs workload-identity tokens
	// with (generated there on first use). Setting it turns the controller into the token
	// issuer + TokenReview endpoint for Vault's kubernetes auth method; empty disables
	// the issuer, and nodes then authenticate to Vault by certificate only.
	JWTSigningKey string `json:"jwtSigningKey"`
	// JWTIssuer is the iss claim of the minted tokens (any stable string; default
	// horchestra).
	JWTIssuer string `json:"jwtIssuer"`
	// StrictNodeRegistration makes a node's FIRST registration prove that its certificate belongs
	// to the host presenting it: the address it connects from is reverse-resolved and the
	// certificate CN must name the host that comes back. Only registration is checked — afterwards
	// the Node object is the record of that decision — so DNS has to be working while a node joins,
	// but a later DNS outage does not evict a running fleet. Off by default: a node's displayed
	// name is its certificate CN either way, and without this it need not resolve at all.
	StrictNodeRegistration bool `json:"strictNodeRegistration"`
	// FeatureGates opts this deployment into named capabilities that are off by default,
	// in the "Name=true,Other=false" form. See api/features for what a gate is and what
	// this build knows.
	FeatureGates string `json:"featureGates,omitempty"`
	// CatalogNamespace is the namespace an unqualified service-discovery query (`?ns=` absent)
	// answers. Consul Enterprise answers `default`, which is the default here too — but a fleet
	// whose workloads live in `platform` would otherwise hand every client that cannot send the
	// parameter an empty catalog, which reads as "the service is gone" rather than "you asked the
	// wrong question".
	CatalogNamespace string `json:"catalogNamespace,omitempty"`
	// RoutedCIDR is the range workload addresses are cut from when a fleet runs isolated
	// networks. ONE range for the whole fleet — not a slice per node: which node an address lives
	// on is the datapath's business, and the flat range is what gets announced outward as a single
	// prefix. Empty — the default — means every workload shares its node's network, no address is
	// ever chosen, and `spec.hostNetwork: false` is refused at admission rather than admitted and
	// silently flattened.
	//
	// Setting it is a statement about the FLEET, not about the control plane: the nodes must have
	// the network helper for a workload to be wired, and a node without one refuses to start such
	// a workload instead of running it flat.
	RoutedCIDR string `json:"routedCIDR,omitempty"`
	// ServiceCIDR is the range a Service's cluster address is allocated from when its author
	// declares none. Empty — the default — allocates nothing: an address is only ever as real as
	// whatever answers on it, and a declared one comes with that knowledge while an allocated one
	// needs something that translates it (the eBPF datapath). Naming a range is how a deployment
	// says those addresses are handled in its fleet.
	ServiceCIDR string `json:"serviceCIDR,omitempty"`
	// VaultPKI* sign node CSRs through a Vault/OpenBao PKI engine instead of a local CA key,
	// so the controller holds no signing key at all. Setting VaultPKIServer selects it;
	// it is mutually exclusive with --cluster-ca-key, and --cluster-ca must still name the
	// engine's certificate, which is what clients verify against.
	VaultPKIServer   string `json:"vaultPKIServer,omitempty"`
	VaultPKIMount    string `json:"vaultPKIMount,omitempty"`
	VaultPKIRole     string `json:"vaultPKIRole,omitempty"`
	VaultPKICA       string `json:"vaultPKICA,omitempty"`
	VaultPKIAuthPath string `json:"vaultPKIAuthPath,omitempty"`
	VaultPKIAuthRole string `json:"vaultPKIAuthRole,omitempty"`
	VaultPKICert     string `json:"vaultPKICert,omitempty"`
	VaultPKIKey      string `json:"vaultPKIKey,omitempty"`
	VaultPKISelfRole string `json:"vaultPKISelfRole,omitempty"`

	// Resolved by Complete; not serialized.
	ServerTLS    *tls.Config      `json:"-"` // serving config; nil => plain HTTP
	ClientCA     []byte           `json:"-"` // client CA PEM, for verifying client certificates
	SignerCert   []byte           `json:"-"` // node-join signer CA cert; nil => offline-CA mode
	SignerKey    []byte           `json:"-"` // node-join signer CA key
	ReadyTimeout time.Duration    `json:"-"`
	Gates        features.Gates   `json:"-"` // parsed FeatureGates
	VaultPKI     *vaultpki.Config `json:"-"` // nil => sign locally (or offline-CA)
}

// Default returns the built-in configuration, before any flag overrides.
func Default() Config {
	return Config{
		Addr:             ":8443",
		Storage:          DefaultStorage,
		NodeReadyTimeout: DefaultNodeReadyTimeout.String(),
	}
}

// AddFlags binds the controller flags to c on fs. Call it on a Config produced by Default so
// each flag's default matches the built-in configuration.
func (c *Config) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.Addr, "addr", c.Addr, "listen address")
	fs.StringVar(&c.Storage, "storage", c.Storage, "storage backend DSN (bolt:<path>; postgres:// reserved)")
	fs.StringVar(&c.TLSCert, "tls-cert", c.TLSCert, "server certificate for HTTPS")
	fs.StringVar(&c.TLSKey, "tls-key", c.TLSKey, "server private key")
	fs.StringVar(&c.TLSCA, "tls-ca", c.TLSCA, "CA that verifies client certificates (enables mTLS)")
	fs.StringVar(&c.ClusterCA, "cluster-ca", c.ClusterCA, "signer CA certificate for node-join CSRs (a client-auth intermediate)")
	fs.StringVar(&c.JWTSigningKey, "jwt-signing-key", c.JWTSigningKey, "PEM EC P-256 key for workload-identity tokens (generated on first use); enables the issuer + TokenReview for Vault's kubernetes auth")
	fs.StringVar(&c.JWTIssuer, "jwt-issuer", c.JWTIssuer, "iss claim for workload-identity tokens (default horchestra)")
	fs.StringVar(&c.ClusterCAKey, "cluster-ca-key", c.ClusterCAKey, "signer CA private key for node-join CSRs (offline-CA mode if unset)")
	fs.StringVar(&c.AuthConfig, "auth-config", c.AuthConfig, "auth-config (kubeconfig) bundling the serving cert/key, client CA and address (from `node-tool init`)")
	fs.StringVar(&c.NodeReadyTimeout, "node-ready-timeout", c.NodeReadyTimeout, "how long a node's heartbeat may age before it reads NotReady (e.g. 45s, 2m)")
	fs.StringVar(&c.NodeCertTTL, "node-cert-ttl", c.NodeCertTTL, "lifetime of a signed node-join certificate (e.g. 2160h); empty = ~90d default")
	fs.BoolVar(&c.StrictNodeRegistration, "strict-node-registration", c.StrictNodeRegistration,
		"a node may register only if its certificate CN matches the reverse DNS name of the address it connects from")
	fs.StringVar(&c.VaultPKIServer, "pki-vault", c.VaultPKIServer,
		"sign node CSRs through this Vault/OpenBao PKI engine instead of a local CA key (the controller then holds no signing key)")
	fs.StringVar(&c.VaultPKIMount, "pki-vault-mount", c.VaultPKIMount, "PKI engine mount (default pki_int)")
	fs.StringVar(&c.VaultPKIRole, "pki-vault-role", c.VaultPKIRole,
		"PKI role node certificates are issued under; it must pin `organization` to system:nodes (never sign-verbatim)")
	fs.StringVar(&c.VaultPKICA, "pki-vault-ca", c.VaultPKICA, "CA bundle verifying the Vault server's certificate")
	fs.StringVar(&c.VaultPKIAuthPath, "pki-vault-auth-path", c.VaultPKIAuthPath, "cert auth method mount (default cert)")
	fs.StringVar(&c.VaultPKIAuthRole, "pki-vault-auth-role", c.VaultPKIAuthRole, "named cert role to log in against")
	fs.StringVar(&c.VaultPKICert, "pki-vault-cert", c.VaultPKICert, "the controller's own client certificate for Vault cert auth")
	fs.StringVar(&c.VaultPKIKey, "pki-vault-key", c.VaultPKIKey, "private key for --pki-vault-cert")
	fs.StringVar(&c.VaultPKISelfRole, "pki-vault-self-role", c.VaultPKISelfRole,
		"PKI role the controller renews its OWN client credential under, before it expires (empty: renewed out of band)")
	fs.StringVar(&c.CatalogNamespace, "catalog-default-namespace", c.CatalogNamespace,
		"namespace an unqualified service-discovery query (no ?ns=) answers (default `default`)")
	fs.StringVar(&c.RoutedCIDR, "routed-cidr", c.RoutedCIDR,
		"one range for the whole fleet that workload addresses are cut from (e.g. 10.244.0.0/16); unset keeps every workload on its node's network")
	fs.StringVar(&c.ServiceCIDR, "service-cidr", c.ServiceCIDR,
		"range a Service's clusterIP is allocated from when it declares none (e.g. 10.243.0.0/16); unset allocates nothing")
	fs.StringVar(&c.FeatureGates, "feature-gates", c.FeatureGates,
		"comma-separated Name=true|false opting into off-by-default capabilities — "+features.Usage())
}

// Complete resolves the flag values into runtime material: the parsed ready timeout, the serving
// TLS config (mTLS when a client CA is present), the client and node-join signer CAs, and — when
// -addr was left at its default — the bind address from the auth-config's server URL. fs reports
// which flags were set explicitly.
func (c *Config) Complete(fs *pflag.FlagSet) error {
	rt, err := parseReadyTimeout(c.NodeReadyTimeout)
	if err != nil {
		return err
	}
	c.ReadyTimeout = rt

	// Parsed here rather than where a gate is read, so a typo is a startup failure naming
	// what this build knows — not a capability that stays silently off in production.
	if c.Gates, err = features.Parse(c.FeatureGates); err != nil {
		return err
	}

	// Checked at startup rather than at the first Service that needs an address: a malformed range
	// would otherwise surface as a refusal to whoever happened to create one, long after the
	// operator who typed it stopped watching.
	// Checked at startup rather than at the first workload that needs an address: a malformed
	// range would otherwise surface as a refusal to whoever happened to create one.
	if c.RoutedCIDR != "" {
		if _, err := netip.ParsePrefix(c.RoutedCIDR); err != nil {
			return fmt.Errorf("--routed-cidr %q is not a CIDR: %w", c.RoutedCIDR, err)
		}
	}
	if c.ServiceCIDR != "" {
		if _, err := netip.ParsePrefix(c.ServiceCIDR); err != nil {
			return fmt.Errorf("--service-cidr %q is not a CIDR: %w", c.ServiceCIDR, err)
		}
	}

	mat, err := c.servingMaterial()
	if err != nil {
		return err
	}
	c.ClientCA = mat.ca
	if len(mat.cert) > 0 {
		pair, err := tls.X509KeyPair(mat.cert, mat.key)
		if err != nil {
			return err
		}
		c.ServerTLS = &tls.Config{Certificates: []tls.Certificate{pair}}
		if len(mat.ca) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(mat.ca) {
				return fmt.Errorf("no CA certificates in client CA")
			}
			c.ServerTLS.ClientCAs = pool
			c.ServerTLS.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	if !fs.Changed("addr") && len(mat.host) > 0 {
		c.Addr = mat.host
	}

	if err := c.completeVaultPKI(); err != nil {
		return err
	}
	if len(c.ClusterCA) > 0 && len(c.ClusterCAKey) > 0 {
		if c.SignerCert, err = os.ReadFile(c.ClusterCA); err != nil {
			return err
		}
		if c.SignerKey, err = os.ReadFile(c.ClusterCAKey); err != nil {
			return err
		}
	}
	return nil
}

// servingTLS is the resolved serving material: the serving cert/key pair, the client CA PEM,
// and the auth-config's advertised server host (empty for the discrete --tls-* path).
type servingTLS struct {
	cert, key, ca []byte
	host          string
}

// servingMaterial resolves the serving cert/key, the client CA, and the auth-config's server
// host from the auth-config (a kubeconfig, preferred) or the discrete --tls-* files. An
// auth-config missing its serving cert/key is an error.
func (c Config) servingMaterial() (servingTLS, error) {
	var m servingTLS
	switch {
	case len(c.AuthConfig) > 0:
		rc, err := clientcmd.BuildConfigFromFlags("", c.AuthConfig)
		if err != nil {
			return servingTLS{}, err
		}
		if m.cert, err = pemOrFile(rc.TLSClientConfig.CertData, rc.TLSClientConfig.CertFile); err != nil {
			return servingTLS{}, err
		}
		if m.key, err = pemOrFile(rc.TLSClientConfig.KeyData, rc.TLSClientConfig.KeyFile); err != nil {
			return servingTLS{}, err
		}
		if m.ca, err = pemOrFile(rc.TLSClientConfig.CAData, rc.TLSClientConfig.CAFile); err != nil {
			return servingTLS{}, err
		}
		if len(m.cert) == 0 || len(m.key) == 0 {
			return servingTLS{}, fmt.Errorf("auth-config %s has no serving certificate/key", c.AuthConfig)
		}
		if u, perr := url.Parse(rc.Host); perr == nil {
			m.host = u.Host
		}
	case len(c.TLSCert) > 0:
		var err error
		if m.cert, err = os.ReadFile(c.TLSCert); err != nil {
			return servingTLS{}, err
		}
		if m.key, err = os.ReadFile(c.TLSKey); err != nil {
			return servingTLS{}, err
		}
		if len(c.TLSCA) > 0 {
			if m.ca, err = os.ReadFile(c.TLSCA); err != nil {
				return servingTLS{}, err
			}
		}
	}
	return m, nil
}

// BoltPath returns the filesystem path from the storage DSN, erroring unless the backend is bolt
// (the only one implemented). It accepts bolt:horchestra.db and bolt:///var/lib/x.db.
func (c Config) BoltPath() (string, error) {
	u, err := url.Parse(c.Storage)
	if err != nil {
		return "", fmt.Errorf("invalid --storage %q: %w", c.Storage, err)
	}
	if u.Scheme != "bolt" {
		return "", fmt.Errorf("unsupported storage backend %q (only bolt: is implemented)", u.Scheme)
	}
	// An authority-style DSN (bolt://var/lib/x.db) parses the first segment as the host and
	// would silently drop it; reject it so the path is never truncated.
	if u.Host != "" {
		return "", fmt.Errorf("--storage %q: bolt DSN takes no host authority (use bolt:<path> or bolt:///<abs-path>)", c.Storage)
	}
	path := u.Opaque
	if len(path) == 0 {
		path = u.Path
	}
	if len(path) == 0 {
		return "", fmt.Errorf("--storage %q has no path", c.Storage)
	}
	return path, nil
}

// NodeCertTTLDuration parses NodeCertTTL, returning 0 (the loop's default) when empty or invalid.
func (c Config) NodeCertTTLDuration() time.Duration {
	d, err := time.ParseDuration(c.NodeCertTTL)
	if err != nil {
		return 0
	}
	return d
}

// parseReadyTimeout parses the node-ready-timeout duration string, defaulting an empty value and
// rejecting non-positive durations.
func parseReadyTimeout(s string) (time.Duration, error) {
	if len(s) == 0 {
		return DefaultNodeReadyTimeout, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid node-ready-timeout %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("node-ready-timeout must be positive, got %q", s)
	}
	return d, nil
}

// pemOrFile returns inline PEM data when present, otherwise reads the referenced file — a
// client-go REST config carries the TLS material in either form.
func pemOrFile(data []byte, file string) ([]byte, error) {
	if len(data) > 0 {
		return data, nil
	}
	if len(file) > 0 {
		return os.ReadFile(file)
	}
	return nil, nil
}

// completeVaultPKI resolves the Vault-PKI signer from its flags, or leaves it nil.
//
// The two signing modes are refused together rather than ranked. The point of this one is
// that the controller holds NO CA key; a deployment that also passed --cluster-ca-key would
// be one where the key is on disk after all, and silently preferring either would make the
// guarantee depend on which branch a reader happens to find first.
func (c *Config) completeVaultPKI() error {
	if c.VaultPKIServer == "" {
		return nil
	}
	if len(c.ClusterCAKey) > 0 {
		return fmt.Errorf("--pki-vault and --cluster-ca-key are mutually exclusive: the point of signing through Vault is that no CA key is held here")
	}
	if c.VaultPKIRole == "" {
		return fmt.Errorf("--pki-vault-role is required with --pki-vault")
	}
	if c.VaultPKICert == "" || c.VaultPKIKey == "" {
		return fmt.Errorf("--pki-vault-cert and --pki-vault-key are required with --pki-vault: the controller authenticates to Vault as itself")
	}
	cfg := vaultpki.Config{
		Server:   c.VaultPKIServer,
		Mount:    c.VaultPKIMount,
		Role:     c.VaultPKIRole,
		AuthPath: c.VaultPKIAuthPath,
		AuthRole: c.VaultPKIAuthRole,
		CertFile: c.VaultPKICert,
		KeyFile:  c.VaultPKIKey,
		SelfRole: c.VaultPKISelfRole,
	}
	var err error
	if cfg.CertPEM, err = os.ReadFile(c.VaultPKICert); err != nil {
		return fmt.Errorf("--pki-vault-cert: %w", err)
	}
	if cfg.KeyPEM, err = os.ReadFile(c.VaultPKIKey); err != nil {
		return fmt.Errorf("--pki-vault-key: %w", err)
	}
	if c.VaultPKICA != "" {
		if cfg.CABundle, err = os.ReadFile(c.VaultPKICA); err != nil {
			return fmt.Errorf("--pki-vault-ca: %w", err)
		}
	}
	c.VaultPKI = &cfg
	return nil
}
