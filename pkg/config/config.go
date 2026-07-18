package config

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/spf13/pflag"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

// DefaultNodeReadyTimeout is how long a node's heartbeat may age before it is
// reported NotReady when the config leaves it unset.
const DefaultNodeReadyTimeout = 45 * time.Second

type Config struct {
	Addr        string   `json:"addr"`
	DBPath      string   `json:"dbPath"`
	DisableAuth bool     `json:"disableAuth"`
	Authorizer  string   `json:"authorizer"`
	AdminGroups []string `json:"adminGroups"`
	TLSCert     string   `json:"tlsCert"`
	TLSKey      string   `json:"tlsKey"`
	TLSCA       string   `json:"tlsCA"`
	AuthConfig  string   `json:"authConfig"`
	// NodeReadyTimeout is a Go duration string (e.g. "45s", "2m"): a node whose
	// heartbeat is older than this reads as NotReady in `kubectl get nodes`.
	NodeReadyTimeout string `json:"nodeReadyTimeout"`

	// ConfigFile is the path to a YAML config file (--config); it is layered under
	// the explicitly-set flags by Complete and is itself never read from a file.
	ConfigFile string `json:"-"`

	// Resolved TLS material (from AuthConfig or the TLS* files), in memory and
	// not serialized. Read through the accessor methods.
	certPEM []byte
	keyPEM  []byte
	caPEM   []byte
	// readyTimeout is NodeReadyTimeout parsed once by Complete.
	readyTimeout time.Duration
}

// Default returns the built-in configuration, before any file or flag overrides.
func Default() Config {
	return Config{
		Addr:             ":8443",
		DBPath:           "horchestra.db",
		Authorizer:       "rbac",
		AdminGroups:      []string{"system:masters"},
		NodeReadyTimeout: DefaultNodeReadyTimeout.String(),
	}
}

// AddFlags binds the controller flags to c on fs. Call it on a Config produced by
// Default so each flag's default matches the built-in configuration.
func (c *Config) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.Addr, "addr", c.Addr, "listen address")
	fs.StringVar(&c.DBPath, "db", c.DBPath, "BoltDB path")
	fs.BoolVar(&c.DisableAuth, "disable-auth", c.DisableAuth, "disable authentication and authorization")
	fs.StringVar(&c.Authorizer, "authorizer", c.Authorizer, "authorization engine: rbac (live) or casbin")
	fs.StringSliceVar(&c.AdminGroups, "admin-groups", c.AdminGroups, "admin groups (repeatable or comma-separated)")
	fs.StringVar(&c.TLSCert, "tls-cert", c.TLSCert, "server certificate for HTTPS")
	fs.StringVar(&c.TLSKey, "tls-key", c.TLSKey, "server private key")
	fs.StringVar(&c.TLSCA, "tls-ca", c.TLSCA, "CA that verifies client certificates (enables mTLS)")
	fs.StringVar(&c.AuthConfig, "auth-config", c.AuthConfig, "auth-config (kubeconfig) bundling the serving cert/key, client CA and address (from `node-tool init`)")
	fs.StringVar(&c.NodeReadyTimeout, "node-ready-timeout", c.NodeReadyTimeout, "how long a node's heartbeat may age before it reads NotReady (e.g. 45s, 2m)")
	fs.StringVar(&c.ConfigFile, "config", c.ConfigFile, "path to a YAML config file (overridden by explicit flags)")
}

// Complete layers a --config YAML file *under* the explicitly-set flags and
// finalizes the configuration: file values fill fields whose flag was not passed,
// flags that were passed win, then the ready timeout is parsed and the TLS
// material resolved. fs is the flag set AddFlags was called on — it tells which
// flags were set explicitly.
func (c *Config) Complete(fs *pflag.FlagSet) error {
	if len(c.ConfigFile) > 0 {
		file := Default()
		data, err := os.ReadFile(c.ConfigFile)
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(data, &file); err != nil {
			return err
		}
		// The file provides the base; a flag passed on the command line overrides
		// it. Unmarshalling over Default keeps a field the file omits at its default,
		// which then also matches the un-set flag's default — so nothing is wiped.
		for _, m := range []struct {
			name  string
			apply func()
		}{
			{"addr", func() { c.Addr = file.Addr }},
			{"db", func() { c.DBPath = file.DBPath }},
			{"disable-auth", func() { c.DisableAuth = file.DisableAuth }},
			{"authorizer", func() { c.Authorizer = file.Authorizer }},
			{"admin-groups", func() { c.AdminGroups = file.AdminGroups }},
			{"tls-cert", func() { c.TLSCert = file.TLSCert }},
			{"tls-key", func() { c.TLSKey = file.TLSKey }},
			{"tls-ca", func() { c.TLSCA = file.TLSCA }},
			{"auth-config", func() { c.AuthConfig = file.AuthConfig }},
			{"node-ready-timeout", func() { c.NodeReadyTimeout = file.NodeReadyTimeout }},
		} {
			if !fs.Changed(m.name) {
				m.apply()
			}
		}
	}
	readyTimeout, err := parseReadyTimeout(c.NodeReadyTimeout)
	if err != nil {
		return err
	}
	c.readyTimeout = readyTimeout
	// Let the auth-config's server URL set the bind address only when -addr was
	// left at its default.
	return c.resolveTLS(!fs.Changed("addr"))
}

// parseReadyTimeout parses the node-ready-timeout duration string, defaulting an
// empty value and rejecting non-positive durations.
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

// NodeReadyTimeoutDuration is the parsed node-ready timeout.
func (c Config) NodeReadyTimeoutDuration() time.Duration { return c.readyTimeout }

// resolveTLS loads the serving certificate, key and client CA into memory from
// the auth-config (preferred) or the individual -tls-* files. When the material
// comes from the auth-config (a kubeconfig) and the listen address was left at
// its default, deriveAddr lets its server URL set where the controller binds.
func (c *Config) resolveTLS(deriveAddr bool) error {
	switch {
	case len(c.AuthConfig) > 0:
		rc, err := clientcmd.BuildConfigFromFlags("", c.AuthConfig)
		if err != nil {
			return err
		}
		cert, err := pemOrFile(rc.TLSClientConfig.CertData, rc.TLSClientConfig.CertFile)
		if err != nil {
			return err
		}
		key, err := pemOrFile(rc.TLSClientConfig.KeyData, rc.TLSClientConfig.KeyFile)
		if err != nil {
			return err
		}
		ca, err := pemOrFile(rc.TLSClientConfig.CAData, rc.TLSClientConfig.CAFile)
		if err != nil {
			return err
		}
		if len(cert) == 0 || len(key) == 0 {
			return fmt.Errorf("auth-config %s has no serving certificate/key", c.AuthConfig)
		}
		c.certPEM, c.keyPEM, c.caPEM = cert, key, ca
		if deriveAddr && len(rc.Host) > 0 {
			if u, err := url.Parse(rc.Host); err == nil && len(u.Host) > 0 {
				c.Addr = u.Host
			}
		}
	case len(c.TLSCert) > 0:
		cert, err := os.ReadFile(c.TLSCert)
		if err != nil {
			return err
		}
		key, err := os.ReadFile(c.TLSKey)
		if err != nil {
			return err
		}
		c.certPEM, c.keyPEM = cert, key
		if len(c.TLSCA) > 0 {
			ca, err := os.ReadFile(c.TLSCA)
			if err != nil {
				return err
			}
			c.caPEM = ca
		}
	}
	return nil
}

// pemOrFile returns inline PEM data when present, otherwise reads the referenced
// file — a client-go REST config carries the TLS material in either form.
func pemOrFile(data []byte, file string) ([]byte, error) {
	if len(data) > 0 {
		return data, nil
	}
	if len(file) > 0 {
		return os.ReadFile(file)
	}
	return nil, nil
}

// TLSEnabled reports whether a serving certificate was configured (HTTPS).
func (c Config) TLSEnabled() bool { return len(c.certPEM) > 0 }

// ServingCertPEM, ServingKeyPEM and ClientCAPEM expose the resolved TLS material.
func (c Config) ServingCertPEM() []byte { return c.certPEM }
func (c Config) ServingKeyPEM() []byte  { return c.keyPEM }
func (c Config) ClientCAPEM() []byte    { return c.caPEM }
