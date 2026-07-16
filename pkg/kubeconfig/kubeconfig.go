// Package kubeconfig reads and writes the subset of the kubectl config schema
// that horchestra uses: a single cluster/user/context triple with the CA,
// client (or serving) certificate and key embedded. sigs.k8s.io/yaml base64-
// encodes the byte fields into the *-data keys, so files round-trip through
// Marshal/Load unchanged.
package kubeconfig

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

type Config struct {
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	CurrentContext string         `json:"current-context"`
	Clusters       []NamedCluster `json:"clusters"`
	Users          []NamedUser    `json:"users"`
	Contexts       []NamedContext `json:"contexts"`
}

type NamedCluster struct {
	Name    string  `json:"name"`
	Cluster Cluster `json:"cluster"`
}

type Cluster struct {
	Server                   string `json:"server"`
	CertificateAuthorityData []byte `json:"certificate-authority-data,omitempty"`
}

type NamedUser struct {
	Name string `json:"name"`
	User User   `json:"user"`
}

type User struct {
	ClientCertificateData []byte `json:"client-certificate-data,omitempty"`
	ClientKeyData         []byte `json:"client-key-data,omitempty"`
}

type NamedContext struct {
	Name    string  `json:"name"`
	Context Context `json:"context"`
}

type Context struct {
	Cluster string `json:"cluster"`
	User    string `json:"user"`
}

// New builds a single-context kubeconfig. The context and cluster share the
// cluster name; user names the credential. The certificate/key are the client
// identity for a kubectl kubeconfig, or the serving identity for the controller
// kubeconfig — the schema is the same.
func New(cluster, user, server string, caPEM, certPEM, keyPEM []byte) *Config {
	return &Config{
		APIVersion:     "v1",
		Kind:           "Config",
		CurrentContext: cluster,
		Clusters:       []NamedCluster{{Name: cluster, Cluster: Cluster{Server: server, CertificateAuthorityData: caPEM}}},
		Users:          []NamedUser{{Name: user, User: User{ClientCertificateData: certPEM, ClientKeyData: keyPEM}}},
		Contexts:       []NamedContext{{Name: cluster, Context: Context{Cluster: cluster, User: user}}},
	}
}

func (c *Config) Marshal() ([]byte, error) { return yaml.Marshal(c) }

// Load parses a kubeconfig file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse kubeconfig %s: %w", path, err)
	}
	return &c, nil
}

// Current resolves the cluster and user referenced by current-context.
func (c *Config) Current() (Cluster, User, error) {
	var ctx *Context
	for i := range c.Contexts {
		if c.Contexts[i].Name == c.CurrentContext {
			ctx = &c.Contexts[i].Context
			break
		}
	}
	if ctx == nil {
		return Cluster{}, User{}, fmt.Errorf("kubeconfig: current-context %q not found", c.CurrentContext)
	}
	var (
		cl *Cluster
		us *User
	)
	for i := range c.Clusters {
		if c.Clusters[i].Name == ctx.Cluster {
			cl = &c.Clusters[i].Cluster
			break
		}
	}
	for i := range c.Users {
		if c.Users[i].Name == ctx.User {
			us = &c.Users[i].User
			break
		}
	}
	if cl == nil {
		return Cluster{}, User{}, fmt.Errorf("kubeconfig: cluster %q not found", ctx.Cluster)
	}
	if us == nil {
		return Cluster{}, User{}, fmt.Errorf("kubeconfig: user %q not found", ctx.User)
	}
	return *cl, *us, nil
}
