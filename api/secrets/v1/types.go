// Package v1 defines the external secret-store Kinds: a SecretStore holds the connection
// info for a Vault/OpenBao server — where it is and how a node authenticates to it — and
// never a secret value. A Secret of type horchestra.io/vault names a store; the node
// fetches the value from it directly, so the control plane stays out of the value path.
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Auth method discriminators.
const (
	// AuthMethodCert authenticates with the node's mTLS client certificate (the cluster
	// identity Vault is configured to trust) via POST /v1/auth/<path>/login. The default.
	AuthMethodCert = "cert"
	// AuthMethodKubernetes authenticates with the controller-minted workload-identity
	// token via Vault's stock kubernetes auth method: Vault calls the controller's
	// TokenReview endpoint (kubernetes_host = the controller URL) to validate it LIVE,
	// and roles bind plain service-account names/namespaces — per-workload
	// authorization, and the login path when Vault does not trust the cluster CA.
	AuthMethodKubernetes = "kubernetes"
)

// SecretStore is a namespaced reference to an external Vault/OpenBao server. It carries
// connection and authentication configuration only — no value ever rests in it, so a
// control-plane compromise leaks addresses and paths, never secrets.
type SecretStore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec SecretStoreSpec `json:"spec"`
}

// SecretStoreSpec is the "where and how to reach Vault": server, KV mount and the auth
// method a node uses to authenticate as itself.
type SecretStoreSpec struct {
	// Provider documents which implementation the server runs (vault or openbao). The two
	// speak the same API, so the built-in client is one implementation; the field records
	// intent. Optional.
	Provider string `json:"provider,omitempty"`
	// Server is the base URL, e.g. https://vault.example.com:8200.
	Server string `json:"server"`
	// Mount is the KV secrets-engine mount path (default "secret").
	Mount string `json:"mount,omitempty"`
	// KVVersion selects the KV engine API (1 or 2; default 2).
	KVVersion int `json:"kvVersion,omitempty"`
	// VaultNamespace is sent as X-Vault-Namespace (Vault Enterprise namespacing). Optional.
	VaultNamespace string `json:"vaultNamespace,omitempty"`
	// CABundle verifies the server's TLS certificate (PEM). Empty means the system roots.
	CABundle []byte `json:"caBundle,omitempty"`
	// Auth is how a node authenticates to the server (cert by default).
	Auth SecretStoreAuth `json:"auth,omitempty"`
}

// SecretStoreAuth selects and parameterizes the authentication method. It carries no
// credential: the cert method reuses the node's existing client certificate.
type SecretStoreAuth struct {
	// Method is the auth method (AuthMethodCert; empty defaults to cert).
	Method string `json:"method,omitempty"`
	// Path is the auth engine mount path when it differs from the method name.
	Path string `json:"path,omitempty"`
	// Role names the server-side role to log in against (e.g. a named cert role). Optional.
	Role string `json:"role,omitempty"`
}

// SecretStoreList is a list of SecretStores.
type SecretStoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []SecretStore `json:"items"`
}
