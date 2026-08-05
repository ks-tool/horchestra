package authn

import (
	"crypto/tls"
	"errors"
	"net/http"
	"slices"
	"strings"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/oidc"
)

type Identity struct {
	Name   string
	Groups []string
}

type Authenticator interface {
	Authenticate(r *http.Request) (*Identity, error)
}

var ErrUnauthenticated = errors.New("no valid credentials")

// WorkloadVerifier checks a token this control plane minted for one of its own workloads and
// reports what it claims. controller/oidc's Issuer — the same one that mints the tokens pushed to
// the nodes — satisfies it.
type WorkloadVerifier interface {
	VerifyToken(token string) (*oidc.WorkloadClaims, error)
}

type Chain struct {
	Tokens map[string]Identity
	// Workloads, when set, admits a workload's own projected identity token as a caller. It is
	// how an edge reads the catalog: the workload presents the token the agent mounted for it,
	// and it authenticates as itself rather than as a shared secret somebody put in a config file.
	Workloads WorkloadVerifier
}

func (c Chain) Authenticate(r *http.Request) (*Identity, error) {
	if id := identityFromClientCert(r.TLS); id != nil {
		return id, nil
	}
	if tok := bearerToken(r); tok != "" {
		if id, ok := c.Tokens[tok]; ok {
			return &Identity{Name: id.Name, Groups: id.Groups}, nil
		}
		if id := c.workloadIdentity(tok); id != nil {
			return id, nil
		}
	}
	return nil, ErrUnauthenticated
}

// WorkloadGroup is every workload authenticated by its own projected token. A grant to the group
// reaches all of them, which is why it is worth almost never granting: the useful rule names the
// one workload that needs the right.
const WorkloadGroup = "system:workloads"

// WorkloadUser is what one workload authenticates AS. The form mirrors the certificate identities
// beside it — a namespaced principal, readable in an RBAC rule and in a log — and it is
// deliberately not the token's own `sub` claim, which is spelled as a Kubernetes service account
// so that Vault's stock auth method accepts it. Two audiences, two vocabularies; this is ours.
func WorkloadUser(namespace, name string) string {
	return "system:workload:" + namespace + ":" + name
}

// workloadIdentity admits a token this control plane minted FOR THIS API. The audience check is
// the whole of the separation: a workload's Vault token verifies here too — same issuer, same key —
// and accepting it would mean a credential handed out to log in somewhere else silently became a
// credential here.
func (c Chain) workloadIdentity(token string) *Identity {
	if c.Workloads == nil {
		return nil
	}
	claims, err := c.Workloads.VerifyToken(token)
	if err != nil || !slices.Contains(claims.Audiences, corev1.TokenAudienceAPI) {
		return nil
	}
	if claims.Namespace == "" || claims.Name == "" {
		return nil
	}
	return &Identity{Name: WorkloadUser(claims.Namespace, claims.Name), Groups: []string{WorkloadGroup}}
}

// bearerToken is the caller's token from either header it may arrive in.
//
// X-Consul-Token is here because the service-discovery catalog speaks Consul's HTTP API, and a
// Consul client sends its credential in that header and offers no way to send it in another —
// `endpoint.token` in Traefik, `CONSUL_HTTP_TOKEN` in the CLI, `Config.Token` in the Go client.
// Serving the catalog while refusing the only credential its clients can present would be an API
// nobody could authenticate against. It is the same secret checked the same way, not a second
// authentication path: one header or the other, one table.
func bearerToken(r *http.Request) string {
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return tok
	}
	return r.Header.Get("X-Consul-Token")
}

// identityFromClientCert maps a verified client certificate's CN to the user
// name and its Organization values to groups.
func identityFromClientCert(cs *tls.ConnectionState) *Identity {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return nil
	}
	leaf := cs.VerifiedChains[0][0]
	if len(leaf.Subject.CommonName) == 0 {
		return nil
	}
	return &Identity{Name: leaf.Subject.CommonName, Groups: leaf.Subject.Organization}
}
