package authn

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/oidc"
)

// TestConsulTokenHeaderIsAccepted: the catalog speaks Consul's HTTP API, and a Consul client sends
// its credential in X-Consul-Token with no way to send it in another header — Traefik's
// endpoint.token, CONSUL_HTTP_TOKEN, the Go client's Config.Token all land there. Serving the
// catalog while refusing the only credential its clients can present would be an API nobody could
// authenticate against.
func TestConsulTokenHeaderIsAccepted(t *testing.T) {
	c := Chain{Tokens: map[string]Identity{"s3cret": {Name: "prometheus"}}}

	req := httptest.NewRequest(http.MethodGet, "/servicediscovery/v1/catalog/services", nil)
	req.Header.Set("X-Consul-Token", "s3cret")
	id, err := c.Authenticate(req)
	if err != nil {
		t.Fatalf("X-Consul-Token was refused: %v", err)
	}
	if id.Name != "prometheus" {
		t.Errorf("identity = %q, want the token's own", id.Name)
	}
	// It is the same table, not a second way in: an unknown token is unknown in either header.
	req.Header.Set("X-Consul-Token", "guess")
	if _, err := c.Authenticate(req); err == nil {
		t.Error("an unknown token authenticated through the Consul header")
	}
	// And Authorization still wins where both are present, so nothing about the existing path
	// changed shape.
	req.Header.Set("Authorization", "Bearer s3cret")
	if _, err := c.Authenticate(req); err != nil {
		t.Errorf("the Authorization header stopped working: %v", err)
	}
}

// fakeVerifier stands in for the issuer: it verifies exactly one token and reports the claims it
// was built with.
type fakeVerifier struct {
	token  string
	claims *oidc.WorkloadClaims
}

func (f fakeVerifier) VerifyToken(tok string) (*oidc.WorkloadClaims, error) {
	if tok != f.token {
		return nil, errors.New("not this issuer's token")
	}
	return f.claims, nil
}

func withToken(tok string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/servicediscovery/v1/catalog/services", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

// TestAWorkloadAuthenticatesAsItself: the edge reads the catalog with the token the agent mounted
// for it, and it is a caller with a name — not a shared secret somebody put in a config file.
func TestAWorkloadAuthenticatesAsItself(t *testing.T) {
	chain := Chain{Workloads: fakeVerifier{token: "jwt", claims: &oidc.WorkloadClaims{
		Namespace: "team-a", Name: "edge", Audiences: []string{corev1.TokenAudienceAPI},
	}}}
	id, err := chain.Authenticate(withToken("jwt"))
	if err != nil {
		t.Fatalf("a valid workload token was refused: %v", err)
	}
	if id.Name != "system:workload:team-a:edge" {
		t.Errorf("user = %q, want the namespaced workload principal", id.Name)
	}
	if len(id.Groups) != 1 || id.Groups[0] != WorkloadGroup {
		t.Errorf("groups = %v, want %q", id.Groups, WorkloadGroup)
	}
}

// TestAVaultTokenIsNotAnAPICredential is the whole of the audience separation: the same issuer
// signs both, so this token VERIFIES here — and must still not authenticate, or a credential handed
// out to log in somewhere else would silently become a credential at this API.
func TestAVaultTokenIsNotAnAPICredential(t *testing.T) {
	chain := Chain{Workloads: fakeVerifier{token: "jwt", claims: &oidc.WorkloadClaims{
		Namespace: "team-a", Name: "edge", Audiences: []string{corev1.TokenAudienceVault},
	}}}
	if _, err := chain.Authenticate(withToken("jwt")); err == nil {
		t.Fatal("a Vault-audience token authenticated at the API")
	}
}

// TestAnUnknownTokenIsNobody: a token this issuer did not mint buys nothing, and the X-Consul-Token
// header is the same table and the same answer.
func TestAnUnknownTokenIsNobody(t *testing.T) {
	chain := Chain{Workloads: fakeVerifier{token: "jwt", claims: &oidc.WorkloadClaims{
		Namespace: "team-a", Name: "edge", Audiences: []string{corev1.TokenAudienceAPI},
	}}}
	if _, err := chain.Authenticate(withToken("forged")); err == nil {
		t.Fatal("a token the issuer never minted authenticated")
	}
	r := httptest.NewRequest(http.MethodGet, "/servicediscovery/v1/catalog/services", nil)
	r.Header.Set("X-Consul-Token", "jwt")
	if _, err := chain.Authenticate(r); err != nil {
		t.Errorf("the header a Consul client sends was not read: %v", err)
	}
}
