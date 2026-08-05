package apiserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/controller/authn"
)

// TestUnidentifiedCallerIsRefused is what replaced the compiled bypass. There used to be a
// switch — a flag, then a constant — that swapped the authenticator for one which said yes to
// everybody; both are gone, and with them the type that answered yes. What guards the property
// now is the property itself: the identity path, wired exactly as the controller wires it,
// refuses a caller it cannot identify.
//
// A cert-less caller gets as far as the middleware because the serving TLS is
// VerifyClientCertIfGiven: the connection is accepted, the request is read, and only then is
// there anyone to ask who sent it. Every route is behind this — discovery and the OpenAPI
// documents included — so the answer for a caller carrying no identity is 401 everywhere.
func TestUnidentifiedCallerIsRefused(t *testing.T) {
	sch := scheme.New()
	corev1.AddToScheme(sch)
	// The server, with the middleware the controller composes it with.
	srv := New(sch, nil, Auth(authn.Chain{}))

	rec := httptest.NewRecorder()
	// No TLS state at all: no client certificate, and no bearer token either.
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/apis/horchestra.io/v1/namespaces/default/applications", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — body: %s", rec.Code, rec.Body.String())
	}
}

// TestBearerTokenIsNotAnIdentityPath: the Chain the controller builds registers no tokens, so a
// Bearer header cannot name anyone. A built-in token would be an unauthenticated system:masters
// backdoor, since the serving TLS lets a cert-less caller through to here.
func TestBearerTokenIsNotAnIdentityPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/apis/horchestra.io/v1/applications", nil)
	req.Header.Set("Authorization", "Bearer whatever")

	if _, err := (authn.Chain{}).Authenticate(req); err == nil {
		t.Fatal("a bearer token was accepted by the chain the controller wires")
	}
}
