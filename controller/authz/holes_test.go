package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ks-tool/horchestra/controller/authn"
)

func attrsFor(t *testing.T, path string) Attributes {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	return AttributesFromRequest(req, &authn.Identity{Name: "bob"})
}

// TestSubresourceIsItsOwnPermission: the segment after an object's name used to be dropped,
// so every subresource inherited its parent's rule. That is wrong in the direction that
// matters — reading a Node is capacity and labels, reading its journal is other tenants'
// object names, node identities and SecretStore addresses — and the two must be grantable
// apart.
func TestSubresourceIsItsOwnPermission(t *testing.T) {
	at := attrsFor(t, "/apis/horchestra.io/v1/nodes/fedora-01/log")
	if at.Resource != "nodes" || at.Name != "fedora-01" {
		t.Fatalf("resource=%q name=%q", at.Resource, at.Name)
	}
	if at.Subresource != "log" {
		t.Fatalf("subresource = %q — the third segment was dropped", at.Subresource)
	}
	if at.Target() != "nodes/log" {
		t.Errorf("target = %q, want nodes/log — this is what a rule names", at.Target())
	}

	// The object itself is unaffected: a plain get still targets the resource.
	plain := attrsFor(t, "/apis/horchestra.io/v1/nodes/fedora-01")
	if plain.Subresource != "" || plain.Target() != "nodes" {
		t.Errorf("a plain object request grew a subresource: %+v", plain)
	}

	// Namespaced objects too, where the subresource sits one segment further along.
	ns := attrsFor(t, "/apis/horchestra.io/v1/namespaces/team-a/applications/web/status")
	if ns.Namespace != "team-a" || ns.Resource != "applications" || ns.Name != "web" || ns.Subresource != "status" {
		t.Errorf("namespaced subresource parsed as %+v", ns)
	}
}

// TestNodeAuthorizerDoesNotWidenToSubresources: the built-in Node grant exists so a machine
// can register and report itself. It is compared against the full target, so it cannot start
// carrying a subresource of the same object that nobody weighed — a node reports status over
// the gRPC session, not this path, so there is nothing it loses.
func TestNodeAuthorizerDoesNotWidenToSubresources(t *testing.T) {
	node := &authn.Identity{Name: "fedora-01", Groups: []string{NodeGroup}}
	own := Attributes{User: node, Group: "horchestra.io", Resource: "nodes", Verb: "get"}
	if !nodeAuthorizes(own) {
		t.Fatal("a node must still be able to read its own Node")
	}
	sub := own
	sub.Subresource = "log"
	if nodeAuthorizes(sub) {
		t.Error("the built-in node grant reaches a subresource it never named")
	}
}

// TestNonResourcePathsDefaultToDeny: the default used to be ALLOW — anything that was not
// /apis/{group}/{version}/... was served to whoever held a certificate. Nothing sensitive
// lived at such a path, so nothing leaked; but the next endpoint outside the resource tree
// would have been readable by the whole fleet on the day it landed, with no line of code
// saying so.
func TestNonResourcePathsDefaultToDeny(t *testing.T) {
	// What every authenticated caller gets, and what Kubernetes grants through
	// system:discovery: discovery and the schemas kubectl validates against.
	for _, path := range []string{
		"/api", "/api/v1", "/apis",
		"/apis/horchestra.io", "/apis/horchestra.io/v1",
		"/openapi", "/openapi/v3", "/openapi/v3/apis/horchestra.io/v1",
		"/api/v1/pods", "/api/v1/pods/web/log", // the alias authorizes itself, per namespace
		// `kubectl version` asks for this, and a first cut of the allowlist that left it out
		// turned a working command into "Error from server (Forbidden)".
		"/version", "/livez", "/readyz",
	} {
		if !AllowedNonResourcePath(path) {
			t.Errorf("%q must stay reachable: it is discovery, schemas, or the self-authorizing pods alias", path)
		}
	}
	// Everything else, including the endpoints this change exists to make safe. /healthz is on
	// the list too: it is served by the OUTER mux and never reaches this decision, so refusing
	// it here costs nothing and stops the allowlist from quietly becoming the place someone
	// adds an exception.
	for _, path := range []string{
		"/logs", "/logs/horchestra-controller", "/debug/pprof/",
		"/bootstrap/ca", "/healthz", "/", "/anything",
		// The exporter. It was on the allowlist, reachable by anyone with a certificate and
		// guarded only by a check its own handler made against a DIFFERENT permission; it is
		// now an ordinary nonResourceURLs grant.
		"/metrics",
	} {
		if AllowedNonResourcePath(path) {
			t.Errorf("%q is served to any authenticated caller with no rule behind it", path)
		}
	}
}

// TestUnroutedPathsAreRefused drives the decision the way the middleware does, so the
// allowlist is not merely a function nobody calls.
func TestUnroutedPathsAreRefused(t *testing.T) {
	cb, err := NewCasbin()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bob := &authn.Identity{Name: "bob"}

	for path, want := range map[string]bool{
		"/apis":    true,
		"/api/v1":  true,
		"/logs":    false,
		"/metrics": false, // no longer on the allowlist: it needs a nonResourceURLs rule
	} {
		at := AttributesFromRequest(httptest.NewRequest(http.MethodGet, path, nil), bob)
		ok, err := cb.Authorize(ctx, at)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if ok != want {
			t.Errorf("authorize(%s) = %v, want %v", path, ok, want)
		}
	}
}
