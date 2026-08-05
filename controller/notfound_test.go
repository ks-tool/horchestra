package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/controller/admission"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
	"github.com/ks-tool/horchestra/controller/internal/memory"
	"github.com/ks-tool/horchestra/controller/service"

	"github.com/uptrace/bunrouter"
)

// denyAll refuses everything, standing in for the authorizer a caller with no rights meets.
type denyAll struct{}

func (denyAll) Authorize(_ context.Context, _ authz.Attributes) (bool, error) { return false, nil }

// fixedAuthn is an authenticator that always answers the same way.
type fixedAuthn struct {
	id  *authn.Identity
	err error
}

func (a fixedAuthn) Authenticate(*http.Request) (*authn.Identity, error) { return a.id, a.err }

func notFoundServer(t *testing.T, a authn.Authenticator) *APIServer {
	t.Helper()
	sch := scheme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	srv := New(sch, service.New(store, sch, admission.DefaultChain(nil, nil)),
		Auth(a), Authz(denyAll{}))
	srv.SetAuthenticator(a)
	return srv
}

// TestUnroutedPathIs404ForAnAuthenticatedCaller is the rule the whole arrangement exists for:
// a path no route serves is "there is nothing there", not "you may not". bunrouter resolves the
// route BEFORE the middleware runs, so the not-found handler used to be wrapped by an authorizer
// with nothing to authorize — it refused, as it must for a path no rule can name, and every typo
// came back 403. The authorizer here denies everything, and the answer must still be 404.
func TestUnroutedPathIs404ForAnAuthenticatedCaller(t *testing.T) {
	srv := notFoundServer(t, fixedAuthn{id: &authn.Identity{Name: "bob"}})

	for _, path := range []string{"/nonsense", "/apis/horchestra.io/v1/widgets", "/metrics/debug"} {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (body=%s)", path, w.Code, w.Body.String())
		}
		var status map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			t.Fatalf("GET %s: body is not a Status: %v (%s)", path, err, w.Body.String())
		}
		if status["reason"] != "NotFound" || status["kind"] != "Status" {
			t.Errorf("GET %s: body = %s, want a v1.Status with reason NotFound", path, w.Body.String())
		}
	}
}

// TestUnroutedPathIs401ForAnAnonymousCaller: the not-found handler sits outside the middleware
// chain, so nothing else on that path would ever check who is asking — and whether a path exists
// is information about the server. It authenticates for itself.
func TestUnroutedPathIs401ForAnAnonymousCaller(t *testing.T) {
	srv := notFoundServer(t, fixedAuthn{err: fmt.Errorf("no client certificate")})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nonsense", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /nonsense = %d, want 401 (body=%s)", w.Code, w.Body.String())
	}
}

// TestRoutedPathsStillRunTheChain: moving the not-found handler out of the middleware stack must
// not move anything else out of it. A path that IS routed still meets the authorizer.
func TestRoutedPathsStillRunTheChain(t *testing.T) {
	srv := notFoundServer(t, fixedAuthn{id: &authn.Identity{Name: "bob"}})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apis/horchestra.io/v1/namespaces/team-a/applications", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET a routed path with a denying authorizer = %d, want 403 (body=%s)", w.Code, w.Body.String())
	}
}

// TestNotFoundHandlerIsUnwrapped pins the registration order New depends on: bunrouter binds the
// not-found handler to the middleware stack that exists when WithNotFoundHandler is applied, so
// declaring it after Use would silently put it back inside the chain and restore the 403.
func TestNotFoundHandlerIsUnwrapped(t *testing.T) {
	ran := false
	mw := func(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
		return func(w http.ResponseWriter, req bunrouter.Request) error {
			ran = true
			return next(w, req)
		}
	}
	sch := scheme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	srv := New(sch, service.New(store, sch, admission.DefaultChain(nil, nil)), mw)

	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nonsense", nil))
	if ran {
		t.Error("the middleware chain wrapped the not-found handler — WithNotFoundHandler must be applied before Use")
	}
}
