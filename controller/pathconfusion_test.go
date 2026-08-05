package apiserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/admission"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
	"github.com/ks-tool/horchestra/controller/internal/memory"
	"github.com/ks-tool/horchestra/controller/service"

	"github.com/uptrace/bunrouter"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var nsWidgetGVK = schema.GroupVersionKind{Group: "test.horchestra.io", Version: "v1", Kind: "NsWidget"}

func newNamespacedServer(t *testing.T) *APIServer {
	t.Helper()
	sch := scheme.New()
	sch.AddResource(nsWidgetGVK, func() types.Object { return new(widget) },
		scheme.Resource{Plural: "nswidgets", Namespaced: true})
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	return New(sch, service.New(store, sch, admission.DefaultChain(nil, nil)))
}

// TestEncodedPathRejected: a request-URI carrying percent-encoded path characters is
// refused before routing. It is the guard for the routing/authorization split-brain —
// bunrouter dispatches on the raw path while the authorizer parses the decoded one, so a
// %2F would let the two disagree about which namespace is addressed.
func TestEncodedPathRejected(t *testing.T) {
	s := newNamespacedServer(t)

	cases := []struct {
		name string
		path string
		want int
	}{
		{
			name: "canonical path is served",
			path: "/apis/test.horchestra.io/v1/namespaces/team-a/nswidgets",
			want: http.StatusOK,
		},
		{
			name: "encoded separators in the filler version segment",
			path: "/apis/test.horchestra.io/v1%2Fnamespaces%2Fmine%2Fnswidgets%2Fx/namespaces/victim/nswidgets/db",
			want: http.StatusBadRequest,
		},
		{
			name: "encoded separator in the namespace segment",
			path: "/apis/test.horchestra.io/v1/namespaces/team-a%2Fnswidgets%2Fx/nswidgets",
			want: http.StatusBadRequest,
		},
		{
			name: "encoded ordinary character",
			path: "/apis/test.horchestra.io/v1/namespaces/te%61m-a/nswidgets",
			want: http.StatusBadRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doReq(t, s, http.MethodGet, tc.path, "", "")
			if w.Code != tc.want {
				t.Fatalf("GET %s = %d, want %d (body=%s)", tc.path, w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestAuthzAndRouterAgreeOnNamespace locks the invariant the guard exists to protect: for
// every request the server accepts, the namespace/name the authorizer decides on are the
// same ones the router dispatches to. A regression here means a permission is checked
// against one object while another is served.
func TestAuthzAndRouterAgreeOnNamespace(t *testing.T) {
	paths := []string{
		"/apis/test.horchestra.io/v1/namespaces/team-a/nswidgets/db",
		"/apis/test.horchestra.io/v1%2Fnamespaces%2Fmine%2Fnswidgets%2Fx/namespaces/victim/nswidgets/db",
		"/apis/test.horchestra.io/v1/namespaces/team-a%2Fx/nswidgets/db",
	}

	router := bunrouter.New()
	var gotNS, gotName string
	gv := router.NewGroup("/apis/:group/:version")
	gv.WithGroup("/namespaces/:namespace/nswidgets", func(gr *bunrouter.Group) {
		gr.GET("/:name", func(_ http.ResponseWriter, req bunrouter.Request) error {
			gotNS, gotName = req.Param("namespace"), req.Param("name")
			return nil
		})
	})

	id := &authn.Identity{Name: "alice"}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		if err := rejectEncodedPath(req); err != nil {
			continue // refused at the edge; the two views can no longer diverge
		}
		gotNS, gotName = "", ""
		router.ServeHTTP(httptest.NewRecorder(), req)
		at := authz.AttributesFromRequest(req, id)
		if at.Namespace != gotNS || at.Name != gotName {
			t.Fatalf("split brain on %s: authorized {ns=%q name=%q} but routed {ns=%q name=%q}",
				p, at.Namespace, at.Name, gotNS, gotName)
		}
	}
}
