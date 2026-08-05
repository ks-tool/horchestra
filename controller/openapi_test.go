package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"

	"github.com/uptrace/bunrouter"
)

// openAPIServer returns a server serving one addressable Kind, with the routes wired as
// production wires them.
func openAPIServer(t *testing.T) *APIServer {
	t.Helper()
	sch := scheme.New()
	sch.AddResource(gvkOf(discGroup, "v1", "Widget"),
		func() types.Object { return &discoveryObj{} },
		scheme.Resource{Plural: "widgets", Namespaced: true})
	s := &APIServer{scheme: sch}
	s.router = bunrouter.New(bunrouter.WithNotFoundHandler(s.notFound))
	s.build()
	return s
}

func getJSON(t *testing.T, s *APIServer, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body is not JSON: %v", path, err)
		}
	}
	return rec.Code, body
}

// TestOpenAPIIndexPointsAtTheDocument: the index is a client's only way in — it names one
// document per group-version and the URL to fetch it at, and that URL has to actually serve.
func TestOpenAPIIndexPointsAtTheDocument(t *testing.T) {
	s := openAPIServer(t)

	code, index := getJSON(t, s, "/openapi/v3")
	if code != http.StatusOK {
		t.Fatalf("/openapi/v3 = %d, want 200", code)
	}
	paths, _ := index["paths"].(map[string]any)
	entry, _ := paths["apis/"+discGroup+"/v1"].(map[string]any)
	if entry == nil {
		t.Fatalf("index does not name the served group-version: %v", paths)
	}
	url, _ := entry["serverRelativeURL"].(string)
	if !strings.Contains(url, "hash=") {
		t.Errorf("serverRelativeURL carries no hash, so a client cannot cache it: %q", url)
	}

	code, doc := getJSON(t, s, url)
	if code != http.StatusOK {
		t.Fatalf("%s = %d, want 200 — the index pointed at a URL that does not serve", url, code)
	}
	comps, _ := doc["components"].(map[string]any)
	sch, _ := comps["schemas"].(map[string]any)
	if _, ok := sch["io.horchestra.orch.v1.Widget"]; !ok {
		t.Errorf("document carries no schema for the served Kind: %v", sch)
	}
}

// TestOpenAPIUnknownGroupVersionIs404: a group-version the server does not serve is absent, not
// an empty document that would tell a client its Kinds are schema-less.
func TestOpenAPIUnknownGroupVersionIs404(t *testing.T) {
	s := openAPIServer(t)
	if code, _ := getJSON(t, s, "/openapi/v3/apis/example.com/v1"); code != http.StatusNotFound {
		t.Errorf("unknown group-version = %d, want 404", code)
	}
}
