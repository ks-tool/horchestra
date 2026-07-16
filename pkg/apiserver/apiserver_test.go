package apiserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/admission"
	"ks-tool.dev/horchestra/pkg/service"
	"ks-tool.dev/horchestra/pkg/storage/bolt"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	store, err := bolt.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return New(service.New(store, admission.DefaultChain(store)), v1.BaseResources, 0, nil)
}

// TestKubectlSurface exercises the discovery + REST surface kubectl relies on
// over HTTP: /api, create, merge-patch (kubectl apply/edit), and the discovery
// fields (patch verb, namespaced=false, short names).
func TestKubectlSurface(t *testing.T) {
	srv := httptest.NewServer(newTestServer(t))
	defer srv.Close()
	c := srv.Client()

	// kubectl probes the legacy core group first.
	resp, err := c.Get(srv.URL + "/api")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api: err=%v status=%v", err, resp.StatusCode)
	}
	var versions metav1.APIVersions
	decode(t, resp, &versions)
	if versions.Kind != "APIVersions" {
		t.Fatalf("GET /api kind = %q", versions.Kind)
	}

	// The node an application pins to must exist (nodeExists admission), so register
	// it first.
	nodesURL := srv.URL + "/apis/orch.ks-tool.dev/v1/nodes"
	resp, err = c.Post(nodesURL, "application/json",
		strings.NewReader(`{"apiVersion":"orch.ks-tool.dev/v1","kind":"Node","metadata":{"name":"n1"}}`))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST node: err=%v status=%v", err, resp.StatusCode)
	}
	_ = resp.Body.Close()

	appsURL := srv.URL + "/apis/orch.ks-tool.dev/v1/applications"
	create := `{"apiVersion":"orch.ks-tool.dev/v1","kind":"Application","metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1"}}`
	resp, err = c.Post(appsURL, "application/json", strings.NewReader(create))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST application: err=%v status=%v", err, resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Default() ran server-side: the stored object carries restartPolicy=Always
	// even though the request omitted it.
	resp, err = c.Get(appsURL + "/demo")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET application: err=%v status=%v", err, resp.StatusCode)
	}
	var created map[string]any
	decode(t, resp, &created)
	if rp := created["spec"].(map[string]any)["restartPolicy"]; rp != "Always" {
		t.Fatalf("defaulted restartPolicy = %v, want Always", rp)
	}

	// Merge-patch the image, as `kubectl apply`/`edit` would.
	req, _ := http.NewRequest(http.MethodPatch, appsURL+"/demo", strings.NewReader(`{"spec":{"image":"reg/app:v2"}}`))
	req.Header.Set("Content-Type", "application/merge-patch+json")
	resp, err = c.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH application: err=%v status=%v", err, resp.StatusCode)
	}
	var obj map[string]any
	decode(t, resp, &obj)
	if got := obj["spec"].(map[string]any)["image"]; got != "reg/app:v2" {
		t.Fatalf("patched image = %v", got)
	}

	// A media-type parameter on the Content-Type must not mis-route the patch.
	req, _ = http.NewRequest(http.MethodPatch, appsURL+"/demo", strings.NewReader(`{"spec":{"image":"reg/app:v3"}}`))
	req.Header.Set("Content-Type", "application/merge-patch+json; charset=utf-8")
	resp, err = c.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH with charset param: err=%v status=%v", err, resp.StatusCode)
	}
	_ = resp.Body.Close()

	// An unsupported patch type is rejected with 415, as kube-apiserver does.
	req, _ = http.NewRequest(http.MethodPatch, appsURL+"/demo", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	resp, err = c.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("PATCH strategic-merge: err=%v status=%v (want 415)", err, resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Discovery advertises the patch verb, cluster scope, and short names.
	resp, err = c.Get(srv.URL + "/apis/orch.ks-tool.dev/v1")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET apiresourcelist: err=%v status=%v", err, resp.StatusCode)
	}
	var rl metav1.APIResourceList
	decode(t, resp, &rl)
	var app *metav1.APIResource
	for i := range rl.APIResources {
		if rl.APIResources[i].Name == "applications" {
			app = &rl.APIResources[i]
		}
	}
	if app == nil {
		t.Fatal("applications not in discovery")
	}
	if app.Namespaced {
		t.Error("applications should be cluster-scoped")
	}
	if !contains(app.Verbs, "patch") {
		t.Errorf("verbs missing patch: %v", app.Verbs)
	}
	if !contains(app.ShortNames, "app") {
		t.Errorf("short names missing app: %v", app.ShortNames)
	}
	if app.SingularName != "application" {
		t.Errorf("singular = %q", app.SingularName)
	}
}

func decode(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode %T: %v (body: %s)", v, err, body)
	}
}
