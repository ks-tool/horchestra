package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/apiserver"
	"github.com/ks-tool/horchestra/apiserver/admission"
	"github.com/ks-tool/horchestra/apiserver/internal/memory"
	"github.com/ks-tool/horchestra/apiserver/service"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testServer is a running APIServer over a real HTTP listener, backed by an
// in-memory fake store. Everything is torn down when the test finishes.
type testServer struct {
	*httptest.Server
	t *testing.T
}

func startServer(t *testing.T) *testServer {
	t.Helper()
	sch := scheme.New()
	corev1.AddToScheme(sch)
	rbacv1.AddToScheme(sch)

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	api := apiserver.New(sch, service.New(store, sch, admission.DefaultChain(nil)))
	api.EmulatePodsAPI()

	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return &testServer{Server: srv, t: t}
}

// do performs an HTTP request against the server and returns the status code and
// response body.
func (s *testServer) do(method, path, contentType string, body []byte) (int, []byte) {
	s.t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, s.URL+path, r)
	if err != nil {
		s.t.Fatalf("new request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, b
}

func (s *testServer) get(path string) (int, []byte) { return s.do(http.MethodGet, path, "", nil) }
func (s *testServer) del(path string) (int, []byte) { return s.do(http.MethodDelete, path, "", nil) }

func (s *testServer) create(path string, obj any) (int, []byte) {
	return s.do(http.MethodPost, path, "application/json", mustJSON(s.t, obj))
}

func (s *testServer) put(path string, obj any) (int, []byte) {
	return s.do(http.MethodPut, path, "application/json", mustJSON(s.t, obj))
}

func (s *testServer) merge(path, patch string) (int, []byte) {
	return s.do(http.MethodPatch, path, "application/merge-patch+json", []byte(patch))
}

// getInto GETs path and, on 200, decodes the body into out. Returns the status.
func (s *testServer) getInto(path string, out any) int {
	code, b := s.get(path)
	if code == http.StatusOK && out != nil {
		decode(s.t, b, out)
	}
	return code
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func decode(t *testing.T, b []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

func resourcePath(group, version, plural, name string) string {
	p := "/apis/" + group + "/" + version + "/" + plural
	if name != "" {
		p += "/" + name
	}
	return p
}

func appPath(name string) string  { return resourcePath("horchestra.io", "v1", "applications", name) }
func nodePath(name string) string { return resourcePath("horchestra.io", "v1", "nodes", name) }
func pvPath(name string) string {
	return resourcePath("horchestra.io", "v1", "persistentvolumes", name)
}
func rolePath(name string) string { return resourcePath("rbac.horchestra.io", "v1", "roles", name) }
func rbPath(name string) string {
	return resourcePath("rbac.horchestra.io", "v1", "rolebindings", name)
}

func labeledApp(name, image string, labels map[string]string) *corev1.Application {
	a := newApp(name, "n1", image)
	a.Labels = labels
	return a
}

func newApp(name, node, image string) *corev1.Application {
	return &corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.ApplicationSpec{NodeName: node, Image: image},
	}
}
