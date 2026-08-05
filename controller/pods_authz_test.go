package apiserver

import (
	"context"
	"encoding/json"
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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// nsAuthorizer allows a verb on applications only in the namespaces it lists, mimicking a
// caller whose RoleBinding covers one namespace.
type nsAuthorizer struct {
	allowed map[string]bool
	calls   int
}

func (a *nsAuthorizer) Authorize(_ context.Context, at authz.Attributes) (bool, error) {
	a.calls++
	if !at.ResourceRequest || at.Resource != "applications" {
		return false, nil
	}
	return a.allowed[at.Namespace], nil
}

// recordingStreamer records every log stream that is actually opened, so a test can assert
// that an unauthorized request never reached the transport.
type recordingStreamer struct{ opened []string }

func (r *recordingStreamer) StreamNodeLogs(_ context.Context, node string, _ bool, _ int64) (<-chan []byte, func() error, error) {
	r.opened = append(r.opened, "node/"+node)
	ch := make(chan []byte, 1)
	ch <- []byte("agent unit line\n")
	close(ch)
	return ch, func() error { return nil }, nil
}

func (r *recordingStreamer) StreamLogs(_ context.Context, node, app string, _ bool, _ int64) (<-chan []byte, func() error, error) {
	r.opened = append(r.opened, node+"/"+app)
	ch := make(chan []byte, 1)
	ch <- []byte("secret log line\n")
	close(ch)
	return ch, func() error { return nil }, nil
}

func newPodsServer(t *testing.T, az authz.Authorizer) (*APIServer, *recordingStreamer) {
	t.Helper()
	sch := scheme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	logs := &recordingStreamer{}
	srv := New(sch, service.New(store, sch, admission.DefaultChain(nil, nil)))
	srv.EmulatePodsAPI()
	srv.SetLogStreamer(logs)
	if az != nil {
		srv.SetAuthorizer(az)
	}
	seedApp(t, srv, "team-a", "mine", "node-1")
	seedApp(t, srv, "team-b", "victim", "node-1")
	return srv, logs
}

// seedApp stores one Application pinned to node.
func seedApp(t *testing.T, s *APIServer, ns, name, node string) {
	t.Helper()
	data, err := json.Marshal(&corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.ApplicationSpec{Image: "example.com/app:v1", Placement: corev1.Placement{NodeName: node}},
	})
	if err != nil {
		t.Fatalf("marshal %s/%s: %v", ns, name, err)
	}
	if _, err := s.svc.Create(context.Background(), corev1.GroupVersion.WithKind("Application"), data, ns); err != nil {
		t.Fatalf("seed %s/%s: %v", ns, name, err)
	}
}

// TestPodsAliasIsAuthorized: the legacy /api/v1 pods alias is classified as a non-resource
// request by AttributesFromRequest and so is waved through by the Authz middleware — it must
// therefore authorize itself, per Application namespace. A caller permitted only in team-a
// must not list, resolve, or log-stream team-b's workload.
func TestPodsAliasIsAuthorized(t *testing.T) {
	az := &nsAuthorizer{allowed: map[string]bool{"team-a": true}}
	s, logs := newPodsServer(t, az)

	t.Run("list is scoped to the authorized namespace", func(t *testing.T) {
		w := doReq(t, s, http.MethodGet, "/api/v1/pods", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("list pods = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
		var got podList
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode podList: %v (body=%s)", err, w.Body.String())
		}
		if len(got.Items) != 1 || got.Items[0].Name != "mine" {
			t.Fatalf("pods = %+v, want exactly the team-a workload", got.Items)
		}
	})

	t.Run("another namespace's workload is not resolvable", func(t *testing.T) {
		w := doReq(t, s, http.MethodGet, "/api/v1/pods/victim", "", "")
		if w.Code != http.StatusNotFound {
			t.Fatalf("get pods/victim = %d, want 404 (body=%s)", w.Code, w.Body.String())
		}
	})

	t.Run("another namespace's logs are never streamed", func(t *testing.T) {
		w := doReq(t, s, http.MethodGet, "/api/v1/pods/victim/log", "", "")
		if w.Code != http.StatusNotFound {
			t.Fatalf("get pods/victim/log = %d, want 404 (body=%s)", w.Code, w.Body.String())
		}
		if len(logs.opened) != 0 {
			t.Fatalf("log stream opened for an unauthorized app: %v", logs.opened)
		}
	})

	t.Run("the caller's own workload still works", func(t *testing.T) {
		if w := doReq(t, s, http.MethodGet, "/api/v1/pods/mine", "", ""); w.Code != http.StatusOK {
			t.Fatalf("get pods/mine = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
		w := doReq(t, s, http.MethodGet, "/api/v1/pods/mine/log", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("get pods/mine/log = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
		if len(logs.opened) != 1 {
			t.Fatalf("opened log streams = %v, want exactly the team-a workload", logs.opened)
		}
	})
}

// TestPodsAliasDeniesEverythingWhenUnauthorized: with an authorizer that grants nothing, the
// alias must disclose nothing — not the workload list, and not whether a name exists.
func TestPodsAliasDeniesEverythingWhenUnauthorized(t *testing.T) {
	s, logs := newPodsServer(t, &nsAuthorizer{allowed: map[string]bool{}})

	w := doReq(t, s, http.MethodGet, "/api/v1/pods", "", "")
	var got podList
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode podList: %v", err)
	}
	if len(got.Items) != 0 {
		t.Fatalf("pods = %+v, want none", got.Items)
	}
	for _, p := range []string{"/api/v1/pods/mine", "/api/v1/pods/mine/log", "/api/v1/pods/victim/log"} {
		if w := doReq(t, s, http.MethodGet, p, "", ""); w.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", p, w.Code)
		}
	}
	if len(logs.opened) != 0 {
		t.Fatalf("log stream opened without authorization: %v", logs.opened)
	}
}

// TestPodsAliasConfinesNodeCallerToItsOwnNode: a node credential resolves and streams only the
// workloads placed on its own node. The alias opens the stream against the node named in the
// resolved OBJECT, so a node identity that may read Applications at all (here: an authorizer
// granting every namespace, as an operator-supplied RoleBinding would) would otherwise tap the
// live output of a workload on someone else's hardware.
func TestPodsAliasConfinesNodeCallerToItsOwnNode(t *testing.T) {
	s, logs := newPodsServer(t, &nsAuthorizer{allowed: map[string]bool{"team-a": true, "team-b": true}})
	seedApp(t, s, "team-b", "elsewhere", "node-2")
	node := &authn.Identity{Name: "node-1", Groups: []string{authz.NodeGroup}}

	t.Run("list shows only this node's workloads", func(t *testing.T) {
		w := doReqAs(t, s, node, "/api/v1/pods")
		var got podList
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode podList: %v (body=%s)", err, w.Body.String())
		}
		for _, p := range got.Items {
			if p.Spec.NodeName != "node-1" {
				t.Fatalf("pods = %+v, want only node-1's workloads", got.Items)
			}
		}
		if len(got.Items) != 2 {
			t.Fatalf("pods = %+v, want both node-1 workloads", got.Items)
		}
	})

	t.Run("another node's workload is not resolvable", func(t *testing.T) {
		if w := doReqAs(t, s, node, "/api/v1/pods/elsewhere"); w.Code != http.StatusNotFound {
			t.Fatalf("get pods/elsewhere = %d, want 404 (body=%s)", w.Code, w.Body.String())
		}
	})

	t.Run("another node's logs are never streamed", func(t *testing.T) {
		if w := doReqAs(t, s, node, "/api/v1/pods/elsewhere/log"); w.Code != http.StatusNotFound {
			t.Fatalf("get pods/elsewhere/log = %d, want 404 (body=%s)", w.Code, w.Body.String())
		}
		if len(logs.opened) != 0 {
			t.Fatalf("log stream opened on another node: %v", logs.opened)
		}
	})

	t.Run("its own node's workload still streams", func(t *testing.T) {
		if w := doReqAs(t, s, node, "/api/v1/pods/mine/log"); w.Code != http.StatusOK {
			t.Fatalf("get pods/mine/log = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
		if len(logs.opened) != 1 {
			t.Fatalf("opened log streams = %v, want exactly node-1's workload", logs.opened)
		}
	})
}

// doReqAs issues a GET carrying id as the authenticated identity.
func doReqAs(t *testing.T, s *APIServer, id *authn.Identity, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(authn.WithIdentity(context.Background(), id))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// TestPodsAliasWithoutAuthorizer: no authorizer wired keeps the alias fully
// open, matching the unset-nsFilter convention — the guard must not break local development.
func TestPodsAliasWithoutAuthorizer(t *testing.T) {
	s, _ := newPodsServer(t, nil)
	w := doReq(t, s, http.MethodGet, "/api/v1/pods", "", "")
	var got podList
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode podList: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("pods = %+v, want both workloads", got.Items)
	}
}
