package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestNodeLogsAreUnreachableWithoutTheGate is the whole security property of this feature, and it
// is enforced by the ROUTE not existing rather than by a check inside a handler. A node's journal
// is the log of the process that runs every workload on that host — an operator's object, not a
// tenant's — so with the gate off there must be no path to it at all, not a path that says no.
//
// The 404 also means the gate cannot be probed: it is the router's ordinary answer for an unknown
// path, so asking about a node tells a caller nothing about whether that node exists.
func TestNodeLogsAreUnreachableWithoutTheGate(t *testing.T) {
	srv, _ := newPodsServer(t, nil) // EnableNodeLogs is NOT called: the gate is off
	w := doReqAs(t, srv, nil, "/apis/horchestra.io/v1/nodes/node-1/log")
	if w.Code != http.StatusNotFound {
		t.Errorf("node log route answered %d with the gate off; it must not exist", w.Code)
	}
}

// TestNodeLogsStreamWhenGated: with the gate on the route streams the agent's unit journal, and it
// resolves the Node first, so an unknown name is a 404 rather than a stream to nowhere.
func TestNodeLogsStreamWhenGated(t *testing.T) {
	srv, logs := newPodsServer(t, nil)
	srv.EnableNodeLogs()
	seedNodeObject(t, srv, "node-1")

	w := doReqAs(t, srv, nil, "/apis/horchestra.io/v1/nodes/node-1/log")
	if w.Code != http.StatusOK {
		t.Fatalf("node log = %d, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "agent unit line") {
		t.Errorf("body = %q, want the agent's journal", w.Body.String())
	}
	// The workload path is untouched: a node log stream must never be addressed as a workload.
	if got := strings.Join(logs.opened, ","); !strings.Contains(got, "node/node-1") {
		t.Errorf("streams opened = %q, want the node-unit stream", got)
	}

	if w := doReqAs(t, srv, nil, "/apis/horchestra.io/v1/nodes/nope/log"); w.Code != http.StatusNotFound {
		t.Errorf("unknown node = %d, want 404", w.Code)
	}
}

func seedNodeObject(t *testing.T, s *APIServer, name string) {
	t.Helper()
	data, err := json.Marshal(&corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.svc.Create(context.Background(), corev1.GroupVersion.WithKind("Node"), data, ""); err != nil {
		t.Fatalf("seed node %s: %v", name, err)
	}
}

// TestAnUnroutedPathAnswersWithAStatus: the not-found path has no error-rendering middleware in
// front of it, so a handler that RETURNS its error renders nothing and bunrouter falls back to its
// own plain-text `404 page not found`. A client cannot read that as an API answer and reports what
// it can make of it — "the server could not find the requested resource", cause
// UnexpectedServerResponse — which says the server is not speaking the protocol and sends the
// reader looking in the wrong place.
func TestAnUnroutedPathAnswersWithAStatus(t *testing.T) {
	srv, _ := newPodsServer(t, nil)
	w := doReqAs(t, srv, nil, "/apis/horchestra.io/v1/nodes/node-1/log") // gate off: unrouted
	if w.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("Content-Type = %q, want JSON — a plain-text 404 is not an API answer", ct)
	}
	var status struct {
		Kind, Status, Reason string
		Code                 int
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("body is not a Status: %v (%s)", err, w.Body.String())
	}
	if status.Kind != "Status" || status.Reason != "NotFound" || status.Code != 404 {
		t.Errorf("status = %+v, want a NotFound Status", status)
	}
}
