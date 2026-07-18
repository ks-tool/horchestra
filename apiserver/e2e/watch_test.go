package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestApplication_Watch(t *testing.T) {
	s := startServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+appPath("")+"?watch=true", nil)
	if err != nil {
		t.Fatalf("new watch request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open watch: %v", err)
	}
	// Cancel the stream before closing the body so the server handler unwinds.
	defer resp.Body.Close()
	defer cancel()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("watch status = %d", resp.StatusCode)
	}
	dec := json.NewDecoder(resp.Body)

	// The subscription is registered by the time the response headers arrive, so
	// writes made now are observed on the stream.
	_, body := s.create(appPath(""), newApp("db", "n1", "img:1"))
	if e := waitEvent(t, dec); e.Type != "ADDED" {
		t.Fatalf("event 1 = %q, want ADDED", e.Type)
	} else if got := watchedApp(t, e); got.Name != "db" || got.Spec.Image != "img:1" {
		t.Fatalf("ADDED object = %s/%s", got.Name, got.Spec.Image)
	}

	var created corev1.Application
	decode(t, body, &created)
	created.Spec.Image = "img:2"
	if code, b := s.put(appPath("db"), &created); code != http.StatusOK {
		t.Fatalf("update = %d, %s", code, b)
	}
	if e := waitEvent(t, dec); e.Type != "MODIFIED" {
		t.Fatalf("event 2 = %q, want MODIFIED", e.Type)
	} else if got := watchedApp(t, e); got.Spec.Image != "img:2" {
		t.Fatalf("MODIFIED image = %q, want img:2", got.Spec.Image)
	}

	if code, _ := s.del(appPath("db")); code != http.StatusOK {
		t.Fatalf("delete failed")
	}
	if e := waitEvent(t, dec); e.Type != "DELETED" {
		t.Fatalf("event 3 = %q, want DELETED", e.Type)
	}
}

func TestApplication_WatchKindIsolation(t *testing.T) {
	// A watch on one Kind must not receive another Kind's events.
	s := startServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+nodePath("")+"?watch=true", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open node watch: %v", err)
	}
	defer resp.Body.Close()
	defer cancel()
	dec := json.NewDecoder(resp.Body)

	// Create an Application (different Kind) then a Node; the node watch must
	// deliver only the Node event.
	if code, _ := s.create(appPath(""), newApp("db", "n1", "img")); code != http.StatusCreated {
		t.Fatalf("create app failed")
	}
	if code, _ := s.create(nodePath(""), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}); code != http.StatusCreated {
		t.Fatalf("create node failed")
	}
	e := waitEvent(t, dec)
	if e.Type != "ADDED" {
		t.Fatalf("event = %q, want ADDED", e.Type)
	}
	var node corev1.Node
	decode(t, e.Object.Raw, &node)
	if node.Kind != "Node" || node.Name != "node-1" {
		t.Fatalf("node watch delivered %s/%s, want Node/node-1", node.Kind, node.Name)
	}
}

func TestWatch_LabelSelector(t *testing.T) {
	s := startServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+appPath("")+"?watch=true&labelSelector=env%3Dprod", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open watch: %v", err)
	}
	defer resp.Body.Close()
	defer cancel()
	dec := json.NewDecoder(resp.Body)

	// The non-matching object is filtered out (no event); only the matching one
	// is delivered, so it must be the first frame on the stream.
	mustCreate(t, s, appPath(""), labeledApp("dev", "img", map[string]string{"env": "dev"}))
	mustCreate(t, s, appPath(""), labeledApp("prod", "img", map[string]string{"env": "prod"}))

	if got := watchedApp(t, waitEvent(t, dec)); got.Name != "prod" {
		t.Fatalf("watch delivered %q, want prod (env=dev must be filtered out)", got.Name)
	}
}

func TestWatch_NoInitialReplay(t *testing.T) {
	s := startServer(t)

	// An object that already exists before the watch is opened.
	_, body := s.create(appPath(""), newApp("db", "n1", "img:1"))
	var created corev1.Application
	decode(t, body, &created)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+appPath("")+"?watch=true", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open watch: %v", err)
	}
	defer resp.Body.Close()
	defer cancel()
	dec := json.NewDecoder(resp.Body)

	// The watch does not replay pre-existing state; the first frame is the update.
	created.Spec.Image = "img:2"
	if code, b := s.put(appPath("db"), &created); code != http.StatusOK {
		t.Fatalf("update = %d, %s", code, b)
	}
	if e := waitEvent(t, dec); e.Type != "MODIFIED" {
		t.Fatalf("first event = %q, want MODIFIED (no ADDED replay of existing state)", e.Type)
	}
}

func waitEvent(t *testing.T, dec *json.Decoder) metav1.WatchEvent {
	t.Helper()
	type result struct {
		e   metav1.WatchEvent
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var e metav1.WatchEvent
		err := dec.Decode(&e)
		ch <- result{e, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("decode watch event: %v", r.err)
		}
		return r.e
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for watch event")
		return metav1.WatchEvent{}
	}
}

func watchedApp(t *testing.T, e metav1.WatchEvent) *corev1.Application {
	t.Helper()
	var app corev1.Application
	decode(t, e.Object.Raw, &app)
	return &app
}
