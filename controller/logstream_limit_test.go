package apiserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ks-tool/horchestra/controller/authn"

	"github.com/uptrace/bunrouter"
)

// TestLogStreamPerCallerLimit: each live log stream pins a controller-side chunk buffer for as
// long as its request lives, and a client that never reads the body keeps the handler parked in
// Write — so one identity holding nothing but `get applications` in its own namespace must not be
// able to open an unbounded number of them.
func TestLogStreamPerCallerLimit(t *testing.T) {
	s, _ := newPodsServer(t, nil)
	ctx := authn.WithIdentity(t.Context(), &authn.Identity{Name: "tenant-a"})

	releases := make([]func(), 0, maxLogStreamsPerCaller)
	for i := range maxLogStreamsPerCaller {
		release, err := s.acquireLogStream(ctx)
		if err != nil {
			t.Fatalf("stream %d must be admitted: %v", i, err)
		}
		releases = append(releases, release)
	}
	if _, err := s.acquireLogStream(ctx); err == nil {
		t.Fatalf("stream %d must be refused past the per-caller limit", maxLogStreamsPerCaller+1)
	}

	// A different identity has its own budget.
	other := authn.WithIdentity(t.Context(), &authn.Identity{Name: "tenant-b"})
	releaseOther, err := s.acquireLogStream(other)
	if err != nil {
		t.Fatalf("another caller must have its own budget: %v", err)
	}
	releaseOther()

	// Releasing frees a slot, and a double release must not free two.
	releases[0]()
	releases[0]()
	if _, err := s.acquireLogStream(ctx); err != nil {
		t.Fatalf("a released slot must be reusable: %v", err)
	}
	if _, err := s.acquireLogStream(ctx); err == nil {
		t.Fatal("a double release must not hand out a second slot")
	}

	for _, release := range releases[1:] {
		release()
	}
	s.logStreamsMu.Lock()
	defer s.logStreamsMu.Unlock()
	if got := s.logStreams["tenant-b"]; got != 0 {
		t.Fatalf("the counter map must be pruned back, tenant-b = %d", got)
	}
}

// TestRecoverMiddleware: a panic anywhere below the recovery middleware must become a 500 for
// that request, with the connection and the audit trail intact. net/http's per-connection
// recovery aborts the connection instead, so a reachable panic degraded into a stream of
// unattributable dropped requests.
func TestRecoverMiddleware(t *testing.T) {
	router := bunrouter.New(bunrouter.Use(Recover))
	router.GET("/boom", func(http.ResponseWriter, bunrouter.Request) error {
		var m map[string]string
		m["key"] = "assignment to entry in nil map"
		return nil
	})

	w := httptest.NewRecorder()
	err := router.ServeHTTPError(w, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if err == nil {
		t.Fatal("the recovered panic must surface as an error, not a silent success")
	}
	writeError(w, err)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}
