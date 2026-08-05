package apiserver

import (
	"net/http"
	"testing"
)

// TestWatchListIsRefusedSoTheClientFallsBack: `sendInitialEvents=true` asks for a guarantee about
// the stream's BEGINNING — an initial batch closed by an `initial-events-end` bookmark — that this
// server does not make. Serving an ordinary watch instead looks like compliance and hangs the
// caller forever waiting for a bookmark that never comes; `kubectl delete`, which waits by
// default, sat for minutes on a delete that had already completed. Refused, client-go treats it as
// "the server does not have it" and falls back to LIST + WATCH, which this server serves.
func TestWatchListIsRefusedSoTheClientFallsBack(t *testing.T) {
	s, _ := newPodsServer(t, nil)

	w := doReq(t, s, http.MethodGet,
		"/apis/horchestra.io/v1/namespaces/team-a/applications?watch=true&sendInitialEvents=true&resourceVersionMatch=NotOlderThan", "", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("watch-list = %d, want 400 so the client falls back (body=%s)", w.Code, w.Body.String())
	}
}
