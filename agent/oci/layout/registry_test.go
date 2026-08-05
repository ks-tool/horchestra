//go:build linux

package layout

import (
	"net/http"
	"testing"
	"time"
)

func TestParseReference(t *testing.T) {
	const dgst = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	tests := []struct {
		in       string
		insecure bool
		host     string
		repo     string
		tag      string
		dgst     string
		name     string
		scheme   string
	}{
		// A bare name is Docker Hub, and an official image is under library/ — but the ref
		// name keeps what was typed, since that is what a person selects the image by.
		{in: "postgres", host: dockerHubAPI, repo: "library/postgres", tag: "latest",
			name: "postgres:latest", scheme: "https"},
		{in: "postgres:18-alpine", host: dockerHubAPI, repo: "library/postgres", tag: "18-alpine",
			name: "postgres:18-alpine", scheme: "https"},
		{in: "bitnami/redis:7", host: dockerHubAPI, repo: "bitnami/redis", tag: "7",
			name: "bitnami/redis:7", scheme: "https"},
		// A first element that looks like a host is one; one that does not, is not.
		{in: "ghcr.io/team/app:v1", host: "ghcr.io", repo: "team/app", tag: "v1",
			name: "team/app:v1", scheme: "https"},
		{in: "localhost:5000/wh:test", host: "localhost:5000", repo: "wh", tag: "test",
			name: "wh:test", scheme: "https"},
		{in: "localhost:5000/wh", host: "localhost:5000", repo: "wh", tag: "latest",
			name: "wh:latest", scheme: "https"},
		// The ':' of a port is not the ':' of a tag.
		{in: "reg.local:5000/team/app", host: "reg.local:5000", repo: "team/app", tag: "latest",
			name: "team/app:latest", scheme: "https"},
		// By digest: no tag is invented, and the name carries the digest.
		{in: "alpine@" + dgst, host: dockerHubAPI, repo: "library/alpine", dgst: dgst,
			name: "alpine@" + dgst, scheme: "https"},
		{in: "ghcr.io/team/app:v1", insecure: true, host: "ghcr.io", repo: "team/app", tag: "v1",
			name: "team/app:v1", scheme: "http"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			r, err := parseReference(tt.in, tt.insecure)
			if err != nil {
				t.Fatalf("parseReference(%q): %v", tt.in, err)
			}
			if r.host != tt.host || r.repo != tt.repo || r.tag != tt.tag ||
				string(r.dgst) != tt.dgst || r.name != tt.name || r.scheme != tt.scheme {
				t.Errorf("got host=%q repo=%q tag=%q dgst=%q name=%q scheme=%q",
					r.host, r.repo, r.tag, r.dgst, r.name, r.scheme)
			}
		})
	}
}

func TestParseReferenceRejects(t *testing.T) {
	for _, in := range []string{"", ":latest", "alpine@sha256:not-a-digest", "alpine@bogus"} {
		if r, err := parseReference(in, false); err == nil {
			t.Errorf("parseReference(%q) = %+v, want an error", in, r)
		}
	}
}

func TestReferenceTarget(t *testing.T) {
	byTag, err := parseReference("alpine:3.21", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := byTag.target(); got != "3.21" {
		t.Errorf("target() = %q, want the tag", got)
	}

	const dgst = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	byDigest, err := parseReference("alpine@"+dgst, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := byDigest.target(); got != dgst {
		t.Errorf("target() = %q, want the digest", got)
	}
}

func TestParseChallenge(t *testing.T) {
	scheme, params := parseChallenge(
		`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"`)
	if scheme != "Bearer" {
		t.Errorf("scheme = %q", scheme)
	}
	for k, want := range map[string]string{
		"realm":   "https://auth.docker.io/token",
		"service": "registry.docker.io",
		"scope":   "repository:library/alpine:pull",
	} {
		if params[k] != want {
			t.Errorf("params[%q] = %q, want %q", k, params[k], want)
		}
	}
}

// A scope naming two repositories contains a comma inside its quotes, and splitting on every comma
// would turn one parameter into two halves of a broken one.
func TestParseChallengeQuotedComma(t *testing.T) {
	_, params := parseChallenge(
		`Bearer realm="https://auth/token",scope="repository:a:pull,repository:b:pull"`)
	if got, want := params["scope"], "repository:a:pull,repository:b:pull"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
}

func TestRetryableStatus(t *testing.T) {
	for _, code := range []int{408, 429, 500, 502, 503, 504} {
		if !retryableStatus(code) {
			t.Errorf("retryableStatus(%d) = false", code)
		}
	}
	// A 404 or a 403 answers the same way however many times it is asked.
	for _, code := range []int{200, 400, 401, 403, 404, 501} {
		if retryableStatus(code) {
			t.Errorf("retryableStatus(%d) = true", code)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	resp := func(v string) *http.Response {
		h := http.Header{}
		if len(v) > 0 {
			h.Set("Retry-After", v)
		}
		return &http.Response{Header: h}
	}
	if got := retryAfter(resp("")); got != 0 {
		t.Errorf("no header: %v", got)
	}
	if got := retryAfter(resp("7")); got != 7*time.Second {
		t.Errorf("seconds: %v", got)
	}
	if got := retryAfter(resp("not a number")); got != 0 {
		t.Errorf("garbage: %v", got)
	}
	// An HTTP-date already past means come back now, not travel backwards.
	if got := retryAfter(resp(time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))); got != 0 {
		t.Errorf("past date: %v", got)
	}
	if got := retryAfter(resp(time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))); got <= 0 {
		t.Errorf("future date: %v", got)
	}
}

func TestBackoff(t *testing.T) {
	// Exponential, jittered, and capped: each attempt at least doubles the previous base, and no
	// attempt ever exceeds the cap plus one jitter.
	for attempt := 1; attempt <= 20; attempt++ {
		got := backoff(attempt, 0)
		if got < backoffBase {
			t.Errorf("attempt %d: %v below the base", attempt, got)
		}
		if got > backoffCap+backoffJit {
			t.Errorf("attempt %d: %v above the cap", attempt, got)
		}
	}
	if got := backoff(1, time.Minute); got != time.Minute {
		t.Errorf("Retry-After is a floor, got %v", got)
	}
	if got := backoff(1, time.Nanosecond); got < backoffBase {
		t.Errorf("a floor below the backoff must not shorten it, got %v", got)
	}
}

func TestLimiterPaces(t *testing.T) {
	l := newLimiter(50) // 20ms apart
	start := time.Now()
	for range 3 {
		if err := l.wait(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// Three requests are two gaps; the first does not wait.
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("three requests took %v, want at least two 20ms gaps", elapsed)
	}
	if newLimiter(0).gap != 0 {
		t.Error("qps 0 must not pace at all")
	}
}
