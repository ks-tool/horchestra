package layout

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
)

// dockerHub is the registry a bare name like "postgres:18" refers to, and the API host it is
// actually served from — the two differ, which is why the name people type is never a usable host.
const (
	dockerHub     = "docker.io"
	dockerHubAPI  = "registry-1.docker.io"
	dockerHubAuth = "https://index.docker.io/v1/"
)

// The retry envelope. A registry in front of a CDN answers with 429 and 5xx under load far more
// often than it fails outright, so backing off is the normal path and giving up immediately would
// turn a busy minute into a failed deploy.
const (
	backoffBase = 500 * time.Millisecond
	backoffCap  = 30 * time.Second
	backoffJit  = 250 * time.Millisecond
)

// reference is one image to fetch, split into the parts the registry API takes.
type reference struct {
	host   string        // API host, e.g. registry-1.docker.io
	repo   string        // full repository path, e.g. library/postgres
	tag    string        // empty when dgst is set
	dgst   digest.Digest // empty when tag is set
	name   string        // what goes in the layout's ref.name annotation
	scheme string        // https, or http for -insecure
}

// String renders the reference the way a registry client logs it.
func (r reference) String() string {
	if len(r.dgst) > 0 {
		return r.host + "/" + r.repo + "@" + r.dgst.String()
	}
	return r.host + "/" + r.repo + ":" + r.tag
}

// target is the manifest path element: a tag or a digest, whichever was given.
func (r reference) target() string {
	if len(r.dgst) > 0 {
		return r.dgst.String()
	}
	return r.tag
}

// parseReference splits [registry/]repo[:tag|@digest] the way every container tool does: the first
// path element is a registry only if it looks like a host (a dot, a port, or "localhost"), which is
// the rule that lets "postgres" and "ghcr.io/foo/bar" both be unambiguous.
//
// The stored ref.name deliberately keeps the repository as typed, without the registry host and
// without Docker Hub's implicit "library/": it is the string a consumer selects the image by in
// the layout, and it should be the one a person would write.
func parseReference(s string, insecure bool) (reference, error) {
	r := reference{scheme: "https"}
	if insecure {
		r.scheme = "http"
	}

	rest := s
	if repo, d, ok := strings.Cut(rest, "@"); ok {
		parsed, err := digest.Parse(d)
		if err != nil {
			return reference{}, fmt.Errorf("reference %q: %w", s, err)
		}
		rest, r.dgst = repo, parsed
	}

	// A ':' belongs to a tag only when it comes after the last '/'; before it, it is a port.
	if i := strings.LastIndexByte(rest, ':'); i > strings.LastIndexByte(rest, '/') {
		rest, r.tag = rest[:i], rest[i+1:]
	}
	if len(rest) == 0 {
		return reference{}, fmt.Errorf("reference %q: no repository", s)
	}

	r.host = dockerHub
	if first, remainder, ok := strings.Cut(rest, "/"); ok &&
		(strings.ContainsAny(first, ".:") || first == "localhost") {
		r.host, rest = first, remainder
	}

	r.name = rest
	if len(r.tag) == 0 && len(r.dgst) == 0 {
		r.tag = "latest"
	}
	if len(r.dgst) > 0 {
		r.name += "@" + r.dgst.String()
	} else {
		r.name += ":" + r.tag
	}

	r.repo = rest
	if r.host == dockerHub {
		// Official images live under library/; the API has no default namespace.
		if !strings.Contains(r.repo, "/") {
			r.repo = "library/" + r.repo
		}
		r.host = dockerHubAPI
	}
	return r, nil
}

// limits are the knobs that keep a pull from being either a stampede or a hang.
type limits struct {
	jobs    int           // layers fetched and unpacked at once
	retries int           // extra attempts after the first
	qps     float64       // requests per second, 0 for unlimited
	timeout time.Duration // how long a request may take to produce its response headers
}

// limiter paces requests to no more than one every gap. A registry's rate limit is per client, not
// per connection, so pacing has to happen here rather than by limiting concurrency: -j bounds how
// many layers are in flight, this bounds how hard the API itself is hit.
type limiter struct {
	mu   sync.Mutex
	next time.Time
	gap  time.Duration
}

func newLimiter(qps float64) *limiter {
	if qps <= 0 {
		return &limiter{}
	}
	return &limiter{gap: time.Duration(float64(time.Second) / qps)}
}

// wait blocks until this caller's turn, or until ctx is done.
func (l *limiter) wait(ctx context.Context) error {
	if l.gap == 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	slot := l.next
	if slot.Before(now) {
		slot = now
	}
	l.next = slot.Add(l.gap)
	l.mu.Unlock()
	return sleep(ctx, time.Until(slot))
}

// client talks the registry v2 API for one repository. The token it obtains is scoped to that
// repository, so nothing here is reusable across images and nothing tries to be. It is safe for
// concurrent use: -j layers share one client, one token and one rate limiter.
type client struct {
	http    *http.Client
	ref     reference
	user    string
	pass    string
	limit   *limiter
	retries int

	mu   sync.Mutex
	auth string // the Authorization header value, once a challenge has been answered
}

func newClient(ref reference, creds string, lim limits) (*client, error) {
	c := &client{
		ref:     ref,
		limit:   newLimiter(lim.qps),
		retries: lim.retries,
		http: &http.Client{
			// No Client.Timeout: it bounds the whole exchange including the body, and a layer
			// body is as long as the layer is big. The bounds that belong here are the ones on
			// getting a response at all.
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          2 * lim.jobs,
				MaxIdleConnsPerHost:   lim.jobs + 1,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: lim.timeout,
				ExpectContinueTimeout: time.Second,
			},
		},
	}
	switch {
	case len(creds) > 0:
		user, pass, ok := strings.Cut(creds, ":")
		if !ok {
			return nil, errors.New("-u: want user:password")
		}
		c.user, c.pass = user, pass
	default:
		c.user, c.pass = dockerConfigAuth(ref.host)
	}
	return c, nil
}

// get issues an authenticated GET, answering an auth challenge and retrying the failures that are
// worth retrying. The registry answers the first request of a session with 401 and the terms for a
// token; that is the normal path, not an error, and it does not consume a retry.
func (c *client) get(ctx context.Context, path string, accept ...string) (*http.Response, error) {
	target := c.ref.scheme + "://" + c.ref.host + path
	var last error
	auths, attempt := 0, 0
	for {
		if err := c.limit.wait(ctx); err != nil {
			return nil, err
		}
		resp, err := c.send(ctx, target, accept)

		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			last = err
		case resp.StatusCode == http.StatusUnauthorized && auths < 2:
			// A 401 mid-pull is an expired token, not a refusal: answer again and carry on.
			auths++
			challenge := resp.Header.Get("Www-Authenticate")
			drain(resp)
			if err := c.answer(ctx, challenge); err != nil {
				return nil, err
			}
			continue
		case !retryableStatus(resp.StatusCode):
			return resp, checkStatus(resp, path)
		default:
			wait := retryAfter(resp)
			last = statusError(resp, path)
			if attempt++; attempt > c.retries {
				return nil, givingUp(path, attempt, last)
			}
			if err := sleep(ctx, backoff(attempt, wait)); err != nil {
				return nil, err
			}
			continue
		}

		if attempt++; attempt > c.retries {
			return nil, givingUp(path, attempt, last)
		}
		if err := sleep(ctx, backoff(attempt, 0)); err != nil {
			return nil, err
		}
	}
}

func (c *client) send(ctx context.Context, target string, accept []string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	for _, a := range accept {
		req.Header.Add("Accept", a)
	}
	c.mu.Lock()
	auth := c.auth
	c.mu.Unlock()
	if len(auth) > 0 {
		req.Header.Set("Authorization", auth)
	}
	return c.http.Do(req)
}

// answer turns a WWW-Authenticate challenge into an Authorization header: a Bearer challenge names
// a token service to ask, a Basic one needs credentials up front.
func (c *client) answer(ctx context.Context, challenge string) error {
	scheme, params := parseChallenge(challenge)
	var auth string
	switch strings.ToLower(scheme) {
	case "bearer":
		token, err := c.token(ctx, params)
		if err != nil {
			return err
		}
		auth = "Bearer " + token
	case "basic":
		if len(c.user) == 0 {
			return fmt.Errorf("%s: registry wants credentials; pass -u user:password or log in with docker", c.ref.host)
		}
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.user+":"+c.pass))
	default:
		return fmt.Errorf("%s: unsupported authentication scheme %q", c.ref.host, scheme)
	}
	c.mu.Lock()
	c.auth = auth
	c.mu.Unlock()
	return nil
}

// token asks the challenge's realm for a repository-scoped pull token, anonymously unless
// credentials are known. The token service gets the same retry treatment as the registry: it is
// the same infrastructure and fails the same ways.
func (c *client) token(ctx context.Context, params map[string]string) (string, error) {
	realm := params["realm"]
	if len(realm) == 0 {
		return "", fmt.Errorf("%s: bearer challenge without a realm", c.ref.host)
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if s := params["service"]; len(s) > 0 {
		q.Set("service", s)
	}
	scope := params["scope"]
	if len(scope) == 0 {
		scope = "repository:" + c.ref.repo + ":pull"
	}
	q.Set("scope", scope)
	u.RawQuery = q.Encode()

	var last error
	for attempt := 0; ; {
		if err := c.limit.wait(ctx); err != nil {
			return "", err
		}
		token, retry, err := c.tokenOnce(ctx, u)
		if err == nil {
			return token, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		last = err
		if !retry {
			return "", err
		}
		if attempt++; attempt > c.retries {
			return "", givingUp("token from "+u.Host, attempt, last)
		}
		if err := sleep(ctx, backoff(attempt, 0)); err != nil {
			return "", err
		}
	}
}

func (c *client) tokenOnce(ctx context.Context, u *url.URL) (token string, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", false, err
	}
	if len(c.user) > 0 {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", true, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", retryableStatus(resp.StatusCode), fmt.Errorf("token from %s: %s", u.Host, resp.Status)
	}

	// Some registries answer with "token", others with "access_token"; both are the same thing.
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", true, fmt.Errorf("token from %s: %w", u.Host, err)
	}
	if len(body.Token) > 0 {
		return body.Token, false, nil
	}
	if len(body.AccessToken) > 0 {
		return body.AccessToken, false, nil
	}
	return "", false, fmt.Errorf("token from %s: empty response", u.Host)
}

// manifest fetches one manifest and returns it verbatim with its media type. The bytes are
// returned unparsed because they are stored as a blob exactly as received: a manifest's digest
// covers its serialisation, so re-encoding it would change its identity.
func (c *client) manifest(ctx context.Context, target string) ([]byte, string, digest.Digest, error) {
	resp, err := c.get(ctx, "/v2/"+c.ref.repo+"/manifests/"+target, manifestTypes...)
	if err != nil {
		return nil, "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded by the spec's ceiling, and by a reader that FAILS on excess rather than truncating:
	// io.LimitReader would hand back a short document whose digest then mismatches, reporting a
	// substituted manifest when the registry merely sent an oversized one.
	raw, err := io.ReadAll(bound(resp.Body, MaxManifestBytes, "the manifest size ceiling"))
	if err != nil {
		return nil, "", "", err
	}
	d := digest.FromBytes(raw)
	// A reference by digest is a promise about the bytes; check it rather than trust the server.
	if want, err := digest.Parse(target); err == nil && want != d {
		return nil, "", "", fmt.Errorf("manifest %s: registry served %s", want, d)
	}
	mediaType := resp.Header.Get("Content-Type")
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = strings.TrimSpace(mediaType[:i])
	}
	return raw, mediaType, d, nil
}

// blob opens a blob for streaming. The digest is NOT checked here — the caller consumes the body
// through a verifier, because a layer is unpacked as it arrives and buffering it whole to check
// first would cost the size of the image in memory or a second copy on disk. A body that fails
// part-way is therefore not retried here either: the caller discards the half-unpacked layer and
// asks again, which is the only unit that can be restarted cleanly.
func (c *client) blob(ctx context.Context, d digest.Digest) (io.ReadCloser, int64, error) {
	resp, err := c.get(ctx, "/v2/"+c.ref.repo+"/blobs/"+d.String())
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// retryableStatus reports whether a status is worth asking again: the registry is busy, throttling
// or briefly broken. Everything else — 404, 403, a malformed request — would answer the same way
// however many times it is asked.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryAfter reads the server's own instruction for when to come back, in either spelling the RFC
// allows. It is a floor on the backoff, never a replacement: a registry that says "in an hour"
// under a rate limit is telling the truth, and guessing shorter only burns the quota further.
func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if len(v) == 0 {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// backoff is exponential with jitter, floored by whatever the server asked for. The jitter matters
// with -j: without it every parallel layer would retry in the same millisecond.
func backoff(attempt int, floor time.Duration) time.Duration {
	d := backoffBase << min(attempt-1, 16)
	if d > backoffCap {
		d = backoffCap
	}
	d += time.Duration(rand.Int64N(int64(backoffJit)))
	if floor > d {
		return floor
	}
	return d
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func givingUp(what string, attempts int, last error) error {
	return fmt.Errorf("%s: giving up after %d attempts: %w", what, attempts, last)
}

// drain empties a response body before discarding it, so the connection goes back to the pool
// instead of being torn down — which matters most on the 401 that every session starts with.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// checkStatus turns a non-2xx answer into an error carrying the registry's own explanation, which
// is the difference between "manifest unknown" and a bare 404.
//
// It is only reached for a status that retryableStatus already rejected, so the error is permanent:
// otherwise the layer-level retry would download a missing blob three more times to be told the
// same thing, and a wrong credential would cost three attempts per layer instead of one.
func checkStatus(resp *http.Response, path string) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return permanent(statusError(resp, path))
}

// statusError consumes and closes the body, so the caller is left holding nothing.
func statusError(resp *http.Response, path string) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	_ = resp.Body.Close()
	msg := strings.TrimSpace(string(body))
	var errs struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &errs) == nil && len(errs.Errors) > 0 {
		msg = errs.Errors[0].Code + ": " + errs.Errors[0].Message
	}
	if len(msg) == 0 {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return fmt.Errorf("GET %s: %s (%s)", path, resp.Status, msg)
}

// parseChallenge splits `Bearer realm="https://…",service="…"` into its scheme and parameters.
func parseChallenge(h string) (scheme string, params map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params = make(map[string]string)
	for _, part := range splitParams(rest) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		params[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return scheme, params
}

// splitParams splits a challenge's parameter list on commas that are not inside a quoted value —
// a scope like "repository:a:pull,repository:b:pull" is one parameter, not two.
func splitParams(s string) []string {
	var parts []string
	var quoted bool
	start := 0
	for i, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// dockerConfigAuth reads credentials for host out of the docker CLI's config, so a registry the
// user is already logged into needs no flag. Only the plain "auth" entry is read: a credential
// helper would mean executing whatever the config names, which this tool will not do.
func dockerConfigAuth(host string) (user, pass string) {
	dir := os.Getenv("DOCKER_CONFIG")
	if len(dir) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", ""
		}
		dir = filepath.Join(home, ".docker")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return "", ""
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return "", ""
	}
	keys := []string{host, "https://" + host}
	if host == dockerHubAPI {
		// Docker Hub logins are filed under the v1 index URL, not the API host.
		keys = append(keys, dockerHubAuth, dockerHub)
	}
	for _, k := range keys {
		entry, ok := cfg.Auths[k]
		if !ok || len(entry.Auth) == 0 {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
		if err != nil {
			continue
		}
		if u, p, ok := strings.Cut(string(decoded), ":"); ok {
			return u, p
		}
	}
	return "", ""
}
