package secret

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func staticRoleSecret(role, keys string) corev1.Secret {
	ann := map[string]string{
		corev1.AnnExternalSecretStore:      "corp",
		corev1.AnnExternalSecretStaticRole: role,
	}
	if keys != "" {
		ann[corev1.AnnExternalSecretKeys] = keys
	}
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "db", Annotations: ann},
		Type:       corev1.SecretTypeVault,
	}
}

// staticRoleServer is Vault's static-creds endpoint: it hands out the password Vault
// currently holds and says how many seconds remain before it rotates it again. rotate()
// stands in for Vault's own scheduled rotation.
type staticRoleServer struct {
	srv *httptest.Server
	// Guarded: once a test runs the refresher as its own goroutine, the handler and the test
	// body touch these concurrently — which is the shape the code under test now has.
	mu       sync.Mutex
	reads    int
	password string
	ttl      int64
	path     string // the last static-creds path requested
}

func (s *staticRoleServer) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func (s *staticRoleServer) lastPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

func (s *staticRoleServer) setPassword(pw string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.password = pw
}

func newStaticRoleServer(t *testing.T, ttl int64) *staticRoleServer {
	t.Helper()
	s := &staticRoleServer{password: "pw-1", ttl: ttl}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/cert/login", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok-1"}})
	})
	mux.HandleFunc("GET /v1/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.path = strings.TrimPrefix(r.URL.Path, "/v1/")
		if !strings.Contains(s.path, "/static-creds/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"errors":["no handler"]}`)
			return
		}
		if r.Header.Get("X-Vault-Token") != "tok-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		s.reads++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"username":            "app-rw",
			"password":            s.password,
			"last_vault_rotation": "2026-08-03T09:00:00Z",
			"rotation_period":     86400,
			"ttl":                 s.ttl,
		}})
	})
	s.srv = httptest.NewUnstartedServer(mux)
	s.srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

func (s *staticRoleServer) client(t *testing.T) (*Vault, []secretsv1.SecretStore) {
	t.Helper()
	cert := s.srv.TLS.Certificates[0]
	v := NewVault(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil })
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw})
	return v, []secretsv1.SecretStore{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "corp"},
		Spec:       secretsv1.SecretStoreSpec{Server: s.srv.URL, Mount: "kv", CABundle: caPEM},
	}}
}

// TestStaticRoleFetch: the credential comes from <mount>/static-creds/<role> — the engine
// mount the annotation names, NOT the store's KV mount, which is a different engine
// entirely — and projects as Vault's own username/password.
func TestStaticRoleFetch(t *testing.T) {
	s := newStaticRoleServer(t, 3600)
	v, stores := s.client(t)

	data, err := v.Fetch(context.Background(), staticRoleSecret("database/app-rw", ""), stores, "")
	if err != nil {
		t.Fatal(err)
	}
	if s.lastPath() != "database/static-creds/app-rw" {
		t.Errorf("read %q, want database/static-creds/app-rw", s.lastPath())
	}
	if string(data["username"]) != "app-rw" || string(data["password"]) != "pw-1" {
		t.Fatalf("data = %v", data)
	}
	// The keys annotation projects here exactly as it does for a KV path.
	only, err := v.Fetch(context.Background(), staticRoleSecret("database/app-rw", "password"), stores, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(only) != 1 || string(only["password"]) != "pw-1" {
		t.Errorf("keys projection = %v", only)
	}
}

// TestStaticRoleCacheFollowsVaultsSchedule: the re-read is timed by the ttl VAULT reports —
// the seconds until it rotates this role — so the node picks up the new password just after
// the turnover instead of serving one the database has already stopped accepting. That is
// the whole difference from a KV path, whose staleness bound this agent picks for itself.
func TestStaticRoleCacheFollowsVaultsSchedule(t *testing.T) {
	s := newStaticRoleServer(t, 30) // Vault rotates in 30s
	v, stores := s.client(t)
	sec := staticRoleSecret("database/app-rw", "")
	base := time.Now()
	v.now = func() time.Time { return base }

	if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
		t.Fatal(err)
	}
	if s.readCount() != 1 {
		t.Fatalf("want 1 read, got %d", s.readCount())
	}
	// Before the rotation the cached value is served: a per-tick converge must not become a
	// per-tick Vault read.
	v.now = func() time.Time { return base.Add(20 * time.Second) }
	if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
		t.Fatal(err)
	}
	if s.readCount() != 1 {
		t.Fatalf("want the cached value before the rotation, got %d reads", s.readCount())
	}
	// Vault rotates; past ttl+skew the REFRESHER re-reads — well inside the 5-minute bound a
	// KV path would have waited, and without the converge goroutine ever touching the network.
	s.setPassword("pw-2")
	v.now = func() time.Time { return base.Add(30*time.Second + rotationSkew + time.Second) }
	v.refreshDue(context.Background())
	if s.readCount() != 2 {
		t.Fatalf("after the rotation: %d reads", s.readCount())
	}
	data, err := v.Fetch(context.Background(), sec, stores, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(data["password"]) != "pw-2" {
		t.Fatalf("the workload still sees %q after the rotation", data["password"])
	}
}

// TestStaticRoleLongTTLStillBoundedByTheKVWindow: a role rotating daily reports a ttl of
// hours. Caching for that long would mean an operator's manual `rotate-role` in the middle
// of an incident is not picked up until the next scheduled rotation, so the window is
// capped at the same bound a KV value gets.
func TestStaticRoleLongTTLStillBoundedByTheKVWindow(t *testing.T) {
	s := newStaticRoleServer(t, int64((20 * time.Hour).Seconds()))
	v, stores := s.client(t)
	sec := staticRoleSecret("database/app-rw", "")
	base := time.Now()
	v.now = func() time.Time { return base }

	if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return base.Add(vaultCacheTTL + time.Second) }
	v.refreshDue(context.Background())
	if s.readCount() != 2 {
		t.Fatalf("a long ttl must not pin the value past the KV bound, got %d reads", s.readCount())
	}
}

// TestStaticRoleFailsClosed: a response missing the credential must abort the
// materialization rather than project an empty password. An empty value reaching a workload
// as a real one fails wherever it is used, not here, and looks like a database problem.
func TestStaticRoleFailsClosed(t *testing.T) {
	s := newStaticRoleServer(t, 60)
	v, stores := s.client(t)
	s.setPassword("")
	if _, err := v.Fetch(context.Background(), staticRoleSecret("database/app-rw", ""), stores, ""); err == nil {
		t.Fatal("a credential-less response must be an error")
	}

	// A dynamic role read through this annotation lands on the same guard: its response has
	// no static-creds shape, and saying so names the mistake.
	if _, err := v.Fetch(context.Background(), staticRoleSecret("database/creds", ""), stores, ""); err == nil {
		t.Fatal("a non-static-role path must be an error")
	}
}

// TestVaultSourceIsExactlyOne: the two annotations name different things — a value someone
// wrote versus a credential Vault owns — so a secret carrying both, or neither, is refused
// on the node as well as at admission. The node checks because it must never be the case
// that which one wins depends on which branch the fetch tests first.
func TestVaultSourceIsExactlyOne(t *testing.T) {
	s := newStaticRoleServer(t, 60)
	v, stores := s.client(t)

	both := staticRoleSecret("database/app-rw", "")
	both.Annotations[corev1.AnnExternalSecretPath] = "prod/db"
	if _, err := v.Fetch(context.Background(), both, stores, ""); err == nil ||
		!strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want a mutual-exclusion error, got %v", err)
	}

	neither := staticRoleSecret("", "")
	delete(neither.Annotations, corev1.AnnExternalSecretStaticRole)
	if _, err := v.Fetch(context.Background(), neither, stores, ""); err == nil {
		t.Fatal("a vault secret naming no source must be an error")
	}
}
