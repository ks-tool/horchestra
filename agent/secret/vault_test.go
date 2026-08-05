package secret

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func vaultSecret(ns, name, store, path, keys string) corev1.Secret {
	ann := map[string]string{
		corev1.AnnExternalSecretStore: store,
		corev1.AnnExternalSecretPath:  path,
	}
	if keys != "" {
		ann[corev1.AnnExternalSecretKeys] = keys
	}
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: ann},
		Type:       corev1.SecretTypeVault,
	}
}

// fakeVault speaks just enough of the Vault API over TLS: a cert login that requires a
// client certificate, and one KV v2 path gated on the issued token. reads counts data
// reads so the cache behavior is observable.
func fakeVault(t *testing.T) (srv *httptest.Server, reads *int) {
	t.Helper()
	reads = new(int)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/cert/login", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["no client certificate"]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok-1"}})
	})
	mux.HandleFunc("POST /v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ JWT, Role string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.JWT != "wl-jwt" || body.Role != "workloads" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["bad token"]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok-1"}})
	})
	mux.HandleFunc("GET /v1/kv/data/prod/db", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		*reads++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":     map[string]any{"password": "s3cr3t", "username": "admin", "port": 5432},
				"metadata": map[string]any{"version": 1},
			},
		})
	})
	srv = httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, reads
}

// testVault builds a client whose certificate is the fake server's own keypair (any cert
// satisfies the fake's login) and a store trusting the fake's serving certificate.
func testVault(t *testing.T, srv *httptest.Server) (*Vault, []secretsv1.SecretStore) {
	t.Helper()
	cert := srv.TLS.Certificates[0]
	v := NewVault(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil })
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	stores := []secretsv1.SecretStore{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "corp"},
		Spec:       secretsv1.SecretStoreSpec{Server: srv.URL, Mount: "kv", CABundle: caPEM},
	}}
	return v, stores
}

func TestVaultFetch(t *testing.T) {
	srv, reads := fakeVault(t)
	v, stores := testVault(t, srv)

	data, err := v.Fetch(context.Background(), vaultSecret("team", "db", "corp", "prod/db", "password,username"), stores, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(data["password"]) != "s3cr3t" || string(data["username"]) != "admin" {
		t.Fatalf("data = %v", data)
	}
	if _, leaked := data["port"]; leaked {
		t.Fatal("the keys annotation must project only the listed keys")
	}
	if *reads != 1 {
		t.Fatalf("want 1 read, got %d", *reads)
	}

	// Within the TTL a second materialization serves the cache — no second read.
	if _, err := v.Fetch(context.Background(), vaultSecret("team", "db", "corp", "prod/db", "password,username"), stores, ""); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("want the cached value inside the TTL, got %d reads", *reads)
	}

	// Past the TTL the value is STILL served from the cache — a converge never waits on the
	// network for a value it already has. The re-read is the refresher's job.
	v.now = func() time.Time { return time.Now().Add(vaultCacheTTL + time.Minute) }
	if _, err := v.Fetch(context.Background(), vaultSecret("team", "db", "corp", "prod/db", "password,username"), stores, ""); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("a stale value must be served, not re-read on the converge path; got %d reads", *reads)
	}
	// The refresher re-reads it — off the converge path, when the deadline says to.
	v.refreshDue(context.Background())
	if *reads != 2 {
		t.Fatalf("want the refresher to re-read past the TTL, got %d reads", *reads)
	}
}

func TestVaultFetchAllKeys(t *testing.T) {
	srv, _ := fakeVault(t)
	v, stores := testVault(t, srv)
	data, err := v.Fetch(context.Background(), vaultSecret("team", "db", "corp", "prod/db", ""), stores, "")
	if err != nil {
		t.Fatal(err)
	}
	// No keys annotation projects everything; a non-string value keeps its JSON form.
	if len(data) != 3 || string(data["port"]) != "5432" {
		t.Fatalf("data = %v", data)
	}
}

func TestVaultFetchFailClosed(t *testing.T) {
	srv, _ := fakeVault(t)
	v, stores := testVault(t, srv)

	if _, err := v.Fetch(context.Background(), vaultSecret("team", "db", "other", "prod/db", ""), stores, ""); err == nil ||
		!strings.Contains(err.Error(), "not available") {
		t.Fatalf("want a missing-store error, got %v", err)
	}
	if _, err := v.Fetch(context.Background(), vaultSecret("team", "db", "corp", "prod/db", "absent"), stores, ""); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("want a missing-key error, got %v", err)
	}
	if _, err := v.Fetch(context.Background(), vaultSecret("team", "db", "corp", "", ""), stores, ""); err == nil {
		t.Fatal("want an error for a vault secret with no path annotation")
	}
	noCert := NewVault(nil)
	if _, err := noCert.Fetch(context.Background(), vaultSecret("team", "db", "corp", "prod/db", ""), stores, ""); err == nil ||
		!strings.Contains(err.Error(), "no client certificate") {
		t.Fatalf("want a no-certificate error, got %v", err)
	}
}

// TestVaultFetchKubernetes: a kubernetes-method store logs in with the controller-minted
// workload token instead of a client certificate — the client needs no certificate at
// all, and a missing token fails closed with an actionable error.
func TestVaultFetchKubernetes(t *testing.T) {
	srv, _ := fakeVault(t)
	_, base := testVault(t, srv)
	stores := []secretsv1.SecretStore{{
		ObjectMeta: base[0].ObjectMeta,
		Spec: secretsv1.SecretStoreSpec{Server: srv.URL, Mount: "kv", CABundle: base[0].Spec.CABundle,
			Auth: secretsv1.SecretStoreAuth{Method: secretsv1.AuthMethodKubernetes, Role: "workloads"}},
	}}
	v := NewVault(nil) // no client certificate anywhere — the token path must not need one

	data, err := v.Fetch(context.Background(), vaultSecret("team", "db", "corp", "prod/db", "password"), stores, "wl-jwt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data["password"]) != "s3cr3t" {
		t.Fatalf("data = %v", data)
	}
	if _, err := v.Fetch(context.Background(), vaultSecret("team", "db2", "corp", "prod/db", ""), stores, ""); err == nil ||
		!strings.Contains(err.Error(), "no workload token") {
		t.Fatalf("want a no-token fail-closed error, got %v", err)
	}
}

// TestMaterializeVault is the end-to-end store path: a horchestra.io/vault secret mounted
// by an app materializes from the fake server through the controllerStore routing.
func TestMaterializeVault(t *testing.T) {
	srv, _ := fakeVault(t)
	v, stores := testVault(t, srv)
	s := NewControllerStore(v)
	s.(NodeBound).BindNode(testNode)

	pushed := []corev1.Secret{vaultSecret("team", "db", "corp", "prod/db", "password")}
	vols, err := s.Materialize(context.Background(), app("team", "web", secretMount("db", false)), pushed, stores)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 1 || string(vols[0].Content["password"]) != "s3cr3t" {
		t.Fatalf("vols = %+v", vols)
	}
}
