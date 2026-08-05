package secret

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func dynamicSecret(role string) corev1.Secret {
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "db", Annotations: map[string]string{
			corev1.AnnExternalSecretStore:       "corp",
			corev1.AnnExternalSecretDynamicRole: role,
		}},
		Type: corev1.SecretTypeVault,
	}
}

// dynamicServer is a database engine that mints a credential per request and tracks the
// leases it handed out, so a test can see which of them were renewed and which released.
type dynamicServer struct {
	srv *httptest.Server

	mu        sync.Mutex
	issued    int
	renews    int
	revoked   []string
	live      map[string]bool
	renewable bool
	leaseSecs int64
	renewFail bool
}

func newDynamicServer(t *testing.T, leaseSecs int64, renewable bool) *dynamicServer {
	t.Helper()
	d := &dynamicServer{live: map[string]bool{}, renewable: renewable, leaseSecs: leaseSecs}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/cert/login", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok-1"}})
	})
	mux.HandleFunc("GET /v1/database/creds/app", func(w http.ResponseWriter, _ *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.issued++
		id := "database/creds/app/" + strconv.Itoa(d.issued)
		d.live[id] = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"lease_id": id, "lease_duration": d.leaseSecs, "renewable": d.renewable,
			"data": map[string]any{"username": "v-" + strconv.Itoa(d.issued), "password": "pw-" + strconv.Itoa(d.issued)},
		})
	})
	mux.HandleFunc("PUT /v1/sys/leases/renew", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.renewFail {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"errors":["lease is not renewable"]}`)
			return
		}
		d.renews++
		_ = json.NewEncoder(w).Encode(map[string]any{"lease_duration": d.leaseSecs, "renewable": d.renewable})
	})
	mux.HandleFunc("PUT /v1/sys/leases/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			LeaseID string `json:"lease_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		d.mu.Lock()
		defer d.mu.Unlock()
		d.revoked = append(d.revoked, body.LeaseID)
		delete(d.live, body.LeaseID)
		w.WriteHeader(http.StatusNoContent)
	})
	d.srv = httptest.NewUnstartedServer(mux)
	d.srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	d.srv.StartTLS()
	t.Cleanup(d.srv.Close)
	return d
}

func (d *dynamicServer) stats() (issued, renews int, revoked []string, live int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.issued, d.renews, append([]string(nil), d.revoked...), len(d.live)
}

func (d *dynamicServer) setRenewFail(v bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.renewFail = v
}

func (d *dynamicServer) client(t *testing.T) (*Vault, []secretsv1.SecretStore) {
	t.Helper()
	cert := d.srv.TLS.Certificates[0]
	v := NewVault(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil })
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.srv.Certificate().Raw})
	return v, []secretsv1.SecretStore{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "corp"},
		Spec:       secretsv1.SecretStoreSpec{Server: d.srv.URL, CABundle: caPEM},
	}}
}

// TestDynamicCredentialIsIssuedAndHeld: Vault creates the credential, and the node holds the
// lease that owns it. Per-consumer identity is the whole reason to pay for this shape — the
// credential exists for this request and nothing else.
func TestDynamicCredentialIsIssuedAndHeld(t *testing.T) {
	d := newDynamicServer(t, 60, true)
	v, stores := d.client(t)

	data, err := v.Fetch(context.Background(), dynamicSecret("database/app"), stores, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(data["username"]) != "v-1" || string(data["password"]) != "pw-1" {
		t.Fatalf("data = %v", data)
	}
	issued, _, _, live := d.stats()
	if issued != 1 || live != 1 {
		t.Fatalf("issued=%d live=%d — one request, one credential", issued, live)
	}
}

// TestLeaseIsRenewedNotReissued: re-reading would mint a SECOND database user and leave the
// first to expire, so a workload that has already connected would find its credential
// replaced for no reason. Renewal is both cheaper and what keeps the credential stable.
func TestLeaseIsRenewedNotReissued(t *testing.T) {
	d := newDynamicServer(t, 60, true)
	v, stores := d.client(t)
	sec := dynamicSecret("database/app")
	base := time.Now()
	v.now = func() time.Time { return base }
	if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
		t.Fatal(err)
	}

	// Two-thirds of a 60s lease: due at 40s.
	v.now = func() time.Time { return base.Add(41 * time.Second) }
	v.refreshDue(context.Background())

	issued, renews, revoked, live := d.stats()
	if renews != 1 {
		t.Errorf("renews = %d, want 1", renews)
	}
	if issued != 1 {
		t.Errorf("issued = %d — a renewable lease must not be re-issued", issued)
	}
	if len(revoked) != 0 || live != 1 {
		t.Errorf("revoked=%v live=%d — nothing was replaced", revoked, live)
	}
	// The workload still holds the same credential.
	data, err := v.Fetch(context.Background(), sec, stores, "")
	if err != nil || string(data["password"]) != "pw-1" {
		t.Fatalf("after renewal: %v %q", err, data["password"])
	}
}

// TestUnrenewableLeaseIsReplacedAndReleased: at max_ttl Vault stops extending, so a new
// credential is issued — and the old lease is REVOKED rather than left to age out, or the
// database accumulates users nobody is using until they expire on their own.
func TestUnrenewableLeaseIsReplacedAndReleased(t *testing.T) {
	d := newDynamicServer(t, 60, true)
	v, stores := d.client(t)
	sec := dynamicSecret("database/app")
	base := time.Now()
	v.now = func() time.Time { return base }
	if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
		t.Fatal(err)
	}
	d.setRenewFail(true)

	v.now = func() time.Time { return base.Add(41 * time.Second) }
	v.refreshDue(context.Background())

	issued, _, revoked, live := d.stats()
	if issued != 2 {
		t.Fatalf("issued = %d, want a replacement credential", issued)
	}
	if len(revoked) != 1 || revoked[0] != "database/creds/app/1" {
		t.Fatalf("revoked = %v, want the replaced lease", revoked)
	}
	if live != 1 {
		t.Errorf("live leases = %d, want exactly the replacement", live)
	}
	data, err := v.Fetch(context.Background(), sec, stores, "")
	if err != nil || string(data["password"]) != "pw-2" {
		t.Fatalf("the workload must see the replacement: %v %q", err, data["password"])
	}
}

// TestDepartedWorkloadsLeaseIsReleased is the half without which "revocation is precise and
// guaranteed" — the reason to take a dynamic credential at all — stops being true. An
// application that leaves the node stops asking for its secret; the entry ages out, and the
// lease goes with it rather than leaking a live database user until Vault's max_ttl.
func TestDepartedWorkloadsLeaseIsReleased(t *testing.T) {
	d := newDynamicServer(t, 3600, true)
	v, stores := d.client(t)
	base := time.Now()
	v.now = func() time.Time { return base }
	if _, err := v.Fetch(context.Background(), dynamicSecret("database/app"), stores, ""); err != nil {
		t.Fatal(err)
	}

	// Nothing asks for it any more.
	v.now = func() time.Time { return base.Add(idleEvict + time.Minute) }
	v.refreshDue(context.Background())

	_, _, revoked, live := d.stats()
	if len(revoked) != 1 || live != 0 {
		t.Fatalf("revoked=%v live=%d — a departed workload's credential must be destroyed", revoked, live)
	}
	if _, ok := v.nextDeadline(); ok {
		t.Error("the entry survived its eviction")
	}
}

// TestStalenessIsReportedNotSwallowed: keeping the workload on its last good value is the
// decided answer, but a silent one is indistinguishable from everything being fine. StaleFor
// is what the reconcile pass puts on the application's status.
func TestStalenessIsReportedNotSwallowed(t *testing.T) {
	d := newDynamicServer(t, 60, false) // not renewable: a refresh must re-issue
	v, stores := d.client(t)
	sec := dynamicSecret("database/app")
	base := time.Now()
	v.now = func() time.Time { return base }
	if _, err := v.Fetch(context.Background(), sec, stores, ""); err != nil {
		t.Fatal(err)
	}
	if _, stale := v.StaleFor(sec, stores); stale {
		t.Fatal("a fresh value must not read as stale")
	}

	d.srv.Close() // Vault is gone
	v.now = func() time.Time { return base.Add(41 * time.Second) }
	v.refreshDue(context.Background())

	data, err := v.Fetch(context.Background(), sec, stores, "")
	if err != nil || string(data["password"]) != "pw-1" {
		t.Fatalf("the last good value must survive: %v %q", err, data["password"])
	}
	v.now = func() time.Time { return base.Add(10 * time.Minute) }
	staleFor, stale := v.StaleFor(sec, stores)
	if !stale {
		t.Fatal("a value served past its deadline must report as stale")
	}
	if staleFor <= 0 {
		t.Errorf("staleness = %v, want how long it has been aging", staleFor)
	}
}
