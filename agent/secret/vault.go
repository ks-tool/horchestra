package secret

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"

	"github.com/rs/zerolog/log"
)

// vaultCacheTTL bounds how often a vault secret is re-fetched: within it, a reconcile tick
// serves the cached value so the level-driven converge does not turn into a per-tick Vault
// read; past it, the next materialization re-fetches — which is what turns a server-side
// rotation into a unit restart (the content-hash stamp flips). Rotation latency is
// therefore at most this.
const vaultCacheTTL = 5 * time.Minute

// rotationSkew is added to a static role's remaining ttl before it is cached, so the
// re-fetch lands just AFTER Vault rotates rather than in the same second and racing it.
const rotationSkew = 5 * time.Second

// Refresh retry bounds and idle eviction. A failed renewal keeps the last good value and
// backs off rather than hammering a server that is already unwell; a value nothing has asked
// for in idleEvict is dropped, which is how a secret whose application left the node stops
// being renewed — the converge asks for what it still wants on every tick, so anything still
// in use is touched every few seconds and never ages out.
const (
	refreshRetryBase = 30 * time.Second
	refreshRetryMax  = vaultCacheTTL
	idleEvict        = 15 * time.Minute
	// renewFraction of a lease's remaining life is when it is renewed — the same two-thirds
	// the agent's own certificate rotation uses, so being a tick late is absorbed rather than
	// fatal. renewFloor stops a pathologically short lease from turning the renewer into a
	// spin loop against Vault.
	renewNumer = 2
	renewDenom = 3
	renewFloor = 5 * time.Second
)

// vaultBodyLimit caps a server response, mirroring the 1 MiB Secret size cap the
// admission chain enforces on inline secrets.
const vaultBodyLimit = 2 << 20

// Vault is the node-direct Vault/OpenBao client: it authenticates as this node — the mTLS
// client certificate, the same identity the controller session uses — reads a KV path and
// returns the projected keys. The value goes straight from the server into the caller's
// memory: never through the controller, never to disk, and the login token is dropped at
// the end of the call.
type Vault struct {
	// getCert supplies the node's client certificate for the cert auth method and the TLS
	// handshake; nil means this node has no certificate and cert auth fails closed.
	getCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

	mu    sync.Mutex
	cache map[string]vaultEntry
	now   func() time.Time
	// wake re-arms the refresher when a new value enters the cache, since its deadline may be
	// earlier than the one the refresher is currently sleeping on. Buffered by one: a pending
	// wake-up already covers any number of additions.
	wake chan struct{}
}

// fetchSpec is everything a re-read needs, captured when a value is first fetched. The
// refresher holds no Application and no desired state — only this — so renewing a value asks
// nothing of the converge path.
type fetchSpec struct {
	store       secretsv1.SecretStore
	path        string
	staticRole  string
	dynamicRole string
	keys        string
}

// vaultEntry is a cached value and the moment it stops being served. An explicit expiry
// rather than a fetch time, because the two sources answer "when is this stale" differently:
// a KV value goes stale on a fixed bound this agent chose, a static role's on the schedule
// VAULT chose and reports back.
type vaultEntry struct {
	data    map[string][]byte
	expires time.Time
	// lastUsed is the last converge that asked for this value; it is what idle eviction reads.
	lastUsed time.Time
	spec     fetchSpec
	// token is the freshest workload identity a caller supplied. Refreshed on every serve, so
	// a renewal uses the newest token the controller pushed rather than the one that happened
	// to be current when the value was first read.
	token    string
	failures int
	// leaseID is set for a DYNAMIC credential: Vault created a database user for this value
	// and will destroy it when the lease ends. Holding it is what the entry is for — renewed
	// while the workload wants the value, released the moment it does not.
	leaseID   string
	renewable bool
	// staleSince is when a refresh first failed and the last good value started being served
	// past its deadline; zero while the value is current. It is what the agent reports, so a
	// credential quietly aging is visible through the API rather than only in a node's log.
	staleSince time.Time
}

// NewVault builds the client around the node's client-certificate source (from the same
// rest.Config the controller session uses — one identity for both).
func NewVault(getCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) *Vault {
	return &Vault{getCert: getCert, cache: map[string]vaultEntry{}, now: time.Now, wake: make(chan struct{}, 1)}
}

// Fetch resolves one horchestra.io/vault Secret: find the SecretStore its annotations
// name (in the secret's own namespace — the push already scoped both to this node), log
// in, read the KV path and project the annotated keys. token is the workload's identity
// JWT for a jwt-method store (empty under cert auth). Fail-closed: a missing store, a
// failed login or a missing key is an error, never empty content.
//
// The value cache is keyed by store+path+keys, not by the login identity: two apps that
// may reach the same secret are same-namespace by construction (a secret ref cannot cross
// namespaces, and the push scoped both here), so a cached value never crosses a tenant
// boundary the annotations could not already cross.
func (v *Vault) Fetch(ctx context.Context, sec corev1.Secret, stores []secretsv1.SecretStore, token string) (map[string][]byte, error) {
	spec, ck, err := resolveFetch(sec, stores)
	if err != nil {
		return nil, err
	}
	if data, ok := v.serve(ck, token); ok {
		return data, nil
	}
	// Only the FIRST read of a value happens here, on the converge goroutine, and it is
	// synchronous on purpose: an application must never start without a credential its spec
	// declares, so this is the fail-closed point. Every later read is the refresher's, off
	// this path, because a slow server must not delay the convergence of workloads that
	// reference no secret at all.
	res, err := v.readSpec(ctx, spec, token)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.cache[ck] = vaultEntry{
		data: res.data, expires: v.now().Add(res.until), lastUsed: v.now(),
		spec: spec, token: token, leaseID: res.leaseID, renewable: res.renewable,
	}
	v.mu.Unlock()
	v.signal()
	return res.data, nil
}

// resolveFetch turns a secret's annotations into what a read needs, plus the cache key.
//
// The key is store+path/role+keys, not the login identity: two applications that may reach
// the same secret are same-namespace by construction — a secret reference cannot cross
// namespaces and the push scoped both to this node — so a cached value never crosses a
// boundary the annotations could not already cross.
func resolveFetch(sec corev1.Secret, stores []secretsv1.SecretStore) (fetchSpec, string, error) {
	storeName := sec.Annotations[corev1.AnnExternalSecretStore]
	path := strings.Trim(sec.Annotations[corev1.AnnExternalSecretPath], "/")
	staticRole := strings.TrimSpace(sec.Annotations[corev1.AnnExternalSecretStaticRole])
	dynamicRole := strings.TrimSpace(sec.Annotations[corev1.AnnExternalSecretDynamicRole])
	named := 0
	for _, v := range []string{path, staticRole, dynamicRole} {
		if v != "" {
			named++
		}
	}
	switch {
	case storeName == "":
		return fetchSpec{}, "", fmt.Errorf("annotation %s is required on a %s secret",
			corev1.AnnExternalSecretStore, corev1.SecretTypeVault)
	case named > 1:
		return fetchSpec{}, "", fmt.Errorf("annotations %s, %s and %s are mutually exclusive: a secret names ONE source",
			corev1.AnnExternalSecretPath, corev1.AnnExternalSecretStaticRole, corev1.AnnExternalSecretDynamicRole)
	case named == 0:
		return fetchSpec{}, "", fmt.Errorf("a %s secret needs annotation %s, %s or %s",
			corev1.SecretTypeVault, corev1.AnnExternalSecretPath,
			corev1.AnnExternalSecretStaticRole, corev1.AnnExternalSecretDynamicRole)
	}
	for i := range stores {
		if stores[i].Namespace == sec.Namespace && stores[i].Name == storeName {
			spec := fetchSpec{
				store:       stores[i],
				path:        path,
				staticRole:  staticRole,
				dynamicRole: dynamicRole,
				keys:        sec.Annotations[corev1.AnnExternalSecretKeys],
			}
			ck := strings.Join([]string{spec.store.Namespace, spec.store.Name, spec.store.Spec.Server,
				spec.store.Spec.Mount, path, staticRole, dynamicRole, spec.keys}, "\x00")
			return spec, ck, nil
		}
	}
	return fetchSpec{}, "", fmt.Errorf("secretstore %q not available", storeName)
}

// serve hands back a cached value and records that something still wants it.
//
// However old it is, deliberately. A value the refresher could not renew is kept rather than
// withheld: the failure is in the control path, not in the workload, and holding an
// application because Vault is briefly unreachable is the worse answer than letting it run on
// the credential it already has.
func (v *Vault) serve(ck, token string) (map[string][]byte, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[ck]
	if !ok {
		return nil, false
	}
	e.lastUsed = v.now()
	if token != "" {
		e.token = token
	}
	v.cache[ck] = e
	return e.data, true
}

// readResult is one read's outcome: the projected values, how long until the value should be
// attended to again, and the lease Vault bound it to. A KV path and a static role hold no
// lease — nothing on this node has to stay alive to keep those credentials alive.
type readResult struct {
	data      map[string][]byte
	until     time.Duration
	leaseID   string
	renewable bool
}

// readSpec performs one read: a dynamic role's freshly issued credential, a static role's
// current one, or a KV path.
func (v *Vault) readSpec(ctx context.Context, spec fetchSpec, token string) (readResult, error) {
	var (
		res readResult
		raw map[string][]byte
		err error
	)
	switch {
	case spec.dynamicRole != "":
		raw, res, err = v.readDynamicRole(ctx, &spec.store, spec.dynamicRole, token)
	case spec.staticRole != "":
		raw, res.until, err = v.readStaticRole(ctx, &spec.store, spec.staticRole, token)
	default:
		res.until = vaultCacheTTL
		raw, err = v.read(ctx, &spec.store, spec.path, token)
	}
	if err != nil {
		return readResult{}, err
	}
	if res.data, err = filterKeys(raw, spec.keys); err != nil {
		return readResult{}, err
	}
	return res, nil
}

// readDynamicRole asks Vault to CREATE a credential: POST /v1/<mount>/creds/<role> returns a
// database user made for this request and the lease that owns its lifetime.
//
// The returned deadline is a fraction of the lease, not its whole length: a renewal that
// lands exactly at expiry is a renewal that races the credential's destruction, and the
// workload finds out by failing to authenticate.
func (v *Vault) readDynamicRole(ctx context.Context, store *secretsv1.SecretStore, annotation, workloadJWT string) (map[string][]byte, readResult, error) {
	ref, err := corev1.ParseEngineRole(annotation)
	if err != nil {
		return nil, readResult{}, fmt.Errorf("annotation %s: %w", corev1.AnnExternalSecretDynamicRole, err)
	}
	client, err := v.httpClient(store)
	if err != nil {
		return nil, readResult{}, err
	}
	token, err := v.login(ctx, client, store, workloadJWT)
	if err != nil {
		return nil, readResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(store.Spec.Server, "/")+"/v1/"+ref.CredsPath(), nil)
	if err != nil {
		return nil, readResult{}, err
	}
	req.Header.Set("X-Vault-Token", token)
	if ns := store.Spec.VaultNamespace; ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
	var payload struct {
		LeaseID       string `json:"lease_id"`
		LeaseDuration int64  `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
		Data          struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"data"`
	}
	if err := v.do(client, req, &payload); err != nil {
		return nil, readResult{}, fmt.Errorf("issue dynamic credential %s: %w", ref.CredsPath(), err)
	}
	// Fail closed on a half-answer, exactly as the static path does: an empty credential
	// reaching a workload as a real one fails wherever it is used and looks like a database
	// problem rather than a control-plane one.
	if payload.Data.Username == "" || payload.Data.Password == "" {
		return nil, readResult{}, fmt.Errorf("issue dynamic credential %s: the response carries no username/password", ref.CredsPath())
	}
	if payload.LeaseID == "" {
		return nil, readResult{}, fmt.Errorf("issue dynamic credential %s: no lease in the response (is this a dynamic role?)", ref.CredsPath())
	}
	return map[string][]byte{
			corev1.CredentialUsername: []byte(payload.Data.Username),
			corev1.CredentialPassword: []byte(payload.Data.Password),
		}, readResult{
			until:     renewAfter(time.Duration(payload.LeaseDuration) * time.Second),
			leaseID:   payload.LeaseID,
			renewable: payload.Renewable,
		}, nil
}

// renewAfter is how long to wait before renewing a lease of this length.
func renewAfter(lease time.Duration) time.Duration {
	return max(renewFloor, lease*renewNumer/renewDenom)
}

// renewLease extends a lease in place and reports how long the extension bought. Vault may
// grant LESS than asked, or refuse outright once max_ttl is reached, which is why the answer
// is read back rather than assumed.
func (v *Vault) renewLease(ctx context.Context, store *secretsv1.SecretStore, leaseID, workloadJWT string) (time.Duration, bool, error) {
	client, err := v.httpClient(store)
	if err != nil {
		return 0, false, err
	}
	token, err := v.login(ctx, client, store, workloadJWT)
	if err != nil {
		return 0, false, err
	}
	body, err := json.Marshal(map[string]any{"lease_id": leaseID})
	if err != nil {
		return 0, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		strings.TrimSuffix(store.Spec.Server, "/")+"/v1/sys/leases/renew", bytes.NewReader(body))
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("X-Vault-Token", token)
	var payload struct {
		LeaseDuration int64 `json:"lease_duration"`
		Renewable     bool  `json:"renewable"`
	}
	if err := v.do(client, req, &payload); err != nil {
		return 0, false, fmt.Errorf("renew lease: %w", err)
	}
	return time.Duration(payload.LeaseDuration) * time.Second, payload.Renewable, nil
}

// revokeLease destroys the credential a lease owns — for a database role, it DROPs the user.
// That is the point of the whole shape: revocation touches one consumer and nobody else.
func (v *Vault) revokeLease(ctx context.Context, store *secretsv1.SecretStore, leaseID, workloadJWT string) error {
	client, err := v.httpClient(store)
	if err != nil {
		return err
	}
	token, err := v.login(ctx, client, store, workloadJWT)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"lease_id": leaseID})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		strings.TrimSuffix(store.Spec.Server, "/")+"/v1/sys/leases/revoke", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	if err := v.do(client, req, nil); err != nil {
		return fmt.Errorf("revoke lease: %w", err)
	}
	return nil
}

func (v *Vault) signal() {
	select {
	case v.wake <- struct{}{}:
	default:
	}
}

// Refresh renews cached values as their deadlines come due, and drops the ones nothing asks
// for any more. Run it as its own goroutine for the agent's lifetime.
//
// Its own goroutine, and waking at the NEAREST deadline rather than on a tick, is the point.
// The reconcile goroutine is the converge: a blocking Vault call there delays every
// workload's convergence, not one value's refresh, so a slow server would stall applications
// that reference no secret at all. And a fixed tick would tie a value's freshness to the
// heartbeat interval, which has nothing to do with when the value actually changes — a Vault
// static role's deadline is the one VAULT reports.
func (v *Vault) Refresh(ctx context.Context) {
	timer := time.NewTimer(idleEvict)
	defer timer.Stop()
	for {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		// Nothing cached yet, or nothing due: sleep until the sweep would matter. A new value
		// re-arms this through wake, since its deadline may be earlier than the one chosen here.
		wait := idleEvict
		if d, ok := v.nextDeadline(); ok {
			wait = max(0, d.Sub(v.now()))
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-v.wake:
		case <-timer.C:
		}
		v.refreshDue(ctx)
	}
}

// nextDeadline is the earliest moment any cached value needs attention.
func (v *Vault) nextDeadline() (time.Time, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var earliest time.Time
	for _, e := range v.cache {
		if earliest.IsZero() || e.expires.Before(earliest) {
			earliest = e.expires
		}
	}
	return earliest, !earliest.IsZero()
}

// refreshDue attends to every value whose deadline has passed and evicts the idle ones. The
// network happens outside the lock, so a serve on the converge goroutine never waits on it —
// which is the whole reason this runs here rather than there.
//
// A leased value is RENEWED where it can be: re-reading would mint a second database user and
// leave the first to expire, so renewal is both cheaper and what makes the credential stable
// under a workload that has already connected with it. Only when the lease cannot be extended
// — not renewable, or Vault refusing because max_ttl is reached — is a new credential issued,
// and the old lease is then revoked rather than left to age out.
func (v *Vault) refreshDue(ctx context.Context) {
	type due struct {
		ck    string
		spec  fetchSpec
		token string
		lease string
		renew bool
	}
	var work, evicted []due
	now := v.now()
	v.mu.Lock()
	for ck, e := range v.cache {
		if now.Sub(e.lastUsed) >= idleEvict {
			// Its application is gone. Stop renewing what nobody reads, and release the
			// credential rather than leaving a live database user until Vault's max_ttl —
			// "revocation is precise" is the reason to take a dynamic credential at all.
			delete(v.cache, ck)
			if e.leaseID != "" {
				evicted = append(evicted, due{ck: ck, spec: e.spec, token: e.token, lease: e.leaseID})
			}
			continue
		}
		if !now.Before(e.expires) {
			work = append(work, due{ck: ck, spec: e.spec, token: e.token, lease: e.leaseID, renew: e.renewable})
		}
	}
	v.mu.Unlock()

	for _, e := range evicted {
		if err := v.revokeLease(ctx, &e.spec.store, e.lease, e.token); err != nil {
			log.Warn().Err(err).Str("store", e.spec.store.Name).Msg("vault: releasing the lease of a departed workload")
			continue
		}
		log.Info().Str("store", e.spec.store.Name).Str("role", e.spec.dynamicRole).
			Msg("vault: released the lease of a departed workload")
	}

	for _, w := range work {
		// Renewal first where the lease allows it; a re-read is the fallback, not the norm.
		if w.lease != "" && w.renew {
			if lease, renewable, err := v.renewLease(ctx, &w.spec.store, w.lease, w.token); err == nil {
				v.settle(w.ck, readResult{until: renewAfter(lease), leaseID: w.lease, renewable: renewable}, false)
				continue
			} else {
				log.Info().Err(err).Str("store", w.spec.store.Name).
					Msg("vault: lease not renewable, issuing a new credential")
			}
		}
		res, err := v.readSpec(ctx, w.spec, w.token)
		if err != nil {
			v.fail(w.ck, w.spec, err)
			continue
		}
		v.settle(w.ck, res, true)
		// The value the workload reads is now the new credential, so the old lease has no
		// reader left. Released rather than left to expire, best-effort: a failure here costs
		// a stale database user until max_ttl, not a broken workload.
		if w.lease != "" && w.lease != res.leaseID {
			if err := v.revokeLease(ctx, &w.spec.store, w.lease, w.token); err != nil {
				log.Warn().Err(err).Str("store", w.spec.store.Name).Msg("vault: releasing the replaced lease")
			}
		}
	}
}

// settle records a successful renewal or re-read: the value is current again, so whatever
// staleness was being reported ends here.
func (v *Vault) settle(ck string, res readResult, newValue bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[ck]
	if !ok {
		return // evicted while the call was in flight
	}
	if newValue {
		e.data = res.data
	}
	e.expires = v.now().Add(res.until)
	e.leaseID, e.renewable = res.leaseID, res.renewable
	e.failures = 0
	if !e.staleSince.IsZero() {
		log.Info().Str("store", e.spec.store.Name).Dur("wasStaleFor", v.now().Sub(e.staleSince)).
			Msg("vault: value is current again")
		e.staleSince = time.Time{}
	}
	v.cache[ck] = e
}

// fail keeps the last good value and comes back later.
//
// Keeping it is the decided answer: a credential that cannot be renewed must not tear down a
// workload running fine on the one it holds — the failure is in the control path, not in the
// workload. Backing off matters more than it looks: every cached value tends to come due
// together after an outage, and retrying each on the next pass is a herd against a server
// that is already unwell. The staleness is stamped ONCE, on the transition, and reported
// through the application's status so the condition is visible in the API rather than only in
// this node's journal.
func (v *Vault) fail(ck string, spec fetchSpec, cause error) {
	v.mu.Lock()
	e, ok := v.cache[ck]
	if !ok {
		v.mu.Unlock()
		return
	}
	first := e.staleSince.IsZero()
	if first {
		e.staleSince = v.now()
	}
	e.failures++
	e.expires = v.now().Add(min(refreshRetryMax, refreshRetryBase<<min(e.failures-1, 8)))
	retryAt, staleSince := e.expires, e.staleSince
	v.cache[ck] = e
	v.mu.Unlock()

	ev := log.Warn().Err(cause).Str("store", spec.store.Name).Time("retryAt", retryAt)
	if first {
		ev.Str("event", "secret-stale").Msg("vault: refresh failed, serving the last good value")
		return
	}
	ev.Dur("staleFor", v.now().Sub(staleSince)).Msg("vault: refresh still failing, serving the last good value")
}

// staleFor is how long a value has been served past its deadline, and whether it has at all.
func (v *Vault) staleFor(ck string) (time.Duration, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[ck]
	if !ok || e.staleSince.IsZero() {
		return 0, false
	}
	return v.now().Sub(e.staleSince), true
}

// StaleFor reports how long the value a secret resolves to has been stale. It is the
// agent-facing half of the staleness signal: the reconcile pass asks per application, so a
// credential quietly aging shows up on the object an operator looks at.
func (v *Vault) StaleFor(sec corev1.Secret, stores []secretsv1.SecretStore) (time.Duration, bool) {
	_, ck, err := resolveFetch(sec, stores)
	if err != nil {
		return 0, false
	}
	return v.staleFor(ck)
}

// read logs in and reads one KV path: GET /v1/<mount>/data/<path> (KV v2, the default) or
// /v1/<mount>/<path> (KV v1). The login token lives for exactly this call.
func (v *Vault) read(ctx context.Context, store *secretsv1.SecretStore, path, workloadJWT string) (map[string][]byte, error) {
	client, err := v.httpClient(store)
	if err != nil {
		return nil, err
	}
	token, err := v.login(ctx, client, store, workloadJWT)
	if err != nil {
		return nil, err
	}
	mount := store.Spec.Mount
	if mount == "" {
		mount = "secret"
	}
	kv2 := store.Spec.KVVersion != 1
	url := strings.TrimSuffix(store.Spec.Server, "/") + "/v1/" + strings.Trim(mount, "/")
	if kv2 {
		url += "/data"
	}
	url += "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	if ns := store.Spec.VaultNamespace; ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
	var payload struct {
		Data json.RawMessage `json:"data"`
	}
	if err := v.do(client, req, &payload); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	raw := payload.Data
	if kv2 { // v2 wraps the values in a second data envelope beside the version metadata
		var inner struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &inner); err != nil || inner.Data == nil {
			return nil, fmt.Errorf("read %s: unexpected KV v2 response shape", path)
		}
		raw = inner.Data
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	out := make(map[string][]byte, len(values))
	for k, val := range values {
		if s, ok := val.(string); ok {
			out[k] = []byte(s)
			continue
		}
		b, err := json.Marshal(val) // a non-string value keeps its JSON form
		if err != nil {
			return nil, fmt.Errorf("read %s: key %q: %w", path, k, err)
		}
		out[k] = b
	}
	return out, nil
}

// readStaticRole reads a database static role's CURRENT credential:
// GET /v1/<mount>/static-creds/<role>, whose data is Vault's own {username, password} plus
// the rotation schedule. It returns how long that value may be cached alongside it.
//
// The cache window is the response's own ttl — the seconds Vault says remain before it
// rotates this role again — plus a skew, so the node re-reads just after the turnover
// instead of serving a password the database no longer accepts. It is capped at
// vaultCacheTTL rather than trusted outright: a role rotating daily would otherwise pin a
// value here for a day, and an operator's `rotate-role` in the middle of an incident would
// not be picked up until the next scheduled rotation. So the bound is "no later than the
// rotation, and no longer than the KV bound either".
//
// There is NO LEASE here, which is the whole reason this shape exists: Vault owns one fixed
// database user and rotates its password on a schedule, so nothing on this node has to stay
// alive to keep the credential alive. An agent restart costs one re-read; it cannot cost a
// workload its access, the way a dropped dynamic-secret lease would.
func (v *Vault) readStaticRole(ctx context.Context, store *secretsv1.SecretStore, annotation, workloadJWT string) (map[string][]byte, time.Duration, error) {
	ref, err := corev1.ParseEngineRole(annotation)
	if err != nil {
		return nil, 0, fmt.Errorf("annotation %s: %w", corev1.AnnExternalSecretStaticRole, err)
	}
	client, err := v.httpClient(store)
	if err != nil {
		return nil, 0, err
	}
	token, err := v.login(ctx, client, store, workloadJWT)
	if err != nil {
		return nil, 0, err
	}
	url := strings.TrimSuffix(store.Spec.Server, "/") + "/v1/" + ref.StaticCredsPath()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Vault-Token", token)
	if ns := store.Spec.VaultNamespace; ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
	var payload struct {
		Data struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TTL      int64  `json:"ttl"` // seconds until the next scheduled rotation
		} `json:"data"`
	}
	if err := v.do(client, req, &payload); err != nil {
		return nil, 0, fmt.Errorf("read static role %s: %w", ref.StaticCredsPath(), err)
	}
	// Fail closed on a half-answer. An empty password reaching a workload as a real value is
	// worse than the app being held: it authenticates as nobody and the failure surfaces
	// wherever the credential is used, not here.
	if payload.Data.Username == "" || payload.Data.Password == "" {
		return nil, 0, fmt.Errorf("read static role %s: the response carries no username/password (is it a static role, or a dynamic one?)", ref.StaticCredsPath())
	}
	data := map[string][]byte{
		corev1.CredentialUsername: []byte(payload.Data.Username),
		corev1.CredentialPassword: []byte(payload.Data.Password),
	}
	until := vaultCacheTTL
	if ttl := time.Duration(payload.Data.TTL)*time.Second + rotationSkew; payload.Data.TTL > 0 && ttl < until {
		until = ttl
	}
	return data, until, nil
}

// login authenticates to the store and returns a client token. Two methods: cert (the
// default) presents the node's client certificate in the TLS handshake — the cluster
// identity Vault is configured to trust; kubernetes sends the controller-minted workload
// identity token to Vault's stock kubernetes auth method — per-workload authorization
// that needs no CA trust at all.
func (v *Vault) login(ctx context.Context, client *http.Client, store *secretsv1.SecretStore, workloadJWT string) (string, error) {
	auth := store.Spec.Auth
	method := auth.Method
	if method == "" {
		method = secretsv1.AuthMethodCert
	}
	body := map[string]string{}
	var mountPath string
	switch method {
	case secretsv1.AuthMethodCert:
		if v.getCert == nil {
			return "", fmt.Errorf("auth method cert: this node has no client certificate")
		}
		mountPath = "cert"
		if auth.Role != "" {
			body["name"] = auth.Role
		}
	case secretsv1.AuthMethodKubernetes:
		if workloadJWT == "" {
			return "", fmt.Errorf("auth method %s: no workload token was pushed for this app (is the controller's --jwt-signing-key set?)", method)
		}
		mountPath = "kubernetes"
		body["jwt"] = workloadJWT
		if auth.Role != "" {
			body["role"] = auth.Role
		}
	default:
		return "", fmt.Errorf("auth method %q is not supported", method)
	}
	if auth.Path != "" {
		mountPath = auth.Path
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	url := strings.TrimSuffix(store.Spec.Server, "/") + "/v1/auth/" + strings.Trim(mountPath, "/") + "/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	var payload struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := v.do(client, req, &payload); err != nil {
		return "", fmt.Errorf("%s login: %w", method, err)
	}
	if payload.Auth.ClientToken == "" {
		return "", fmt.Errorf("%s login: no client token in the response", method)
	}
	return payload.Auth.ClientToken, nil
}

// do runs one request and decodes the JSON response, folding a non-200 status into an
// error carrying the response excerpt (Vault reports errors as {"errors":[...]}).
func (v *Vault) do(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, vaultBodyLimit))
	if err != nil {
		return err
	}
	// 204 is what a revoke answers with — an operation whose success has nothing to report.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		excerpt := strings.TrimSpace(string(body))
		if len(excerpt) > 256 {
			excerpt = excerpt[:256]
		}
		return fmt.Errorf("%s: %s", resp.Status, excerpt)
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

// httpClient builds the per-store TLS client: the store's caBundle anchors the server,
// the node's client certificate rides the handshake for cert auth.
func (v *Vault) httpClient(store *secretsv1.SecretStore) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, GetClientCertificate: v.getCert}
	if len(store.Spec.CABundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(store.Spec.CABundle) {
			return nil, fmt.Errorf("secretstore %s/%s: caBundle holds no certificate", store.Namespace, store.Name)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// filterKeys projects the comma-separated keys annotation onto the fetched values; empty
// means every key. A listed key absent at the path is an error (fail-closed), the same
// way a missing Items key is on an inline secret.
func filterKeys(data map[string][]byte, csv string) (map[string][]byte, error) {
	if strings.TrimSpace(csv) == "" {
		return data, nil
	}
	out := map[string][]byte{}
	for _, k := range strings.Split(csv, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		val, ok := data[k]
		if !ok {
			return nil, fmt.Errorf("key %q not found at the store path", k)
		}
		out[k] = val
	}
	return out, nil
}
