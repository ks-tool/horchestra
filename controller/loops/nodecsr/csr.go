// Package nodecsr is the control-plane approval loop for node CertificateSigningRequests. The
// only auto-approved path is selfnodeclient rotation: a verified system:nodes identity re-issuing
// a short-lived certificate for its OWN name (requester CN == subject CN). It signs such a CSR
// into a fresh system:nodes client certificate — the signing groups are the loop's decision
// (system:nodes), never taken from the CSR, so a request cannot escalate to system:masters.
// Initial node identity is provisioned out-of-band by node-tool (which owns the PKI), so any
// non-rotation CSR is left Pending for manual/offline-CA approval.
package nodecsr

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	"github.com/ks-tool/horchestra/api/types"

	"github.com/rs/zerolog"
)

const (
	// defaultTTL is the ~90-day lifetime of an issued node certificate. A short TTL plus rotation
	// is the only revocation lever (there is no CRL).
	defaultTTL = 90 * 24 * time.Hour
	// defaultRetention is how long a decided (Approved/Denied) CSR is kept before it is
	// garbage-collected — long enough for the node to poll its signed certificate, then reclaimed.
	defaultRetention = 1 * time.Hour
	// defaultMaxPendingAge bounds how long an un-approved (Pending) CSR lingers, so a node cannot
	// pile up unbounded requests; a still-wanted CSR is simply re-created on the next attempt.
	defaultMaxPendingAge = 24 * time.Hour
)

// Signer signs an approved CSR into a client certificate; *pki.CA satisfies it. A nil signer
// is offline-CA mode: approved CSRs are marked Approved and signed out-of-band.
type Signer interface {
	SignCSR(csrPEM []byte, groups []string, ttl time.Duration) (certPEM []byte, err error)
}

// Cluster is the control-plane surface the approval loop reads and writes.
type Cluster interface {
	CSRs(ctx context.Context) ([]certv1.CertificateSigningRequest, error)
	UpdateCSRStatus(ctx context.Context, csr *certv1.CertificateSigningRequest) error
	DeleteCSR(ctx context.Context, name string) error
}

// Config holds the loop's signer, cert TTL and CSR garbage-collection ages.
type Config struct {
	Signer Signer // nil = offline-CA mode
	// AutoApproval lets a node's renewal of its OWN certificate be signed without an
	// operator. The zero value holds every renewal Pending, which is the safe polarity for a
	// field a caller can forget: the composition root sets it from the AutoNodeCertRotation
	// feature gate, and the loop only needs to know which it is.
	AutoApproval  bool
	TTL           time.Duration
	Retention     time.Duration // how long a decided CSR is kept before GC (default 1h)
	MaxPendingAge time.Duration // how long a Pending CSR may linger before GC (default 24h)
	Logger        *zerolog.Logger
}

// Controller is the loop.Reconciler that approves and signs node CSRs.
type Controller struct {
	cluster       Cluster
	signer        Signer
	autoApprove   bool
	ttl           time.Duration
	retention     time.Duration
	maxPendingAge time.Duration
	now           func() time.Time
	log           zerolog.Logger
}

// New builds the controller.
func New(cluster Cluster, cfg Config) *Controller {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	retention := cfg.Retention
	if retention <= 0 {
		retention = defaultRetention
	}
	maxPendingAge := cfg.MaxPendingAge
	if maxPendingAge <= 0 {
		maxPendingAge = defaultMaxPendingAge
	}
	log := zerolog.Nop()
	if cfg.Logger != nil {
		log = *cfg.Logger
	}
	return &Controller{
		cluster: cluster, signer: cfg.Signer, autoApprove: cfg.AutoApproval, ttl: ttl,
		retention: retention, maxPendingAge: maxPendingAge, now: time.Now, log: log,
	}
}

func (*Controller) Name() string { return "nodecsr" }

func (*Controller) Watches() []types.ObjectMeta {
	return []types.ObjectMeta{{ApiVersion: certv1.GroupVersion.String(), Kind: "CertificateSigningRequest"}}
}

func (c *Controller) ReconcileOnce(ctx context.Context) { c.reconcileOnce(ctx) }

func (c *Controller) reconcileOnce(ctx context.Context) {
	csrs, err := c.cluster.CSRs(ctx)
	if err != nil {
		c.log.Error().Err(err).Msg("nodecsr: list csrs")
		return
	}
	for i := range csrs {
		if c.gc(ctx, &csrs[i]) {
			continue // reclaimed; nothing more to do with it
		}
		c.reconcileCSR(ctx, &csrs[i])
	}
}

// gc reclaims a spent or stale CSR, reporting whether it deleted it. A decided (Approved/Denied)
// CSR is kept for `retention` — long enough for the node to fetch its certificate — then removed;
// an un-approved Pending CSR older than maxPendingAge is removed so a node cannot accumulate
// unbounded requests (a still-wanted CSR is re-created). A CSR with no creation timestamp is left
// alone.
func (c *Controller) gc(ctx context.Context, csr *certv1.CertificateSigningRequest) bool {
	created := csr.CreationTimestamp.Time
	if created.IsZero() {
		return false
	}
	age := c.now().Sub(created)
	decided := csr.Status.Phase != "" && csr.Status.Phase != certv1.CSRPending
	switch {
	case decided && age > c.retention:
	case !decided && age > c.maxPendingAge:
	default:
		return false
	}
	if err := c.cluster.DeleteCSR(ctx, csr.Name); err != nil {
		c.log.Warn().Err(err).Str("csr", csr.Name).Msg("nodecsr: gc")
		return false
	}
	c.log.Info().Str("csr", csr.Name).Dur("age", age).Bool("decided", decided).Msg("nodecsr: garbage-collected CSR")
	return true
}

func (c *Controller) reconcileCSR(ctx context.Context, csr *certv1.CertificateSigningRequest) {
	if csr.Status.Phase != "" && csr.Status.Phase != certv1.CSRPending {
		return // already decided
	}
	cn, err := csrCommonName(csr.Spec.Request)
	if err != nil {
		c.setStatus(ctx, csr, certv1.CertificateSigningRequestStatus{Phase: certv1.CSRDenied, Reason: "unparseable CSR: " + err.Error()})
		return
	}
	// Rotation is the only auto-approved path: a verified system:nodes identity re-issuing a
	// cert for its OWN name. Its CN is the node's own, so there is no squatting risk. Anything
	// else is left Pending — initial node identity is provisioned out-of-band by node-tool,
	// and an operator can approve any other CSR manually — but it is left Pending WITH THE
	// REASON, because a request that will never move on its own and says nothing about why is
	// indistinguishable from one the loop has not reached yet.
	if why := notSelfRotation(csr, cn); why != "" {
		c.hold(ctx, csr, cn, why)
		return
	}
	if !c.autoApprove {
		c.hold(ctx, csr, cn, "automatic node certificate rotation is off (--feature-gates=AutoNodeCertRotation=true enables it)")
		return
	}
	c.sign(ctx, csr, cn)
}

// remedies is what an operator can actually DO about a held request, named on the object
// because none of it is an operation on the object.
const remedies = "issue it out of band with `node-tool cert`, turn the automation on with " +
	"--feature-gates=AutoNodeCertRotation=true, or sign through a Vault PKI engine (--pki-vault), " +
	"where the PKI role is the policy"

// hold leaves a request Pending and says why, once.
//
// For a rotation the identity check above is satisfied by whoever holds the node's key, so it
// cannot tell a thief from the owner — and neither can anything else here: a live session
// proves only that SOMEONE is connected, and it is the real agent's session that would satisfy
// any test for one. Rather than pretend otherwise, this path removes the automation.
//
// What it does NOT do is wait for an approval, and the reason says so. There is no approval
// verb: a CertificateSigningRequest has no status subresource, a whole-object write cannot
// carry a status, and the loop never re-decides a request it has already held. A held request
// is a SIGNAL, and every remedy for it is outside the object — which is why the earlier
// "awaiting operator approval" was worse than saying nothing: it named an action that does not
// exist and sent an operator looking for it.
//
// Stamped only once: the loop re-lists on every wake, and a per-tick write would wake every
// watcher of this Kind for as long as the request sits there.
func (c *Controller) hold(ctx context.Context, csr *certv1.CertificateSigningRequest, cn, why string) {
	if csr.Status.Reason != "" {
		return
	}
	c.setStatus(ctx, csr, certv1.CertificateSigningRequestStatus{
		Phase:  certv1.CSRPending,
		Reason: "held: " + why + " — " + remedies,
	})
	c.log.Info().Str("csr", csr.Name).Str("cn", cn).Str("reason", why).
		Msg("nodecsr: held; this controller will not sign it on its own")
}

// notSelfRotation explains why a request is not a node renewing its own certificate, or
// returns empty when it is. The explanation is the message an operator reads, so it names the
// two identities that failed to match rather than reporting that a predicate was false.
func notSelfRotation(csr *certv1.CertificateSigningRequest, cn string) string {
	requester := csr.Annotations[certv1.AnnRequester]
	switch {
	case cn == "":
		return "the request carries no common name, so it names no identity to issue a certificate for"
	case requester == "":
		return "the request carries no verified requester, so it cannot be a node renewing its own certificate"
	case !slices.Contains(strings.Split(csr.Annotations[certv1.AnnRequesterGroups], ","), certv1.GroupNodes):
		return fmt.Sprintf("%q is not a %s identity, and only a node renews a node certificate", requester, certv1.GroupNodes)
	case requester != cn:
		return fmt.Sprintf("%q asks for a certificate naming %q, and a node renews only its own name", requester, cn)
	}
	return ""
}

// sign issues the certificate for an approved CSR (or records the approval in offline-CA mode).
func (c *Controller) sign(ctx context.Context, csr *certv1.CertificateSigningRequest, cn string) {
	if c.signer == nil {
		// Offline-CA mode: record the approval; node-tool signs the CSR out-of-band.
		c.setStatus(ctx, csr, certv1.CertificateSigningRequestStatus{Phase: certv1.CSRApproved})
		return
	}
	certPEM, err := c.signer.SignCSR(csr.Spec.Request, []string{certv1.GroupNodes}, c.ttl)
	if err != nil {
		c.log.Error().Err(err).Str("csr", csr.Name).Msg("nodecsr: sign")
		return
	}
	c.setStatus(ctx, csr, certv1.CertificateSigningRequestStatus{Phase: certv1.CSRApproved, Certificate: certPEM})
	c.log.Info().Str("csr", csr.Name).Str("cn", cn).Msg("nodecsr: approved and signed")
}

func (c *Controller) setStatus(ctx context.Context, csr *certv1.CertificateSigningRequest, status certv1.CertificateSigningRequestStatus) {
	csr.Status = status
	if err := c.cluster.UpdateCSRStatus(ctx, csr); err != nil {
		c.log.Warn().Err(err).Str("csr", csr.Name).Msg("nodecsr: write status")
	}
}

func csrCommonName(csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return "", fmt.Errorf("not a PEM block")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	return req.Subject.CommonName, nil
}
