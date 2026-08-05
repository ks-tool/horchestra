// Package oidc is the controller's workload-identity issuer: it mints the short-lived
// per-workload tokens the nodes exchange for Vault tokens — shaped like Kubernetes
// projected service-account tokens — and answers the TokenReview calls Vault's stock
// kubernetes auth method validates them with (kubernetes_host = this controller). The
// controller thereby enters the CREDENTIAL path, never the value path: a token authorizes
// a fetch, the fetched value still goes server→node directly.
//
// The signing key is dedicated — never the TLS key — so certificate rotation and token
// trust stay independent. ES256 only: one modern algorithm, no negotiation surface.
package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// The audiences live in api/core/v1: an audience is who a credential is FOR, which is model
// vocabulary a manifest names (`volume.audience`), not a detail of how a token is signed. Neither
// is accepted where the other belongs — a workload that mounts a catalog token has not been handed
// a Vault login, and a Vault login presented at this API does not authenticate.
const TokenAudienceVault = corev1.TokenAudienceVault

// WorkloadTokenTTL is the minted token's lifetime. Short: a token exists only to be
// exchanged at the next materialization, and the controller re-mints and re-pushes over
// the Session well before expiry.
const WorkloadTokenTTL = 15 * time.Minute

// Issuer signs workload-identity tokens with a dedicated ES256 key and validates them
// back for TokenReview.
type Issuer struct {
	key    *ecdsa.PrivateKey
	kid    string
	issuer string
	now    func() time.Time
}

// LoadOrGenerate builds the issuer from the PEM EC private key at path, generating and
// persisting one (0600) on first use — the key must survive restarts, or every
// outstanding token dies with the process that minted it. issuer becomes the iss claim.
func LoadOrGenerate(path, issuer string) (*Issuer, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		key, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if kerr != nil {
			return nil, kerr
		}
		der, kerr := x509.MarshalECPrivateKey(key)
		if kerr != nil {
			return nil, kerr
		}
		b = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if kerr = os.WriteFile(path, b, 0o600); kerr != nil {
			return nil, fmt.Errorf("persist the signing key: %w", kerr)
		}
	} else if err != nil {
		return nil, err
	}
	return New(b, issuer)
}

// New builds the issuer from a PEM EC private key.
func New(keyPEM []byte, issuer string) (*Issuer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("jwt signing key: not PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwt signing key: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("jwt signing key: ES256 needs a P-256 key, got %s", key.Curve.Params().Name)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pub)
	return &Issuer{key: key, kid: base64.RawURLEncoding.EncodeToString(sum[:8]), issuer: issuer, now: time.Now}, nil
}

// MintWorkloadToken mints the identity token for one namespace-qualified workload id
// ("<ns>_<name>"). The token has the SHAPE of a Kubernetes projected service-account
// token — sub system:serviceaccount:<ns>:<name> plus the kubernetes.io claim block — so
// Vault/OpenBao's stock kubernetes auth method accepts it as-is (roles bind plain
// service-account names/namespaces, TokenReview validates it against this controller).
// uid is the workload's object UID, so a delete-and-recreate under the same name is a
// visibly different identity.
func (i *Issuer) MintWorkloadToken(workload, uid, audience string) (token string, exp time.Time, err error) {
	if audience == "" {
		audience = TokenAudienceVault
	}
	ns, name, _ := strings.Cut(workload, "_")
	now := i.now()
	exp = now.Add(WorkloadTokenTTL)
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": i.kid})
	if err != nil {
		return "", time.Time{}, err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": i.issuer,
		"sub": WorkloadSubject(workload),
		"aud": []string{audience},
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      ns,
			"serviceaccount": map[string]string{"name": name, "uid": uid},
		},
	})
	if err != nil {
		return "", time.Time{}, err
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, digest[:])
	if err != nil {
		return "", time.Time{}, err
	}
	// JWS ES256: fixed-width big-endian r||s, 32 bytes each — not ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), exp, nil
}

// WorkloadSubject is the sub claim for a namespace-qualified workload id ("<ns>_<name>",
// the WorkloadID form the push already keys everything by). The service-account form is
// deliberate: it is what Vault's kubernetes auth method parses role bindings against.
func WorkloadSubject(workloadID string) string {
	ns, name, ok := strings.Cut(workloadID, "_")
	if !ok {
		return "system:serviceaccount::" + workloadID
	}
	return "system:serviceaccount:" + ns + ":" + name
}
