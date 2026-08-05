package oidc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	i, err := LoadOrGenerate(filepath.Join(t.TempDir(), "jwt.key"), "horchestra")
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// TestMintedTokenVerifies pins the token contract: ES256 over the signing input, the
// projected-SA-token claim shape (sub + kubernetes.io) Vault's kubernetes auth method
// parses, and acceptance by the issuer's own verifier (the one behind TokenReview).
func TestMintedTokenVerifies(t *testing.T) {
	i := testIssuer(t)
	token, exp, err := i.MintWorkloadToken("team-a_web", "uid-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(exp) <= 0 || time.Until(exp) > WorkloadTokenTTL {
		t.Fatalf("exp = %v, want within (now, now+%v]", exp, WorkloadTokenTTL)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	var header struct{ Alg, Typ, Kid string }
	mustDecodeJSON(t, parts[0], &header)
	if header.Alg != "ES256" || header.Kid != i.kid {
		t.Fatalf("header = %+v", header)
	}
	var claims struct {
		Iss, Sub   string
		Aud        []string
		Kubernetes struct {
			Namespace      string                     `json:"namespace"`
			ServiceAccount struct{ Name, UID string } `json:"serviceaccount"`
		} `json:"kubernetes.io"`
	}
	mustDecodeJSON(t, parts[1], &claims)
	if claims.Iss != "horchestra" || claims.Sub != "system:serviceaccount:team-a:web" ||
		len(claims.Aud) != 1 || claims.Aud[0] != TokenAudienceVault {
		t.Fatalf("claims = %+v", claims)
	}
	if claims.Kubernetes.Namespace != "team-a" || claims.Kubernetes.ServiceAccount.Name != "web" ||
		claims.Kubernetes.ServiceAccount.UID != "uid-1" {
		t.Fatalf("kubernetes.io claims = %+v", claims.Kubernetes)
	}

	// The raw signature is fixed-width r||s over the signing input.
	sig := mustB64(t, parts[2])
	if len(sig) != 64 {
		t.Fatalf("signature length %d, want 64 (fixed-width r||s)", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&i.key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the minted signature does not verify against the signing key")
	}

	// And the production verifier agrees, returning the parsed identity.
	got, err := i.VerifyToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if got.Namespace != "team-a" || got.Name != "web" || got.UID != "uid-1" {
		t.Fatalf("verified claims = %+v", got)
	}
}

// TestLoadOrGeneratePersists: the key must survive a controller restart, or every
// outstanding token dies with the process that minted it.
func TestLoadOrGeneratePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwt.key")
	a, err := LoadOrGenerate(path, "horchestra")
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrGenerate(path, "horchestra")
	if err != nil {
		t.Fatal(err)
	}
	if a.kid != b.kid {
		t.Fatal("a second load must reuse the persisted key (same kid)")
	}
}

func mustDecodeJSON(t *testing.T, b64 string, into any) {
	t.Helper()
	raw := mustB64(t, b64)
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
