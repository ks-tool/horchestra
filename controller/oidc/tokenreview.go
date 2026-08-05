package oidc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"
)

// verifySkew tolerates clock drift between the controller and a validator on nbf/exp.
const verifySkew = 60 * time.Second

// WorkloadClaims is what a verified workload token asserts.
type WorkloadClaims struct {
	Subject   string // system:serviceaccount:<ns>:<name>
	Namespace string
	Name      string
	UID       string
	Audiences []string
}

// VerifyToken checks a compact JWS against the issuer's own key — signature, kid, and the
// nbf/exp window — and returns its claims. It is the validation half behind TokenReview:
// only tokens this issuer minted ever verify.
func (i *Issuer) VerifyToken(token string) (*WorkloadClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWS")
	}
	headerB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	var header struct{ Alg, Kid string }
	if err := json.Unmarshal(headerB, &header); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	if header.Alg != "ES256" || header.Kid != i.kid {
		return nil, fmt.Errorf("unknown signing key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf("malformed signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&i.key.PublicKey, digest[:],
		new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, fmt.Errorf("signature mismatch")
	}
	claimsB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}
	var claims struct {
		Iss        string   `json:"iss"`
		Sub        string   `json:"sub"`
		Aud        []string `json:"aud"`
		Nbf        int64    `json:"nbf"`
		Exp        int64    `json:"exp"`
		Kubernetes struct {
			Namespace      string `json:"namespace"`
			ServiceAccount struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"serviceaccount"`
		} `json:"kubernetes.io"`
	}
	if err := json.Unmarshal(claimsB, &claims); err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}
	now := i.now()
	if claims.Iss != i.issuer {
		return nil, fmt.Errorf("issuer mismatch")
	}
	if now.Add(verifySkew).Unix() < claims.Nbf {
		return nil, fmt.Errorf("token not yet valid")
	}
	if now.Add(-verifySkew).Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}
	return &WorkloadClaims{
		Subject:   claims.Sub,
		Namespace: claims.Kubernetes.Namespace,
		Name:      claims.Kubernetes.ServiceAccount.Name,
		UID:       claims.Kubernetes.ServiceAccount.UID,
		Audiences: claims.Aud,
	}, nil
}

// TokenReviewHandler serves POST /apis/authentication.k8s.io/v1/tokenreviews — just
// enough of the Kubernetes TokenReview API for Vault/OpenBao's stock kubernetes auth
// method to validate workload tokens against this controller (kubernetes_host = the
// controller URL). An invalid reviewed token is a NORMAL response with
// status.authenticated=false, exactly as the real API answers.
//
// The request itself must be authenticated: the caller's bearer has to be a token this
// issuer signed. That is precisely what the auth method sends when token_reviewer_jwt is
// left unset — it reuses the login JWT as the reviewer credential — so a caller can only
// ever "probe" a token it already holds.
func (i *Issuer) TokenReviewHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, err := i.VerifyToken(bearer); err != nil {
			http.Error(w, "unauthorized: the reviewer bearer is not an issuer-signed token", http.StatusUnauthorized)
			return
		}
		var req struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "malformed TokenReview", http.StatusBadRequest)
			return
		}
		status := map[string]any{}
		if claims, err := i.VerifyToken(req.Spec.Token); err != nil {
			status["authenticated"] = false
			status["error"] = err.Error()
		} else if aud := audienceIntersection(claims.Audiences, req.Spec.Audiences); len(req.Spec.Audiences) > 0 && len(aud) == 0 {
			status["authenticated"] = false
			status["error"] = "token audience does not match the requested audiences"
		} else {
			status["authenticated"] = true
			status["audiences"] = aud
			status["user"] = map[string]any{
				"username": claims.Subject,
				"uid":      claims.UID,
				"groups":   []string{"system:serviceaccounts", "system:serviceaccounts:" + claims.Namespace},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // a create, as the real API answers it
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": "authentication.k8s.io/v1",
			"kind":       "TokenReview",
			"status":     status,
		})
	}
}

// audienceIntersection is the token's audiences narrowed to the requested ones (the
// token's own set when nothing was requested).
func audienceIntersection(token, requested []string) []string {
	if len(requested) == 0 {
		return token
	}
	out := []string{}
	for _, a := range token {
		if slices.Contains(requested, a) {
			out = append(out, a)
		}
	}
	return out
}
