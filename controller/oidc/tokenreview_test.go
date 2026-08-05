package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func postReview(t *testing.T, h http.HandlerFunc, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// TestTokenReview is the stock-kubernetes-auth contract: Vault posts a TokenReview with
// the login JWT as its own bearer, and reads back authenticated + the service-account
// username it binds roles against.
func TestTokenReview(t *testing.T) {
	i := testIssuer(t)
	token, _, err := i.MintWorkloadToken("team-a_web", "uid-1", "")
	if err != nil {
		t.Fatal(err)
	}
	h := i.TokenReviewHandler()

	w := postReview(t, h, token, `{"spec":{"token":"`+token+`"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	var resp struct {
		Kind   string `json:"kind"`
		Status struct {
			Authenticated bool `json:"authenticated"`
			User          struct {
				Username string   `json:"username"`
				UID      string   `json:"uid"`
				Groups   []string `json:"groups"`
			} `json:"user"`
		} `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Kind != "TokenReview" || !resp.Status.Authenticated {
		t.Fatalf("resp = %s", w.Body.String())
	}
	if resp.Status.User.Username != "system:serviceaccount:team-a:web" || resp.Status.User.UID != "uid-1" {
		t.Fatalf("user = %+v", resp.Status.User)
	}

	// A garbage reviewed token is a NORMAL answer with authenticated=false — how the real
	// API reports it, and what lets Vault distinguish "invalid login" from "broken host".
	w = postReview(t, h, token, `{"spec":{"token":"garbage"}}`)
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatalf("want authenticated=false for garbage, got %d %s", w.Code, w.Body.String())
	}

	// No (or foreign) reviewer bearer → 401: the endpoint is not an open token oracle.
	if w = postReview(t, h, "", `{"spec":{"token":"`+token+`"}}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without a bearer, got %d", w.Code)
	}

	// An expired token no longer reviews as authenticated.
	i.now = func() time.Time { return time.Now().Add(WorkloadTokenTTL + 2*verifySkew) }
	w = postReview(t, h, token, `{"spec":{"token":"`+token+`"}}`)
	if w.Code != http.StatusUnauthorized && strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatalf("an expired token must not authenticate: %d %s", w.Code, w.Body.String())
	}
}

// TestTokenReviewAudiences: a requested audience the token does not carry fails; the
// matching one narrows.
func TestTokenReviewAudiences(t *testing.T) {
	i := testIssuer(t)
	token, _, err := i.MintWorkloadToken("team-a_web", "uid-1", "")
	if err != nil {
		t.Fatal(err)
	}
	h := i.TokenReviewHandler()
	w := postReview(t, h, token, `{"spec":{"token":"`+token+`","audiences":["vault"]}}`)
	if !strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatalf("aud=vault must authenticate: %s", w.Body.String())
	}
	w = postReview(t, h, token, `{"spec":{"token":"`+token+`","audiences":["other"]}}`)
	if strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatalf("a foreign audience must not authenticate: %s", w.Body.String())
	}
}
