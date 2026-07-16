package authn

import (
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
)

type Identity struct {
	Name   string
	Groups []string
}

type Authenticator interface {
	Authenticate(r *http.Request) (*Identity, error)
}

var ErrUnauthenticated = errors.New("no valid credentials")

type AllowAll struct{}

func (AllowAll) Authenticate(*http.Request) (*Identity, error) {
	return &Identity{Name: "system:admin", Groups: []string{"system:masters"}}, nil
}

type Chain struct {
	Tokens map[string]Identity
}

func (c Chain) Authenticate(r *http.Request) (*Identity, error) {
	if id := identityFromClientCert(r.TLS); id != nil {
		return id, nil
	}
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		if id, ok := c.Tokens[strings.TrimPrefix(v, "Bearer ")]; ok {
			return &Identity{Name: id.Name, Groups: id.Groups}, nil
		}
	}
	return nil, ErrUnauthenticated
}

// identityFromClientCert maps a verified client certificate's CN to the user
// name and its Organization values to groups.
func identityFromClientCert(cs *tls.ConnectionState) *Identity {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return nil
	}
	leaf := cs.VerifiedChains[0][0]
	if len(leaf.Subject.CommonName) == 0 {
		return nil
	}
	return &Identity{Name: leaf.Subject.CommonName, Groups: leaf.Subject.Organization}
}
