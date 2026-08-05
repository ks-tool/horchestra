package v1

import (
	"fmt"
	"strings"
)

// CredentialUsername and CredentialPassword are the two keys a database role projects,
// static or dynamic. They are Vault's own field names, so a manifest listing them in the keys
// annotation reads the same as the Vault response it selects from.
const (
	CredentialUsername = "username"
	CredentialPassword = "password"
)

// EngineRole names a role on a Vault/OpenBao secrets engine: the engine's mount and the role
// on it. One type for both credential shapes, because only the endpoint differs.
//
// A STATIC role is the middle ground between a KV path and a full dynamic credential. Vault
// owns ONE fixed database user and rotates its password on its own schedule; there is no
// lease to hold and nothing to renew, so nothing on a node has to stay alive to keep the
// credential alive — but the long-lived shared password an operator forgets to change is
// gone all the same. What it does not give is a per-consumer identity: every workload reading
// the role gets the same user, so the database's audit log names the role, not the caller.
//
// A DYNAMIC role is the other half of that trade: Vault CREATES a database user per request
// and binds it to a lease, so each consumer is its own identity and revoking one touches
// nobody else. The cost is that the lease has to be held — renewed before it expires and
// released when the workload it belongs to goes away — which is machinery a static role needs
// none of.
type EngineRole struct {
	Mount string
	Role  string
}

// StaticCredsPath is where a static role's current credential is read from; CredsPath is
// where a dynamic one is issued.
func (r EngineRole) StaticCredsPath() string { return r.Mount + "/static-creds/" + r.Role }
func (r EngineRole) CredsPath() string       { return r.Mount + "/creds/" + r.Role }

// ParseEngineRole reads the annotation form, "<mount>/<role>" — e.g. "database/app-rw", or
// "db/prod/app-rw" for an engine mounted deeper. The LAST segment is the role and
// everything before it the mount, which is how Vault addresses one.
//
// Both halves are validated here rather than at the request, because this string becomes a
// URL path on a node: an empty half would read the engine's list endpoint instead of a
// credential, and a traversal segment would read some other engine entirely under the
// node's own token.
func ParseEngineRole(v string) (EngineRole, error) {
	v = strings.Trim(strings.TrimSpace(v), "/")
	i := strings.LastIndex(v, "/")
	if i < 0 {
		return EngineRole{}, fmt.Errorf("%q: want <mount>/<role>, e.g. database/app-rw", v)
	}
	ref := EngineRole{Mount: v[:i], Role: v[i+1:]}
	for _, part := range []struct{ name, value string }{{"mount", ref.Mount}, {"role", ref.Role}} {
		if part.value == "" {
			return EngineRole{}, fmt.Errorf("%q: the %s is empty", v, part.name)
		}
		for seg := range strings.SplitSeq(part.value, "/") {
			if seg == "" || seg == "." || seg == ".." {
				return EngineRole{}, fmt.Errorf("%q: %q is not a path segment", v, seg)
			}
		}
	}
	if strings.ContainsAny(v, " \t\r\n?#%") {
		return EngineRole{}, fmt.Errorf("%q: a mount or role may not carry whitespace or URL punctuation", v)
	}
	return ref, nil
}
