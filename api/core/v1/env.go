package v1

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// ValidEnvName rejects an environment-variable name a shell or an environment file could not
// express: it must be non-empty and match [A-Za-z_][A-Za-z0-9_]*. The rule is not cosmetic —
// the resolved variables are written as an environment file the node's PID1 parses, and a name
// carrying '=', whitespace or a newline would either be dropped silently or split the line into
// a second assignment. Enforced at admission for an author-supplied name or prefix, and again
// on the node for the names a wildcard import derives from a Secret's keys.
func ValidEnvName(name, what string) error {
	if name == "" {
		return fmt.Errorf("%s is required", what)
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return fmt.Errorf("%s %q is not a valid environment variable name (letters, digits and '_', not starting with a digit)", what, name)
		}
	}
	return nil
}

// ValidEnvPrefix rejects a wildcard import prefix that would produce an invalid name. An empty
// prefix is fine (no prefix at all); otherwise it must be a legal name on its own, which also
// guarantees prefix+key is legal whenever key is.
func ValidEnvPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	return ValidEnvName(prefix, "env prefix")
}

// ValidEnvValue rejects a resolved value an environment file cannot carry: a newline would end
// the assignment and turn the remainder into a forged variable, and a NUL cannot survive
// execve. A multi-line credential (a PEM key, a kubeconfig) belongs in a file mount, so this
// fails loudly rather than truncating at the newline.
func ValidEnvValue(name, value string) error {
	if i := strings.IndexAny(value, "\n\r\x00"); i >= 0 {
		return fmt.Errorf("value of %s carries a newline or NUL at byte %d; an environment variable cannot express it — mount it as a file instead", name, i)
	}
	return nil
}

// SecretRefs returns the names of every Secret this Application consumes, from its volume
// mounts and from its env, deduplicated and sorted. It is the ONE definition of "which Secrets
// does this app use": the controller pushes exactly these to the app's node, refuses to delete
// one while an app still uses it, and validates that a non-optional one exists. Two copies of
// that predicate would diverge, and a Secret the node never receives is an app that never
// converges.
func (a Application) SecretRefs() []string { return a.secretRefs(true) }

// RequiredSecretRefs is SecretRefs limited to the references the application cannot start
// without — an optional one may be absent, so admission must not reject an app for it.
func (a Application) RequiredSecretRefs() []string { return a.secretRefs(false) }

func (a Application) secretRefs(includeOptional bool) []string {
	seen := map[string]struct{}{}
	for _, m := range a.Spec.Volumes {
		optional := m.Volume.Optional != nil && *m.Volume.Optional
		if m.IsSecret() && m.SecretName() != "" && (includeOptional || !optional) {
			seen[m.SecretName()] = struct{}{}
		}
	}
	for _, v := range a.Spec.Env {
		if v.IsSecret() && v.SecretRef.Name != "" && (includeOptional || !v.SecretRef.IsOptional()) {
			seen[v.SecretRef.Name] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}
