package authz

import (
	"slices"
	"strings"
)

// nonResourceGrant is one projected rule over request paths: the methods it allows and the
// paths it allows them on. It is kept out of the Casbin table on purpose — every column there
// is matched by equality or a bare "*", and a path is matched by prefix, so putting one in
// would mean either a second model or a wildcard that means something different per column.
type nonResourceGrant struct {
	verbs []string
	urls  []string
}

// allows reports whether this grant covers verb on path.
func (g nonResourceGrant) allows(verb, path string) bool {
	if !slices.Contains(g.verbs, verb) && !slices.Contains(g.verbs, "*") {
		return false
	}
	return slices.ContainsFunc(g.urls, func(u string) bool { return matchesPath(u, path) })
}

// matchesPath reports whether the nonResourceURLs pattern covers path. A trailing "*" matches
// by prefix and "*" alone matches everything; anything else is compared literally, so a pattern
// is never accidentally a subtree. This is Kubernetes' rule, kept identical so a manifest that
// works there works here.
func matchesPath(pattern, path string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(path, prefix)
	}
	return pattern == path
}

// allowsPath reports whether any of the caller's subjects holds a nonResourceURLs grant
// covering this request.
func (c *Casbin) allowsPath(at Attributes) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.paths) == 0 {
		return false
	}
	for _, sub := range subjectsOf(at.User) {
		for _, g := range c.paths[sub] {
			if g.allows(at.Verb, at.Path) {
				return true
			}
		}
	}
	return false
}
