package v1

import "testing"

// TestParseStaticRole: the annotation becomes a URL path on a node, under the node's own
// Vault token. So the split is pinned (the LAST segment is the role, everything before it
// the mount, which is how Vault addresses one) and anything that would address a different
// endpoint is refused here — where admission and the agent both parse through this one
// function and so cannot disagree.
func TestParseEngineRole(t *testing.T) {
	for in, want := range map[string]string{
		"database/app-rw":     "database/static-creds/app-rw",
		"/database/app-rw/":   "database/static-creds/app-rw",
		"  database/app-rw  ": "database/static-creds/app-rw",
		"db/prod/app-rw":      "db/prod/static-creds/app-rw", // an engine mounted deeper
	} {
		ref, err := ParseEngineRole(in)
		if err != nil {
			t.Errorf("ParseEngineRole(%q): %v", in, err)
			continue
		}
		if ref.StaticCredsPath() != want {
			t.Errorf("ParseEngineRole(%q).Path() = %q, want %q", in, ref.StaticCredsPath(), want)
		}
	}

	for _, bad := range []string{
		"",                     // nothing
		"app-rw",               // no mount: would read the engine's own root
		"database/",            // no role: the engine's list endpoint
		"/app-rw",              // ditto, once trimmed
		"database/../secret/x", // another engine entirely
		"database/./app-rw",
		"database//app-rw",
		"database/app rw",  // a space splits a URL
		"database/app?x=1", // query punctuation
		"database/app#f",
		"database/app\nrw",
	} {
		if ref, err := ParseEngineRole(bad); err == nil {
			t.Errorf("ParseEngineRole(%q) was accepted as %q", bad, ref.StaticCredsPath())
		}
	}
}
