package oci

import (
	"github.com/opencontainers/go-digest"

	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStoreKeyIsNamespaceScoped locks the tenancy of the store key: the same
// source in two namespaces yields two keys (so one tenant can never address —
// let alone evict — another's binding), the pair is unambiguous, and the key is
// always a safe file name.
func TestStoreKeyIsNamespaceScoped(t *testing.T) {
	if storeKey("team-a", "app:v1") == storeKey("team-b", "app:v1") {
		t.Fatal("the same source in two namespaces must map to two store keys")
	}
	if storeKey("", "app:v1") == storeKey("ns", "app:v1") {
		t.Fatal("the empty namespace must not collide with a named one")
	}
	// The pair must be unambiguous: no concatenation of (namespace, source) may
	// alias another split of the same bytes.
	if storeKey("ab", "c") == storeKey("a", "bc") {
		t.Fatal("(namespace, source) must be separated unambiguously")
	}
	key := storeKey("team-a", "reg.example/app:v1")
	if key != storeKey("team-a", "reg.example/app:v1") {
		t.Fatal("the key must be stable")
	}
	if strings.ContainsAny(key, "/:@") || len(key) != 64 {
		t.Fatalf("key %q must be a fixed-width hex file name", key)
	}
}

// TestRefRoundTrip checks two tenants' bindings for the same image coexist: both
// resolve to the shared digest, neither write disturbs the other, and removing
// one leaves the other readable — the property whose absence caused the eviction
// ping-pong.
func TestRefRoundTrip(t *testing.T) {
	layout := t.TempDir()
	shared := digestOf([]byte("one manifest, two tenants"))
	if err := writeRef(layout, "team-a", "app:v1", shared); err != nil {
		t.Fatal(err)
	}
	if err := writeRef(layout, "team-b", "docker.io/app:v1", shared); err != nil {
		t.Fatal(err)
	}
	// Re-binding the same pair must be idempotent, not additive.
	if err := writeRef(layout, "team-a", "app:v1", shared); err != nil {
		t.Fatal(err)
	}

	a, err := readRef(layout, "team-a", "app:v1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := readRef(layout, "team-b", "docker.io/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != shared || b.Digest != shared {
		t.Fatalf("both bindings must resolve to the shared digest, got %s and %s", a.Digest, b.Digest)
	}
	if a.Namespace != "team-a" || b.Namespace != "team-b" {
		t.Fatalf("bindings must record their namespaces, got %q and %q", a.Namespace, b.Namespace)
	}

	refs, err := listRefs(layout)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("listRefs = %d bindings, want 2", len(refs))
	}
	for _, r := range refs {
		if !r.valid() {
			t.Errorf("binding %q/%q must sit at its storeKey file", r.Namespace, r.Source)
		}
	}

	if err := os.Remove(refPath(layout, "team-a", "app:v1")); err != nil {
		t.Fatal(err)
	}
	if _, err := readRef(layout, "team-a", "app:v1"); err == nil {
		t.Fatal("a removed binding must read as a miss")
	}
	if _, err := readRef(layout, "team-b", "docker.io/app:v1"); err != nil {
		t.Fatalf("removing one tenant's binding must not touch the other's: %v", err)
	}
}

// TestListRefsFailsLoudlyOnCorruption: a corrupt binding must fail the listing
// (purge would otherwise treat its image as unreferenced wreckage and delete it
// out from under the binding) — never be skipped silently.
func TestListRefsFailsLoudlyOnCorruption(t *testing.T) {
	layout := t.TempDir()
	if err := writeRef(layout, "team-a", "app:v1", digestOf([]byte("m"))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, refsDir, storeKey("team-b", "other")), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listRefs(layout); err == nil {
		t.Fatal("a corrupt binding must fail the listing loudly")
	}
}

// digestOf is a stand-in manifest digest: the tests only need two distinct, well-formed ones.
func digestOf(b []byte) digest.Digest { return digest.FromBytes(b) }
