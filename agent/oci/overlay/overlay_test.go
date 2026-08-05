package overlay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The layer order is a security property, not a formatting detail: overlayfs resolves its
// lowerdir list left to right, so a reversal that dropped out would let a base layer shadow
// the application layer on top of it.
func TestLowerdirOptionReversesToOverlayOrder(t *testing.T) {
	opts, err := lowerdirOption([]string{"/mountpoints", "/base", "/app"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "lowerdir=/app:/base:/mountpoints,ro"; opts != want {
		t.Fatalf("lowerdirOption = %q, want %q", opts, want)
	}
}

func TestLowerdirOptionRejectsShortStack(t *testing.T) {
	for _, dirs := range [][]string{nil, {"/only"}} {
		if _, err := lowerdirOption(dirs); err == nil {
			t.Fatalf("accepted %d lower layers", len(dirs))
		}
	}
}

func TestLowerdirOptionRejectsSeparatorsInPaths(t *testing.T) {
	for _, bad := range []string{"/lay:er", "/lay,er"} {
		if _, err := lowerdirOption([]string{"/base", bad}); err == nil {
			t.Fatalf("accepted lower layer %q", bad)
		}
	}
}

func TestLowerdirOptionRejectsOversizedStack(t *testing.T) {
	dirs := make([]string, 64)
	for i := range dirs {
		dirs[i] = "/layers/" + strings.Repeat("a", 64)
	}
	if _, err := lowerdirOption(dirs); err == nil {
		t.Fatal("accepted an option string past the kernel mount-option limit")
	}
}

func TestEnsureWithin(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	if err := os.MkdirAll(filepath.Join(root, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}

	if err := EnsureWithin(root, filepath.Join(root, "run")); err != nil {
		t.Fatalf("rejected a contained target: %v", err)
	}
	// The target need not exist yet — mounts are made on directories created afterwards.
	if err := EnsureWithin(root, filepath.Join(root, "run", "state")); err != nil {
		t.Fatalf("rejected a contained target that does not exist yet: %v", err)
	}
	if err := EnsureWithin(root, filepath.Join(root, "escape")); err == nil {
		t.Fatal("accepted a symlink out of the root")
	}
	if err := EnsureWithin(root, filepath.Join(root, "escape", "deeper")); err == nil {
		t.Fatal("accepted a path under a symlink out of the root")
	}
}
