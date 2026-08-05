//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The config lists layers bottom-to-top; overlayfs takes them top-to-bottom. Getting this
// backwards stacks every image upside down without any error to notice.
func TestOverlayOptionsReversesToKernelOrder(t *testing.T) {
	opts, err := overlayOptions([]string{"/skeleton", "/base", "/top"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "lowerdir=/top:/base:/skeleton,ro"; opts != want {
		t.Errorf("opts = %q, want %q", opts, want)
	}
}

func TestOverlayOptionsRejectsEmptyAndOversized(t *testing.T) {
	if _, err := overlayOptions(nil); err == nil {
		t.Error("expected an error with no layers")
	}
	var many []string
	for i := 0; i < 200; i++ {
		many = append(many, "/var/lib/layers/"+strings.Repeat("a", 40))
	}
	if _, err := overlayOptions(many); err == nil {
		t.Error("expected an error once the option string exceeds the kernel limit")
	}
}

// An image shipping /var/run -> /run (or worse, an absolute link out of the tree) must not be
// able to redirect a mount onto the host.
func TestEnsureWithin(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("run", filepath.Join(root, "var-run")); err != nil {
		t.Fatal(err)
	}

	if err := ensureWithin(root, filepath.Join(root, "run")); err != nil {
		t.Errorf("a plain directory inside the root: %v", err)
	}
	if err := ensureWithin(root, filepath.Join(root, "var-run")); err != nil {
		t.Errorf("a relative symlink staying inside the root: %v", err)
	}
	if err := ensureWithin(root, filepath.Join(root, "tmp", "not-yet")); err != nil {
		t.Errorf("a path that does not exist yet but stays inside: %v", err)
	}
	if err := ensureWithin(root, filepath.Join(root, "escape")); err == nil {
		t.Error("a symlink pointing out of the root must be refused")
	}
	if err := ensureWithin(root, filepath.Join(root, "escape", "deeper")); err == nil {
		t.Error("a path under an escaping symlink must be refused")
	}
}

// A volume at /run/state must be mounted after /run, or the parent tmpfs masks it and the
// workload silently gets an empty directory instead of its volume.
func TestByDepthOrdersParentsFirst(t *testing.T) {
	got := byDepth([]TmpfsMount{{Path: "/run/state/deep"}, {Path: "/tmp"}, {Path: "/run/state"}, {Path: "/run"}})
	want := []string{"/tmp", "/run", "/run/state", "/run/state/deep"}
	for i := range want {
		if got[i].Path != want[i] {
			t.Fatalf("byDepth = %v, want %v", got, want)
		}
	}
}
