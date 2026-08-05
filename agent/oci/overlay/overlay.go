// Package overlay assembles an image's unpacked layers into a read-only overlayfs rootfs.
//
// It is in-tree rather than borrowed because this mount is the security boundary around
// tenant-supplied image content: the per-mount flags, the layer order and the refusal of a
// path that could splice itself into the option string are invariants this repository owns
// and tests, not behaviour to inherit and hope stays put.
package overlay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// lowerdirMaxBytes caps the overlayfs option string. The kernel limits mount options to one
// page (~4096 bytes); the rest is headroom for the flags.
const lowerdirMaxBytes = 3072

// MountOptions describes a read-only overlay mount built from unpacked layers.
type MountOptions struct {
	// LowerDirs are the layers bottom-to-top, the order a manifest records them in.
	// overlayfs reads its lowerdir list top-to-bottom, so Mount reverses them: get this
	// backwards and a base layer silently shadows the application on top of it.
	LowerDirs []string
	Target    string
	// Flags are per-mount VFS flags (MS_NOSUID, MS_NODEV, …) OR'd into the mount syscall.
	//
	// They belong here rather than in a follow-up remount because the kernel applies them
	// only on the call that creates the mount: anything added afterwards leaves a window in
	// which the mount is live without them. For image content that window is a local
	// privilege-escalation race — a setuid binary inside a tenant's layer is executable
	// until the second syscall lands.
	Flags uintptr
}

// lowerdirOption builds the overlayfs option string from layers given bottom-to-top.
//
// Fewer than two layers is refused rather than papered over with a synthetic empty one: the
// kernel wants at least two lowerdirs when there is no upperdir, and the caller already
// prepends a mount-point layer to every image, so a short list means the caller is broken.
func lowerdirOption(lowerDirs []string) (string, error) {
	if len(lowerDirs) < 2 {
		return "", fmt.Errorf("overlay needs at least 2 lower layers without an upperdir, got %d", len(lowerDirs))
	}
	rev := make([]string, len(lowerDirs))
	for i, d := range lowerDirs {
		if err := validLowerDir(d); err != nil {
			return "", err
		}
		rev[len(lowerDirs)-1-i] = d
	}
	opts := "lowerdir=" + strings.Join(rev, ":") + ",ro"
	if len(opts) > lowerdirMaxBytes {
		return "", fmt.Errorf("lowerdir option string is %d bytes, exceeds the kernel mount-option limit "+
			"(too many layers; squash the image)", len(opts))
	}
	return opts, nil
}

// validLowerDir vets a path destined for the lowerdir option string, where ':' separates
// layers and ',' separates options: either character inside a path splices an extra layer or
// an extra mount option into the mount. Neither is escapable — overlayfs has no quoting — so
// the only safe answer is to refuse the path.
func validLowerDir(p string) error {
	if strings.ContainsAny(p, ":,") {
		return fmt.Errorf("lower layer %q must not contain ':' or ','", p)
	}
	return nil
}

// EnsureWithin verifies that target, with every symlink resolved, stays inside root. It
// guards against a mount target escaping the overlay through a symlink — for example an
// image's /var/run -> /run, which would otherwise land a mount on the host's real /run. Call
// it only after the overlay is mounted, so symlinks resolve against image content.
//
// The sandbox module carries its own copy of this (sandbox/path.go, ensureWithin). That is
// deliberate, not an oversight to consolidate: the module takes no horchestra imports, which
// is the property that lets it be audited and vendored on its own. Do not resolve the
// duplication by making sandbox depend on this package — this copy dies with
// agent/runtime/userns, the transitional runtime the sandbox module replaces.
func EnsureWithin(root, target string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve root %q: %w", root, err)
	}

	// Resolve the longest existing prefix of target, then re-append the remaining
	// (not-yet-created) suffix and check containment.
	probe := filepath.Clean(target)
	suffix := ""
	for {
		if realPath, err := filepath.EvalSymlinks(probe); err == nil {
			full := filepath.Join(realPath, suffix)
			if full != realRoot && !strings.HasPrefix(full, realRoot+string(os.PathSeparator)) {
				return fmt.Errorf("target %q resolves to %q, outside root %q", target, full, realRoot)
			}
			return nil
		}
		suffix = filepath.Join(filepath.Base(probe), suffix)
		parent := filepath.Dir(probe)
		if parent == probe {
			return fmt.Errorf("cannot resolve any ancestor of %q", target)
		}
		probe = parent
	}
}
