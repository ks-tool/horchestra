//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// lowerdirMaxBytes caps the overlayfs option string. The kernel limits mount
// options to one page (~4096 bytes); the rest is headroom for the flags.
const lowerdirMaxBytes = 3072

// overlayOptions builds the overlayfs option string from lowers given
// bottom-to-top, which is the order this sandbox's config uses; overlayfs
// itself takes them top-to-bottom, so they are reversed here.
func overlayOptions(lowers []string) (string, error) {
	if len(lowers) == 0 {
		return "", fmt.Errorf("no layers to mount")
	}
	rev := make([]string, len(lowers))
	for i, d := range lowers {
		rev[len(lowers)-1-i] = d
	}
	opts := "lowerdir=" + strings.Join(rev, ":") + ",ro"
	if len(opts) > lowerdirMaxBytes {
		return "", fmt.Errorf("lowerdir option string is %d bytes, exceeds the kernel mount-option limit "+
			"(too many layers; squash the image)", len(opts))
	}
	return opts, nil
}

// ensureWithin verifies that target, with every symlink resolved, stays
// inside root. It guards against a mount target escaping the overlay
// through a symlink — for example an image's /var/run -> /run, which would
// otherwise land a mount on the host's real /run. Call it only after the
// overlay is mounted, so symlinks resolve against image content.
func ensureWithin(root, target string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve root %q: %w", root, err)
	}

	// Resolve the longest existing prefix of target, then re-append the
	// remaining (not-yet-created) suffix and check containment.
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

// byDepth orders mount paths parents-first, so a tmpfs at /run/state is
// mounted after the /run that would otherwise mask it. The caller's order is
// preserved among paths of equal depth.
func byDepth(mounts []TmpfsMount) []TmpfsMount {
	out := make([]TmpfsMount, len(mounts))
	for i, m := range mounts {
		m.Path = filepath.Clean(m.Path)
		out[i] = m
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.Count(out[i].Path, "/") < strings.Count(out[j].Path, "/")
	})
	return out
}
