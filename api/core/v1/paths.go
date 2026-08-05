package v1

import (
	"fmt"
	"path"
	"strings"
)

// ValidMountPath rejects a container mount destination that is not a clean absolute path, or
// that carries the delimiters an attacker uses to break out of a single mount entry: whitespace
// and ':' split systemd's space-separated BindPaths/BindReadOnlyPaths/ReadWritePaths/
// TemporaryFileSystem lists into extra source:dest binds (a host file mounted into the
// workload), and a '..' component escapes the per-workload mount root on the node. Enforced at
// admission and re-checked in the unit renderer so a tenant path string can never inject a
// directive or traverse the host filesystem.
func ValidMountPath(p string) error {
	if p == "" {
		return fmt.Errorf("mountPath is required")
	}
	if !path.IsAbs(p) {
		return fmt.Errorf("mountPath %q must be absolute", p)
	}
	return cleanContainerPath(p, "mountPath")
}

// ValidRelPath rejects a secret projection path (VolumeSource.Items[].Path) that is absolute,
// not clean, escapes the mount via '..', or carries whitespace/':'/'\\'/control characters — the
// same injection and traversal vectors ValidMountPath guards, for the relative per-key
// destination.
func ValidRelPath(p string) error {
	if p == "" {
		return fmt.Errorf("path is required")
	}
	if path.IsAbs(p) {
		return fmt.Errorf("path %q must be relative", p)
	}
	return cleanContainerPath(p, "path")
}

// ValidBaseName rejects a single path component that cannot be projected as a file name: empty,
// '.'/'..', carrying a '/', or carrying the whitespace/':'/'\\'/control characters
// ValidMountPath and ValidRelPath reject. It is the validator for a Secret's data keys, which
// the agent turns into per-key relative paths when a mount declares no items remapping — so a
// key admitted here is one every node can project, and the API edge cannot admit a secret that
// stops convergence for every application in the namespace.
func ValidBaseName(p, what string) error {
	if strings.ContainsRune(p, '/') {
		return fmt.Errorf("%s %q must be a single path component (no '/')", what, p)
	}
	if p == "." || p == ".." {
		return fmt.Errorf("%s %q must not be '.' or '..'", what, p)
	}
	if p == "" {
		return fmt.Errorf("%s is required", what)
	}
	return cleanContainerPath(p, what)
}

func cleanContainerPath(p, what string) error {
	if p != path.Clean(p) {
		return fmt.Errorf("%s %q must be a clean path (no '.', '..' or redundant separators)", what, p)
	}
	if strings.ContainsAny(p, " \t\r\n\x00:\\") {
		return fmt.Errorf("%s %q must not contain whitespace, ':', '\\' or control characters", what, p)
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == ".." {
			return fmt.Errorf("%s %q must not contain a '..' component", what, p)
		}
	}
	return nil
}
