//go:build linux

package oci

import (
	"context"

	"github.com/arenadata/oci-packer/pkg/overlay"
)

// Mounter assembles an application's root filesystem from an image's unpacked
// layers as a read-only overlay mount. It implements agent.Mounts.
type Mounter struct{}

// Mount assembles lowerDirs read-only at target.
func (Mounter) Mount(_ context.Context, target string, lowerDirs []string) error {
	return overlay.Mount(overlay.MountOptions{LowerDirs: lowerDirs, Target: target})
}

// Unmount tears down the mount at target (lazily).
func (Mounter) Unmount(_ context.Context, target string) error {
	return overlay.Unmount(target, true)
}

// IsMounted reports whether target currently has a mount.
func (Mounter) IsMounted(_ context.Context, target string) (bool, error) {
	m, err := overlay.MountedUnder(target)
	return len(m) > 0, err
}
