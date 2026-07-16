//go:build linux

package agent

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

// fsImmutableFL is FS_IMMUTABLE_FL: a file carrying it cannot be modified,
// deleted, renamed, or have most metadata changed — even by root without
// CAP_LINUX_IMMUTABLE. It is a stable kernel ABI value; x/sys/unix exports the
// FS_IOC_{GET,SET}FLAGS ioctls but not this flag.
const fsImmutableFL = 0x00000010

// hardenLayout tightens permissions on the shared layout and freezes its
// content-addressed metadata blobs immutable, so an out-of-band process cannot
// swap the image config or manifest (which decide what runs and which layers are
// used) without CAP_LINUX_IMMUTABLE. It complements oci-packer's cross-process
// Lock (which guards concurrent oci-packer writers).
//
// Only the regular-file blobs (config/manifest/index — one small file each) are
// frozen. Unpacked layer directories are the applications' rootfs: chmod'ing
// them would strip the exec/read bits the read-only overlay serves (nothing
// would start), and following a symlink inside attacker-influenced image content
// could reach host files — so layer trees are never opened or altered here. It
// is best-effort: an unsupported filesystem or a missing capability is logged at
// debug level, never fatal.
func hardenLayout(layoutPath string) {
	_ = os.Chmod(layoutPath, 0o700)
	for _, f := range []string{"oci-layout", "index.json", "index.lock", "horchestra.lock"} {
		_ = os.Chmod(filepath.Join(layoutPath, f), 0o600)
	}
	walkBlobs(layoutPath, true)
}

// unlockLayout clears the immutable flag on the metadata blobs so oci-packer's
// Delete (which os.RemoveAll's orphaned blobs) can reclaim them; hardenLayout
// refreezes whatever survives.
func unlockLayout(layoutPath string) { walkBlobs(layoutPath, false) }

// walkBlobs sets (lock) or clears (!lock) FS_IMMUTABLE_FL on every regular-file
// blob at blobs/<algo>/<hex>, skipping directories (unpacked layers) and
// symlinks. It does not recurse into layer trees.
func walkBlobs(layoutPath string, lock bool) {
	blobsRoot := filepath.Join(layoutPath, "blobs")
	algos, err := os.ReadDir(blobsRoot)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Str("blobs", blobsRoot).Msg("harden: read blobs")
		}
		return
	}
	for _, algo := range algos {
		if !algo.IsDir() {
			continue
		}
		algoDir := filepath.Join(blobsRoot, algo.Name())
		entries, err := os.ReadDir(algoDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			// Freeze only plain-file blobs (config/manifest/index). Layer
			// directories and any symlink are left entirely untouched.
			if e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
				continue
			}
			if err := setImmutable(filepath.Join(algoDir, e.Name()), lock); err != nil {
				log.Debug().Err(err).Str("path", e.Name()).Bool("lock", lock).Msg("harden: set immutable")
			}
		}
	}
}

// setImmutable adds or removes FS_IMMUTABLE_FL on one metadata blob, opened
// O_NOFOLLOW (never traversing a symlink) and chmod'd 0600 while still mutable
// when freezing. It short-circuits when the flag is already in the desired
// state, so repeated harden passes are cheap and don't fight immutable-blocks-
// chmod.
func setImmutable(path string, lock bool) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	if lock {
		if flags&fsImmutableFL != 0 {
			return nil
		}
		_ = unix.Fchmod(fd, 0o600) // metadata blobs aren't rootfs; must precede +i
		flags |= fsImmutableFL
	} else {
		if flags&fsImmutableFL == 0 {
			return nil
		}
		flags &^= fsImmutableFL
	}
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, flags)
}
