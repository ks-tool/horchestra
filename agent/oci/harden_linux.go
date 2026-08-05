//go:build linux

package oci

import (
	"os"
	"path/filepath"

	"github.com/ks-tool/horchestra/agent/oci/layout"
)

// hardenLayout tightens permissions on the shared layout: the directory to 0700 and the
// bookkeeping files to 0600, so nothing else running as another id on the host reads or
// rewrites the index that decides which manifest an image resolves to.
//
// It also used to freeze the content-addressed metadata blobs with FS_IMMUTABLE_FL, and that
// never once took effect. Setting that flag requires CAP_LINUX_IMMUTABLE against the INITIAL
// user namespace — a userns of one's own does not confer it — and this agent runs with an
// empty effective capability set on purpose. The ioctl returned EPERM for every blob of every
// pull, was logged at debug level and discarded, and the GC paid a thaw/refreeze pass around
// itself for the privilege. It is removed rather than kept "best-effort" because the only
// thing it accomplished was to state a protection that was not there: the layout's real
// defences are this directory mode, the cross-process Lock, and digest verification on the
// write path, and a reader who believed the blobs were frozen would stop looking for them.
//
// Unpacked layer directories are the applications' rootfs and are never touched here:
// chmod'ing them would strip the exec/read bits the read-only overlay serves (nothing would
// start), and following a symlink inside attacker-influenced image content could reach host
// files.
func hardenLayout(layoutPath string) {
	_ = os.Chmod(layoutPath, 0o700)
	for _, f := range []string{"oci-layout", "index.json", layout.LockFile} {
		_ = os.Chmod(filepath.Join(layoutPath, f), 0o600)
	}
}
