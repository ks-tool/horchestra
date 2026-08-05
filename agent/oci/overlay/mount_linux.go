//go:build linux

package overlay

import (
	"os"
	"syscall"
)

// Mount assembles opts.LowerDirs read-only at opts.Target, creating the target if it is
// missing.
//
// MS_RDONLY and opts.Flags travel with the syscall that creates the mount, so there is no
// instant in which the rootfs is live without them. Read-only is doubly assured: the mount
// carries no upperdir, which is also why the kernel wants two lower layers.
func Mount(opts MountOptions) error {
	data, err := lowerdirOption(opts.LowerDirs)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(opts.Target, 0o755); err != nil {
		return err
	}
	return syscall.Mount("overlay", opts.Target, "overlay", syscall.MS_RDONLY|opts.Flags, data)
}
