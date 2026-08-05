//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// devNodes is the minimal host device set bind-mounted into the sandbox /dev: mknod is denied in
// a user namespace, so real nodes are borrowed from the host and these are the only devices that
// exist inside.
var devNodes = []string{"null", "zero", "full", "random", "urandom", "tty"}

// tmpfsModes are the mount options for paths whose expected mode differs from the tmpfs default
// of 1777: world-writable sticky scratch directories, and the 0755 /run every runtime convention
// assumes — a sticky world-writable /run would let any process squat another's runtime dir.
var tmpfsModes = map[string]string{
	"/tmp":     "mode=1777",
	"/var/tmp": "mode=1777",
	"/run":     "mode=0755",
}

// mountOverlay mounts lowers (given bottom-to-top) read-only at target.
// MS_RDONLY|MS_NOSUID|MS_NODEV are applied by the same syscall that creates the mount: flags
// added by a later remount would leave a window in which image content — a setuid binary, a
// device node — is live without them.
func mountOverlay(lowers []string, target string) error {
	opts, err := overlayOptions(lowers)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	return unix.Mount("overlay", target, "overlay",
		unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, opts)
}

// mountTmpfs mounts a writable tmpfs at target, creating it first.
// mountBinds projects the caller's persistent volumes.
//
// Every one is remounted NOSUID|NODEV, and that remount is not decoration: MS_BIND ignores the
// other flags on the way in, so a volume holding tenant data would otherwise honour a setuid binary
// or a device node written into it from anywhere the source is also reachable.
func mountBinds(root string, mounts []BindMount) error {
	for _, m := range mounts {
		target := filepath.Join(root, m.Target)
		if err := ensureWithin(root, target); err != nil {
			return fmt.Errorf("volume %s: %w", m.Target, err)
		}
		// The skeleton supplies this directory unless a tmpfs above masks it; one MkdirAll covers
		// both, and fails honestly on the read-only overlay if neither applies.
		if err := os.MkdirAll(target, 0o755); err != nil {
			return fmt.Errorf("volume %s: %w", m.Target, err)
		}
		if err := unix.Mount(m.Source, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("volume %s: bind: %w", m.Target, err)
		}
		flags := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_NOSUID | unix.MS_NODEV)
		if m.ReadOnly {
			flags |= unix.MS_RDONLY
		}
		if err := unix.Mount("", target, "", flags, ""); err != nil {
			return fmt.Errorf("volume %s: remount: %w", m.Target, err)
		}
	}
	return nil
}

// mountSecrets projects the caller's RAM-backed carriers, read-only and never otherwise.
//
// Recursive on the way in because the carrier is itself a mount, and NOEXEC on top of the volume
// flags because nothing in a secret volume is ever a program. Binding rather than copying is what
// makes a rotated value live under a running workload.
func mountSecrets(root string, mounts []SecretMount) error {
	const flags = unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	for _, m := range mounts {
		target := filepath.Join(root, m.Target)
		if err := ensureWithin(root, target); err != nil {
			return fmt.Errorf("secret volume %s: %w", m.Target, err)
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return fmt.Errorf("secret volume %s: %w", m.Target, err)
		}
		if err := unix.Mount(m.Source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("secret volume %s: bind: %w", m.Target, err)
		}
		// The remount is what makes the read-only real rather than advisory.
		if err := unix.Mount("", target, "", flags, ""); err != nil {
			return fmt.Errorf("secret volume %s: remount ro: %w", m.Target, err)
		}
	}
	return nil
}

func mountTmpfs(target string, flags uintptr, data string) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	return unix.Mount("tmpfs", target, "tmpfs", flags, data)
}

// mountVolumes gives each configured path its own tmpfs, parents first so a nested mount is not
// masked by the one above it. Each target is re-checked against the mounted image's symlinks, so
// image content cannot steer a mount onto the host.
func mountVolumes(root string, mounts []TmpfsMount) error {
	for _, m := range byDepth(mounts) {
		target := filepath.Join(root, m.Path)
		if err := ensureWithin(root, target); err != nil {
			return fmt.Errorf("tmpfs %s: %w", m.Path, err)
		}
		if err := mountTmpfs(target, unix.MS_NOSUID|unix.MS_NODEV, tmpfsData(m)); err != nil {
			return fmt.Errorf("tmpfs %s: %w", m.Path, err)
		}
	}
	return nil
}

// tmpfsData is the mount option string for one configured tmpfs: the mode this path is expected
// to come up with, plus whichever bounds the config gave.
func tmpfsData(m TmpfsMount) string {
	opts := make([]string, 0, 3)
	if mode := tmpfsModes[m.Path]; len(mode) > 0 {
		opts = append(opts, mode)
	}
	if len(m.Size) > 0 {
		opts = append(opts, "size="+m.Size)
	}
	if len(m.Inodes) > 0 {
		opts = append(opts, "nr_inodes="+m.Inodes)
	}
	return strings.Join(opts, ",")
}

// setupDev assembles the sandbox /dev on a private tmpfs. The tmpfs itself carries nosuid but NOT
// nodev — the whole point of it is the device nodes bind-mounted in below.
func setupDev(root string) error {
	dev := filepath.Join(root, "dev")
	if err := ensureWithin(root, dev); err != nil {
		return err
	}
	// nr_inodes alongside size: the workload owns this tmpfs and size= bounds only its blocks,
	// which empty files never consume. The counts are generous against what actually lives here
	// — a dozen nodes and symlinks in /dev, a handful of segments in /dev/shm — and still bound.
	if err := mountTmpfs(dev, unix.MS_NOSUID, "mode=0755,size=4m,nr_inodes=256"); err != nil {
		return err
	}
	for _, n := range devNodes {
		if err := bindFile(filepath.Join("/dev", n), filepath.Join(dev, n)); err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
	}
	if err := mountTmpfs(filepath.Join(dev, "shm"),
		unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=64m,nr_inodes=1k"); err != nil {
		return fmt.Errorf("shm: %w", err)
	}
	// A private devpts instance, so the sandbox's pty numbering and its ptmx are its own and
	// nothing here can reach a terminal outside it.
	pts := filepath.Join(dev, "pts")
	if err := os.MkdirAll(pts, 0755); err != nil {
		return err
	}
	if err := unix.Mount("devpts", pts, "devpts", unix.MS_NOSUID|unix.MS_NOEXEC,
		"newinstance,ptmxmode=0666"); err != nil {
		return fmt.Errorf("pts: %w", err)
	}
	for link, target := range map[string]string{
		"fd":     "/proc/self/fd",
		"stdin":  "/proc/self/fd/0",
		"stdout": "/proc/self/fd/1",
		"stderr": "/proc/self/fd/2",
		"ptmx":   "pts/ptmx",
	} {
		if err := os.Symlink(target, filepath.Join(dev, link)); err != nil {
			return err
		}
	}
	return nil
}

// bindFile bind-mounts a single file; the target is created empty first — a bind needs an
// existing mount point of the same kind.
func bindFile(src, dst string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	_ = f.Close()
	return unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_NOSUID, "")
}

// mountProc mounts a procfs of the sandbox's own pid namespace; host processes are not visible
// through it.
//
// It is nosuid/nodev/noexec but NOT read-only, matching every mainstream runtime: procfs carries
// per-process knobs a workload legitimately writes (/proc/self/oom_score_adj, coredump_filter),
// and a read-only mount fails each of them with EROFS. Nothing is gained by it either — the fresh
// PID namespace already hides every other process, and the workload runs unprivileged behind
// NO_NEW_PRIVS, an empty bounding set and the seccomp filter.
func mountProc(root string) error {
	p := filepath.Join(root, "proc")
	if err := ensureWithin(root, p); err != nil {
		return err
	}
	if err := os.MkdirAll(p, 0755); err != nil {
		return err
	}
	return unix.Mount("proc", p, "proc",
		unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
}

// mountSys mounts /sys read-only, falling back to an empty read-only tmpfs.
//
// The fallback is the normal path here, not an edge case: the kernel only lets a user namespace
// mount sysfs when it owns the network namespace too, and this sandbox deliberately shares the
// host's. An empty /sys is the safe answer — the alternative, binding the host's, would hand the
// workload a window onto host hardware and network state.
func mountSys(root string) error {
	p := filepath.Join(root, "sys")
	if err := ensureWithin(root, p); err != nil {
		return err
	}
	if err := os.MkdirAll(p, 0755); err != nil {
		return err
	}
	const flags = unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	if err := unix.Mount("sysfs", p, "sysfs", flags, ""); err == nil {
		return nil
	}
	if err := unix.Mount("tmpfs", p, "tmpfs", flags, "mode=0555"); err != nil {
		return fmt.Errorf("sys placeholder: %w", err)
	}
	return nil
}

// prepareSkeleton mounts the mount-point skeleton tmpfs on InitDir and lays out the directories
// the runtime mounts (dev, proc, sys, volumes) attach to, plus the workload's working directory,
// so they exist even when no image layer provides them. The tmpfs is private to the sandbox's
// mount namespace; on disk InitDir stays an empty directory for the caller to Remove.
func prepareSkeleton(cfg *Config) error {
	if err := mountTmpfs(cfg.InitDir, unix.MS_NOSUID|unix.MS_NODEV, "size=1m"); err != nil {
		return fmt.Errorf("skeleton tmpfs on %s: %w", cfg.InitDir, err)
	}
	dirs := []string{"/dev", "/proc", "/sys", cfg.WorkingDir}
	for _, m := range cfg.TmpfsMounts {
		dirs = append(dirs, m.Path)
	}
	for _, p := range dirs {
		if err := os.MkdirAll(filepath.Join(cfg.InitDir, p), 0755); err != nil {
			return err
		}
	}
	return nil
}

// requireTmpfs refuses a secrets directory that is not RAM-backed: a secret written to disk
// outlives the sandbox.
func requireTmpfs(dir string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return err
	}
	if st.Type != unix.TMPFS_MAGIC {
		return fmt.Errorf("%s is not on tmpfs", dir)
	}
	return nil
}
