package layout

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

// The two whiteout conventions an image layer speaks. They are AUFS's, which OCI kept as the
// on-the-wire format; overlayfs understands neither, so both are translated below.
const (
	whiteoutPrefix = ".wh."
	whiteoutMeta   = ".wh..wh." // AUFS bookkeeping; ".wh..wh..opq" is the one that means something
	whiteoutOpaque = ".wh..wh..opq"
)

// Why a filesystem, rather than the kernel, may refuse the two calls a whiteout is made of. Both
// are met the same way: an unpack that writes to a container's own overlay instead of a volume.
const (
	noDevices = "overlayfs refuses to create device nodes at all, however privileged the caller"
	noXattrs  = "overlayfs rejects trusted.overlay.* on its own files, and not every filesystem " +
		"carries trusted xattrs"
)

// permanentError marks a failure that fetching the layer again cannot fix: what the layer contains,
// or what this machine lets us create — not how the bytes arrived. The retry loop stops on these,
// so a missing CAP_MKNOD is reported once instead of after four downloads of the same layer.
type permanentError struct{ error }

func permanent(err error) error { return permanentError{err} }

func isPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

// hint explains an EPERM from one of the calls a whiteout is made of. There are two causes and the
// fix for one is not the fix for the other — too little privilege, or a destination filesystem that
// will not hold the marker — so the capability is checked rather than guessed at from the uid,
// which says nothing: root in a container holds CAP_MKNOD and not CAP_SYS_ADMIN.
func hint(what string, capability uintptr, name, refusal string) string {
	if !hasCap(capability) {
		// Not "run as root": uid 0 in a container carries a trimmed capability set, and this is
		// exactly where the two calls part company — CAP_MKNOD is in it, CAP_SYS_ADMIN is not.
		return fmt.Sprintf(" — %s takes %s in the initial user namespace, which uid 0 alone does "+
			"not give: run the unpack as real root, or grant the capability (docker run "+
			"--cap-add=%s). Preparing layers is the privileged half; mounting them is not",
			what, name, strings.TrimPrefix(name, "CAP_"))
	}
	// The privilege is there, so the layout is somewhere that cannot hold layers. This is the
	// ordinary way to meet it: an unpack run inside a container, writing to the container's own
	// overlay rather than to a volume, where even --privileged does not help.
	return fmt.Sprintf(" — %s is permitted here (%s is held), so it is the destination filesystem "+
		"refusing: %s. Put the layout on a filesystem that can hold layers", what, name, refusal)
}

// hasCap reports whether the capability is in this process's effective set.
func hasCap(capability uintptr) bool {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	return data[capability>>5].Effective&(1<<(capability&31)) != 0
}

// stats is what one layer turned out to contain, reported so an unpack that silently dropped
// something says so.
type stats struct {
	entries    int
	whiteouts  int
	opaqueDirs int
	xattrsLost int
}

// extractor unpacks one layer tar into one directory. A layer is unpacked into a directory of its
// own — the overlay stack is exactly these directories — so nothing here ever writes outside dest,
// and nothing ever reaches back into a lower layer: a layer directory is
// named by its content digest and shared between every image that references it, so mutating one
// to satisfy another image's whiteout would corrupt the first.
type extractor struct {
	dest    string
	owner   *ownership // non-nil to chown every entry to a fixed id
	dirs    []dirMeta  // modes and times applied after everything is written
	checked map[string]bool
	stats   stats
}

type dirMeta struct {
	path string
	mode os.FileMode
	hdr  *tar.Header
}

type ownership struct{ uid, gid int }

// unpackLayer decompresses one layer blob according to its media type and extracts it into dest.
func unpackLayer(r io.Reader, mediaType, dest string, owner *ownership, maxBytes int64) (stats, error) {
	var tr io.Reader
	switch mediaType {
	case mediaTypeLayerGzip, mediaTypeDockerLayerGzip:
		zr, err := gzip.NewReader(r)
		if err != nil {
			return stats{}, fmt.Errorf("gzip: %w", err)
		}
		defer func() { _ = zr.Close() }()
		tr = zr
	case mediaTypeLayer, mediaTypeDockerLayerTar:
		tr = r
	case mediaTypeLayerZstd, mediaTypeDockerLayerZstd:
		zr, err := zstd.NewReader(r)
		if err != nil {
			return stats{}, fmt.Errorf("zstd: %w", err)
		}
		defer zr.Close()
		tr = zr
	default:
		return stats{}, permanent(fmt.Errorf("unsupported layer media type %q", mediaType))
	}
	// Capped AFTER decompression: the compressed stream is already held to its declared size, and
	// what a decompression bomb costs is the expansion, not the download.
	tr = bound(tr, maxBytes, fmt.Sprintf("the %d-byte decompressed layer cap", maxBytes))

	e := &extractor{dest: dest, owner: owner, checked: map[string]bool{dest: true}}
	if err := e.run(tar.NewReader(tr)); err != nil {
		return e.stats, err
	}
	return e.stats, e.finish()
}

func (e *extractor) run(tr *tar.Reader) error {
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if err := e.entry(hdr, tr); err != nil {
			return fmt.Errorf("%s: %w", hdr.Name, err)
		}
		e.stats.entries++
	}
}

func (e *extractor) entry(hdr *tar.Header, tr *tar.Reader) error {
	name := filepath.Clean("/" + hdr.Name)
	base := filepath.Base(name)

	switch {
	case base == whiteoutOpaque:
		return e.opaque(filepath.Dir(name))
	case strings.HasPrefix(base, whiteoutMeta):
		// AUFS's own scratch files (.wh..wh.plnk, .wh..wh.orph). They describe the AUFS
		// implementation, not the image, and have no overlayfs equivalent.
		return nil
	case strings.HasPrefix(base, whiteoutPrefix):
		return e.whiteout(filepath.Join(filepath.Dir(name), base[len(whiteoutPrefix):]))
	}

	target, err := e.target(name)
	if err != nil {
		return err
	}
	mode := hdr.FileInfo().Mode()

	switch hdr.Typeflag {
	case tar.TypeDir:
		// A directory entry is the one case whose own path must be vetted, not just its parent:
		// MkdirAll adopts an existing symlink-to-directory instead of failing, so a layer that
		// declared "etc -> /etc" earlier and then ships "etc/" would have finish() apply its mode
		// and timestamps to the host's /etc. Every other type refuses an existing path outright
		// (O_EXCL, Symlink, Link and Mknod all fail with EEXIST), so none of them can follow one.
		if err := e.safeParent(target); err != nil {
			return err
		}
		// Created permissive and fixed at the end: a layer may ship a 0555 directory it then
		// writes into, and the archive order is the builder's, not one that respects modes.
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		e.dirs = append(e.dirs, dirMeta{path: target, mode: mode.Perm(), hdr: hdr})
	case tar.TypeReg:
		if err := e.regular(target, mode, hdr, tr); err != nil {
			return err
		}
	case tar.TypeSymlink:
		if err := os.Symlink(hdr.Linkname, target); err != nil {
			return err
		}
	case tar.TypeLink:
		source, err := e.target(filepath.Clean("/" + hdr.Linkname))
		if err != nil {
			return fmt.Errorf("hard link target: %w", err)
		}
		if err := os.Link(source, target); err != nil {
			return err
		}
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		if err := e.device(target, hdr); err != nil {
			return err
		}
	default:
		// Nothing else appears in an image layer, and guessing at one would be worse than saying so.
		return permanent(fmt.Errorf("unsupported tar entry type %q", hdr.Typeflag))
	}

	e.xattrs(target, hdr)
	if err := e.chown(target, hdr); err != nil {
		return err
	}
	if hdr.Typeflag != tar.TypeSymlink && hdr.Typeflag != tar.TypeDir {
		return os.Chtimes(target, hdr.AccessTime, hdr.ModTime)
	}
	return nil
}

func (e *extractor) regular(target string, mode os.FileMode, hdr *tar.Header, tr *tar.Reader) error {
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, tr); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// O_CREATE's mode is masked by the umask; the image's mode is the one that must survive.
	return os.Chmod(target, mode.Perm())
}

// device reproduces a device node or fifo from the layer. Only a process with CAP_MKNOD can make
// the first two, which is the same privilege the whiteouts need — see whiteout.
func (e *extractor) device(target string, hdr *tar.Header) error {
	mode := uint32(hdr.Mode & 0o7777)
	switch hdr.Typeflag {
	case tar.TypeChar:
		mode |= unix.S_IFCHR
	case tar.TypeBlock:
		mode |= unix.S_IFBLK
	case tar.TypeFifo:
		mode |= unix.S_IFIFO
	}
	err := unix.Mknod(target, mode, int(unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor))))
	if errors.Is(err, unix.EPERM) {
		return permanent(fmt.Errorf("mknod: %w%s", err,
			hint("creating a device node", unix.CAP_MKNOD, "CAP_MKNOD", noDevices)))
	}
	return err
}

// whiteout records that a lower layer's path is deleted from this layer up. overlayfs spells that
// as a character device 0:0, and only mknod can create one — an unprivileged process cannot, on
// any filesystem. The alternative would be to delete the file from the lower layer's directory,
// which is wrong: those directories are content-addressed and shared, and the file is still
// present in every other image built on the same layer.
func (e *extractor) whiteout(name string) error {
	target, err := e.target(name)
	if err != nil {
		return err
	}
	if err := unix.Mknod(target, unix.S_IFCHR, 0); err != nil {
		if errors.Is(err, unix.EPERM) {
			return permanent(fmt.Errorf("whiteout for %s: %w%s", name, err,
				hint("creating an overlayfs whiteout", unix.CAP_MKNOD, "CAP_MKNOD", noDevices)))
		}
		return fmt.Errorf("whiteout for %s: %w", name, err)
	}
	e.stats.whiteouts++
	return e.chown(target, nil)
}

// opaque records that a directory hides the lower layers' version of itself entirely. overlayfs
// reads that from the trusted.overlay.opaque xattr, and the trusted namespace takes CAP_SYS_ADMIN
// — the same reason as whiteout. (The user.overlay.* spelling exists, but only for an overlay
// mounted with the userxattr option: a different mount, and a tree written for one spelling is not
// read by the other.)
func (e *extractor) opaque(dir string) error {
	target, err := e.target(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	if err := unix.Setxattr(target, "trusted.overlay.opaque", []byte("y"), 0); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EOPNOTSUPP) {
			return permanent(fmt.Errorf("opaque marker on %s: %w%s", dir, err,
				hint("writing a trusted.* xattr", unix.CAP_SYS_ADMIN, "CAP_SYS_ADMIN", noXattrs)))
		}
		return fmt.Errorf("opaque marker on %s: %w", dir, err)
	}
	e.stats.opaqueDirs++
	return nil
}

// xattrs copies the layer's extended attributes. Failures are counted rather than fatal: the
// namespaces that need privilege — security.capability above all — carry no meaning to a workload
// that runs under nosuid with an empty capability bounding set, which is the case this tool
// prepares layers for.
func (e *extractor) xattrs(target string, hdr *tar.Header) {
	for k, v := range hdr.PAXRecords {
		attr, ok := strings.CutPrefix(k, "SCHILY.xattr.")
		if !ok {
			continue
		}
		if err := unix.Lsetxattr(target, attr, []byte(v), 0); err != nil {
			e.stats.xattrsLost++
		}
	}
}

// chown applies the fixed ownership when one was asked for. The layer's own uid/gid are otherwise
// discarded on purpose: a rootless consumer maps a single id, so a file owned by anything else
// shows up inside as the overflow uid — faithfully restoring root ownership is what makes an image
// unreadable to a rootless workload, not what makes it correct.
func (e *extractor) chown(target string, _ *tar.Header) error {
	if e.owner == nil {
		return nil
	}
	return os.Lchown(target, e.owner.uid, e.owner.gid)
}

// target maps an archive path to its place under dest and refuses anything that would leave it.
// Two escapes are possible and both are checked: "../" in the name, and a symlink planted earlier
// in the same layer that a later entry then writes through.
func (e *extractor) target(name string) (string, error) {
	p := filepath.Join(e.dest, name)
	if p == e.dest {
		// The layer's own root, which debian-derived images ship as a "./" entry. It has no parent
		// inside the layer to check, and dest is this tool's own freshly created directory.
		return p, nil
	}
	if !strings.HasPrefix(p, e.dest+string(os.PathSeparator)) {
		return "", permanent(fmt.Errorf("path %q escapes the layer directory", name))
	}
	if err := e.safeParent(filepath.Dir(p)); err != nil {
		return "", err
	}
	return p, nil
}

// safeParent verifies that a directory, with every symlink resolved, is still inside dest.
// Results are cached: a layer has far more entries than directories.
func (e *extractor) safeParent(dir string) error {
	if e.checked[dir] {
		return nil
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		// Not created yet — its own ancestors are what matter, and MkdirAll will make it a real
		// directory rather than follow anything.
		if os.IsNotExist(err) {
			parent := filepath.Dir(dir)
			if parent == dir {
				return fmt.Errorf("cannot resolve any ancestor of %q", dir)
			}
			return e.safeParent(parent)
		}
		return err
	}
	if real != e.dest && !strings.HasPrefix(real, e.dest+string(os.PathSeparator)) {
		return permanent(fmt.Errorf("directory %q resolves to %q, outside the layer", dir, real))
	}
	e.checked[dir] = true
	return nil
}

// finish applies the directory modes and timestamps that had to wait until nothing more would be
// written into them. Deepest first, so a directory turned read-only never blocks its own children.
func (e *extractor) finish() error {
	sort.SliceStable(e.dirs, func(i, j int) bool {
		return strings.Count(e.dirs[i].path, "/") > strings.Count(e.dirs[j].path, "/")
	})
	for _, d := range e.dirs {
		if err := os.Chtimes(d.path, d.hdr.AccessTime, d.hdr.ModTime); err != nil {
			return err
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
	}
	return nil
}
