//go:build linux

package layout

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// entry is one tar member: the header, and the bytes that follow it.
type entry struct {
	hdr     tar.Header
	content string
}

func file(name, content string, mode int64) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode}, content: content}
}

func dir(name string, mode int64) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: mode}}
}

func symlink(name, target string) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target}}
}

func hardlink(name, target string) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeLink, Linkname: target}}
}

// layerTar builds an uncompressed layer tar out of entries.
func layerTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := e.hdr
		hdr.Size = int64(len(e.content))
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if len(e.content) > 0 {
			if _, err := io.WriteString(tw, e.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// canWhiteout reports whether this process may create the two things a whiteout is made of. Root in
// a plain container has CAP_MKNOD but not CAP_SYS_ADMIN, so "am I uid 0" is not the question — the
// question is whether the kernel will let these two calls through.
func canWhiteout(t *testing.T) bool {
	t.Helper()
	probe := t.TempDir()
	if err := unix.Mknod(filepath.Join(probe, "wh"), unix.S_IFCHR, 0); err != nil {
		return false
	}
	return unix.Setxattr(probe, "trusted.overlay.opaque", []byte("y"), 0) == nil
}

func TestUnpackLayer(t *testing.T) {
	dest := t.TempDir()
	// A 0555 directory written into afterwards: the archive order is the image builder's, and the
	// mode must survive without blocking the writes that follow it.
	raw := layerTar(t,
		dir("./", 0o755),
		dir("etc/", 0o555),
		file("etc/hosts", "127.0.0.1 localhost\n", 0o644),
		dir("bin/", 0o755),
		file("bin/busybox", "#!/bin/sh\n", 0o755),
		symlink("bin/sh", "busybox"),
		hardlink("bin/ash", "bin/busybox"),
	)
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dest, "etc"), 0o755) })

	st, err := unpackLayer(bytes.NewReader(raw), mediaTypeLayer, dest, nil, 0)
	if err != nil {
		t.Fatalf("unpackLayer: %v", err)
	}
	if st.entries != 7 {
		t.Errorf("entries = %d, want 7", st.entries)
	}

	if got, err := os.ReadFile(filepath.Join(dest, "etc/hosts")); err != nil ||
		string(got) != "127.0.0.1 localhost\n" {
		t.Errorf("etc/hosts = %q, %v", got, err)
	}
	// O_CREATE's mode is masked by the umask; the image's mode is the one that must survive.
	for path, want := range map[string]os.FileMode{
		"etc":         0o555,
		"bin/busybox": 0o755,
		"etc/hosts":   0o644,
	} {
		info, err := os.Lstat(filepath.Join(dest, path))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", path, got, want)
		}
	}

	if target, err := os.Readlink(filepath.Join(dest, "bin/sh")); err != nil || target != "busybox" {
		t.Errorf("bin/sh -> %q, %v", target, err)
	}
	a, err := os.Stat(filepath.Join(dest, "bin/ash"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(dest, "bin/busybox"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Error("bin/ash is not a hard link to bin/busybox")
	}
}

func TestUnpackLayerGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(layerTar(t, file("hello", "world\n", 0o644))); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if _, err := unpackLayer(&buf, mediaTypeLayerGzip, dest, nil, 0); err != nil {
		t.Fatalf("unpackLayer: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "hello")); err != nil || string(got) != "world\n" {
		t.Errorf("hello = %q, %v", got, err)
	}
}

// The "./" entry debian-derived images ship is the layer's own root: it has no parent inside the
// layer to check, and refusing it once cost a whole class of images.
func TestUnpackLayerRootEntry(t *testing.T) {
	dest := t.TempDir()
	_, err := unpackLayer(bytes.NewReader(layerTar(t, dir("./", 0o755))), mediaTypeLayer, dest, nil, 0)
	if err != nil {
		t.Fatalf("unpackLayer: %v", err)
	}
}

// A layer that plants a symlink and then writes through it is the escape that "../" in a name is
// not: the name stays inside the layer, the path it resolves to does not.
func TestUnpackLayerSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	tests := []struct {
		name    string
		linkTo  string
		through string
	}{
		{name: "absolute", linkTo: outside, through: "escape/owned"},
		{name: "relative", linkTo: "../../../../../../etc", through: "escape/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := t.TempDir()
			raw := layerTar(t, symlink("escape", tt.linkTo), file(tt.through, "owned\n", 0o644))

			_, err := unpackLayer(bytes.NewReader(raw), mediaTypeLayer, dest, nil, 0)
			if err == nil {
				t.Fatal("unpackLayer accepted a write through a symlink out of the layer")
			}
			if !isPermanent(err) {
				t.Errorf("an escape must be permanent, not retried: %v", err)
			}
			if _, err := os.Stat(filepath.Join(outside, "owned")); err == nil {
				t.Error("the layer wrote outside its directory")
			}
		})
	}
}

// A hard link naming a path outside the layer would hand the image a file it never shipped.
func TestUnpackLayerHardLinkEscape(t *testing.T) {
	dest := t.TempDir()
	raw := layerTar(t, symlink("escape", "/etc"), hardlink("stolen", "escape/passwd"))

	if _, err := unpackLayer(bytes.NewReader(raw), mediaTypeLayer, dest, nil, 0); err == nil {
		t.Fatal("unpackLayer accepted a hard link out of the layer")
	}
	if _, err := os.Lstat(filepath.Join(dest, "stolen")); err == nil {
		t.Error("the link was created anyway")
	}
}

func TestUnpackLayerMediaTypes(t *testing.T) {
	raw := layerTar(t, file("hello", "world\n", 0o644))
	for _, mt := range []string{"application/octet-stream", ""} {
		_, err := unpackLayer(bytes.NewReader(raw), mt, t.TempDir(), nil, 0)
		if err == nil {
			t.Errorf("%q was accepted", mt)
			continue
		}
		// Re-downloading cannot turn an unknown media type into a known one: fail once, not four
		// times.
		if !isPermanent(err) {
			t.Errorf("%q: want a permanent error, got %v", mt, err)
		}
	}
}

// TestUnpackLayerDecompressedCap holds a layer to the decompressed size the caller allowed: the
// compressed stream is already bounded by what the descriptor declared, so this is the only guard
// against a layer that is small on the wire and enormous on disk.
func TestUnpackLayerDecompressedCap(t *testing.T) {
	raw := layerTar(t, file("big", strings.Repeat("a", 64<<10), 0o644))
	if _, err := unpackLayer(bytes.NewReader(raw), mediaTypeLayer, t.TempDir(), nil, 4<<10); err == nil {
		t.Fatal("a layer past the decompressed cap was accepted")
	}
}

// TestUnpackLayerDirThroughSymlink refuses a directory entry whose own path is a symlink the same
// layer planted. MkdirAll adopts a symlink-to-directory instead of failing, so without the check
// the layer's mode and timestamps would be applied to whatever it points at, outside the layer.
func TestUnpackLayerDirThroughSymlink(t *testing.T) {
	outside := t.TempDir()
	raw := layerTar(t, symlink("etc", outside), dir("etc/", 0o700))
	dest := t.TempDir()
	if _, err := unpackLayer(bytes.NewReader(raw), mediaTypeLayer, dest, nil, 0); err == nil {
		t.Fatal("a directory entry writing through a symlink was accepted")
	}
	if fi, err := os.Stat(outside); err == nil && fi.Mode().Perm() == 0o700 {
		t.Error("the mode was applied to the symlink's target outside the layer")
	}
}

// AUFS's own scratch files describe the AUFS implementation, not the image, and have no overlayfs
// equivalent — but ".wh..wh..opq" is spelled the same way and does mean something.
func TestUnpackLayerAufsMetaIgnored(t *testing.T) {
	dest := t.TempDir()
	raw := layerTar(t, file(".wh..wh.plnk", "", 0o644), file(".wh..wh.orph", "", 0o644))

	st, err := unpackLayer(bytes.NewReader(raw), mediaTypeLayer, dest, nil, 0)
	if err != nil {
		t.Fatalf("unpackLayer: %v", err)
	}
	if st.whiteouts != 0 || st.opaqueDirs != 0 {
		t.Errorf("AUFS bookkeeping was translated: %+v", st)
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("AUFS bookkeeping was written out: %v", entries)
	}
}

// The reason this tool exists rather than a call to oci-packer: a whiteout becomes a character
// device 0:0 and an opaque directory a trusted.overlay.opaque xattr. Both halves are asserted —
// what a privileged unpack produces, and that an unprivileged one is told why rather than handed a
// silently wrong tree.
func TestUnpackLayerWhiteouts(t *testing.T) {
	dest := t.TempDir()
	raw := layerTar(t,
		file(".wh.toplevel", "", 0o644),
		dir("data/", 0o755),
		file("data/.wh.gone", "", 0o644),
		dir("data/opq/", 0o755),
		file("data/opq/.wh..wh..opq", "", 0o644),
	)

	st, err := unpackLayer(bytes.NewReader(raw), mediaTypeLayer, dest, nil, 0)

	if !canWhiteout(t) {
		// Said out loud, because it is half the test being skipped: a plain container has
		// CAP_MKNOD but not CAP_SYS_ADMIN, so the tree itself is only checked under --privileged.
		t.Logf("cannot create whiteouts here; checking the refusal instead of the tree: %v", err)
		if err == nil {
			t.Fatal("an unprivileged unpack of a whiteout layer must fail, not drop the whiteouts")
		}
		if !isPermanent(err) {
			t.Errorf("missing privilege will not fix itself on a retry: %v", err)
		}
		if !strings.Contains(err.Error(), "CAP_") {
			t.Errorf("the error should name the capability at stake, got: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("unpackLayer: %v", err)
	}
	if st.whiteouts != 2 || st.opaqueDirs != 1 {
		t.Errorf("got %d whiteouts and %d opaque dirs, want 2 and 1", st.whiteouts, st.opaqueDirs)
	}

	// The ".wh." prefix is stripped: the marker names the file it deletes.
	for _, name := range []string{"toplevel", "data/gone"} {
		var stat unix.Stat_t
		if err := unix.Lstat(filepath.Join(dest, name), &stat); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFCHR || stat.Rdev != 0 {
			t.Errorf("%s: mode %o rdev %d, want a character device 0:0", name, stat.Mode, stat.Rdev)
		}
	}
	buf := make([]byte, 8)
	n, err := unix.Getxattr(filepath.Join(dest, "data/opq"), "trusted.overlay.opaque", buf)
	if err != nil || string(buf[:n]) != "y" {
		t.Errorf(`data/opq: trusted.overlay.opaque = %q, %v; want "y"`, buf[:n], err)
	}
	// The marker file itself is bookkeeping, not content.
	if _, err := os.Lstat(filepath.Join(dest, "data/opq/.wh..wh..opq")); err == nil {
		t.Error("the opaque marker was written out as a file")
	}
}

func TestUnpackLayerOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("chown to another id needs root")
	}
	dest := t.TempDir()
	raw := layerTar(t, dir("srv/", 0o755), file("srv/data", "x\n", 0o644))

	if _, err := unpackLayer(bytes.NewReader(raw), mediaTypeLayer, dest, &ownership{uid: 999, gid: 998}, 0); err != nil {
		t.Fatalf("unpackLayer: %v", err)
	}
	for _, name := range []string{"srv", "srv/data"} {
		var stat unix.Stat_t
		if err := unix.Lstat(filepath.Join(dest, name), &stat); err != nil {
			t.Fatal(err)
		}
		if stat.Uid != 999 || stat.Gid != 998 {
			t.Errorf("%s owned by %d:%d, want 999:998", name, stat.Uid, stat.Gid)
		}
	}
}
