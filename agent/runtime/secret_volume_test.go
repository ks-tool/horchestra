package runtime

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/ks-tool/horchestra/agent/workload"
)

// carrierRoot is a temp dir the test framework can still clean up: a carrier directory ends at
// mode 0500, which is right on a node and stops RemoveAll dead.
func carrierRoot(t *testing.T) string {
	dir := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, _ error) error {
			if d != nil && d.IsDir() {
				_ = os.Chmod(p, 0o700)
			}
			return nil
		})
	})
	return dir
}

func secretVol(mountPath string, content map[string][]byte) workload.Volume {
	return workload.Volume{Kind: workload.VolumeSecret, MountPath: mountPath, ReadOnly: true, Content: content}
}

// TestSecretVolumeCarrierIsRAMOnlyAndExact: the values live in the agent's tmpfs and nowhere
// else, and the directory holds exactly the projected keys — a key that disappears from the
// Secret disappears from the mount, or a rotation would leave the old one readable beside the new.
func TestSecretVolumeCarrierIsRAMOnlyAndExact(t *testing.T) {
	dir := carrierRoot(t)
	mounts, err := WriteSecretVolumes(dir, "app-1", []workload.Volume{
		secretVol("/creds", map[string][]byte{"password": []byte("s3cr3t"), "ca.pem": []byte("PEM")}),
	}, IDs{})
	if err != nil {
		t.Fatalf("WriteSecretVolumes: %v", err)
	}
	if len(mounts) != 1 || mounts[0].Target != "/creds" {
		t.Fatalf("mounts = %+v", mounts)
	}
	src := mounts[0].Source
	if got, err := os.ReadFile(filepath.Join(src, "password")); err != nil || string(got) != "s3cr3t" {
		t.Fatalf("password = %q, %v", got, err)
	}
	// The files belong to the workload — the agent chowns them to the identity its own namespace
	// maps — so owner-only is exactly right and no group or world bit is handed out.
	fi, err := os.Stat(filepath.Join(src, "password"))
	if err != nil || fi.Mode().Perm() != 0o400 {
		t.Errorf("mode = %v (%v), want 0400 — the file belongs to the workload, so nobody else needs a bit", fi.Mode().Perm(), err)
	}
	if di, err := os.Stat(src); err != nil || di.Mode().Perm() != 0o500 {
		t.Errorf("carrier dir mode = %v (%v), want 0500", di.Mode().Perm(), err)
	}
	// The chain above it is the agent's alone: the "other" bits above only apply to something
	// already inside the runtime dir.
	if pi, err := os.Stat(filepath.Dir(src)); err != nil || pi.Mode().Perm() != 0o700 {
		t.Errorf("carrier parent mode = %v (%v), want 0700", pi.Mode().Perm(), err)
	}

	// A rotation lands IN PLACE: this directory is what the workload has mounted, so the new
	// value is live without a restart, and a key that went away is gone from the mount.
	if _, err = WriteSecretVolumes(dir, "app-1", []workload.Volume{
		secretVol("/creds", map[string][]byte{"password": []byte("rotated")}),
	}, IDs{}); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(src, "password")); err != nil || string(got) != "rotated" {
		t.Errorf("after rotation password = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(src, "ca.pem")); !os.IsNotExist(err) {
		t.Error("a key removed from the Secret is still readable in the mount")
	}
}

// TestSecretVolumeDroppedMountIsReclaimed: an app that stops declaring a secret mount leaves no
// values behind on the node.
func TestSecretVolumeDroppedMountIsReclaimed(t *testing.T) {
	dir := carrierRoot(t)
	mounts, err := WriteSecretVolumes(dir, "app-1", []workload.Volume{
		secretVol("/creds", map[string][]byte{"k": []byte("v")}),
		secretVol("/other", map[string][]byte{"k": []byte("v")}),
	}, IDs{})
	if err != nil {
		t.Fatalf("WriteSecretVolumes: %v", err)
	}
	gone := mounts[0].Source // sorted by target: /creds first

	if _, err := WriteSecretVolumes(dir, "app-1", []workload.Volume{
		secretVol("/other", map[string][]byte{"k": []byte("v")}),
	}, IDs{}); err != nil {
		t.Fatalf("dropping a mount: %v", err)
	}
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Error("the dropped mount's values are still on the node")
	}
}

// TestSecretVolumesAreOrdered: the mounts land in the sandbox config, whose digest decides
// whether the workload restarts. Map iteration order must not make an unchanged workload look
// changed on the next tick.
func TestSecretVolumesAreOrdered(t *testing.T) {
	dir := carrierRoot(t)
	vols := []workload.Volume{
		secretVol("/z", map[string][]byte{"k": []byte("v")}),
		secretVol("/a", map[string][]byte{"k": []byte("v")}),
		secretVol("/m", map[string][]byte{"k": []byte("v")}),
	}
	mounts, err := WriteSecretVolumes(dir, "app-1", vols, IDs{})
	if err != nil {
		t.Fatalf("WriteSecretVolumes: %v", err)
	}
	var got []string
	for _, m := range mounts {
		got = append(got, m.Target)
	}
	if len(got) != 3 || got[0] != "/a" || got[1] != "/m" || got[2] != "/z" {
		t.Errorf("targets = %v, want sorted", got)
	}
}

// TestSecretVolumeRefusesAPathKey: a Secret key is a file basename. One carrying a separator
// would write outside the carrier — the same class of thing the layer unpacker refuses at the
// write path rather than hoping a later check catches it.
func TestSecretVolumeRefusesAPathKey(t *testing.T) {
	dir := carrierRoot(t)
	for _, key := range []string{"../escape", "sub/key", "..", "."} {
		if _, err := WriteSecretVolumes(dir, "app-1", []workload.Volume{
			secretVol("/creds", map[string][]byte{key: []byte("v")}),
		}, IDs{}); err == nil {
			t.Errorf("key %q was accepted", key)
		}
	}
}

// TestSecretRotationIsAtomicForAReader: the workload mounts this directory and re-reads the
// file — that is the whole reason a rotating credential is a mount and not an environment
// variable. So a reader must see either the old value or the new one, and never the gap: the
// remove-then-write it used to do left three (ENOENT, a short read, and EACCES on a 0400 file
// not yet chowned). A Vault static role rotates on Vault's schedule while the workload runs,
// so this is the normal path.
func TestSecretRotationIsAtomicForAReader(t *testing.T) {
	dir := carrierRoot(t)
	// Deliberately different lengths: a short read of the longer value is otherwise a valid
	// prefix of nothing and would slip past an equality check on length alone.
	values := [][]byte{
		[]byte("short"),
		bytes.Repeat([]byte("A"), 64<<10),
		[]byte("medium-length-value"),
	}
	mounts, err := WriteSecretVolumes(dir, "app-1", []workload.Volume{
		secretVol("/creds", map[string][]byte{"password": values[0]}),
	}, IDs{})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(mounts[0].Source, "password")

	stop := make(chan struct{})
	bad := make(chan string, 8)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			got, err := os.ReadFile(file)
			if err != nil {
				select {
				case bad <- "read: " + err.Error():
				default:
				}
				return
			}
			if !slices.ContainsFunc(values, func(v []byte) bool { return bytes.Equal(v, got) }) {
				select {
				case bad <- fmt.Sprintf("torn read: %d bytes, matching no whole value", len(got)):
				default:
				}
				return
			}
		}
	}()

	for i := range 300 {
		v := values[i%len(values)]
		if _, err := WriteSecretVolumes(dir, "app-1", []workload.Volume{
			secretVol("/creds", map[string][]byte{"password": v}),
		}, IDs{}); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case msg := <-bad:
		t.Fatalf("a reader saw the rotation half-done: %s", msg)
	default:
	}
}

// TestSecretRotationLeavesNoTemporaries: the atomic write stages under a temporary name in the
// same directory, and a leftover would be projected into the workload as a key nobody asked
// for.
func TestSecretRotationLeavesNoTemporaries(t *testing.T) {
	dir := carrierRoot(t)
	mounts, err := WriteSecretVolumes(dir, "app-1", []workload.Volume{
		secretVol("/creds", map[string][]byte{"password": []byte("one")}),
	}, IDs{})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := WriteSecretVolumes(dir, "app-1", []workload.Volume{
			secretVol("/creds", map[string][]byte{"password": []byte("two")}),
		}, IDs{}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(mounts[0].Source)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "password" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("carrier holds %v, want only the projected key", names)
	}
}
