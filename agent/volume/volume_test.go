package volume

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// testIDs is a subordinate range shaped like a real node's, so the tests exercise the same
// mapping arithmetic the agent does rather than an identity map that would hide a mistake in it.
var testIDs = corev1.IDRange{Min: 524288, Size: 65536}

// TestReclaimPolicy verifies that a deleted PV's data is reclaimed under Delete (the
// default) but preserved under Retain — the policy captured at provision time, since a
// deleted PV's spec is gone by the time its data would be reclaimed.
func TestReclaimPolicy(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	l := NewLocal(dir, testIDs, testIDs)

	pvs := map[string]corev1.PersistentVolume{
		"keep":  {Spec: corev1.PersistentVolumeSpec{ReclaimPolicy: corev1.ReclaimRetain}},
		"drop":  {Spec: corev1.PersistentVolumeSpec{ReclaimPolicy: corev1.ReclaimDelete}},
		"deflt": {Spec: corev1.PersistentVolumeSpec{}}, // unset => Delete
	}
	if err := l.Provision(ctx, pvs); err != nil {
		t.Fatalf("provision: %v", err)
	}
	for _, name := range []string{"keep", "drop", "deflt"} {
		if _, err := os.Stat(filepath.Join(dir, "volumes", name)); err != nil {
			t.Fatalf("provisioned dir %q missing: %v", name, err)
		}
	}

	// All three PVs are gone cluster-wide (allPVs non-empty but excludes them), none in use.
	if err := l.Reclaim(ctx, map[string]bool{"unrelated": true}, nil); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "volumes", "keep")); err != nil {
		t.Errorf("Retain must keep the data dir, but it is gone: %v", err)
	}
	for _, name := range []string{"drop", "deflt"} {
		if _, err := os.Stat(filepath.Join(dir, "volumes", name)); !os.IsNotExist(err) {
			t.Errorf("Delete must reclaim %q, but it still exists (err=%v)", name, err)
		}
	}
}

// TestResolveSubPathAndReadOnly verifies a pv mount's subPath folds into the resolved host
// path (created on demand, no escaping) and readOnly passes through to the resolved volume.
func TestResolveSubPathAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	l := NewLocal(dir, testIDs, testIDs)
	app := workload.App{
		Name: "web",
		Volumes: []corev1.VolumeMount{{
			Volume:    corev1.VolumeSource{Type: corev1.VolumeTypePV, Name: "data"},
			MountPath: "/data",
			SubPath:   "app1",
			ReadOnly:  true,
		}},
	}
	pvs := map[string]corev1.PersistentVolume{"data": {}}

	vols, err := l.Resolve(app, pvs)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(vols) != 1 {
		t.Fatalf("want 1 resolved volume, got %d", len(vols))
	}
	// The ref is the path under the volume as spelled, not an EvalSymlinks of it: every
	// component BELOW the volume root is proven to be a real directory the agent owns, so there
	// is no symlink left there to resolve. Components ABOVE it (darwin's /var -> /private/var,
	// or wherever the operator put the state dir) are the operator's and are left alone —
	// resolving those would only rewrite the path systemd is asked to bind.
	wantRef := filepath.Join(dir, "volumes", "data", "app1")
	if vols[0].Ref != wantRef {
		t.Errorf("subPath ref = %q, want %q", vols[0].Ref, wantRef)
	}
	if !vols[0].ReadOnly {
		t.Error("readOnly must pass through to the resolved volume")
	}
	if _, err := os.Stat(wantRef); err != nil {
		t.Errorf("the subPath directory must be created: %v", err)
	}

	app.Volumes[0].SubPath = "../../etc"
	if _, err := l.Resolve(app, pvs); err == nil {
		t.Error("a subPath escaping the volume must be rejected")
	}
}

// TestResolveSkipsSecretVolumes checks a secret mount is ignored by the storage port (the
// Secrets port materializes it) — not mistaken for a missing PersistentVolume.
func TestResolveSkipsSecretVolumes(t *testing.T) {
	l := NewLocal(t.TempDir(), testIDs, testIDs)
	app := workload.App{
		Name: "web",
		Volumes: []corev1.VolumeMount{{
			Volume:    corev1.VolumeSource{Type: corev1.VolumeTypeSecret, Name: "db"},
			MountPath: "/creds",
		}},
	}
	if !l.Fits(app, nil) {
		t.Error("a secret mount must not make an app not fit (Fits only gates on PVs)")
	}
	vols, err := l.Resolve(app, nil)
	if err != nil {
		t.Fatalf("a secret mount must be skipped by storage, got %v", err)
	}
	if len(vols) != 0 {
		t.Fatalf("storage must resolve no volumes for a secret-only app, got %d", len(vols))
	}
}

// TestSubPathCannotEscapeViaSymlink: the contents of a PV belong to the workload, so a
// lexical "no '..', not absolute" check is not containment. A workload drops a symlink to /
// inside its own volume, then has its Application updated to name it as subPath; filepath.Join
// is lexical and the bind mount resolves the link, which would mount the host root into the
// container.
//
// Resolving the symlinks and re-checking containment is not enough either, because the path is
// handed to systemd as a BindPaths= source STRING that systemd re-resolves at every start of
// the unit — so a component validated now can be swapped for a symlink before the next restart.
// A symlink component is therefore refused outright, even one that currently points inside the
// volume: the workload can re-point what it planted.
func TestSubPathCannotEscapeViaSymlink(t *testing.T) {
	dir := t.TempDir()
	l := NewLocal(dir, testIDs, testIDs).(*local)
	if err := l.Provision(context.Background(), map[string]corev1.PersistentVolume{"data": {}}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	vol := filepath.Join(dir, "volumes", "data")

	// The escapes a workload can plant in its own volume.
	outside := t.TempDir()
	for _, link := range []struct{ name, target string }{
		{"root", "/"},
		{"etc", "/etc"},
		{"elsewhere", outside},
		{"up", ".."},
	} {
		if err := os.Symlink(link.target, filepath.Join(vol, link.name)); err != nil {
			t.Fatalf("plant %s: %v", link.name, err)
		}
	}
	// A symlink reached through a legitimate subdirectory, so the check cannot just look at
	// the last component.
	if err := os.MkdirAll(filepath.Join(vol, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(vol, "nested", "out")); err != nil {
		t.Fatal(err)
	}

	// A symlink that stays inside the volume is refused too: the workload planted it, so it can
	// re-point it at any time, and systemd resolves the source afresh on every restart.
	if err := os.Symlink("nested", filepath.Join(vol, "inside")); err != nil {
		t.Fatal(err)
	}

	for _, sub := range []string{"root", "etc", "elsewhere", "up", "nested/out", "inside"} {
		t.Run(sub, func(t *testing.T) {
			got, err := l.subPathRef("data", sub)
			if err == nil {
				t.Fatalf("subPath %q escaped the volume and resolved to %q", sub, got)
			}
		})
	}

	// A real subdirectory — created fresh, or already there and owned by the agent — still works.
	for _, sub := range []string{"app1", "nested", "deep/er/still"} {
		t.Run("allowed/"+sub, func(t *testing.T) {
			got, err := l.subPathRef("data", sub)
			if err != nil {
				t.Fatalf("legitimate subPath %q rejected: %v", sub, err)
			}
			if want := filepath.Join(vol, sub); got != want {
				t.Fatalf("resolved %q, want %q inside the volume", got, want)
			}
		})
	}
}

// TestSubPathComponentsAreNotSwappable is the containment invariant itself, stated over the
// filesystem rather than over one call: every component of the bind source belongs to the agent,
// no component below the volume root is a symlink, and the intermediates are not writable by the
// workload's group — so there is no component the workload can unlink, rename or re-point
// between the check and the mount systemd performs at every restart.
func TestSubPathComponentsAreNotSwappable(t *testing.T) {
	dir := t.TempDir()
	l := NewLocal(dir, testIDs, testIDs).(*local)
	if err := l.Provision(context.Background(), map[string]corev1.PersistentVolume{"data": {}}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	vol := filepath.Join(dir, "volumes", "data")

	ref, err := l.subPathRef("data", "a/b/leaf")
	if err != nil {
		t.Fatalf("subPathRef: %v", err)
	}

	// The volume root: agent-owned so the workload cannot chmod it, sticky so the workload
	// cannot remove the agent-owned entries the bind source is made of.
	rootInfo, err := os.Lstat(vol)
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode()&os.ModeSticky == 0 {
		t.Errorf("volume root %s is not sticky: the workload could unlink the subPath chain", vol)
	}
	if uid, ok := ownerUID(rootInfo); !ok || int(uid) != os.Getuid() {
		t.Errorf("volume root %s is owned by uid %d, not the agent — an owner can chmod the sticky bit away", vol, uid)
	}

	for _, p := range []string{filepath.Join(vol, "a"), filepath.Join(vol, "a", "b")} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			t.Errorf("intermediate %s is a symlink", p)
		}
		if uid, ok := ownerUID(fi); !ok || int(uid) != os.Getuid() {
			t.Errorf("intermediate %s is owned by uid %d, not the agent", p, uid)
		}
		if fi.Mode().Perm()&0o020 != 0 {
			t.Errorf("intermediate %s is group-writable (%#o): the workload could rename what is inside it", p, fi.Mode().Perm())
		}
	}

	// The leaf is the one the workload writes into, so it carries the volume's mode — group
	// access, and sticky again, because a deeper subPath may nest inside it.
	leaf, err := os.Lstat(ref)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Mode().Perm()&0o070 == 0 {
		t.Errorf("leaf %s (%#o) is unusable by the workload's group", ref, leaf.Mode().Perm())
	}
	if leaf.Mode()&os.ModeSticky == 0 {
		t.Errorf("leaf %s is not sticky: a nested subPath under it could be unlinked", ref)
	}
	if uid, ok := ownerUID(leaf); !ok || int(uid) != os.Getuid() {
		t.Errorf("leaf %s is owned by uid %d, not the agent", ref, uid)
	}
}

// TestSubPathRejectsWorkloadOwnedComponent: the workload can still CREATE entries in its own
// volume, so it can get to a subPath name before the agent does. A directory it owns is one it
// can rename away, so building the bind source on it fails closed instead. Needs root, because
// the point is a component owned by somebody other than the agent.
func TestSubPathRejectsWorkloadOwnedComponent(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to create a component owned by another uid")
	}
	dir := t.TempDir()
	l := NewLocal(dir, testIDs, testIDs).(*local)
	if err := l.Provision(context.Background(), map[string]corev1.PersistentVolume{"data": {}}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	vol := filepath.Join(dir, "volumes", "data")
	squatted := filepath.Join(vol, "app1")
	if err := os.Mkdir(squatted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(squatted, int(corev1.DefaultRunAsID), int(corev1.DefaultRunAsID)); err != nil {
		t.Fatal(err)
	}
	if got, err := l.subPathRef("data", "app1"); err == nil {
		t.Fatalf("a workload-owned component was adopted as the bind source %q", got)
	}
}

// TestOnlyASubPathTakesTheVolumeRoot pins how narrow the ownership change is. A volume nobody
// takes a subPath of keeps exactly the workload-owned directory it has always had, so ordinary
// mounts — and images that chmod their own data directory — are untouched. The moment a subPath
// is resolved out of that volume, the root has to become agent-owned and sticky, because that
// is the only thing standing between the workload and the components of the bind source.
func TestOnlyASubPathTakesTheVolumeRoot(t *testing.T) {
	dir := t.TempDir()
	l := NewLocal(dir, testIDs, testIDs).(*local)
	pvs := map[string]corev1.PersistentVolume{"plain": {}, "sub": {}}
	if err := l.Provision(context.Background(), pvs); err != nil {
		t.Fatalf("provision: %v", err)
	}

	plain := filepath.Join(dir, "volumes", "plain")
	fi, err := os.Lstat(plain)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSticky != 0 {
		t.Errorf("a volume with no subPath must be left as it was, got mode %#o", fi.Mode())
	}

	// An older agent left volumes workload-owned and without the sticky bit — the state that
	// makes the chain swappable — so resolving a subPath has to repair it in place.
	vol := filepath.Join(dir, "volumes", "sub")
	if err := os.Chmod(vol, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := l.subPathRef("sub", "app1"); err != nil {
		t.Fatalf("subPathRef: %v", err)
	}
	fi, err = os.Lstat(vol)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSticky == 0 {
		t.Errorf("volume root kept mode %#o: without the sticky bit the workload can unlink the subPath chain", fi.Mode())
	}
	if fi.Mode().Perm()&0o070 == 0 {
		t.Errorf("the repair took the workload's access away (%#o)", fi.Mode().Perm())
	}
	if uid, ok := ownerUID(fi); !ok || int(uid) != os.Getuid() {
		t.Errorf("volume root is owned by uid %d, not the agent — an owner can chmod the sticky bit away", uid)
	}
}

// TestVolumeKeepsBothSpecialBits: setgid and sticky are set by two different functions, and both
// used to rebuild the mode from Perm() alone — which drops the other's bit. On a live node that
// left the volume root sticky-without-setgid or setgid-without-sticky depending on the order the
// app happened to declare its mounts in, and the sticky half is what stops the workload unlinking
// the agent-owned chain a subPath bind source is made of.
func TestVolumeKeepsBothSpecialBits(t *testing.T) {
	group := int64(1234)
	root := corev1.VolumeMount{Volume: corev1.VolumeSource{Type: corev1.VolumeTypePV, Name: "data"}, MountPath: "/data"}
	sub := corev1.VolumeMount{Volume: corev1.VolumeSource{Type: corev1.VolumeTypePV, Name: "data"}, MountPath: "/inner", SubPath: "app1"}

	for _, tc := range []struct {
		name  string
		mount []corev1.VolumeMount
	}{
		{"root-then-subpath", []corev1.VolumeMount{root, sub}},
		{"subpath-then-root", []corev1.VolumeMount{sub, root}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			l := NewLocal(dir, testIDs, testIDs)
			pvs := map[string]corev1.PersistentVolume{"data": {}}
			if err := l.Provision(context.Background(), pvs); err != nil {
				t.Fatalf("provision: %v", err)
			}
			app := workload.App{
				Name:            "web",
				SecurityContext: &corev1.SecurityContext{RunAsGroup: &group},
				Volumes:         tc.mount,
			}
			// Twice: the second converge must not undo what the first settled on either.
			for range 2 {
				if _, err := l.Resolve(app, pvs); err != nil {
					t.Fatalf("resolve: %v", err)
				}
			}
			fi, err := os.Lstat(filepath.Join(dir, "volumes", "data"))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode()&os.ModeSticky == 0 {
				t.Errorf("volume root mode %#o lost the sticky bit: the workload can unlink the subPath chain", fi.Mode())
			}
			if fi.Mode()&os.ModeSetgid == 0 {
				t.Errorf("volume root mode %#o lost setgid: files created inside stop landing in the shared group", fi.Mode())
			}
		})
	}
}

// TestSubPathRejectsInjectableCharacters: the resolved path becomes the SOURCE half of a
// systemd bind directive, and BindPaths= is a whitespace-separated list of source:dest triples.
// So a subPath that is relative, clean and free of ".." can still be an injection: a leading
// space appends a second, fully attacker-chosen bind. Containment is necessary but not
// sufficient — the characters matter too.
func TestSubPathRejectsInjectableCharacters(t *testing.T) {
	dir := t.TempDir()
	l := NewLocal(dir, testIDs, testIDs).(*local)
	if err := l.Provision(context.Background(), map[string]corev1.PersistentVolume{"data": {}}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	for _, sub := range []string{
		" /var/lib/horchestra/volumes", // the injection: a second BindPaths= entry
		"app /etc",
		"app:/etc",
		"app\tx",
		"app\nUser=0",
		"./app",  // unclean
		"app/",   // unclean
		"a//b",   // unclean
		"app/..", // traversal that survives a naive suffix check
	} {
		t.Run(sub, func(t *testing.T) {
			if got, err := l.subPathRef("data", sub); err == nil {
				t.Fatalf("subPath %q was accepted and resolved to %q", sub, got)
			}
		})
	}
}

// TestVolumeModeDropsDangerousBits: spec.mode is a tenant string applied by a root agent to a
// directory other local accounts can see. World bits hand every unprivileged account on the node
// read — and at 0777 write — of that tenant's data, which is a tampering primitive against the
// workload that reads it; setuid/setgid are meaningless on a data directory and setgid-root is an
// escalation aid. Neither is the tenant's to grant.
func TestVolumeModeDropsDangerousBits(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want os.FileMode
	}{
		{"", defaultVolumeMode},
		{"0777", 0o770},
		{"777", 0o770},
		{"0755", 0o750},
		{"0750", 0o750},
		{"0700", 0o700},
		{"4755", 0o750},                 // setuid dropped
		{"2777", 0o770},                 // setgid dropped
		{"1777", 0o770 | os.ModeSticky}, // sticky kept, world dropped
		{"nonsense", defaultVolumeMode}, // unparseable
		{"0007", defaultVolumeMode},     // owner cannot use it: a typo, not a request
	} {
		t.Run(tc.in, func(t *testing.T) {
			got := volumeMode(tc.in)
			if got != tc.want {
				t.Fatalf("volumeMode(%q) = %#o, want %#o", tc.in, got, tc.want)
			}
			if got.Perm()&0o007 != 0 {
				t.Fatalf("volumeMode(%q) = %#o grants world access", tc.in, got)
			}
			if got&(os.ModeSetuid|os.ModeSetgid) != 0 {
				t.Fatalf("volumeMode(%q) = %#o carries setuid/setgid", tc.in, got)
			}
		})
	}
}
