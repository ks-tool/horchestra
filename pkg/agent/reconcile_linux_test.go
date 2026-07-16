//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "ks-tool.dev/horchestra/api/v1"
)

func TestResourceMapping(t *testing.T) {
	// CPU limits map to a CPUQuota percentage of one core; requests to a weight
	// (one core = the systemd default of 100); memory to a byte count.
	cases := []struct {
		name, got, want string
	}{
		{"cpuQuota 500m", cpuQuota(resource.MustParse("500m")), "50%"},
		{"cpuQuota 2", cpuQuota(resource.MustParse("2")), "200%"},
		{"cpuQuota unset", cpuQuota(resource.Quantity{}), ""},
		{"cpuWeight 1", cpuWeight(resource.MustParse("1")), "100"},
		{"cpuWeight 100m", cpuWeight(resource.MustParse("100m")), "10"},
		{"memBytes 64Mi", memBytes(resource.MustParse("64Mi")), "67108864"},
		{"memBytes unset", memBytes(resource.Quantity{}), ""},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func testReconciler(t *testing.T) *Reconciler {
	t.Helper()
	return &Reconciler{
		Node:        "n1",
		StateDir:    t.TempDir(),
		provisioned: map[string]bool{},
	}
}

func pv(name, node, mode string) v1.PersistentVolume {
	return v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v1.PersistentVolumeSpec{Node: node, Mode: mode},
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// TestGCVolumesSafety exercises the reclamation guards: only volumes this node
// provisioned are eligible; a reassigned or still-present PV is kept; a mounted
// PV is kept; and an empty PV list never triggers a mass reclaim.
func TestGCVolumesSafety(t *testing.T) {
	r := testReconciler(t)
	myPVs := map[string]v1.PersistentVolume{"a": pv("a", "n1", ""), "b": pv("b", "n1", "")}
	r.provisionPVs(myPVs)
	for _, n := range []string{"a", "b"} {
		if !r.provisioned[n] || !exists(r.pvDir(n)) {
			t.Fatalf("%s not provisioned/created", n)
		}
	}

	// A directory this node never provisioned (e.g. an old layout) must be untouched.
	leftover := filepath.Join(r.StateDir, "volumes", "old-app")
	if err := os.MkdirAll(leftover, 0o755); err != nil {
		t.Fatal(err)
	}

	// All PVs present cluster-wide: reclaim nothing.
	r.gcVolumes(map[string]bool{"a": true, "b": true}, nil)
	if !exists(r.pvDir("a")) || !exists(r.pvDir("b")) || !exists(leftover) {
		t.Fatal("nothing should be reclaimed while all PVs are present")
	}

	// Empty PV list (possible controller state loss): reclaim nothing.
	r.gcVolumes(map[string]bool{}, nil)
	if !exists(r.pvDir("a")) || !exists(r.pvDir("b")) {
		t.Fatal("empty PV list must not reclaim (state-loss guard)")
	}

	// b reassigned to another node: still present cluster-wide → keep it.
	r.gcVolumes(map[string]bool{"a": true, "b": true}, nil)
	if !exists(r.pvDir("b")) {
		t.Fatal("a reassigned PV that still exists cluster-wide must be kept")
	}

	// b deleted cluster-wide, unmounted → reclaimed; a and leftover kept.
	r.gcVolumes(map[string]bool{"a": true}, nil)
	if exists(r.pvDir("b")) {
		t.Fatal("deleted PV b should be reclaimed")
	}
	if r.provisioned["b"] {
		t.Fatal("reclaimed PV must leave the provisioned set")
	}
	if !exists(r.pvDir("a")) || !exists(leftover) {
		t.Fatal("live PV and never-provisioned leftover must be kept")
	}

	// a is deleted cluster-wide but still mounted by a wanted app → keep it.
	want := map[string]App{"app": {Name: "app", VolumeMounts: []v1.VolumeMount{{PV: "a", Path: "/d"}}}}
	r.gcVolumes(map[string]bool{"z": true}, want)
	if !exists(r.pvDir("a")) {
		t.Fatal("a PV still mounted by a wanted app must not be reclaimed")
	}
}

// TestProvisionPVsSetsModeOnce checks the mode is applied at creation and not
// re-applied on later reconciles, so a workload's own adjustment survives.
func TestProvisionPVsSetsModeOnce(t *testing.T) {
	r := testReconciler(t)
	myPVs := map[string]v1.PersistentVolume{"a": pv("a", "n1", "1777")}
	r.provisionPVs(myPVs)
	if err := os.Chmod(r.pvDir("a"), 0o700); err != nil { // workload tightens the mount point
		t.Fatal(err)
	}
	r.provisionPVs(myPVs) // re-reconcile
	fi, err := os.Stat(r.pvDir("a"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("provisionPVs re-applied mode: got %o, want 700", fi.Mode().Perm())
	}
}

func TestFitsNode(t *testing.T) {
	pvs := map[string]v1.PersistentVolume{"a": pv("a", "n1", "")}
	if !fitsNode(App{Name: "x"}, pvs) {
		t.Error("app with no volumes should fit")
	}
	if !fitsNode(App{Name: "x", VolumeMounts: []v1.VolumeMount{{PV: "a", Path: "/d"}}}, pvs) {
		t.Error("app whose volume is on this node should fit")
	}
	if fitsNode(App{Name: "x", VolumeMounts: []v1.VolumeMount{{PV: "b", Path: "/d"}}}, pvs) {
		t.Error("app whose volume is not on this node should not fit")
	}
	// A tmpfs volume needs no PV, so it never blocks placement.
	if !fitsNode(App{Name: "x", VolumeMounts: []v1.VolumeMount{{Path: "/run", Tmpfs: &v1.TmpfsMount{}}}}, pvs) {
		t.Error("app with only a tmpfs volume should fit")
	}
}

func TestTmpfsSpec(t *testing.T) {
	if got := tmpfsSpec("/run", ""); got != "/run" {
		t.Errorf("no size = %q, want /run", got)
	}
	if got := tmpfsSpec("/run", "64Mi"); got != "/run:size=67108864" {
		t.Errorf("64Mi = %q, want /run:size=67108864", got)
	}
	if got := tmpfsSpec("/run", "garbage"); got != "/run" {
		t.Errorf("bad size = %q, want /run", got)
	}
}
