//go:build linux

package userns

import (
	"testing"

	"github.com/ks-tool/horchestra/agent/runtime"
	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// The digest under test here is the rendered sandbox config's, which replaced a hand-listed spec
// hash. The properties it has to hold are the same two, and they pull in opposite directions: it
// must be STABLE across renders of unchanged desired state (or every converge tick reads as drift
// and restarts healthy workloads forever) and SENSITIVE to every input the workload's behaviour
// depends on (or a spec change never reaches the node). What it no longer needs is a hand-kept
// list of which fields count — it digests the bytes the trampoline actually reads.

// baseApp is a fully-populated App whose digested fields are all non-empty, so a mutation to any
// one of them is observable.
func baseApp() workload.App {
	return workload.App{
		UID:       "b4e95624-75d6-4639-9f6d-2a4aa651df6f",
		Name:      "web",
		Namespace: "team-a",
		Node:      "node-1",
		Image:     "registry.example.com/app:1.2.3",
		Command:   []string{"/bin/app", "serve"},
		Args:      []string{"--port", "8080"},
		Env:       []string{"A=1", "B=2"},
	}
}

// baseLaunch is the image side of the render: the resolved layer directories and the config the
// image ships. The layer dirs are what an image reference resolves TO, and they are what the
// digest sees.
func baseLaunch() *runtime.LaunchSpec {
	return &runtime.LaunchSpec{
		LayerDirs:  []string{"/img/l1", "/img/l2"},
		Env:        []string{"PATH=/usr/bin"},
		WorkingDir: "/srv",
	}
}

// baseVolumes is the volume set the runtime projects into the config: two ephemeral tmpfs mounts
// and a PersistentVolume, whose backing directory on the node is the one thing a workload writes
// that outlives it.
func baseVolumes() []workload.Volume {
	return []workload.Volume{
		{Kind: workload.VolumeTmpfs, MountPath: "/run", Size: "64Mi"},
		{Kind: workload.VolumeTmpfs, MountPath: "/cache"},
		{Kind: workload.VolumeHostPath, Ref: "/var/lib/horchestra/volumes/team-a_web-data", MountPath: "/data"},
	}
}

func testRuntime(t *testing.T) *Runtime {
	t.Helper()
	return &Runtime{stateDir: t.TempDir(), runtimeDir: t.TempDir(), sandboxCmd: []string{"/usr/local/bin/horchestra", "sandbox"}}
}

func digest(t *testing.T, r *Runtime, app workload.App, ls *runtime.LaunchSpec, vols []workload.Volume) string {
	t.Helper()
	_, sum, err := marshalSandboxConfig(r.buildConfig(app.ID(), ls, app, vols, "", nil))
	if err != nil {
		t.Fatalf("marshalSandboxConfig: %v", err)
	}
	return sum
}

// (1) Determinism: the same input digests identically across repeated calls, and a freshly
// rebuilt equal input digests the same — reassembling desired state must not flap the digest and
// force a needless respawn.
func TestConfigDigestDeterministic(t *testing.T) {
	r := testRuntime(t)
	want := digest(t, r, baseApp(), baseLaunch(), baseVolumes())
	if want == "" {
		t.Fatal("empty digest")
	}
	for i := range 50 {
		if got := digest(t, r, baseApp(), baseLaunch(), baseVolumes()); got != want {
			t.Fatalf("call %d: digest not deterministic: got %q, want %q", i, got, want)
		}
	}
}

// (2) Field sensitivity: mutating any input the workload's behaviour depends on must yield a
// different digest, or the spec change is missed and no respawn triggered.
func TestConfigDigestFieldSensitivity(t *testing.T) {
	r := testRuntime(t)
	base := digest(t, r, baseApp(), baseLaunch(), baseVolumes())
	runAs := int64(1234)
	cases := []struct {
		name   string
		mutate func(*workload.App, *runtime.LaunchSpec, *[]workload.Volume)
	}{
		// The layers are what an image reference resolves to, and digesting them rather than the
		// ref is more accurate in both directions: re-pointing a tag relaunches when the content
		// behind it changed, and does not when it did not.
		{"layers", func(_ *workload.App, ls *runtime.LaunchSpec, _ *[]workload.Volume) {
			ls.LayerDirs = []string{"/img/l1", "/img/l9"}
		}},
		{"layer-order", func(_ *workload.App, ls *runtime.LaunchSpec, _ *[]workload.Volume) {
			ls.LayerDirs = []string{"/img/l2", "/img/l1"}
		}},
		{"image-env", func(_ *workload.App, ls *runtime.LaunchSpec, _ *[]workload.Volume) {
			ls.Env = []string{"PATH=/opt/bin"}
		}},
		{"workdir", func(_ *workload.App, ls *runtime.LaunchSpec, _ *[]workload.Volume) {
			ls.WorkingDir = "/opt"
		}},
		{"command-content", func(a *workload.App, _ *runtime.LaunchSpec, _ *[]workload.Volume) {
			a.Command = []string{"/bin/app", "run"}
		}},
		{"command-cleared", func(a *workload.App, _ *runtime.LaunchSpec, _ *[]workload.Volume) { a.Command = nil }},
		{"args-content", func(a *workload.App, _ *runtime.LaunchSpec, _ *[]workload.Volume) {
			a.Args = []string{"--port", "9090"}
		}},
		{"args-cleared", func(a *workload.App, _ *runtime.LaunchSpec, _ *[]workload.Volume) { a.Args = nil }},
		{"env-value", func(a *workload.App, _ *runtime.LaunchSpec, _ *[]workload.Volume) {
			a.Env = []string{"A=1", "B=3"}
		}},
		{"env-extra", func(a *workload.App, _ *runtime.LaunchSpec, _ *[]workload.Volume) {
			a.Env = []string{"A=1", "B=2", "C=3"}
		}},
		{"env-cleared", func(a *workload.App, _ *runtime.LaunchSpec, _ *[]workload.Volume) { a.Env = nil }},
		// Declared order is meaningful — a later assignment wins in the workload's environment —
		// so a set would collapse two genuinely different specs onto one digest.
		{"env-order", func(a *workload.App, _ *runtime.LaunchSpec, _ *[]workload.Volume) {
			a.Env = []string{"B=2", "A=1"}
		}},
		{"run-as-user", func(a *workload.App, _ *runtime.LaunchSpec, _ *[]workload.Volume) {
			a.SecurityContext = &corev1.SecurityContext{RunAsUser: &runAs}
		}},
		{"volume-removed", func(_ *workload.App, _ *runtime.LaunchSpec, v *[]workload.Volume) { *v = (*v)[:1] }},
		{"volume-added", func(_ *workload.App, _ *runtime.LaunchSpec, v *[]workload.Volume) {
			*v = append(*v, workload.Volume{Kind: workload.VolumeTmpfs, MountPath: "/tmp"})
		}},
		{"volume-mountpath", func(_ *workload.App, _ *runtime.LaunchSpec, v *[]workload.Volume) {
			(*v)[0].MountPath = "/run2"
		}},
		{"volume-cleared", func(_ *workload.App, _ *runtime.LaunchSpec, v *[]workload.Volume) { *v = nil }},
		// A PersistentVolume's source is the one input that decides WHICH data the workload comes
		// up on. Re-pointing it at another directory — a different volume, a subPath appearing or
		// going away — has to relaunch, or the running process keeps the old one open.
		{"pv-source", func(_ *workload.App, _ *runtime.LaunchSpec, v *[]workload.Volume) {
			(*v)[2].Ref = "/var/lib/horchestra/volumes/team-a_web-other"
		}},
		{"pv-readonly", func(_ *workload.App, _ *runtime.LaunchSpec, v *[]workload.Volume) {
			(*v)[2].ReadOnly = true
		}},
		{"pv-mountpath", func(_ *workload.App, _ *runtime.LaunchSpec, v *[]workload.Volume) {
			(*v)[2].MountPath = "/srv/data"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, ls, vols := baseApp(), baseLaunch(), baseVolumes()
			tc.mutate(&app, ls, &vols)
			if got := digest(t, r, app, ls, vols); got == base {
				t.Fatalf("%s change did not alter the digest (%q) — a respawn would be missed", tc.name, got)
			}
		})
	}
}

// (3) The secret-sourced environment is a PATH in the config and never a value, so rotating a
// secret moves no byte of it. That is deliberate — a resolved secret written to persistent disk
// would outlive the agent that fetched it — and it is why Apply carries a second signal
// (runtime.SecretEnvChanged) rather than relying on this digest alone. The test states the gap so
// a later reader does not close it by putting values in the config.
func TestConfigDigestDoesNotSeeSecretValues(t *testing.T) {
	r := testRuntime(t)
	app := baseApp()
	before := digest(t, r, app, baseLaunch(), baseVolumes())
	app.SecretEnv = []string{"PGPASSWORD=rotated"}
	if got := digest(t, r, app, baseLaunch(), baseVolumes()); got != before {
		t.Fatal("a secret value reached the sandbox config; it must stay in the RAM-backed carrier")
	}
}
