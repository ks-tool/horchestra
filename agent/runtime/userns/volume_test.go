//go:build linux

package userns

import (
	apisandbox "github.com/ks-tool/horchestra/api/sandbox"
	"slices"
	"testing"

	"github.com/ks-tool/horchestra/agent/runtime"
	"github.com/ks-tool/horchestra/agent/workload"
)

// TestBuildConfigProjectsPersistentVolumes: a pv volume reaches the trampoline as a bind of the
// node directory the Volumes driver resolved, and each kind lands in its OWN list. The two used
// to collapse into one — every declared volume became a tmpfs — which is exactly the failure the
// kinds exist to prevent: a workload's writes went to the ephemeral overlay while its status said
// the volume was attached.
func TestBuildConfigProjectsPersistentVolumes(t *testing.T) {
	r := testRuntime(t)
	cfg := r.buildConfig("id", baseLaunch(), baseApp(), []workload.Volume{
		{Kind: workload.VolumeTmpfs, MountPath: "/cache"},
		{Kind: workload.VolumeHostPath, Ref: "/node/volumes/data", MountPath: "/data"},
		{Kind: workload.VolumeHostPath, Ref: "/node/volumes/conf", MountPath: "/etc/app", ReadOnly: true},
	}, "", nil)

	if !slices.Equal(cfg.TmpfsMounts, []apisandbox.TmpfsMount{{Path: "/cache"}}) {
		t.Errorf("tmpfs mounts = %v, want only /cache — a pv leaked into the ephemeral list", cfg.TmpfsMounts)
	}
	want := []apisandbox.BindMount{
		{Source: "/node/volumes/data", Target: "/data"},
		{Source: "/node/volumes/conf", Target: "/etc/app", ReadOnly: true},
	}
	if !slices.Equal(cfg.BindMounts, want) {
		t.Errorf("bind mounts = %+v, want %+v", cfg.BindMounts, want)
	}
}

// TestApplyRefusesVolumesItCannotAttach: a block device or filesystem image is attached by a
// runtime that owns a machine, not bound into a mount namespace. Accepting one here would start
// the workload with its data path silently on the ephemeral overlay, so the refusal is the
// contract — and it must not be widened by accident when a new kind is added.
func TestApplyRefusesVolumesItCannotAttach(t *testing.T) {
	for _, k := range []workload.VolumeKind{workload.VolumeBlockDevice, workload.VolumeImage} {
		vols := []workload.Volume{{Kind: k, Ref: "/dev/sdb1", MountPath: "/data"}}
		if err := supportedVolumes(vols); err == nil {
			t.Errorf("volume kind %d was accepted", k)
		}
	}
	ok := []workload.Volume{
		{Kind: workload.VolumeTmpfs, MountPath: "/cache"},
		{Kind: workload.VolumeSecret, MountPath: "/creds"},
		{Kind: workload.VolumeHostPath, Ref: "/node/volumes/data", MountPath: "/data"},
	}
	if err := supportedVolumes(ok); err != nil {
		t.Errorf("a supported volume set was refused: %v", err)
	}
	// The node-side backstop is a separate gate and stays: a host-path volume with no host path
	// would otherwise be dropped at mount time with the workload started anyway.
	if err := runtime.ValidateVolumes([]workload.Volume{{Kind: workload.VolumeHostPath, MountPath: "/data"}}); err == nil {
		t.Error("a host-path volume with no source was accepted")
	}
}
