package runtime

import (
	"context"
	"reflect"
	"testing"

	"github.com/ks-tool/horchestra/agent/workload"
)

// recorder captures the ordered sequence of port calls Apply makes.
type recorder struct{ calls []string }

func (r *recorder) log(s string) { r.calls = append(r.calls, s) }

// TestValidateVolumes locks the node-side path backstop: a mount destination or secret
// projection path that could inject a systemd mount directive or traverse the node filesystem
// is rejected, while a clean volume set passes.
func TestValidateVolumes(t *testing.T) {
	clean := []workload.Volume{
		{Kind: workload.VolumeTmpfs, MountPath: "/data"},
		{Kind: workload.VolumeHostPath, Ref: "/node/volumes/data", MountPath: "/srv"},
		{Kind: workload.VolumeSecret, MountPath: "/creds", Content: map[string][]byte{"sub/key": nil}},
	}
	if err := ValidateVolumes(clean); err != nil {
		t.Fatalf("clean volumes rejected: %v", err)
	}
	for i, bad := range [][]workload.Volume{
		{{MountPath: "/data /etc:/x"}}, // space injects a bind
		{{MountPath: "/data/../etc"}},  // traversal
		{{MountPath: "rel"}},           // not absolute
		{{MountPath: "/creds", Content: map[string][]byte{"../../etc/shadow": nil}}}, // secret path traversal
		// VolumeHostPath is the zero VolumeKind, so a volume that names no source is both the
		// unset-Kind mistake and a bind of nothing; either way it must not reach a mount.
		{{Kind: workload.VolumeHostPath, MountPath: "/data"}},
		{{Kind: workload.VolumeHostPath, Ref: "volumes/data", MountPath: "/data"}},
	} {
		if err := ValidateVolumes(bad); err == nil {
			t.Errorf("case %d: want rejection, got nil", i)
		}
	}
}

type fakeImages struct {
	ls        *LaunchSpec
	namespace string   // the namespace scope the runtime handed the store
	keep      []string // the keep-set Purge received
}

func (f *fakeImages) Pull(_ context.Context, namespace, _ string) error {
	f.namespace = namespace
	return nil
}
func (f *fakeImages) Spec(_ context.Context, namespace, _ string) (*LaunchSpec, error) {
	f.namespace = namespace
	return f.ls, nil
}
func (f *fakeImages) Remove(context.Context, string, string) error { return nil }
func (f *fakeImages) Purge(_ context.Context, keep []string) ([]string, error) {
	f.keep = keep
	return nil, nil
}

// TestImageSource checks the scheme strip: the canonical source form drops a
// leading oci://|cr:// and leaves everything else (tags, digests) alone.
func TestImageSource(t *testing.T) {
	for in, want := range map[string]string{
		"oci://app:v1":         "app:v1",
		"cr://reg.example/app": "reg.example/app",
		"reg.example/app@sha256:0000000000000000000000000000000000000000000000000000000000000000": "reg.example/app@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"app:v1": "app:v1",
	} {
		if got := ImageSource(in); got != want {
			t.Errorf("ImageSource(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGCImagesNormalizesKeepRefs checks a scheme-prefixed keep ref still protects
// its stored source — otherwise a still-wanted image would be purged.
func TestGCImagesNormalizesKeepRefs(t *testing.T) {
	imgs := &fakeImages{}
	if _, err := GCImages(context.Background(), imgs, []string{"oci://app:v1", "busybox"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"app:v1", "busybox"}; !reflect.DeepEqual(imgs.keep, want) {
		t.Fatalf("Purge keep-set = %v, want %v", imgs.keep, want)
	}
}
