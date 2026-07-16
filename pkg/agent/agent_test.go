package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ocilayout "github.com/arenadata/oci-packer/pkg/registry/oci-layout"
	"github.com/arenadata/oci-packer/pkg/registry/reference"
	digest "github.com/opencontainers/go-digest"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/kubeconfig"
)

// seedImage tags a minimal image (config + one already-unpacked layer) under tag
// in the layout at root.
func seedImage(t *testing.T, root, tag string) {
	t.Helper()
	ctx := context.Background()
	repo, err := ocilayout.New("oci://"+root+":"+tag, ocilayout.Unpack())
	if err != nil {
		t.Fatalf("layout %s: %v", tag, err)
	}
	layer := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageLayerGzip, Digest: digest.FromString(tag + "-layer")}
	if err := os.MkdirAll(filepath.Join(root, "blobs", layer.Digest.Algorithm().String(), layer.Digest.Encoded()), 0o755); err != nil {
		t.Fatal(err)
	}
	var img ocispecv1.Image
	img.Config.Env = []string{"TAG=" + tag} // distinct config per image, no blob collision
	cfgBytes, _ := json.Marshal(img)
	cfg := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageConfig, Digest: digest.FromBytes(cfgBytes), Size: int64(len(cfgBytes))}
	if err := repo.Push(ctx, cfg, bytes.NewReader(cfgBytes)); err != nil {
		t.Fatalf("push cfg %s: %v", tag, err)
	}
	man := ocispecv1.Manifest{Config: cfg, Layers: []ocispecv1.Descriptor{layer}}
	man.SchemaVersion = 2
	man.MediaType = ocispecv1.MediaTypeImageManifest
	manBytes, _ := json.Marshal(man)
	manDesc := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageManifest, Digest: digest.FromBytes(manBytes), Size: int64(len(manBytes))}
	if err := repo.Push(ctx, manDesc, bytes.NewReader(manBytes)); err != nil {
		t.Fatalf("push man %s: %v", tag, err)
	}
	if err := repo.SetTag(ctx, manDesc); err != nil {
		t.Fatalf("tag %s: %v", tag, err)
	}
}

// TestLayoutLockConcurrent exercises both lock-acquisition orders on one layout —
// Purge (horchestra lock -> Delete's internal oci-packer lock) and Pull's order
// (horchestra lock -> oci-packer Layout.Lock()) — concurrently, guarding against
// a deadlock from nesting the two locks.
func TestLayoutLockConcurrent(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	for _, tag := range []string{"keep:1", "b:1", "c:1", "d:1"} {
		seedImage(t, root, tag)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if i%2 == 0 {
					_, _ = Purge(ctx, root, []string{"keep:1"})
					return
				}
				// Mimic Pull's lock order without a registry.
				release, err := lockLayout(root)
				if err != nil {
					return
				}
				defer release()
				repo, err := ocilayout.New(reference.OciScheme.String() + root)
				if err != nil {
					return
				}
				if l, ok := repo.(*ocilayout.Layout); ok {
					if unlock, e := l.Lock(); e == nil {
						unlock()
					}
				}
			}(i)
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("deadlock: concurrent layout locking did not complete")
	}

	// keep:1 must survive; the rest are reclaimable.
	repo, err := ocilayout.New(reference.OciScheme.String() + root)
	if err != nil {
		t.Fatal(err)
	}
	infos, err := repo.(*ocilayout.Layout).List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, info := range infos {
		if info.Ref != "keep:1" {
			t.Fatalf("unexpected surviving image %q", info.Ref)
		}
	}
}

// TestSpec builds an unpacked oci-layout — config and manifest through
// oci-packer's real writer, the layer as an already-unpacked directory — and
// checks Spec reads the config and layer directories back. (Pull unpacks layers
// via archive.Unpack, which chowns and needs root; the test places the unpacked
// result directly so it runs as an ordinary user.)
func TestSpec(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	repo, err := ocilayout.New("oci://"+root+":reg/app:v1", ocilayout.Unpack())
	if err != nil {
		t.Fatalf("layout: %v", err)
	}

	layerDesc := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageLayerGzip, Digest: digest.FromString("layer-a")}
	layerDir := filepath.Join(root, "blobs", layerDesc.Digest.Algorithm().String(), layerDesc.Digest.Encoded())
	if err := os.MkdirAll(filepath.Join(layerDir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "app", "run"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var img ocispecv1.Image
	img.Config.Entrypoint = []string{"/app/run"}
	img.Config.Env = []string{"K=V"}
	cfgBytes, _ := json.Marshal(img)
	cfgDesc := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageConfig, Digest: digest.FromBytes(cfgBytes), Size: int64(len(cfgBytes))}
	if err := repo.Push(ctx, cfgDesc, bytes.NewReader(cfgBytes)); err != nil {
		t.Fatalf("push config: %v", err)
	}

	man := ocispecv1.Manifest{Config: cfgDesc, Layers: []ocispecv1.Descriptor{layerDesc}}
	man.SchemaVersion = 2
	man.MediaType = ocispecv1.MediaTypeImageManifest
	manBytes, _ := json.Marshal(man)
	manDesc := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageManifest, Digest: digest.FromBytes(manBytes), Size: int64(len(manBytes))}
	if err := repo.Push(ctx, manDesc, bytes.NewReader(manBytes)); err != nil {
		t.Fatalf("push manifest: %v", err)
	}
	if err := repo.SetTag(ctx, manDesc); err != nil {
		t.Fatalf("set tag: %v", err)
	}

	spec, err := Spec(ctx, root, "reg/app:v1")
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	if len(spec.Entrypoint) != 1 || spec.Entrypoint[0] != "/app/run" {
		t.Fatalf("entrypoint = %v", spec.Entrypoint)
	}
	if len(spec.Env) != 1 || spec.Env[0] != "K=V" {
		t.Fatalf("env = %v", spec.Env)
	}
	if len(spec.LayerDirs) != 1 || spec.LayerDirs[0] != layerDir {
		t.Fatalf("layerDirs = %v", spec.LayerDirs)
	}
	if _, err := os.Stat(filepath.Join(spec.LayerDirs[0], "app", "run")); err != nil {
		t.Fatalf("unpacked layer missing app/run: %v", err)
	}
}

// TestPurge tags three images in one layout, then purges everything except one
// and checks the excluded image survives and the others are gone.
func TestPurge(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	for _, name := range []string{"keep", "old-a", "old-b"} {
		repo, err := ocilayout.New("oci://"+root+":"+name, ocilayout.Unpack())
		if err != nil {
			t.Fatalf("layout %s: %v", name, err)
		}
		man := ocispecv1.Manifest{
			Config: ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageConfig, Digest: digest.FromString(name + "-cfg"), Size: 1},
			Layers: []ocispecv1.Descriptor{{MediaType: ocispecv1.MediaTypeImageLayerGzip, Digest: digest.FromString(name + "-layer"), Size: 1}},
		}
		man.SchemaVersion = 2
		man.MediaType = ocispecv1.MediaTypeImageManifest
		manBytes, _ := json.Marshal(man)
		manDesc := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageManifest, Digest: digest.FromBytes(manBytes), Size: int64(len(manBytes))}
		if err := repo.Push(ctx, manDesc, bytes.NewReader(manBytes)); err != nil {
			t.Fatalf("push %s: %v", name, err)
		}
		if err := repo.SetTag(ctx, manDesc); err != nil {
			t.Fatalf("tag %s: %v", name, err)
		}
	}

	removed, err := Purge(ctx, root, []string{"keep"})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if len(removed) != 2 {
		t.Fatalf("removed = %v, want 2 images", removed)
	}

	repo, err := ocilayout.New("oci://" + root)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := repo.(*ocilayout.Layout).List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Ref != "keep" {
		t.Fatalf("remaining = %+v, want only \"keep\"", remaining)
	}
}

func TestNormalizeControllerURL(t *testing.T) {
	ok := map[string]string{
		"127.0.0.1":                  "https://127.0.0.1:8443", // the bug: bare IP, no scheme
		"10.0.0.5:8443":              "https://10.0.0.5:8443",  // host:port, no scheme
		"https://ctrl.example:8443":  "https://ctrl.example:8443",
		"https://ctrl.example":       "https://ctrl.example:8443", // default port
		"http://10.0.0.5:9000":       "http://10.0.0.5:9000",
		"https://10.0.0.5:8443/":     "https://10.0.0.5:8443", // path stripped
		"  https://10.0.0.5:8443  ":  "https://10.0.0.5:8443", // trimmed
		"[2001:db8::1]:8443":         "https://[2001:db8::1]:8443",
		"https://[2001:db8::1]:8443": "https://[2001:db8::1]:8443",
	}
	for in, want := range ok {
		got, err := NormalizeControllerURL(in)
		if err != nil {
			t.Errorf("NormalizeControllerURL(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeControllerURL(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"", "   ", "ftp://10.0.0.5", "https://"} {
		if got, err := NormalizeControllerURL(bad); err == nil {
			t.Errorf("NormalizeControllerURL(%q) = %q, want error", bad, got)
		}
	}
}

func TestLoadAuthConfig(t *testing.T) {
	server := "https://10.0.0.5:8443"
	cert := []byte("-----BEGIN CERTIFICATE-----\nnode-cert\n-----END CERTIFICATE-----\n")
	key := []byte("-----BEGIN PRIVATE KEY-----\nnode-key\n-----END PRIVATE KEY-----\n")
	ca := []byte("-----BEGIN CERTIFICATE-----\nca-cert\n-----END CERTIFICATE-----\n")

	data, err := kubeconfig.New("horchestra", "node-a", server, ca, cert, key).Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "node.conf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	creds, err := LoadAuthConfig(path)
	if err != nil {
		t.Fatalf("LoadAuthConfig: %v", err)
	}
	if creds.Controller != server {
		t.Errorf("Controller = %q, want %q", creds.Controller, server)
	}
	if !bytes.Equal(creds.CertPEM, cert) {
		t.Errorf("CertPEM = %q, want %q", creds.CertPEM, cert)
	}
	if !bytes.Equal(creds.KeyPEM, key) {
		t.Errorf("KeyPEM = %q, want %q", creds.KeyPEM, key)
	}
	if !bytes.Equal(creds.CAPEM, ca) {
		t.Errorf("CAPEM = %q, want %q", creds.CAPEM, ca)
	}

	if _, err := LoadAuthConfig(filepath.Join(t.TempDir(), "missing.conf")); err == nil {
		t.Error("LoadAuthConfig(missing) = nil error, want error")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"https://127.0.0.1:8443", "https://localhost:8443", "http://[::1]:8443"}
	for _, u := range loopback {
		if !IsLoopbackHost(u) {
			t.Errorf("IsLoopbackHost(%q) = false, want true", u)
		}
	}
	for _, u := range []string{"https://10.0.0.5:8443", "https://ctrl.example:8443"} {
		if IsLoopbackHost(u) {
			t.Errorf("IsLoopbackHost(%q) = true, want false", u)
		}
	}
}

func TestImageTag(t *testing.T) {
	cases := map[string]string{
		"oci://reg.io/ns/app:v1": "reg.io/ns/app:v1",
		"cr://reg.io/app:2":      "reg.io/app:2",
		"reg.io/app:3":           "reg.io/app:3",
	}
	for src, want := range cases {
		if got := ImageTag(src); got != want {
			t.Errorf("ImageTag(%q) = %q, want %q", src, got, want)
		}
	}
}

// TestSharedLayout stores two distinct images in one layout under source-derived
// tags and checks each resolves independently — the one-node-one-layout model.
func TestSharedLayout(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	build := func(tag, entrypoint string) {
		repo, err := ocilayout.New("oci://"+root+":"+tag, ocilayout.Unpack())
		if err != nil {
			t.Fatalf("layout %s: %v", tag, err)
		}
		layer := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageLayerGzip, Digest: digest.FromString(tag + "-layer")}
		layerDir := filepath.Join(root, "blobs", layer.Digest.Algorithm().String(), layer.Digest.Encoded())
		if err := os.MkdirAll(layerDir, 0o755); err != nil {
			t.Fatal(err)
		}
		var img ocispecv1.Image
		img.Config.Entrypoint = []string{entrypoint}
		cfgBytes, _ := json.Marshal(img)
		cfg := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageConfig, Digest: digest.FromBytes(cfgBytes), Size: int64(len(cfgBytes))}
		if err := repo.Push(ctx, cfg, bytes.NewReader(cfgBytes)); err != nil {
			t.Fatalf("push cfg %s: %v", tag, err)
		}
		man := ocispecv1.Manifest{Config: cfg, Layers: []ocispecv1.Descriptor{layer}}
		man.SchemaVersion = 2
		man.MediaType = ocispecv1.MediaTypeImageManifest
		manBytes, _ := json.Marshal(man)
		manDesc := ocispecv1.Descriptor{MediaType: ocispecv1.MediaTypeImageManifest, Digest: digest.FromBytes(manBytes), Size: int64(len(manBytes))}
		if err := repo.Push(ctx, manDesc, bytes.NewReader(manBytes)); err != nil {
			t.Fatalf("push man %s: %v", tag, err)
		}
		if err := repo.SetTag(ctx, manDesc); err != nil {
			t.Fatalf("tag %s: %v", tag, err)
		}
	}
	build("reg/a:1", "/a")
	build("reg/b:1", "/b")

	for tag, want := range map[string]string{"reg/a:1": "/a", "reg/b:1": "/b"} {
		spec, err := Spec(ctx, root, tag)
		if err != nil {
			t.Fatalf("spec %s: %v", tag, err)
		}
		if len(spec.Entrypoint) != 1 || spec.Entrypoint[0] != want {
			t.Fatalf("spec %s entrypoint = %v, want %q", tag, spec.Entrypoint, want)
		}
	}

	// Removing one image leaves the other resolvable.
	if err := RemoveImage(ctx, root, "reg/a:1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := Spec(ctx, root, "reg/a:1"); err == nil {
		t.Fatal("expected reg/a:1 to be gone")
	}
	if _, err := Spec(ctx, root, "reg/b:1"); err != nil {
		t.Fatalf("reg/b:1 should survive: %v", err)
	}
}

func TestAppFromV1(t *testing.T) {
	var app v1.Application
	body := `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1",` +
		`"resources":{"requests":{"cpu":"500m","memory":"256Mi"}}}}`
	if err := json.Unmarshal([]byte(body), &app); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := appFromV1(app)
	if got.Name != "demo" || got.Image != "reg/app:v1" || got.Node != "n1" {
		t.Fatalf("app = %+v", got)
	}
	if got.Requests.CPU.Cmp(resource.MustParse("500m")) != 0 || got.Requests.Memory.Cmp(resource.MustParse("256Mi")) != 0 {
		t.Fatalf("requests = %+v", got.Requests)
	}
}

func TestEffectiveRequests(t *testing.T) {
	// An unset request field falls back to the corresponding limit; a set one wins.
	a := App{
		Requests: v1.ResourceAmounts{CPU: resource.MustParse("500m")},
		Limits:   v1.ResourceAmounts{CPU: resource.MustParse("1"), Memory: resource.MustParse("256Mi")},
	}
	got := a.effectiveRequests()
	if got.CPU.Cmp(resource.MustParse("500m")) != 0 || got.Memory.Cmp(resource.MustParse("256Mi")) != 0 {
		t.Fatalf("effectiveRequests = %+v", got)
	}
}

func TestAppsForNode(t *testing.T) {
	apps := []App{
		{Name: "a", Node: "n1"},
		{Name: "b", Node: "n2"},
		{Name: "c", Node: "n1"},
		{Name: "d", Node: ""}, // unassigned: belongs to no node
	}
	got := appsForNode(apps, "n1")
	if len(got) != 2 {
		t.Fatalf("want 2 apps on n1, got %d: %v", len(got), got)
	}
	if _, ok := got["a"]; !ok {
		t.Error("a (node n1) should be included")
	}
	if _, ok := got["c"]; !ok {
		t.Error("c (node n1) should be included")
	}
	if _, ok := got["b"]; ok {
		t.Error("b (node n2) must not be included")
	}
	if _, ok := got["d"]; ok {
		t.Error("d (no node) must not be included on a named node")
	}
	// A node with no applications gets an empty (non-nil) map.
	if m := appsForNode(apps, "n3"); len(m) != 0 {
		t.Errorf("want no apps on n3, got %v", m)
	}
}
