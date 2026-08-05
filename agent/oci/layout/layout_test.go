//go:build linux

package layout

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestSelectPlatform(t *testing.T) {
	index := ocispecv1.Index{Manifests: []ocispecv1.Descriptor{
		{Digest: "sha256:aaa", Platform: &ocispecv1.Platform{OS: "linux", Architecture: "amd64"}},
		{Digest: "sha256:bbb", Platform: &ocispecv1.Platform{OS: "linux", Architecture: "arm64"}},
		{Digest: "sha256:ccc", Platform: &ocispecv1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
		// The attestation manifests every buildx image carries; they are not a platform.
		{Digest: "sha256:ddd", Platform: &ocispecv1.Platform{OS: "unknown", Architecture: "unknown"}},
	}}
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct{ platform, want string }{
		{"linux/amd64", "sha256:aaa"},
		// No variant asked for: the first entry for the os/arch, since most indexes name a variant
		// only where it disambiguates.
		{"linux/arm64", "sha256:bbb"},
		{"linux/arm64/v8", "sha256:ccc"},
		// A variant nothing declares still resolves to the architecture.
		{"linux/arm64/v9", "sha256:bbb"},
	}
	for _, tt := range tests {
		desc, err := selectPlatform(raw, tt.platform)
		if err != nil {
			t.Errorf("%s: %v", tt.platform, err)
			continue
		}
		if string(desc.Digest) != tt.want {
			t.Errorf("%s: got %s, want %s", tt.platform, desc.Digest, tt.want)
		}
	}

	_, err = selectPlatform(raw, "windows/amd64")
	if err == nil {
		t.Fatal("windows/amd64 was selected out of a linux-only index")
	}
	// The message has to name what is there, or the fix is a guess.
	if !strings.Contains(err.Error(), "linux/amd64") || strings.Contains(err.Error(), "unknown") {
		t.Errorf("error should list the real platforms: %v", err)
	}
}

func TestLowerdir(t *testing.T) {
	layers := []ocispecv1.Descriptor{
		{Digest: "sha256:base"}, {Digest: "sha256:middle"}, {Digest: "sha256:top"},
	}
	// A manifest lists layers bottom-up and overlayfs takes them top-down.
	want := strings.Join([]string{
		blobPath("/l", "sha256:top"), blobPath("/l", "sha256:middle"), blobPath("/l", "sha256:base"),
	}, ":")
	if got := lowerdir("/l", layers); got != want {
		t.Errorf("lowerdir =\n%s\nwant\n%s", got, want)
	}

	// A layer named twice is one directory, and overlayfs rejects a stack that repeats one.
	dup := []ocispecv1.Descriptor{{Digest: "sha256:a"}, {Digest: "sha256:b"}, {Digest: "sha256:a"}}
	if got, want := lowerdir("/l", dup), blobPath("/l", "sha256:a")+":"+blobPath("/l", "sha256:b"); got != want {
		t.Errorf("lowerdir = %s, want %s", got, want)
	}
}

func TestParseOwner(t *testing.T) {
	own, err := parseOwner("")
	if err != nil || own != nil {
		t.Errorf("no -owner: %v, %v", own, err)
	}
	// A bare uid takes the matching gid, the way every container tool treats USER.
	if own, err = parseOwner("999"); err != nil || own.uid != 999 || own.gid != 999 {
		t.Errorf(`parseOwner("999") = %v, %v`, own, err)
	}
	if own, err = parseOwner("999:998"); err != nil || own.uid != 999 || own.gid != 998 {
		t.Errorf(`parseOwner("999:998") = %v, %v`, own, err)
	}
	for _, in := range []string{"nobody", "999:", "-1", "999:-2", "999:nogroup", ":998"} {
		if own, err := parseOwner(in); err == nil {
			t.Errorf("parseOwner(%q) = %v, want an error", in, own)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for in, want := range map[int64]string{
		0: "0 B", 512: "512 B", 1024: "1.0 KiB", 1536: "1.5 KiB",
		1 << 20: "1.0 MiB", 1 << 30: "1.0 GiB", 1 << 40: "1.0 TiB",
	} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestUpdateIndex(t *testing.T) {
	layoutDir := t.TempDir()
	desc := func(name, dgst string) ocispecv1.Descriptor {
		return ocispecv1.Descriptor{
			MediaType:   ocispecv1.MediaTypeImageManifest,
			Digest:      digest.Digest(dgst),
			Annotations: map[string]string{ocispecv1.AnnotationRefName: name},
		}
	}
	read := func() ocispecv1.Index {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(layoutDir, "index.json"))
		if err != nil {
			t.Fatal(err)
		}
		var index ocispecv1.Index
		if err := json.Unmarshal(raw, &index); err != nil {
			t.Fatal(err)
		}
		return index
	}

	if err := updateIndex(layoutDir, desc("alpine:3.21", "sha256:aaa")); err != nil {
		t.Fatal(err)
	}
	index := read()
	if index.SchemaVersion != 2 || index.ArtifactType != unpackArtifactType {
		t.Errorf("schema %d, artifactType %q", index.SchemaVersion, index.ArtifactType)
	}

	// A layout holds as many images as have been copied into it, sharing whatever layers they have
	// in common — a second image is added, not substituted.
	if err := updateIndex(layoutDir, desc("postgres:18", "sha256:bbb")); err != nil {
		t.Fatal(err)
	}
	if got := len(read().Manifests); got != 2 {
		t.Fatalf("manifests = %d, want 2", got)
	}

	// Re-copying the same ref replaces its entry rather than growing a second one.
	if err := updateIndex(layoutDir, desc("alpine:3.21", "sha256:ccc")); err != nil {
		t.Fatal(err)
	}
	index = read()
	if len(index.Manifests) != 2 {
		t.Fatalf("manifests = %d, want 2", len(index.Manifests))
	}
	for _, m := range index.Manifests {
		if m.Annotations[ocispecv1.AnnotationRefName] == "alpine:3.21" && m.Digest != "sha256:ccc" {
			t.Errorf("alpine:3.21 still points at %s", m.Digest)
		}
	}
}

// fakeRegistry serves one image over the v2 API, including the 401-then-token dance every session
// starts with. failFirst makes each path fail once with a 503, so the retry path is exercised by
// the same test that checks the result.
type fakeRegistry struct {
	repo      string
	manifest  []byte
	blobs     map[digest.Digest][]byte
	failFirst bool

	mu     sync.Mutex
	failed map[string]bool
	hits   map[string]int
}

func (f *fakeRegistry) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits[r.URL.Path]++
	f.mu.Unlock()

	if r.URL.Path == "/token" {
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "opensesame"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer opensesame" {
		w.Header().Set("Www-Authenticate",
			`Bearer realm="http://`+r.Host+`/token",service="fake",scope="repository:`+f.repo+`:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if f.failFirst {
		f.mu.Lock()
		first := !f.failed[r.URL.Path]
		f.failed[r.URL.Path] = true
		f.mu.Unlock()
		if first {
			w.Header().Set("Retry-After", "0")
			http.Error(w, `{"errors":[{"code":"TOOMANYREQUESTS","message":"slow down"}]}`,
				http.StatusServiceUnavailable)
			return
		}
	}

	switch {
	case r.URL.Path == "/v2/"+f.repo+"/manifests/latest":
		w.Header().Set("Content-Type", ocispecv1.MediaTypeImageManifest)
		w.Header().Set("Docker-Content-Digest", digest.FromBytes(f.manifest).String())
		_, _ = w.Write(f.manifest)
	case strings.HasPrefix(r.URL.Path, "/v2/"+f.repo+"/blobs/"):
		blob, ok := f.blobs[digest.Digest(strings.TrimPrefix(r.URL.Path, "/v2/"+f.repo+"/blobs/"))]
		if !ok {
			http.Error(w, `{"errors":[{"code":"BLOB_UNKNOWN","message":"unknown blob"}]}`,
				http.StatusNotFound)
			return
		}
		_, _ = w.Write(blob)
	default:
		http.NotFound(w, r)
	}
}

// newFakeRegistry builds a one-layer image out of layer and returns the server serving it, the
// manifest it describes, and the reference that reaches it.
func newFakeRegistry(t *testing.T, layer []byte, failFirst bool) (*fakeRegistry, ocispecv1.Manifest, reference) {
	t.Helper()

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(layer); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	layerBlob := gz.Bytes()

	config, err := json.Marshal(ocispecv1.Image{
		Platform: ocispecv1.Platform{OS: "linux", Architecture: "amd64"},
		Config:   ocispecv1.ImageConfig{Cmd: []string{"/bin/sh"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	manifest := ocispecv1.Manifest{
		MediaType: ocispecv1.MediaTypeImageManifest,
		Config: ocispecv1.Descriptor{
			MediaType: ocispecv1.MediaTypeImageConfig,
			Digest:    digest.FromBytes(config),
			Size:      int64(len(config)),
		},
		Layers: []ocispecv1.Descriptor{{
			MediaType: mediaTypeLayerGzip,
			Digest:    digest.FromBytes(layerBlob),
			Size:      int64(len(layerBlob)),
		}},
	}
	manifest.SchemaVersion = 2
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeRegistry{
		repo:      "test/app",
		manifest:  raw,
		failFirst: failFirst,
		failed:    map[string]bool{},
		hits:      map[string]int{},
		blobs: map[digest.Digest][]byte{
			manifest.Config.Digest:    config,
			manifest.Layers[0].Digest: layerBlob,
		},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	host, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := parseReference(host.Host+"/test/app:latest", true)
	if err != nil {
		t.Fatal(err)
	}
	return f, manifest, ref
}

// TestCopyImage is the whole tool end to end: challenge, token, manifest, config, layer, unpack,
// index — against a registry that fails every path once, so the retry loop is what gets there.
func TestCopyImage(t *testing.T) {
	layer := layerTar(t, dir("etc/", 0o755), file("etc/motd", "hello\n", 0o644))
	f, manifest, ref := newFakeRegistry(t, layer, true)

	layoutDir := filepath.Join(t.TempDir(), "layers")
	lim := limits{jobs: 2, retries: 3, qps: 0, timeout: 5 * time.Second}
	if _, err := copyImage(t.Context(), ref, layoutDir, testOpts, lim); err != nil {
		t.Fatalf("copyImage: %v", err)
	}

	// oci-layout is what makes the directory a layout rather than a directory with blobs in it.
	raw, err := os.ReadFile(filepath.Join(layoutDir, ocispecv1.ImageLayoutFile))
	if err != nil {
		t.Fatal(err)
	}
	var layout ocispecv1.ImageLayout
	if err := json.Unmarshal(raw, &layout); err != nil || layout.Version != ocispecv1.ImageLayoutVersion {
		t.Errorf("oci-layout = %q, %v", raw, err)
	}

	// The manifest and the image config are stored as received and as files: a digest covers a
	// serialisation, so re-encoding either would change its identity.
	for _, d := range []digest.Digest{digest.FromBytes(f.manifest), manifest.Config.Digest} {
		info, err := os.Stat(blobPath(layoutDir, d))
		if err != nil {
			t.Errorf("blob %s: %v", d, err)
			continue
		}
		if info.IsDir() {
			t.Errorf("blob %s is a directory", d)
		}
	}

	// The layer, though, is a directory — that is the whole point of this layout.
	layerDir := blobPath(layoutDir, manifest.Layers[0].Digest)
	if info, err := os.Stat(layerDir); err != nil || !info.IsDir() {
		t.Fatalf("layer blob is not a directory: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(layerDir, "etc/motd")); err != nil || string(got) != "hello\n" {
		t.Errorf("etc/motd = %q, %v", got, err)
	}

	if raw, err = os.ReadFile(filepath.Join(layoutDir, "index.json")); err != nil {
		t.Fatal(err)
	}
	var index ocispecv1.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	if index.ArtifactType != unpackArtifactType {
		t.Errorf("artifactType = %q; without it a consumer cannot tell these layers from tars",
			index.ArtifactType)
	}
	if len(index.Manifests) != 1 {
		t.Fatalf("manifests = %d, want 1", len(index.Manifests))
	}
	if got, want := index.Manifests[0].Digest, digest.FromBytes(f.manifest); got != want {
		t.Errorf("index names %s, want %s", got, want)
	}
	if got := index.Manifests[0].Annotations[ocispecv1.AnnotationRefName]; got != "test/app:latest" {
		t.Errorf("ref name = %q", got)
	}

	// A second run over the same layout finds the layer already there and does not fetch it again.
	if _, err := copyImage(t.Context(), ref, layoutDir, testOpts, lim); err != nil {
		t.Fatalf("second copyImage: %v", err)
	}
}

// A registry that serves different bytes than the digest promises must not leave a layer behind.
func TestCopyImageDigestMismatch(t *testing.T) {
	layer := layerTar(t, file("hello", "world\n", 0o644))
	f, manifest, ref := newFakeRegistry(t, layer, false)
	f.blobs[manifest.Layers[0].Digest] = []byte("tampered")

	layoutDir := filepath.Join(t.TempDir(), "layers")
	lim := limits{jobs: 1, retries: 0, qps: 0, timeout: 5 * time.Second}
	if _, err := copyImage(t.Context(), ref, layoutDir, testOpts, lim); err == nil {
		t.Fatal("copyImage accepted a layer whose bytes are not its digest")
	}
	if _, err := os.Stat(blobPath(layoutDir, manifest.Layers[0].Digest)); err == nil {
		t.Error("the tampered layer was published under its digest anyway")
	}
	// index.json is written last, so a run that failed anywhere describes nothing.
	if _, err := os.Stat(filepath.Join(layoutDir, "index.json")); err == nil {
		t.Error("index.json names an image that was never completed")
	}
}

// A missing blob is a 404: the registry's own message surfaces, and the layer is not downloaded
// again — three more attempts would be told the same thing three more times.
func TestCopyImageMissingBlob(t *testing.T) {
	layer := layerTar(t, file("hello", "world\n", 0o644))
	f, manifest, ref := newFakeRegistry(t, layer, false)
	delete(f.blobs, manifest.Layers[0].Digest)

	lim := limits{jobs: 1, retries: 2, qps: 0, timeout: 5 * time.Second}
	_, err := copyImage(t.Context(), ref, filepath.Join(t.TempDir(), "layers"), testOpts, lim)
	if err == nil {
		t.Fatal("copyImage succeeded without the layer")
	}
	if !strings.Contains(err.Error(), "BLOB_UNKNOWN") {
		t.Errorf("the registry's own explanation should survive: %v", err)
	}
	if got := f.count("/v2/test/app/blobs/" + manifest.Layers[0].Digest.String()); got != 1 {
		t.Errorf("the missing blob was requested %d times, want 1", got)
	}
}

func TestFetchBlobRejectsWrongDigest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not what you asked for")
	}))
	t.Cleanup(srv.Close)

	host, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := parseReference(host.Host+"/test/app:latest", true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newClient(ref, "", limits{jobs: 1, retries: 0, timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchBlob(t.Context(), c, digest.FromString("something else")); err == nil {
		t.Fatal("fetchBlob accepted bytes that are not the digest")
	}
}

// testOpts is what Pull would have built: the host platform, no credentials, no bounds, and a
// stall window short enough that a hung test fails rather than waits.
var testOpts = Options{Platform: "linux/amd64", Stall: 5 * time.Second, Logf: func(string, ...any) {}}
