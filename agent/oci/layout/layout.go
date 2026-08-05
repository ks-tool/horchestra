package layout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// unpackArtifactType is oci-packer's marker for a layout whose layer blobs are unpacked
// directories (its MediaTypeUnpackLayout). Writing it is what makes this tool's output
// interchangeable with oci-packer's, and what lets a consumer refuse a layout of plain tars
// instead of stacking them as if they were trees.
const unpackArtifactType = "application/vnd.oci.layout.blobs.unpack"

// The media types that appear in the wild. The docker.* spellings are the pre-OCI ones that Docker
// Hub still serves for most images; they are the same bytes under a different name.
const (
	mediaTypeLayer           = ocispecv1.MediaTypeImageLayer
	mediaTypeLayerGzip       = ocispecv1.MediaTypeImageLayerGzip
	mediaTypeLayerZstd       = ocispecv1.MediaTypeImageLayerZstd
	mediaTypeDockerLayerTar  = "application/vnd.docker.image.rootfs.diff.tar"
	mediaTypeDockerLayerGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	mediaTypeDockerLayerZstd = "application/vnd.docker.image.rootfs.diff.tar.zstd"
	mediaTypeDockerManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerIndex     = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// manifestTypes is the Accept header: ask for everything that can answer, and let the registry
// pick. Omitting the docker types would make most of Docker Hub unreachable.
var manifestTypes = []string{
	ocispecv1.MediaTypeImageIndex,
	ocispecv1.MediaTypeImageManifest,
	mediaTypeDockerIndex,
	mediaTypeDockerManifest,
}

// copyImage is the whole operation: resolve the manifest, store it and the image config as blobs,
// unpack every layer, and publish the result in index.json. The index is written last, so a run
// interrupted anywhere leaves a layout that still describes only what is complete.
func copyImage(ctx context.Context, ref reference, layoutDir string, opts Options, lim limits) (ocispecv1.Descriptor, error) {
	platform := opts.Platform
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	c, err := newClient(ref, opts.Creds, lim)
	if err != nil {
		return ocispecv1.Descriptor{}, err
	}

	raw, mediaType, dgst, err := c.manifest(ctx, ref.target())
	if err != nil {
		return ocispecv1.Descriptor{}, err
	}
	// The pin is enforced against the RESOLVED ROOT, before platform selection and before any
	// blob is fetched: what the operator pinned is the multi-arch index, not the per-arch
	// manifest it happens to select on this node.
	if err := checkPin(opts.Pin, dgst); err != nil {
		return ocispecv1.Descriptor{}, fmt.Errorf("%s: %w", ref, err)
	}
	if mediaType == ocispecv1.MediaTypeImageIndex || mediaType == mediaTypeDockerIndex {
		desc, err := selectPlatform(raw, platform)
		if err != nil {
			return ocispecv1.Descriptor{}, fmt.Errorf("%s: %w", ref, err)
		}
		opts.Logf("index: %s selects %s", platform, desc.Digest)
		if raw, mediaType, dgst, err = c.manifest(ctx, desc.Digest.String()); err != nil {
			return ocispecv1.Descriptor{}, err
		}
	}

	var manifest ocispecv1.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ocispecv1.Descriptor{}, fmt.Errorf("manifest %s: %w", dgst, err)
	}
	if len(manifest.Layers) == 0 {
		return ocispecv1.Descriptor{}, fmt.Errorf("manifest %s has no layers", dgst)
	}
	declared, err := checkManifest(manifest, opts.Bounds)
	if err != nil {
		return ocispecv1.Descriptor{}, fmt.Errorf("manifest %s: %w", dgst, err)
	}
	if opts.Approve != nil {
		if err := opts.Approve(manifest, declared); err != nil {
			return ocispecv1.Descriptor{}, err
		}
	}
	if opts.NameByDigest {
		ref.name = dgst.String()
	}

	if err := prepareLayout(layoutDir); err != nil {
		return ocispecv1.Descriptor{}, err
	}

	opts.Logf("config: %s", manifest.Config.Digest)
	config, err := fetchBlob(ctx, c, manifest.Config.Digest)
	if err != nil {
		return ocispecv1.Descriptor{}, fmt.Errorf("image config: %w", err)
	}
	if err := writeBlob(layoutDir, manifest.Config.Digest, config); err != nil {
		return ocispecv1.Descriptor{}, err
	}

	if err := unpackLayers(ctx, c, layoutDir, manifest.Layers, opts, lim); err != nil {
		return ocispecv1.Descriptor{}, err
	}

	if err := writeBlob(layoutDir, dgst, raw); err != nil {
		return ocispecv1.Descriptor{}, err
	}

	osName, arch, _ := strings.Cut(platform, "/")
	desc := ocispecv1.Descriptor{
		MediaType:   mediaType,
		Digest:      dgst,
		Size:        int64(len(raw)),
		Platform:    &ocispecv1.Platform{OS: osName, Architecture: arch},
		Annotations: map[string]string{ocispecv1.AnnotationRefName: ref.name},
	}
	if err := updateIndex(layoutDir, desc); err != nil {
		return ocispecv1.Descriptor{}, err
	}

	opts.Logf("%s -> %s (%d layers)", ref, layoutDir, len(manifest.Layers))
	opts.Logf("lowerdir=%s", lowerdir(layoutDir, manifest.Layers))
	return desc, nil
}

// lowerdir renders the overlayfs lower stack for the layers just unpacked. A manifest lists layers
// bottom-up and overlayfs takes them top-down, so the order is reversed — getting it backwards
// produces a mount that works until the first file two layers both contain.
func lowerdir(layoutDir string, layers []ocispecv1.Descriptor) string {
	dirs := make([]string, 0, len(layers))
	seen := make(map[digest.Digest]bool, len(layers))
	for i := len(layers) - 1; i >= 0; i-- {
		// A layer repeated in the manifest is one directory, and overlayfs rejects a stack that
		// names the same directory twice.
		if seen[layers[i].Digest] {
			continue
		}
		seen[layers[i].Digest] = true
		dirs = append(dirs, blobPath(layoutDir, layers[i].Digest))
	}
	return strings.Join(dirs, ":")
}

// unpackLayers fetches and unpacks the layers, at most -j at a time. Layers are independent by
// construction — each lands in its own content-addressed directory and none reads another — so the
// only shared state is the client's token and rate limiter.
//
// The first failure cancels the rest rather than letting a doomed pull finish downloading: every
// other layer is about to be thrown away anyway, and stopping now is what keeps a wrong credential
// from costing the whole image in traffic.
func unpackLayers(ctx context.Context, c *client, layoutDir string, layers []ocispecv1.Descriptor,
	opts Options, lim limits) error {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	sem := make(chan struct{}, lim.jobs)
	// A manifest may name the same layer twice — an image built on itself, a base layer repeated.
	// Unpacking it once is not an optimisation here but a correctness rule: two goroutines racing
	// on the same directory would have one of them rename onto the other's finished work.
	seen := make(map[digest.Digest]bool, len(layers))

	for i, layer := range layers {
		if seen[layer.Digest] {
			continue
		}
		seen[layer.Digest] = true

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return contextOr(ctx, &mu, &first)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := unpackOne(ctx, c, layoutDir, layer, i+1, len(layers), opts, lim.retries); err != nil {
				mu.Lock()
				if first == nil {
					first = fmt.Errorf("layer %d/%d %s: %w", i+1, len(layers), layer.Digest, err)
					cancel()
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return contextOr(ctx, &mu, &first)
}

// contextOr prefers the recorded failure over the cancellation it caused, so the message names the
// layer that actually went wrong rather than "context canceled".
func contextOr(ctx context.Context, mu *sync.Mutex, first *error) error {
	mu.Lock()
	defer mu.Unlock()
	if *first != nil {
		return *first
	}
	return ctx.Err()
}

// unpackOne downloads one layer and extracts it into its content-addressed directory, retrying the
// whole layer when the attempt failed for a reason that might not repeat. The layer is the retry
// unit rather than the HTTP request because the body is consumed as it is extracted: once bytes
// have gone into the tar reader there is no resuming, only starting over.
func unpackOne(ctx context.Context, c *client, layoutDir string, layer ocispecv1.Descriptor,
	n, total int, opts Options, retries int) error {

	dir := blobPath(layoutDir, layer.Digest)
	if st, err := os.Stat(dir); err == nil {
		if !st.IsDir() {
			return errors.New("already present as a file; the layout stores tars, not unpacked layers")
		}
		opts.Logf("layer %d/%d: %s (present)", n, total, layer.Digest)
		return nil
	}

	var last error
	for attempt := 0; ; {
		stats, err := fetchAndUnpack(ctx, c, dir, layer, n, total, opts)
		if err == nil {
			opts.Logf("layer %d/%d: %d entries, %d whiteouts, %d opaque dirs",
				n, total, stats.entries, stats.whiteouts, stats.opaqueDirs)
			if stats.xattrsLost > 0 {
				opts.Logf("layer %d/%d: %d xattrs not restored (privileged namespaces; "+
					"meaningless under nosuid)", n, total, stats.xattrsLost)
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A layer that cannot be represented on this filesystem, by this user, will fail the same
		// way however many times it is downloaded.
		if isPermanent(err) {
			return err
		}
		last = err
		if attempt++; attempt > retries {
			return givingUp(fmt.Sprintf("layer %d/%d", n, total), attempt, last)
		}
		opts.Logf("layer %d/%d: %v; retrying", n, total, err)
		if err := sleep(ctx, backoff(attempt, 0)); err != nil {
			return err
		}
	}
}

// fetchAndUnpack is one attempt: stream the blob through the digest verifier into a temporary
// directory, and publish it only once the digest checks out.
func fetchAndUnpack(ctx context.Context, c *client, dir string, layer ocispecv1.Descriptor,
	n, total int, opts Options) (stats, error) {

	body, size, err := c.blob(ctx, layer.Digest)
	if err != nil {
		return stats{}, err
	}
	defer func() { _ = body.Close() }()
	if size < 0 {
		size = layer.Size
	}
	opts.Logf("layer %d/%d: %s (%s)", n, total, layer.Digest, humanBytes(size))

	// Unpacked beside its final home so the rename is atomic and on the same filesystem; anything
	// that fails leaves the temporary directory, never a half-unpacked layer under its digest.
	tmp, err := os.MkdirTemp(filepath.Dir(dir), ".unpack-*")
	if err != nil {
		return stats{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tmp)
		}
	}()

	// The digest covers the compressed bytes, so it is verified on the way in, before the tar
	// reader ever sees them — and checked below, since a layer is extracted as it streams and the
	// verdict only exists once the last byte has arrived.
	verifier := layer.Digest.Verifier()
	// Held to exactly what the manifest declared (pre-checked against the image cap, which is
	// what makes that cap real: without this a registry could declare kilobytes and stream
	// terabytes), and abandoned if it stops making progress rather than pinning the reconcile.
	stream := bound(&stallReader{r: body, window: opts.Stall}, layer.Size, "its declared size")
	st, err := unpackLayer(io.TeeReader(stream, verifier), layer.MediaType, tmp, opts.Owner,
		opts.Bounds.MaxLayerBytes)
	if err != nil {
		return st, err
	}
	// The tar stream ends before the blob does — trailing padding, and gzip's own footer.
	if _, err := io.Copy(io.Discard, io.TeeReader(stream, verifier)); err != nil {
		return st, err
	}
	if !verifier.Verified() {
		return st, errors.New("digest mismatch: the registry served different bytes")
	}

	if err := os.Rename(tmp, dir); err != nil {
		// Another unpack — a second run of this tool, or a concurrent one — got there first. Its
		// content is this content: the directory is named by the digest both of them verified.
		if info, statErr := os.Stat(dir); statErr == nil && info.IsDir() {
			return st, nil
		}
		return st, err
	}
	committed = true
	return st, nil
}

// selectPlatform picks the manifest for platform out of a multi-platform index. An exact variant
// match wins; otherwise the first entry for the os/arch does, since most indexes name a variant
// only for the architectures where it disambiguates.
func selectPlatform(raw []byte, platform string) (ocispecv1.Descriptor, error) {
	var index ocispecv1.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		return ocispecv1.Descriptor{}, err
	}
	wantOS, rest, _ := strings.Cut(platform, "/")
	wantArch, wantVariant, _ := strings.Cut(rest, "/")

	var fallback *ocispecv1.Descriptor
	available := make([]string, 0, len(index.Manifests))
	for i, m := range index.Manifests {
		p := m.Platform
		if p == nil || p.OS != wantOS || p.Architecture != wantArch {
			if p != nil && p.OS != "unknown" {
				available = append(available, p.OS+"/"+p.Architecture)
			}
			continue
		}
		if p.Variant == wantVariant {
			return index.Manifests[i], nil
		}
		if fallback == nil {
			fallback = &index.Manifests[i]
		}
	}
	if fallback != nil {
		return *fallback, nil
	}
	return ocispecv1.Descriptor{}, fmt.Errorf("no manifest for %s; the index has %s",
		platform, strings.Join(available, ", "))
}

// fetchBlob reads a small blob whole and verifies it. Only manifests and image configs go through
// here — a layer is streamed instead.
func fetchBlob(ctx context.Context, c *client, d digest.Digest) ([]byte, error) {
	body, _, err := c.blob(ctx, d)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	raw, err := io.ReadAll(bound(body, MaxManifestBytes, "the metadata size ceiling"))
	if err != nil {
		return nil, err
	}
	if got := digest.FromBytes(raw); got != d {
		return nil, fmt.Errorf("digest mismatch: asked for %s, got %s", d, got)
	}
	return raw, nil
}

// prepareLayout creates the layout and its version marker, which is what makes the directory an
// OCI layout rather than a directory with blobs in it.
func prepareLayout(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(ocispecv1.ImageLayout{Version: ocispecv1.ImageLayoutVersion})
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, ocispecv1.ImageLayoutFile), append(raw, '\n'))
}

// updateIndex publishes one image in the layout's index, replacing any entry under the same ref
// name. Existing entries are kept: a layout holds as many images as have been copied into it, and
// they share whatever layers they have in common.
func updateIndex(dir string, desc ocispecv1.Descriptor) error {
	var index ocispecv1.Index
	if raw, err := os.ReadFile(filepath.Join(dir, "index.json")); err == nil {
		if err := json.Unmarshal(raw, &index); err != nil {
			return fmt.Errorf("index.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	index.SchemaVersion = 2
	index.MediaType = ocispecv1.MediaTypeImageIndex
	index.ArtifactType = unpackArtifactType

	name := desc.Annotations[ocispecv1.AnnotationRefName]
	replaced := false
	for i, m := range index.Manifests {
		if m.Annotations[ocispecv1.AnnotationRefName] == name {
			index.Manifests[i], replaced = desc, true
			break
		}
	}
	if !replaced {
		index.Manifests = append(index.Manifests, desc)
	}

	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "index.json"), append(raw, '\n'))
}

func blobPath(layoutDir string, d digest.Digest) string {
	return filepath.Join(layoutDir, "blobs", d.Algorithm().String(), d.Hex())
}

// writeBlob stores a blob under its digest. A blob already there is by definition the same bytes.
func writeBlob(layoutDir string, d digest.Digest, data []byte) error {
	path := blobPath(layoutDir, d)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// writeFileAtomic replaces a file in one step, so a reader never sees a partial index.json.
func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// parseOwner reads -owner uid[:gid]; an omitted gid follows the uid, the way every container tool
// treats a bare USER.
func parseOwner(s string) (*ownership, error) {
	if len(s) == 0 {
		return nil, nil
	}
	u, g, ok := strings.Cut(s, ":")
	uid, err := strconv.Atoi(u)
	if err != nil || uid < 0 {
		return nil, fmt.Errorf("-owner %q: want uid[:gid]", s)
	}
	gid := uid
	if ok {
		if gid, err = strconv.Atoi(g); err != nil || gid < 0 {
			return nil, fmt.Errorf("-owner %q: want uid[:gid]", s)
		}
	}
	return &ownership{uid: uid, gid: gid}, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
