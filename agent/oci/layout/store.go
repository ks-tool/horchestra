package layout

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/opencontainers/go-digest"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"
)

// LockFile is the layout's cross-process lock. The name matches what oci-packer used, so a
// layout written by either tool is guarded by the same file and a mixed fleet cannot end up
// with two writers that do not see each other's lock.
const LockFile = "index.lock"

// Store is a local OCI layout whose layer blobs are unpacked directories. It is the whole
// interface the node needs over an image store: pull an image in, resolve one to what it takes
// to launch (config + the ordered layer directories), list what is here, drop an entry and
// reclaim what nothing references.
//
// It is deliberately NOT a generic content-addressable store with Fetcher/Pusher/Resolver
// seams. The node does exactly these six things, a layout is a directory with an index and
// some blobs, and every abstraction between the two was code to maintain for no reader's
// benefit.
type Store struct{ dir string }

// Image is a stored image: its index entry, the manifest and config it resolves to, and the
// unpacked layer directories ready to pass to an overlay mount.
type Image struct {
	Name       string
	Descriptor ocispecv1.Descriptor
	Manifest   ocispecv1.Manifest
	Config     ocispecv1.Image
	// LayerDirs is the unpacked layer directories in the MANIFEST's order: bottom-most (base)
	// first. That is the order every caller here composes in — the runtime prepends its
	// synthetic mount-point layer to it — and overlay.Mount reverses the whole stack once, at
	// the end, into the top-down order `-o lowerdir=` wants. Reversing here as well would be a
	// mount that works until the first file two layers both contain. A layer a manifest names
	// twice appears once.
	LayerDirs []string
}

// Open binds a Store to dir. It touches no filesystem beyond resolving the path: an absent
// layout reads as an empty one (Resolve says ErrNotExist, List says nothing, GC says nothing),
// which is what the reboot fast-path wants — the reconciler probes before it pulls, and a probe
// must not create anything.
//
// Binding cannot fail on a missing directory on purpose. It used to prepare the layout here,
// which put a MkdirAll and an atomic rewrite of the oci-layout marker on a path that runs for
// every workload on every converge tick. Creating is the writer's job: Pull prepares the layout
// it is about to fill, and Lock makes the directory it needs to lock in.
func Open(dir string) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &Store{dir: abs}, nil
}

// Pull fetches image into the store, unpacking every layer, and resolves what it stored. It is
// idempotent by digest: a layer already present and complete is not fetched again, so the
// reboot path costs no registry round-trip for an image the node already has.
func (s *Store) Pull(ctx context.Context, image string, opts Options) (Image, error) {
	ref, err := ParseReference(image, opts.Insecure)
	if err != nil {
		return Image{}, err
	}
	desc, err := Pull(ctx, ref, s.dir, opts)
	if err != nil {
		return Image{}, err
	}
	// The entry names itself: with NameByDigest the caller could not have known the name, and
	// re-deriving it from opts would be a second source of truth for what Pull already decided.
	return s.image(desc.Annotations[ocispecv1.AnnotationRefName], desc)
}

// Resolve reads everything needed to launch the named image: its manifest, its config and the
// layer directories in stack order. A name the index does not carry is ErrNotExist, so a
// caller can tell "never pulled" from "pulled and broken" without parsing an error string.
func (s *Store) Resolve(name string) (Image, error) {
	index, err := s.index()
	if err != nil {
		return Image{}, err
	}
	for _, desc := range index.Manifests {
		if desc.Annotations[ocispecv1.AnnotationRefName] != name {
			continue
		}
		return s.image(name, desc)
	}
	return Image{}, fmt.Errorf("image %q: %w", name, os.ErrNotExist)
}

// List resolves every image the index names. An entry whose manifest or config is unreadable
// is reported rather than skipped: a layout that half-describes an image is a bug worth
// surfacing, not something to paper over during a GC pass.
func (s *Store) List() ([]Image, error) {
	index, err := s.index()
	if err != nil {
		return nil, err
	}
	out := make([]Image, 0, len(index.Manifests))
	for _, desc := range index.Manifests {
		img, err := s.image(desc.Annotations[ocispecv1.AnnotationRefName], desc)
		if err != nil {
			return nil, err
		}
		out = append(out, img)
	}
	return out, nil
}

// Remove drops the named entry from the index. It deletes no blobs: another image may share
// them, and reclaiming is GC's decision, made once over the whole index rather than per
// removal.
func (s *Store) Remove(name string) error {
	index, err := s.index()
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(index.Manifests, func(d ocispecv1.Descriptor) bool {
		return d.Annotations[ocispecv1.AnnotationRefName] == name
	})
	if len(kept) == len(index.Manifests) {
		return fmt.Errorf("image %q: %w", name, os.ErrNotExist)
	}
	index.Manifests = kept
	return s.writeIndex(index)
}

// GC removes every blob no index entry reaches — manifests, configs and unpacked layer
// directories alike — and returns what it removed. Reachability is computed from the index in
// full before anything is deleted, so a blob shared by two images survives the removal of one.
//
// The caller holds Lock: a concurrent Pull that has written blobs but not yet published its
// index entry would otherwise look exactly like garbage.
func (s *Store) GC() ([]string, error) {
	index, err := s.index()
	if err != nil {
		return nil, err
	}
	reachable := map[string]bool{}
	for _, desc := range index.Manifests {
		img, err := s.image(desc.Annotations[ocispecv1.AnnotationRefName], desc)
		if err != nil {
			return nil, err
		}
		reachable[desc.Digest.Hex()] = true
		reachable[img.Manifest.Config.Digest.Hex()] = true
		for _, l := range img.Manifest.Layers {
			reachable[l.Digest.Hex()] = true
		}
	}
	algDir := filepath.Join(s.dir, "blobs", digest.SHA256.String())
	entries, err := os.ReadDir(algDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var removed []string
	for _, e := range entries {
		if reachable[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(algDir, e.Name())); err != nil {
			return removed, err
		}
		removed = append(removed, digest.SHA256.String()+":"+e.Name())
	}
	return removed, nil
}

// Lock takes the layout's exclusive cross-process lock and returns the release. It blocks: the
// operations it guards (pull, GC) are long and rare, and failing fast would only push the
// retry into every caller.
func (s *Store) Lock() (func(), error) {
	// The lock guards writers, and the first writer on a node meets no layout at all — so the
	// directory is made here rather than assumed. This is the one place Open's laziness has to
	// be paid for, and it is on the write path where a mkdir costs nothing.
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, LockFile), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", s.dir, err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// image reads a manifest and its config, and maps the layers onto their unpacked directories.
func (s *Store) image(name string, desc ocispecv1.Descriptor) (Image, error) {
	var manifest ocispecv1.Manifest
	if err := s.blobJSON(desc.Digest, &manifest); err != nil {
		return Image{}, fmt.Errorf("image %q manifest: %w", name, err)
	}
	var config ocispecv1.Image
	if err := s.blobJSON(manifest.Config.Digest, &config); err != nil {
		return Image{}, fmt.Errorf("image %q config: %w", name, err)
	}
	dirs := make([]string, 0, len(manifest.Layers))
	seen := make(map[digest.Digest]bool, len(manifest.Layers))
	for _, l := range manifest.Layers {
		if seen[l.Digest] {
			continue
		}
		seen[l.Digest] = true
		dirs = append(dirs, blobPath(s.dir, l.Digest))
	}
	return Image{Name: name, Descriptor: desc, Manifest: manifest, Config: config, LayerDirs: dirs}, nil
}

// blobJSON decodes a blob into v.
func (s *Store) blobJSON(d digest.Digest, v any) error {
	raw, err := os.ReadFile(blobPath(s.dir, d))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// index reads index.json. A layout with no index yet is an empty one, not an error.
func (s *Store) index() (ocispecv1.Index, error) {
	var index ocispecv1.Index
	raw, err := os.ReadFile(filepath.Join(s.dir, "index.json"))
	if err != nil {
		if os.IsNotExist(err) {
			// SchemaVersion comes from the embedded specs.Versioned, so it cannot be set in the
			// literal.
			empty := ocispecv1.Index{MediaType: ocispecv1.MediaTypeImageIndex}
			empty.SchemaVersion = 2
			return empty, nil
		}
		return index, err
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return index, fmt.Errorf("index.json: %w", err)
	}
	if index.ArtifactType != "" && index.ArtifactType != unpackArtifactType {
		return index, fmt.Errorf("index.json: artifactType %q — this layout holds plain tars, not unpacked layers", index.ArtifactType)
	}
	return index, nil
}

// writeIndex publishes the index, keeping the unpacked-layout marker so a consumer can still
// tell these layers apart from plain tars.
func (s *Store) writeIndex(index ocispecv1.Index) error {
	index.SchemaVersion = 2
	index.MediaType = ocispecv1.MediaTypeImageIndex
	index.ArtifactType = unpackArtifactType
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.dir, "index.json"), append(raw, '\n'))
}
