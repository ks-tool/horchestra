package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/arenadata/oci-packer/pkg/registry"
	ocilayout "github.com/arenadata/oci-packer/pkg/registry/oci-layout"
	"github.com/arenadata/oci-packer/pkg/registry/reference"
	"github.com/arenadata/oci-packer/pkg/registry/remote"
	"github.com/containerd/platforms"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rogpeppe/go-internal/lockedfile"
)

// lockLayout takes horchestra's own exclusive, cross-process lock on the layout.
// It brackets the immutable thaw/refreeze around a mutation so a second process
// (a manual `purge` racing the daemon) cannot re-freeze a blob between one
// process's thaw and its Delete's os.RemoveAll — which would leave an
// unreclaimable immutable orphan.
//
// It is deliberately a SEPARATE lock file from oci-packer's index.lock: fcntl
// (Linux F_OFD_SETLK) and flock locks are per-open-file-description, so
// re-locking the same file in one process deadlocks — and Delete already locks
// index.lock internally. Held outer to oci-packer's lock, always in that order,
// so the two never deadlock.
func lockLayout(layoutPath string) (func(), error) {
	return lockedfile.MutexAt(filepath.Join(layoutPath, "horchestra.lock")).Lock()
}

type LaunchSpec struct {
	Rootfs     string
	LayerDirs  []string
	Entrypoint []string
	Cmd        []string
	Env        []string
	User       string
	WorkingDir string
}

// ImageTag is the ref name under which a source image is stored in the node's
// shared oci-layout. spec.source is a plain image reference (e.g.
// reg.io/ns/app:v1, no scheme); ImageTag returns it verbatim, which is a valid,
// human-readable ref name (no "//", which reference.Parse rejects) and keys
// images by source so apps sharing a source share one deduplicated image. A
// leading oci://|cr:// scheme is still tolerated and stripped.
func ImageTag(source string) string {
	for _, scheme := range []string{reference.OciScheme.String(), reference.RegistryScheme.String()} {
		if strings.HasPrefix(source, scheme) {
			return strings.TrimPrefix(source, scheme)
		}
	}
	return source
}

// Pull copies an OCI image from a registry into the shared oci-layout at
// layoutPath, tagged tag, with layers unpacked ready to overlay-mount. It reuses
// oci-packer's registry client (no external oci-packer/skopeo binary needed) and
// is idempotent: blobs already present from another image are reused, not
// refetched.
func Pull(ctx context.Context, source, layoutPath, tag string) error {
	// spec.source is a plain image reference; remote.New wants the cr:// registry
	// scheme (oci:// there would select a local layout), so add it. ImageTag
	// first strips any scheme a caller included out of habit.
	srcRepo, err := remote.New(reference.RegistryScheme.String() + ImageTag(source))
	if err != nil {
		return err
	}
	dstRepo, err := ocilayout.New(reference.OciScheme.String()+layoutPath+":"+tag, ocilayout.Unpack())
	if err != nil {
		return err
	}
	l, ok := dstRepo.(*ocilayout.Layout)
	if !ok {
		return fmt.Errorf("%s is not an OCI layout", layoutPath)
	}
	// Serialise the harden against a concurrent delete's thaw (horchestra lock),
	// outer to oci-packer's own copy-vs-delete lock.
	release, err := lockLayout(layoutPath)
	if err != nil {
		return err
	}
	defer release()
	// registry.Copy does not lock, so hold oci-packer's cross-process layout lock
	// across the whole copy+tag: a concurrent delete/purge (which locks) then
	// cannot GC a shared layer this copy is adding, nor clobber the index write.
	unlock, err := l.Lock()
	if err != nil {
		return err
	}
	defer unlock()

	desc, err := srcRepo.Resolve(ctx, reference.Reference{})
	if err != nil {
		return err
	}
	// Select the host platform out of a multi-arch index before copying, so a
	// multi-platform tag (e.g. postgres:18-alpine) does not drag every
	// architecture's layers onto the node. A single-platform manifest passes
	// through unchanged.
	desc, err = registry.SelectPlatform(ctx, srcRepo, desc, platforms.Only(platforms.DefaultSpec()))
	if err != nil {
		return err
	}
	if err := registry.Copy(ctx, l, srcRepo, desc); err != nil {
		return err
	}
	if err := l.SetTag(ctx, desc); err != nil {
		return err
	}
	hardenLayout(layoutPath)
	return nil
}

// RemoveImage deletes the image tagged tag from the shared oci-layout at
// layoutPath, letting oci-packer garbage-collect blobs no surviving image
// references. A layer still overlay-mounted under a running application is kept.
func RemoveImage(ctx context.Context, layoutPath, tag string) error {
	ref, err := reference.Parse(reference.OciScheme.String() + layoutPath)
	if err != nil {
		return err
	}
	repo, err := ocilayout.Open(ref)
	if err != nil {
		return err
	}
	l, ok := repo.(*ocilayout.Layout)
	if !ok {
		return fmt.Errorf("%s is not an OCI layout", layoutPath)
	}
	release, err := lockLayout(layoutPath)
	if err != nil {
		return err
	}
	defer release()
	// Thaw immutable blobs so Delete's blob GC can remove orphans, then refreeze
	// whatever survives. Held under the horchestra lock so no concurrent Pull can
	// re-freeze a blob between the thaw and Delete's os.RemoveAll.
	unlockLayout(layoutPath)
	defer hardenLayout(layoutPath)
	return l.Delete(ctx, reference.Reference{Ref: tag})
}

// Purge removes every image in the oci-layout at layoutPath whose ref name is
// not in exclude, letting oci-packer garbage-collect blobs no surviving image
// references. Untagged entries are left untouched (they can't be addressed by
// ref name). It is best-effort: a per-image Delete failure (e.g. a layer still
// overlay-mounted) is collected and skipped so every other reclaimable image is
// still removed; the removed ref names are returned alongside any joined error.
func Purge(ctx context.Context, layoutPath string, exclude []string) (removed []string, err error) {
	// Open (not New): New would create an empty layout for a mistyped path
	// instead of failing, which is the wrong default for a destructive command.
	ref, err := reference.Parse(reference.OciScheme.String() + layoutPath)
	if err != nil {
		return nil, err
	}
	repo, err := ocilayout.Open(ref)
	if err != nil {
		return nil, err
	}
	l, ok := repo.(*ocilayout.Layout)
	if !ok {
		return nil, fmt.Errorf("%s is not an OCI layout", layoutPath)
	}
	images, err := l.List()
	if err != nil {
		return nil, err
	}
	keep := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		keep[e] = true
	}
	var victims []string
	for _, img := range images {
		if len(img.Ref) > 0 && !keep[img.Ref] {
			victims = append(victims, img.Ref)
		}
	}
	if len(victims) == 0 {
		return nil, nil // nothing to reclaim — skip the lock and thaw/refreeze walks
	}
	release, err := lockLayout(layoutPath)
	if err != nil {
		return nil, err
	}
	defer release()
	// Blobs are frozen immutable on write; thaw before deleting, refreeze after,
	// under the horchestra lock so a concurrent Pull can't re-freeze mid-delete.
	unlockLayout(layoutPath)
	defer hardenLayout(layoutPath)
	var errs []error
	for _, ref := range victims {
		if e := l.Delete(ctx, reference.Reference{Ref: ref}); e != nil {
			errs = append(errs, fmt.Errorf("delete %q: %w", ref, e))
			continue
		}
		removed = append(removed, ref)
	}
	return removed, errors.Join(errs...)
}

// Spec reads the image tagged tag from the shared unpacked OCI layout and returns
// its launch specification: the image config plus the ordered unpacked layer
// directories to overlay-mount.
func Spec(ctx context.Context, layoutPath, tag string) (*LaunchSpec, error) {
	repo, err := ocilayout.New(reference.OciScheme.String() + layoutPath + ":" + tag)
	if err != nil {
		return nil, err
	}
	l, ok := repo.(*ocilayout.Layout)
	if !ok {
		return nil, fmt.Errorf("%s is not an OCI layout", layoutPath)
	}
	dirs, err := l.LayerDirs(ctx, reference.Reference{})
	if err != nil {
		return nil, err
	}
	img, err := imageConfig(ctx, l, reference.Reference{})
	if err != nil {
		return nil, err
	}
	return &LaunchSpec{
		LayerDirs:  dirs,
		Entrypoint: img.Config.Entrypoint,
		Cmd:        img.Config.Cmd,
		Env:        img.Config.Env,
		User:       img.Config.User,
		WorkingDir: img.Config.WorkingDir,
	}, nil
}

// imageConfig resolves the host-platform image manifest in the layout (following
// a multi-platform index) and decodes its config blob.
func imageConfig(ctx context.Context, l *ocilayout.Layout, ref reference.Reference) (ocispecv1.Image, error) {
	desc, err := l.Resolve(ctx, ref)
	if err != nil {
		return ocispecv1.Image{}, err
	}
	if isIndex(desc.MediaType) {
		var idx ocispecv1.Index
		if err := fetchJSON(ctx, l, desc.Digest.String(), &idx); err != nil {
			return ocispecv1.Image{}, err
		}
		match := platforms.Only(platforms.DefaultSpec())
		desc = ocispecv1.Descriptor{}
		for _, m := range idx.Manifests {
			if m.Platform != nil && match.Match(*m.Platform) {
				desc = m
				break
			}
		}
		if len(desc.Digest) == 0 {
			return ocispecv1.Image{}, fmt.Errorf("no manifest matches host platform %s", platforms.Format(platforms.DefaultSpec()))
		}
	}
	var manifest ocispecv1.Manifest
	if err := fetchJSON(ctx, l, desc.Digest.String(), &manifest); err != nil {
		return ocispecv1.Image{}, err
	}
	var img ocispecv1.Image
	if err := fetchJSON(ctx, l, manifest.Config.Digest.String(), &img); err != nil {
		return ocispecv1.Image{}, err
	}
	return img, nil
}

func fetchJSON(ctx context.Context, l *ocilayout.Layout, dgst string, v any) error {
	r, err := l.Fetch(ctx, reference.Reference{Ref: dgst})
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	return json.NewDecoder(r).Decode(v)
}

func isIndex(mediaType string) bool {
	return mediaType == ocispecv1.MediaTypeImageIndex ||
		mediaType == "application/vnd.docker.distribution.manifest.list.v2+json"
}
