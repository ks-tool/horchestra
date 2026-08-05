//go:build linux

package oci

import (
	"context"

	"github.com/ks-tool/horchestra/agent/runtime"
)

// Store is the node's shared, layer-deduplicated image backend: a single on-disk
// oci-layout under layoutPath, into which every application's image is pulled and
// unpacked. Entries are bound per (namespace, source) — blobs are deduplicated
// node-wide, but one tenant's spelling of an image can never evict another's
// binding (refs.go) — and every pull is held to the configured limits. It
// implements runtime.Images.
type Store struct {
	layoutPath string
	limits     runtime.ImageLimits
}

// NewStore binds a Store to the oci-layout directory at layoutPath, enforcing
// limits on every pull (zero fields take the runtime.ImageLimits defaults).
func NewStore(layoutPath string, limits runtime.ImageLimits) *Store {
	return &Store{layoutPath: layoutPath, limits: limits}
}

// Pull fetches source into the layout for namespace, unpacked ready to mount.
func (s *Store) Pull(ctx context.Context, namespace, source string) error {
	return pull(ctx, s.layoutPath, namespace, runtime.ImageSource(source), s.limits)
}

// Spec returns the launch specification of namespace's image at source: the
// ordered unpacked layer directories to mount plus the image config. Rootfs is
// left empty — the reconciler fills it with the app's mount target.
func (s *Store) Spec(ctx context.Context, namespace, source string) (*runtime.LaunchSpec, error) {
	binding, err := readRef(s.layoutPath, namespace, runtime.ImageSource(source))
	if err != nil {
		return nil, err
	}
	dirs, cfg, err := imageSpec(ctx, s.layoutPath, binding.Digest.String())
	if err != nil {
		return nil, err
	}
	return &runtime.LaunchSpec{
		LayerDirs:  dirs,
		Entrypoint: cfg.Entrypoint,
		Cmd:        cfg.Cmd,
		Env:        cfg.Env,
		User:       cfg.User,
		WorkingDir: cfg.WorkingDir,
	}, nil
}

// Remove drops namespace's binding for source, deleting the image and GC-ing its
// blobs only when no other binding still uses it.
func (s *Store) Remove(ctx context.Context, namespace, source string) error {
	return removeImage(ctx, s.layoutPath, namespace, runtime.ImageSource(source))
}

// Purge removes every binding whose source is not in keep (matched across all
// namespaces) and every image no surviving binding references, returning what was
// removed.
func (s *Store) Purge(ctx context.Context, keep []string) ([]string, error) {
	return purge(ctx, s.layoutPath, keep)
}

var _ runtime.Images = (*Store)(nil)
