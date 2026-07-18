//go:build linux

package oci

import (
	"context"

	"github.com/ks-tool/horchestra/agent"
)

// Store is the node's shared, layer-deduplicated image backend: a single on-disk
// oci-layout under layoutPath, into which every application's image is pulled and
// unpacked. It implements agent.Images.
type Store struct {
	layoutPath string
}

// NewStore binds a Store to the oci-layout directory at layoutPath.
func NewStore(layoutPath string) *Store { return &Store{layoutPath: layoutPath} }

// Pull fetches source into the layout under tag, unpacked ready to mount.
func (s *Store) Pull(ctx context.Context, source, tag string) error {
	return pull(ctx, source, s.layoutPath, tag)
}

// Spec returns the launch specification of the image stored under tag: the
// ordered unpacked layer directories to mount plus the image config. Rootfs is
// left empty — the reconciler fills it with the app's mount target.
func (s *Store) Spec(ctx context.Context, tag string) (*agent.LaunchSpec, error) {
	dirs, cfg, err := imageSpec(ctx, s.layoutPath, tag)
	if err != nil {
		return nil, err
	}
	return &agent.LaunchSpec{
		LayerDirs:  dirs,
		Entrypoint: cfg.Entrypoint,
		Cmd:        cfg.Cmd,
		Env:        cfg.Env,
		User:       cfg.User,
		WorkingDir: cfg.WorkingDir,
	}, nil
}

// Remove deletes the image tagged tag, GC-ing blobs no surviving image uses.
func (s *Store) Remove(ctx context.Context, tag string) error {
	return removeImage(ctx, s.layoutPath, tag)
}

// Purge removes every stored image whose tag is not in keep, returning the tags
// removed.
func (s *Store) Purge(ctx context.Context, keep []string) ([]string, error) {
	return purge(ctx, s.layoutPath, keep)
}

var (
	_ agent.Images = (*Store)(nil)
	_ agent.Mounts = Mounter{}
)
