//go:build linux

package oci

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/ks-tool/horchestra/agent/oci/layout"
	"github.com/ks-tool/horchestra/agent/runtime"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"github.com/opencontainers/go-digest"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// pull copies an OCI image from a registry into the shared layout at layoutPath and binds it to
// (namespace, source), with layers unpacked ready to overlay-mount. It is idempotent: a layer
// another image already landed is reused, not refetched. source is scheme-stripped
// (runtime.ImageSource) by the Store.
//
// The index entry is named by the image's OWN manifest digest (NameByDigest) — idempotent however
// many (namespace, source) bindings point at it — and the per-tenant binding lives in the
// horchestra ref map (refs.go), so co-tenants sharing an image share its blobs without being able
// to evict each other's entry.
//
// Everything the operator can bound is checked before a layer byte is fetched: a digest-pinned
// source must resolve to exactly its pin, the manifest's declared shape must fit the limits, and
// the declared bytes must fit both the store budget and the free disk space.
func pull(ctx context.Context, layoutPath, namespace, source string, limits runtime.ImageLimits) error {
	store, err := layout.Open(layoutPath)
	if err != nil {
		return err
	}
	// Held across the whole pull, so a concurrent purge cannot GC a shared layer this pull is
	// adding, nor clobber the index write, nor re-freeze a blob between another process's thaw
	// and its delete.
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()

	pin, _ := pinnedDigest(source)
	img, err := store.Pull(ctx, source, layout.Options{
		NameByDigest: true,
		Pin:          pin,
		Bounds: layout.Bounds{
			MaxLayers:     limits.EffectiveMaxLayers(),
			MaxImageBytes: limits.EffectiveMaxImageBytes(),
			MaxLayerBytes: limits.EffectiveMaxLayerBytes(),
		},
		Approve: func(_ ocispecv1.Manifest, declared int64) error {
			return checkStoreBudget(layoutPath, declared, limits)
		},
		Owner: layoutOwner(),
	})
	if err != nil {
		return err
	}
	// Past this point the image is intact and index-referenced; a failed binding write leaves
	// purge-reclaimable wreckage, not untracked blobs, so nothing is rolled back for it.
	if err := writeRef(layoutPath, namespace, source, img.Descriptor.Digest); err != nil {
		return err
	}
	hardenLayout(layoutPath)
	return nil
}

// layoutOwner leaves the ids the layers carry. The workload's uid comes from its namespace's
// block and differs per application, while a layer directory is shared node-wide by every image
// built on it — chowning it to one workload would be chowning it away from the others. The
// sandbox reaches its root through a userns id map instead.
func layoutOwner() *layout.Ownership { return nil }

// pinnedDigest returns the digest a (scheme-stripped) source reference pins (repo@sha256:…), if
// any. A source that carries no digest is unpinned; one that carries a malformed digest is
// reported unpinned here and fails the reference parse before anything is fetched.
func pinnedDigest(source string) (digest.Digest, bool) {
	_, after, found := strings.Cut(source, "@")
	if !found {
		return "", false
	}
	d, err := digest.Parse(after)
	if err != nil {
		return "", false
	}
	return d, true
}

// checkStoreBudget refuses a pull whose declared bytes cannot fit: past the operator's
// StoreBudget for the whole store (when one is set), or past the free space actually left on the
// store's filesystem (always — a full disk takes every co-tenant workload, and on a monolith host
// the controller's database, down with it, so the pull that would fill it is refused instead).
// The rejection surfaces as the workload's converge error; reclamation stays manual
// (`agent purge`).
func checkStoreBudget(layoutPath string, declared int64, limits runtime.ImageLimits) error {
	if budget := limits.StoreBudget.Value(); budget > 0 {
		used, err := storeUsage(layoutPath)
		if err != nil {
			return fmt.Errorf("measure image store: %w", err)
		}
		if used+declared > budget {
			return fmt.Errorf("pulling %d declared bytes would put the image store over its %d-byte budget (%d bytes in use): reclaim with `agent purge` or raise images.storeBudget",
				declared, budget, used)
		}
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(layoutPath, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", layoutPath, err)
	}
	if avail := int64(st.Bavail) * st.Bsize; declared > avail {
		return fmt.Errorf("image declares %d bytes but only %d bytes are free under %s", declared, avail, layoutPath)
	}
	return nil
}

// storeUsage sums the regular-file bytes under layoutPath — the store's current footprint.
// Walked only when a budget is set, and only on the pull-on-miss path.
func storeUsage(layoutPath string) (int64, error) {
	var total int64
	err := filepath.WalkDir(layoutPath, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// removeImage drops (namespace, source)'s binding from the shared layout at layoutPath. The
// index entry is dropped, and its blobs reclaimed, only when no other binding — in any namespace
// — still points at its digest.
func removeImage(_ context.Context, layoutPath, namespace, source string) error {
	store, err := layout.Open(layoutPath)
	if err != nil {
		return err
	}
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()

	binding, err := readRef(layoutPath, namespace, source)
	if err != nil {
		return err
	}
	if err := os.Remove(refPath(layoutPath, namespace, source)); err != nil {
		return err
	}
	refs, err := listRefs(layoutPath)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(refs, func(r storedRef) bool { return r.Digest == binding.Digest }) {
		return nil // another binding still uses the image; its blobs stay
	}
	if err := store.Remove(binding.Digest.String()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return reclaim(store, layoutPath)
}

// purge removes every binding in the layout at layoutPath whose source is not in keepSources —
// matched across all namespaces, so a kept ref protects the image for every tenant — then deletes
// every index entry no surviving binding references and reclaims the blobs. An index entry with
// no binding at all (the wreckage of a failed pull, or state written by an older build) is
// deleted too, never migrated.
//
// It is best-effort: a per-image failure (e.g. a layer still overlay-mounted) is collected and
// skipped so every other reclaimable image is still removed; the removed bindings
// (namespace-qualified) and entries are returned alongside any joined error.
func purge(_ context.Context, layoutPath string, keepSources []string) (removed []string, err error) {
	// The layout must already exist. Open reads an absent one as empty, which for a destructive
	// command would mean a mistyped path reports "purged nothing" instead of failing.
	if _, err := os.Stat(filepath.Join(layoutPath, "index.json")); err != nil {
		return nil, fmt.Errorf("%s is not an OCI layout: %w", layoutPath, err)
	}
	store, err := layout.Open(layoutPath)
	if err != nil {
		return nil, err
	}
	unlock, err := store.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	refs, err := listRefs(layoutPath)
	if err != nil {
		return nil, err
	}
	keep := make(map[string]bool, len(keepSources))
	for _, s := range keepSources {
		keep[s] = true
	}
	var errs []error
	for _, r := range refs {
		if keep[r.Source] && r.valid() {
			continue // a mis-filed binding (a crashed writeRef's temp) is dropped even when kept
		}
		if e := os.Remove(filepath.Join(layoutPath, refsDir, r.file)); e != nil {
			errs = append(errs, e)
			continue
		}
		removed = append(removed, corev1.WorkloadID(r.Namespace, r.Source))
	}
	// Survivors are re-listed rather than tracked, so a binding whose removal failed above still
	// protects its image from the entry sweep below.
	survivors, err := listRefs(layoutPath)
	if err != nil {
		return removed, errors.Join(append(errs, err)...)
	}
	kept := make(map[string]bool, len(survivors))
	for _, r := range survivors {
		kept[r.Digest.String()] = true
	}
	images, err := store.List()
	if err != nil {
		return removed, errors.Join(append(errs, err)...)
	}
	var dropped bool
	for _, img := range images {
		if img.Name == "" || kept[img.Name] {
			continue
		}
		if e := store.Remove(img.Name); e != nil {
			errs = append(errs, fmt.Errorf("delete %q: %w", img.Name, e))
			continue
		}
		removed = append(removed, img.Name)
		dropped = true
	}
	if dropped {
		if e := reclaim(store, layoutPath); e != nil {
			errs = append(errs, e)
		}
	}
	return removed, errors.Join(errs...)
}

// reclaim drops every blob no surviving index entry reaches, then re-applies the layout's
// permissions: the GC rewrites index.json, and a freshly written file carries the process
// umask rather than the mode the layout is meant to keep.
func reclaim(store *layout.Store, layoutPath string) error {
	defer hardenLayout(layoutPath)
	_, err := store.GC()
	return err
}

// imageSpec reads the image whose index name is refName (the manifest digest a binding resolved
// to — see refs.go) from the shared unpacked layout and returns the overlay lower stack to mount
// plus the image config (entrypoint/cmd/env/user/workdir) needed to run it.
//
// A missing layout resolves to os.ErrNotExist like a missing image, which is the answer the
// reconciler wants: it probes Spec before pulling (the reboot fast path), and both misses mean
// the same thing to it. Open reads nothing and creates nothing, so this runs every converge
// tick for every workload without touching the disk beyond the blobs it must read.
func imageSpec(_ context.Context, layoutPath, refName string) ([]string, ocispecv1.ImageConfig, error) {
	store, err := layout.Open(layoutPath)
	if err != nil {
		return nil, ocispecv1.ImageConfig{}, err
	}
	img, err := store.Resolve(refName)
	if err != nil {
		return nil, ocispecv1.ImageConfig{}, err
	}
	return img.LayerDirs, img.Config.Config, nil
}
