package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
)

// refsDir holds horchestra's own image ref map: one file per (namespace, source)
// pair, named by storeKey, recording the manifest digest that pair verified to.
// It exists because the layout index keeps ONE ref-name annotation per manifest
// digest — SetTag replaces the matching entry — so naming index entries after
// tenant-supplied refs let two spellings of one image (or two tenants) evict each
// other's entry forever, each eviction forcing the other back to the registry on
// every heartbeat. With the map, index entries are annotated by their own digest
// (idempotent however many refs point at them) and any number of per-namespace
// bindings resolve onto one shared, deduplicated image. It lives outside blobs/
// so the layout's own blob walks never see it.
const refsDir = "horchestra-refs"

// imageRef is one stored binding: which namespace asked for which source, and the
// platform-selected manifest digest the pull verified.
type imageRef struct {
	Namespace string        `json:"namespace,omitempty"`
	Source    string        `json:"source"`
	Digest    digest.Digest `json:"digest"`
}

// storeKey is the store-local identity of an image: a digest over the
// (namespace, source) pair, so the key space is per-tenant — one namespace's
// entry can never be evicted or renamed by another namespace sharing the node
// (mirroring how corev1.WorkloadID scopes workloads). Hashed so the key is a
// safe file name whatever characters the source carries; the NUL separator makes
// the pair unambiguous (neither part may contain NUL).
func storeKey(namespace, source string) string {
	h := sha256.New()
	h.Write([]byte(namespace))
	h.Write([]byte{0})
	h.Write([]byte(source))
	return hex.EncodeToString(h.Sum(nil))
}

// refPath is the on-disk file recording (namespace, source)'s binding.
func refPath(layoutPath, namespace, source string) string {
	return filepath.Join(layoutPath, refsDir, storeKey(namespace, source))
}

// writeRef records the binding atomically (write + rename), so a concurrent Spec
// read sees the old binding or the new one, never a torn file.
func writeRef(layoutPath, namespace, source string, dgst digest.Digest) error {
	dir := filepath.Join(layoutPath, refsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create image ref dir: %w", err)
	}
	b, err := json.Marshal(imageRef{Namespace: namespace, Source: source, Digest: dgst})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "ref-*")
	if err != nil {
		return err
	}
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Close()
	} else {
		_ = tmp.Close()
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), refPath(layoutPath, namespace, source))
}

// readRef returns the binding for (namespace, source). A missing file is the
// pull-on-miss signal; a corrupt one is an error to re-pull over, never to fall
// back from.
func readRef(layoutPath, namespace, source string) (imageRef, error) {
	b, err := os.ReadFile(refPath(layoutPath, namespace, source))
	if err != nil {
		return imageRef{}, err
	}
	var r imageRef
	if err := json.Unmarshal(b, &r); err != nil {
		return imageRef{}, fmt.Errorf("corrupt image ref for %q in %q: %w", source, namespace, err)
	}
	// The digest read back from disk addresses an index entry and a blob directory, so it is
	// validated before use rather than trusted for having once been written by a verified pull.
	if err := r.Digest.Validate(); err != nil {
		return imageRef{}, fmt.Errorf("image ref for %q in %q holds a malformed digest %q: %w", source, namespace, r.Digest, err)
	}
	return r, nil
}

// storedRef is a binding as found on disk: the imageRef plus the file that holds
// it, so purge can remove exactly what it listed (a temp file a crashed writeRef
// left behind is not at the path storeKey would recompute).
type storedRef struct {
	imageRef
	file string
}

// valid reports whether the file really is (namespace, source)'s binding — a
// leftover writeRef temp or a renamed file is wreckage for purge to drop.
func (r storedRef) valid() bool { return r.file == storeKey(r.Namespace, r.Source) }

// listRefs returns every stored binding. A corrupt entry fails the listing loudly
// rather than being skipped — skipping would make purge treat its image as
// unreferenced wreckage and delete it out from under the binding.
func listRefs(layoutPath string) ([]storedRef, error) {
	entries, err := os.ReadDir(filepath.Join(layoutPath, refsDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	refs := make([]storedRef, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(layoutPath, refsDir, e.Name()))
		if err != nil {
			return nil, err
		}
		var r imageRef
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("corrupt image ref %s: %w", e.Name(), err)
		}
		if err := r.Digest.Validate(); err != nil {
			return nil, fmt.Errorf("image ref %s holds a malformed digest %q: %w", e.Name(), r.Digest, err)
		}
		refs = append(refs, storedRef{imageRef: r, file: e.Name()})
	}
	return refs, nil
}
