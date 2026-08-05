package bolt

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"

	"go.etcd.io/bbolt"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var vaultGVK = schema.GroupVersionKind{Group: "test.horchestra.io", Version: "v1", Kind: "Vault"}

func vaultScheme() *scheme.Scheme {
	sch := scheme.New()
	sch.AddResource(vaultGVK, func() types.Object { return new(widget) },
		scheme.Resource{Plural: "vaults", Namespaced: true, NoHistory: true})
	sch.AddResource(widgetGVK, func() types.Object { return new(widget) },
		scheme.Resource{Plural: "widgets", Namespaced: true})
	return sch
}

// TestNoHistoryKindRetainsNothing: a Kind marked NoHistory (a Secret in the real scheme) must
// keep no superseded revision. Rotation replaced the value while the copy-on-write history bucket
// kept the previous plaintext for up to maxHistory further writes, and the only purge path —
// Delete — is unreachable for a Secret an Application still mounts, so a backup taken AFTER a
// rotation still carried the credential the operator believed was dead.
//
// The guarantee is that no addressable record of the old revision survives. Freed bbolt pages are
// not zeroed, so a byte pattern can still linger in the file until its page is reused; that is
// part of the documented at-rest exposure (Secrets are stored in cleartext), not of this fix.
func TestNoHistoryKindRetainsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	b, err := Open(path, vaultScheme())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := t.Context()

	v := newWidget("Vault", "db-password")
	v.Spec.Image = "old-plaintext"
	stored := mustWidget(t, mustCreate(t, b, v))
	stored.Spec.Image = "rotated-plaintext"
	stored = mustWidget(t, mustUpdate(t, b, stored))

	if _, err := b.Rollback(ctx, metaFor("Vault", "db-password"), string(stored.UID), 1); err == nil {
		t.Fatal("a NoHistory Kind must not be rollback-able: it keeps no revisions")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertNoHistory(t, path, vaultGVK)

	// A history bucket written by an earlier build is the same exposure, so opening the database
	// must drop it rather than carry it.
	if err := writeStaleHistory(path, vaultGVK, "leftover-plaintext"); err != nil {
		t.Fatalf("seed stale history: %v", err)
	}
	b2, err := Open(path, vaultScheme())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := b2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertNoHistory(t, path, vaultGVK)
}

// TestHistoryKeptForOrdinaryKinds: the exclusion is per-Kind, so Rollback still works for
// everything that is not marked NoHistory.
func TestHistoryKeptForOrdinaryKinds(t *testing.T) {
	b, err := Open(filepath.Join(t.TempDir(), "test.db"), vaultScheme())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	w := newWidget("Widget", "db")
	w.Spec.Image = "v1"
	stored := mustWidget(t, mustCreate(t, b, w))
	uid, rv := string(stored.UID), stored.ResourceVersion
	stored.Spec.Image = "v2"
	mustUpdate(t, b, stored)

	target, err := strconv.ParseInt(rv, 10, 64)
	if err != nil {
		t.Fatalf("parse rv %q: %v", rv, err)
	}
	rolled, err := b.Rollback(t.Context(), metaFor("Widget", "db"), uid, target)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := mustWidget(t, rolled).Spec.Image; got != "v1" {
		t.Fatalf("rolled back image = %q, want v1", got)
	}
}

// assertNoHistory fails when the database holds any history record for gvk.
func assertNoHistory(t *testing.T, path string, gvk schema.GroupVersionKind) {
	t.Helper()
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	bkey, err := bucketKeyFor(gvk)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		h := tx.Bucket([]byte(bkey + historySuffix))
		if h == nil {
			return nil
		}
		if k, _ := h.Cursor().First(); k != nil {
			t.Fatalf("%s still has a history record (%q)", gvk.Kind, k)
		}
		return nil
	}); err != nil {
		t.Fatalf("view: %v", err)
	}
}

// writeStaleHistory fabricates the history bucket an earlier build would have written for gvk.
func writeStaleHistory(path string, gvk schema.GroupVersionKind, payload string) error {
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	bkey, err := bucketKeyFor(gvk)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		h, e := tx.CreateBucketIfNotExists([]byte(bkey + historySuffix))
		if e != nil {
			return e
		}
		return h.Put(historyKey("stale-uid", 1), []byte(payload))
	})
}
