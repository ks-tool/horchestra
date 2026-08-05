package storage

import (
	"context"
	"errors"

	"github.com/ks-tool/horchestra/api/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// ErrNotFound is returned by Get/Update/UpdateSubresource/Delete/Rollback when the
	// addressed object does not exist.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists is returned by Create when the name is already taken.
	ErrAlreadyExists = errors.New("already exists")
	// ErrConflict is returned by a write whose resourceVersion no longer matches the stored
	// one (optimistic-concurrency failure).
	ErrConflict = errors.New("modified concurrently")
)

// Storage is the persistence contract every backend implements (BoltDB in production, an
// in-memory fake in tests). Every controller write reaches it only through
// controller/service, so admission runs on each mutation.
//
// resourceVersion is an OPAQUE, monotonically increasing cursor the backend stamps into
// metadata.resourceVersion on every write to an object's CORE state — Create, Update, Rollback.
// A subresource write (UpdateSubresource) leaves it alone: a status is not a version of the
// object, so reporting one neither invalidates a spec writer's token nor advances the line the
// object's own history is kept on. Callers MUST treat it as an opaque token — never parse it,
// increment it, order objects by its magnitude, or otherwise do arithmetic on it.
// Its only sanctioned uses are equality (optimistic concurrency: a write carrying a stale
// resourceVersion is rejected with ErrConflict, an empty one is an unconditional write) and
// as a Watch resume point (metav1.ListOptions.ResourceVersion). A backend today may mint the
// cursor per-GVK — each Kind advancing its own counter — but because nothing depends on that,
// swapping in a single global counter is a drop-in upgrade: the cursor stays monotonic and
// the equality/resume semantics are unchanged. The one numeric parameter, Rollback's targetRV,
// names a specific past revision of one object (keyed by its uid), not an arithmetic step over
// a Kind's version line.
type Storage interface {
	Create(ctx context.Context, obj types.Object) (types.Object, error)
	Update(ctx context.Context, obj types.Object) (types.Object, error)
	// UpdateSubresource replaces only the named top-level field (e.g. "status") of the stored
	// object. It advances neither metadata.generation nor metadata.resourceVersion and records
	// no history revision, and a write that changes nothing is skipped outright — no stored
	// record touched, no watch event. Watchers still see a real subresource change.
	UpdateSubresource(ctx context.Context, subresource string, obj types.Object) (types.Object, error)
	Rollback(ctx context.Context, meta types.ObjectMeta, uid string, targetRV int64) (types.Object, error)
	// GetRevision returns the historical snapshot (uid, targetRV) read-only, WITHOUT writing a
	// new head, so a caller can re-admit the target before Rollback commits it. ErrNotFound if the
	// revision does not exist.
	GetRevision(ctx context.Context, meta types.ObjectMeta, uid string, targetRV int64) (types.Object, error)
	Delete(ctx context.Context, meta types.ObjectMeta) error
	Get(ctx context.Context, meta types.ObjectMeta) (types.Object, error)
	List(ctx context.Context, meta types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error)
	Watch(ctx context.Context, meta types.ObjectMeta, opts metav1.ListOptions) (<-chan metav1.WatchEvent, error)
	Close() error
}
