// Package bolt is an embedded BoltDB-backed implementation of storage.Storage.
//
// Each Kind gets its own bucket keyed by "group/kind" (version-independent, so
// every served version of a Kind shares one set of objects). resourceVersion is
// a per-GVK monotonic counter (bucket __rv_seq, keyed by "group/kind"). Every
// write also appends the resulting object to a per-Kind history bucket keyed by
// "uid\x00<zero-padded rv>", retaining the last maxHistory revisions, which backs
// Rollback — except for a Kind the scheme marks NoHistory (a Secret), whose
// superseded revisions are never written and whose stale history bucket is
// dropped at Open. An in-process watch bus fans committed changes out to Watch
// subscribers as best-effort events, filtered by label selector.
package bolt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/api/utils"

	"github.com/LastPossum/kamino"
	"go.etcd.io/bbolt"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	seqBucket     = "__rv_seq"
	historySuffix = "\x00history"
	watchBuf      = 64
	sep           = "\x00"
	maxHistory    = 10 // retained revisions per object, bounding history growth
)

// DB stores API objects in a BoltDB file. Read paths decode stored JSON back into
// typed objects through the scheme, so Get/List/Watch return the same concrete
// Kinds the caller created.
type DB struct {
	db     *bbolt.DB
	scheme *scheme.Scheme
	// noHistory holds the bucket keys of Kinds whose superseded revisions must not be retained
	// (scheme.Resource.NoHistory), so a rotated Secret's plaintext does not outlive the write
	// that replaced it. Built once at Open from the scheme.
	noHistory map[string]bool

	// writeMu serializes each commit with its watch publish so events are
	// delivered in resourceVersion order (bbolt already serializes the commits).
	writeMu sync.Mutex

	mu   sync.RWMutex
	subs map[string][]*subscription
	done chan struct{} // closed by Close to tear down live watches
}

// subscription is one live Watch: events for its Kind are delivered to ch,
// filtered to selector. closeOnce guards ch against a double close between the
// per-watch goroutine and Close.
type subscription struct {
	ch        chan metav1.WatchEvent
	selector  labels.Selector
	namespace string // empty = all namespaces; else only events for this namespace
	closeOnce sync.Once
}

func (sub *subscription) close() { sub.closeOnce.Do(func() { close(sub.ch) }) }

var _ storage.Storage = (*DB)(nil)

// Open opens (creating if needed) the BoltDB file at path. sch is the registry
// used to reconstruct typed objects on read; every Kind stored must be
// registered in it.
func Open(path string, sch *scheme.Scheme) (*DB, error) {
	if sch == nil {
		return nil, fmt.Errorf("bolt: scheme is required")
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	noHistory := map[string]bool{}
	for gvk, r := range sch.Resources() {
		if !r.NoHistory {
			continue
		}
		bkey, e := bucketKeyFor(gvk)
		if e != nil {
			_ = db.Close()
			return nil, e
		}
		noHistory[bkey] = true
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		if _, e := tx.CreateBucketIfNotExists([]byte(seqBucket)); e != nil {
			return e
		}
		// A history bucket left by an earlier build (or by a Kind that has since become
		// NoHistory) still holds the plaintext the exclusion exists to remove, and nothing on
		// the write path would ever reclaim it. Drop it at open rather than carry it.
		for bkey := range noHistory {
			if tx.Bucket([]byte(bkey+historySuffix)) == nil {
				continue
			}
			if e := tx.DeleteBucket([]byte(bkey + historySuffix)); e != nil {
				return e
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &DB{
		db:        db,
		scheme:    sch,
		noHistory: noHistory,
		subs:      map[string][]*subscription{},
		done:      make(chan struct{}),
	}, nil
}

// Close closes the database and tears down every live Watch: it signals the
// per-watch goroutines and closes their channels, so watches tied to a
// never-cancelled context do not leak.
func (s *DB) Close() error {
	s.mu.Lock()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	for _, subs := range s.subs {
		for _, sub := range subs {
			sub.close()
		}
	}
	s.subs = map[string][]*subscription{}
	s.mu.Unlock()
	return s.db.Close()
}

func (s *DB) Create(_ context.Context, obj types.Object) (types.Object, error) {
	out, acc, err := s.clone(obj)
	if err != nil {
		return nil, err
	}
	bkey, err := bucketKeyFor(out.GetObjectKind().GroupVersionKind())
	if err != nil {
		return nil, err
	}
	if acc.GetName() == "" {
		return nil, fmt.Errorf("bolt: metadata.name is required")
	}
	key := recordKey(acc.GetNamespace(), acc.GetName())

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var enc []byte
	err = s.db.Update(func(tx *bbolt.Tx) error {
		if b := tx.Bucket([]byte(bkey)); b != nil && b.Get([]byte(key)) != nil {
			return storage.ErrAlreadyExists
		}
		rv, e := nextRV(tx, bkey)
		if e != nil {
			return e
		}

		uid := utils.NewUIDv4()
		acc.SetUID(apitypes.UID(uid))
		acc.SetResourceVersion(strconv.FormatUint(rv, 10))
		acc.SetGeneration(1)                                 // spec revision counter; bumped only on spec writes, not on status
		acc.SetCreationTimestamp(metav1.Now().Rfc3339Copy()) // second precision matches storage

		enc, e = json.Marshal(out)
		if e != nil {
			return e
		}
		return s.commit(tx, bkey, key, uid, rv, enc)
	})
	if err != nil {
		return nil, err
	}
	s.publish(bkey, watch.Added, enc, acc.GetNamespace(), acc.GetLabels())
	return out, nil
}

// Update replaces the object's CORE state — apiVersion, kind, metadata, spec — and keeps the
// stored subresource fields, whatever the caller's body carried in them. A subresource is
// written through UpdateSubresource alone, and this is the half that makes that true from the
// other side: a spec write must not carry a status back, least of all a stale one read before
// the node last reported. (Rollback does the same merge for the same reason.)
func (s *DB) Update(_ context.Context, obj types.Object) (types.Object, error) {
	out, acc, err := s.clone(obj)
	if err != nil {
		return nil, err
	}
	bkey, err := bucketKeyFor(out.GetObjectKind().GroupVersionKind())
	if err != nil {
		return nil, err
	}
	key := recordKey(acc.GetNamespace(), acc.GetName())

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var enc []byte
	var result types.Object
	err = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bkey))
		if b == nil {
			return storage.ErrNotFound
		}
		cur := b.Get([]byte(key))
		if cur == nil {
			return storage.ErrNotFound
		}
		oldAcc, e := accessorOf(s.decode(cur))
		if e != nil {
			return e
		}
		if e := checkResourceVersion(acc, oldAcc); e != nil {
			return e
		}
		rv, e := nextRV(tx, bkey)
		if e != nil {
			return e
		}
		acc.SetUID(oldAcc.GetUID())
		acc.SetCreationTimestamp(oldAcc.GetCreationTimestamp())
		acc.SetResourceVersion(strconv.FormatUint(rv, 10))
		gen, e := nextGeneration(out, cur, oldAcc.GetGeneration())
		if e != nil {
			return e
		}
		acc.SetGeneration(gen)

		merged, e := mergeCore(out, cur)
		if e != nil {
			return e
		}
		result, e = s.decode(merged)
		if e != nil {
			return e
		}
		enc = merged
		return s.commit(tx, bkey, key, string(oldAcc.GetUID()), rv, enc)
	})
	if err != nil {
		return nil, err
	}
	s.publish(bkey, watch.Modified, enc, acc.GetNamespace(), acc.GetLabels())
	return result, nil
}

// mergeCore serializes obj's core state over stored's subresource fields: core comes from obj,
// everything else from stored.
// nextGeneration is metadata.generation after this write: one more than the stored one when the
// write changes the object's DESIRED state, and the stored one when it does not.
//
// generation is what a spec-watcher gates on — the node dedups its pushes by it, and a rollout
// names the version it is waiting for with it — so it must move when, and only when, the thing
// being watched moves. Two writes must therefore leave it alone. A status write already does,
// by going through UpdateSubresource; a metadata write did NOT, so labelling an object pushed
// its whole spec back down to a node that was already running exactly that spec. Kubernetes
// draws the line in the same place and for the same reason: its registry bumps generation only
// when DeepEqual says the spec differs.
//
// "Desired state" is every core field except metadata: spec for the Kinds that have one, and
// for the Kinds that do not — a Secret's data, a Role's rules — the body itself, which is the
// only thing a change to them could mean.
func nextGeneration(incoming types.Object, stored []byte, current int64) (int64, error) {
	b, err := json.Marshal(incoming)
	if err != nil {
		return 0, err
	}
	var inc, cur map[string]json.RawMessage
	if err := json.Unmarshal(b, &inc); err != nil {
		return 0, err
	}
	if err := json.Unmarshal(stored, &cur); err != nil {
		return 0, err
	}
	// Both sides are the output of marshalling the same typed Kind, so the encoder's field order
	// is identical and the bytes compare directly. A field dropped by the write counts as a
	// change too — clearing a spec is a change to it.
	for _, m := range []struct{ a, b map[string]json.RawMessage }{{inc, cur}, {cur, inc}} {
		for k, v := range m.a {
			if !coreField(k) || k == "metadata" {
				continue
			}
			if !bytes.Equal(v, m.b[k]) {
				return current + 1, nil
			}
		}
	}
	return current, nil
}

func mergeCore(obj types.Object, stored []byte) ([]byte, error) {
	incoming, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var incMap, storedMap map[string]json.RawMessage
	if err := json.Unmarshal(incoming, &incMap); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(stored, &storedMap); err != nil {
		return nil, err
	}
	for k := range incMap {
		if !coreField(k) {
			delete(incMap, k)
		}
	}
	for k, v := range storedMap {
		if !coreField(k) {
			incMap[k] = v
		}
	}
	return json.Marshal(incMap)
}

// UpdateSubresource replaces only the top-level field named subresource (e.g. "status") of the
// stored object with the same field of obj, leaving spec and the other fields untouched.
//
// It does NOT advance the Kind's resourceVersion, and it appends no history revision — a
// subresource is not a version of the object. Both follow from what the two are FOR:
// resourceVersion is the token a spec writer holds for optimistic concurrency, and history is
// what Rollback restores, which is core state alone (Rollback already keeps the current
// subresource fields). A node reporting status every heartbeat would otherwise invalidate every
// spec writer's token on a five-second cycle, and fill all maxHistory revisions of an
// Application with status snapshots inside a minute, leaving nothing to roll back TO.
//
// A write that changes nothing is not a write: an unchanged subresource returns the stored
// object without touching the record or waking a watcher. The node reports its status every
// tick unconditionally — that is the level-driven design, and this is where it stops costing
// anything.
//
// Watchers still see a status change: the event is published on its own, independent of the
// version line. A watch here is a live subscription (opts.ResourceVersion is not a resume
// cursor — see Watch), so a status event carrying an unchanged resourceVersion loses a consumer
// nothing.
func (s *DB) UpdateSubresource(_ context.Context, subresource string, obj types.Object) (types.Object, error) {
	if subresource == "" {
		return nil, fmt.Errorf("bolt: subresource is required")
	}
	out, acc, err := s.clone(obj)
	if err != nil {
		return nil, err
	}
	bkey, err := bucketKeyFor(out.GetObjectKind().GroupVersionKind())
	if err != nil {
		return nil, err
	}
	key := recordKey(acc.GetNamespace(), acc.GetName())

	incoming, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	var incMap map[string]json.RawMessage
	if err := json.Unmarshal(incoming, &incMap); err != nil {
		return nil, err
	}
	subVal, ok := incMap[subresource]
	if !ok {
		return nil, fmt.Errorf("bolt: object has no field %q for subresource", subresource)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var enc []byte
	var lbls map[string]string
	var ns string
	var result types.Object
	err = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bkey))
		if b == nil {
			return storage.ErrNotFound
		}
		cur := b.Get([]byte(key))
		if cur == nil {
			return storage.ErrNotFound
		}
		var storedMap map[string]json.RawMessage
		if e := json.Unmarshal(cur, &storedMap); e != nil {
			return e
		}
		storedAcc, e := accessorOf(s.decode(cur))
		if e != nil {
			return e
		}
		if e := checkResourceVersion(acc, storedAcc); e != nil {
			return e
		}
		if bytes.Equal(storedMap[subresource], subVal) {
			result, e = s.decode(cur)
			return e
		}

		// Merge only the named subresource field into the stored object and decode it once.
		// metadata rides through the merge untouched, so the object keeps the resourceVersion
		// and generation of the core state it describes — the whole point of the subresource.
		storedMap[subresource] = subVal
		merged, e := json.Marshal(storedMap)
		if e != nil {
			return e
		}
		result, e = s.decode(merged)
		if e != nil {
			return e
		}
		rAcc, e := meta.Accessor(result)
		if e != nil {
			return e
		}
		if enc, e = json.Marshal(result); e != nil {
			return e
		}
		lbls, ns = rAcc.GetLabels(), rAcc.GetNamespace()
		return putHead(tx, bkey, key, enc)
	})
	if err != nil {
		return nil, err
	}
	if enc == nil {
		return result, nil // nothing changed: no record written, no watcher woken
	}
	s.publish(bkey, watch.Modified, enc, ns, lbls)
	return result, nil
}

func (s *DB) GetRevision(_ context.Context, m types.ObjectMeta, uid string, targetRV int64) (types.Object, error) {
	bkey, err := bucketKeyForMeta(m)
	if err != nil {
		return nil, err
	}
	if uid == "" {
		return nil, fmt.Errorf("bolt: uid is required")
	}
	if targetRV <= 0 {
		return nil, storage.ErrNotFound
	}
	var out types.Object
	err = s.db.View(func(tx *bbolt.Tx) error {
		h := tx.Bucket([]byte(bkey + historySuffix))
		if h == nil {
			return storage.ErrNotFound
		}
		snap := h.Get(historyKey(uid, uint64(targetRV)))
		if snap == nil {
			return storage.ErrNotFound
		}
		obj, e := s.decode(snap)
		if e != nil {
			return e
		}
		out = obj
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Rollback restores the object identified by (meta, uid) to the historical
// revision whose resourceVersion is targetRV, writing it as a new current version
// with a fresh resourceVersion. Only the core state (metadata + spec) is rolled
// back; the current subresource fields (status, …) are preserved, mirroring the
// independent mutation paths of assets/ddl.sql. It fails if no such revision
// exists (including after Delete, which wipes history).
// GetRevision returns the historical snapshot (uid, targetRV) read-only — the resolve half of
// Rollback, without writing a new head — so the service can re-admit the target before committing.
func (s *DB) Rollback(_ context.Context, m types.ObjectMeta, uid string, targetRV int64) (types.Object, error) {
	bkey, err := bucketKeyForMeta(m)
	if err != nil {
		return nil, err
	}
	if uid == "" {
		return nil, fmt.Errorf("bolt: uid is required")
	}
	if targetRV <= 0 {
		return nil, storage.ErrNotFound
	}
	if s.noHistory[bkey] {
		return nil, fmt.Errorf("bolt: %s retains no revisions, so it cannot be rolled back", m.Kind)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var enc []byte
	var lbls map[string]string
	var ns string
	var result types.Object
	err = s.db.Update(func(tx *bbolt.Tx) error {
		h := tx.Bucket([]byte(bkey + historySuffix))
		if h == nil {
			return storage.ErrNotFound
		}
		snap := h.Get(historyKey(uid, uint64(targetRV)))
		if snap == nil {
			return storage.ErrNotFound
		}
		var snapMap map[string]json.RawMessage
		if e := json.Unmarshal(snap, &snapMap); e != nil {
			return e
		}
		snapAcc, e := accessorOf(s.decode(snap))
		if e != nil {
			return e
		}
		key := recordKey(snapAcc.GetNamespace(), snapAcc.GetName())

		b := tx.Bucket([]byte(bkey))
		if b == nil {
			return storage.ErrNotFound
		}
		cur := b.Get([]byte(key))
		if cur == nil {
			return storage.ErrNotFound
		}
		var curMap map[string]json.RawMessage
		if e := json.Unmarshal(cur, &curMap); e != nil {
			return e
		}
		// Keep the current subresource fields; roll back only the core state.
		for k := range snapMap {
			if !coreField(k) {
				delete(snapMap, k)
			}
		}
		for k, v := range curMap {
			if !coreField(k) {
				snapMap[k] = v
			}
		}
		rv, e := nextRV(tx, bkey)
		if e != nil {
			return e
		}
		// The merged raw map is decoded once to a typed object, which is then stamped with the
		// fresh resourceVersion and a bumped generation and re-marshaled — the same typed path
		// Create/Update persist through, so there is no parallel raw-metadata stamping.
		merged, e := json.Marshal(snapMap)
		if e != nil {
			return e
		}
		result, e = s.decode(merged)
		if e != nil {
			return e
		}
		rAcc, e := meta.Accessor(result)
		if e != nil {
			return e
		}
		curAcc, e := accessorOf(s.decode(cur))
		if e != nil {
			return e
		}
		rAcc.SetResourceVersion(strconv.FormatUint(rv, 10))
		// Rollback rewrites the core state, so it advances generation like any spec write — and
		// like any spec write, only when the state it restores actually differs from the current
		// one. Bumped from the CURRENT generation so it never regresses to the snapshot's older
		// value.
		gen, e := nextGeneration(result, cur, curAcc.GetGeneration())
		if e != nil {
			return e
		}
		rAcc.SetGeneration(gen)
		if enc, e = json.Marshal(result); e != nil {
			return e
		}
		lbls, ns = rAcc.GetLabels(), rAcc.GetNamespace()
		return s.commit(tx, bkey, key, uid, rv, enc)
	})
	if err != nil {
		return nil, err
	}
	s.publish(bkey, watch.Modified, enc, ns, lbls)
	return result, nil
}

func (s *DB) Delete(_ context.Context, m types.ObjectMeta) error {
	bkey, err := bucketKeyForMeta(m)
	if err != nil {
		return err
	}
	key := recordKey(m.Namespace, m.Name)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var raw []byte
	var lbls map[string]string
	var ns string
	err = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bkey))
		if b == nil {
			return storage.ErrNotFound
		}
		cur := b.Get([]byte(key))
		if cur == nil {
			return storage.ErrNotFound
		}
		raw = copyBytes(cur)
		acc, e := accessorOf(s.decode(cur))
		if e != nil {
			return e
		}
		lbls, ns = acc.GetLabels(), acc.GetNamespace()
		if e := b.Delete([]byte(key)); e != nil {
			return e
		}
		return deleteHistory(tx, bkey, string(acc.GetUID()))
	})
	if err != nil {
		return err
	}
	s.publish(bkey, watch.Deleted, raw, ns, lbls)
	return nil
}

func (s *DB) Get(_ context.Context, m types.ObjectMeta) (types.Object, error) {
	bkey, err := bucketKeyForMeta(m)
	if err != nil {
		return nil, err
	}
	key := recordKey(m.Namespace, m.Name)

	var out types.Object
	err = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bkey))
		if b == nil {
			return storage.ErrNotFound
		}
		v := b.Get([]byte(key))
		if v == nil {
			return storage.ErrNotFound
		}
		o, e := s.decode(v)
		if e != nil {
			return e
		}
		out = o
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *DB) List(_ context.Context, m types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error) {
	bkey, err := bucketKeyForMeta(m)
	if err != nil {
		return nil, err
	}
	sel, err := parseSelector(opts.LabelSelector)
	if err != nil {
		return nil, err
	}

	var out []types.Object
	err = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bkey))
		if b == nil {
			return nil // unknown Kind or nothing written yet: empty list, not an error
		}
		return forEach(b, func(v []byte) error {
			o, e := s.decode(v)
			if e != nil {
				return e
			}
			if m.Namespace != "" {
				acc, e := meta.Accessor(o)
				if e != nil {
					return e
				}
				if acc.GetNamespace() != m.Namespace {
					return nil // a namespaced list is scoped to its namespace
				}
			}
			ok, e := matches(o, sel)
			if e != nil {
				return e
			}
			if ok {
				out = append(out, o)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *DB) Watch(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) (<-chan metav1.WatchEvent, error) {
	bkey, err := bucketKeyForMeta(m)
	if err != nil {
		return nil, err
	}
	sel, err := parseSelector(opts.LabelSelector)
	if err != nil {
		return nil, err
	}

	sub := &subscription{ch: make(chan metav1.WatchEvent, watchBuf), selector: sel, namespace: m.Namespace}
	s.mu.Lock()
	s.subs[bkey] = append(s.subs[bkey], sub)
	s.mu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
		case <-s.done:
		}
		s.mu.Lock()
		s.removeSub(bkey, sub)
		s.mu.Unlock()
		sub.close()
	}()
	return sub.ch, nil
}

// removeSub drops sub from bkey's subscriber list, deleting the map entry when it
// becomes empty. Caller holds s.mu.
func (s *DB) removeSub(bkey string, sub *subscription) {
	subs := s.subs[bkey]
	i := slices.Index(subs, sub)
	if i < 0 {
		return
	}
	subs = slices.Delete(subs, i, i+1)
	if len(subs) == 0 {
		delete(s.subs, bkey)
	} else {
		s.subs[bkey] = subs
	}
}

// publish fans an event out to bkey's subscribers whose selector matches. Sends
// are non-blocking: a subscriber that is not keeping up drops the event rather
// than stalling every writer — tolerable because the consumers are level-driven
// and re-list on their heartbeat. Ordering relative to commit is preserved by the
// caller holding writeMu across commit and publish.
func (s *DB) publish(bkey string, et watch.EventType, raw []byte, ns string, lbls map[string]string) {
	evt := metav1.WatchEvent{Type: string(et), Object: runtime.RawExtension{Raw: raw}}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sub := range s.subs[bkey] {
		if sub.namespace != "" && sub.namespace != ns {
			continue // a namespaced watch only sees its namespace's events
		}
		if sub.selector != nil && !sub.selector.Empty() && !sub.selector.Matches(labels.Set(lbls)) {
			continue
		}
		select {
		case sub.ch <- evt:
		default:
		}
	}
}

// clone returns an owned deep copy of obj plus its metadata accessor, so writes
// never mutate the caller's object.
func (s *DB) clone(obj types.Object) (types.Object, metav1.Object, error) {
	out, err := kamino.Clone(obj)
	if err != nil {
		return nil, nil, err
	}
	acc, err := meta.Accessor(out)
	if err != nil {
		return nil, nil, err
	}
	return out, acc, nil
}

// decode reconstructs a typed object from stored JSON, using its apiVersion/kind
// to pick the Go type from the scheme.
func (s *DB) decode(data []byte) (types.Object, error) {
	obj, err := s.scheme.Decode(data)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// commit writes enc as the current object at key, appends it to the Kind's
// history at (uid, rv), and prunes the object's history to maxHistory revisions.
// A Kind marked scheme.Resource.NoHistory skips the append entirely: its
// superseded revisions are the hazard, so no copy of them is kept and Rollback
// has nothing to restore.
func (s *DB) commit(tx *bbolt.Tx, bkey, key, uid string, rv uint64, enc []byte) error {
	if err := putHead(tx, bkey, key, enc); err != nil {
		return err
	}
	if s.noHistory[bkey] {
		return nil
	}
	h, err := tx.CreateBucketIfNotExists([]byte(bkey + historySuffix))
	if err != nil {
		return err
	}
	if err := h.Put(historyKey(uid, rv), enc); err != nil {
		return err
	}
	return pruneHistory(h, uid)
}

// putHead writes enc as the current object at key, with no history revision. It is the whole of
// a subresource write and the first half of a core one.
func putHead(tx *bbolt.Tx, bkey, key string, enc []byte) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bkey))
	if err != nil {
		return err
	}
	return b.Put([]byte(key), enc)
}

// pruneHistory keeps at most maxHistory revisions for uid, deleting the oldest.
// History keys embed a zero-padded rv, so cursor order is resourceVersion order.
func pruneHistory(h *bbolt.Bucket, uid string) error {
	prefix := []byte(uid + sep)
	var keys [][]byte
	c := h.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		keys = append(keys, bytes.Clone(k))
	}
	for i := 0; i < len(keys)-maxHistory; i++ {
		if err := h.Delete(keys[i]); err != nil {
			return err
		}
	}
	return nil
}

// deleteHistory removes every history revision of the object identified by uid.
func deleteHistory(tx *bbolt.Tx, bkey, uid string) error {
	h := tx.Bucket([]byte(bkey + historySuffix))
	if h == nil {
		return nil
	}
	c := h.Cursor()
	prefix := []byte(uid + sep)
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		if err := c.Delete(); err != nil {
			return err
		}
	}
	return nil
}

// nextRV increments and returns the per-GVK monotonic resourceVersion for bkey.
func nextRV(tx *bbolt.Tx, bkey string) (uint64, error) {
	b := tx.Bucket([]byte(seqBucket))
	var rv uint64
	if v := b.Get([]byte(bkey)); v != nil {
		rv, _ = strconv.ParseUint(string(v), 10, 64)
	}
	rv++
	return rv, b.Put([]byte(bkey), []byte(strconv.FormatUint(rv, 10)))
}

// checkResourceVersion enforces optimistic concurrency: a caller-supplied
// resourceVersion must match the stored one; an empty one is an unconditional write.
func checkResourceVersion(want, stored metav1.Object) error {
	if rv := want.GetResourceVersion(); rv != "" && rv != stored.GetResourceVersion() {
		return storage.ErrConflict
	}
	return nil
}

// coreField reports whether a top-level object field is core state (owned by
// Create/Update/Rollback) rather than a subresource (owned by UpdateSubresource).
//
// It is a DENY-list of the subresources, not an allow-list of "apiVersion, kind, metadata, spec",
// and that distinction is load-bearing: a Kind whose payload does not live under `spec` — a
// Secret's data/type/immutable, a ConfigMap's — would otherwise be silently dropped by every
// Update, which reported success, advanced the generation and stored the old value. Anything the
// server does not own through its own subresource endpoint belongs to whoever wrote the object.
func coreField(k string) bool { return !subresourceField(k) }

// subresourceField names the top-level fields written only through UpdateSubresource. Adding a
// subresource means adding it here, in the one place both halves of the split read.
func subresourceField(k string) bool { return k == "status" }

// bucketKeyFor ignores the version so all served versions of a Kind share storage.
func bucketKeyFor(gvk schema.GroupVersionKind) (string, error) {
	if gvk.Kind == "" {
		return "", fmt.Errorf("bolt: object kind is required")
	}
	return gvk.Group + "/" + gvk.Kind, nil
}

func bucketKeyForMeta(m types.ObjectMeta) (string, error) {
	gv, err := schema.ParseGroupVersion(m.ApiVersion)
	if err != nil {
		return "", err
	}
	return bucketKeyFor(gv.WithKind(m.Kind))
}

// recordKey is the in-bucket key of an object: "<namespace>/<name>". A cluster-scoped
// kind has an empty namespace, so its key is "/<name>" — uniform, so write and read
// always agree.
func recordKey(namespace, name string) string { return namespace + "/" + name }

func historyKey(uid string, rv uint64) []byte {
	return fmt.Appendf(nil, "%s%s%020d", uid, sep, rv)
}

// forEach calls fn for each object in b.
func forEach(b *bbolt.Bucket, fn func([]byte) error) error {
	return b.ForEach(func(_, v []byte) error { return fn(v) })
}

func matches(o types.Object, sel labels.Selector) (bool, error) {
	if sel == nil || sel.Empty() {
		return true, nil
	}
	acc, err := meta.Accessor(o)
	if err != nil {
		return false, err
	}
	return sel.Matches(labels.Set(acc.GetLabels())), nil
}

func parseSelector(s string) (labels.Selector, error) {
	if s == "" {
		return labels.Everything(), nil
	}
	return labels.Parse(s)
}

// accessorOf adapts (obj, err) from a decode into a metadata accessor.
func accessorOf(obj types.Object, err error) (metav1.Object, error) {
	if err != nil {
		return nil, err
	}
	return meta.Accessor(obj)
}

// copyBytes returns a copy of src; BoltDB values are only valid inside their tx.
func copyBytes(src []byte) []byte { return bytes.Clone(src) }
