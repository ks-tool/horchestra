// Package bolt is an embedded BoltDB-backed implementation of storage.Storage.
//
// Each Kind gets its own bucket keyed by "group/kind" (version-independent, so
// every served version of a Kind shares one set of objects). resourceVersion is
// a per-GVK monotonic counter (bucket __rv_seq, keyed by "group/kind"). Every
// write also appends the resulting object to a per-Kind history bucket keyed by
// "uid\x00<zero-padded rv>", retaining the last maxHistory revisions, which backs
// Rollback. An in-process watch bus fans committed changes out to Watch
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
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte(seqBucket))
		return e
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &DB{
		db:     db,
		scheme: sch,
		subs:   map[string][]*subscription{},
		done:   make(chan struct{}),
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
	key := acc.GetName()

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
		acc.SetCreationTimestamp(metav1.Now().Rfc3339Copy()) // second precision matches storage

		enc, e = json.Marshal(out)
		if e != nil {
			return e
		}
		return commit(tx, bkey, key, uid, rv, enc)
	})
	if err != nil {
		return nil, err
	}
	s.publish(bkey, watch.Added, enc, acc.GetLabels())
	return out, nil
}

func (s *DB) Update(_ context.Context, obj types.Object) (types.Object, error) {
	out, acc, err := s.clone(obj)
	if err != nil {
		return nil, err
	}
	bkey, err := bucketKeyFor(out.GetObjectKind().GroupVersionKind())
	if err != nil {
		return nil, err
	}
	key := acc.GetName()

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var enc []byte
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

		enc, e = json.Marshal(out)
		if e != nil {
			return e
		}
		return commit(tx, bkey, key, string(oldAcc.GetUID()), rv, enc)
	})
	if err != nil {
		return nil, err
	}
	s.publish(bkey, watch.Modified, enc, acc.GetLabels())
	return out, nil
}

// UpdateSubresource replaces only the top-level field named subresource (e.g.
// "status") of the stored object with the same field of obj, leaving spec and the
// other fields untouched. It bumps the Kind's resourceVersion like any write.
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
	key := acc.GetName()

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
		rv, e := nextRV(tx, bkey)
		if e != nil {
			return e
		}

		storedMap[subresource] = subVal
		if e := setRawResourceVersion(storedMap, rv); e != nil {
			return e
		}
		enc, e = json.Marshal(storedMap)
		if e != nil {
			return e
		}
		result, e = s.decode(enc)
		if e != nil {
			return e
		}
		rAcc, e := meta.Accessor(result)
		if e != nil {
			return e
		}
		lbls = rAcc.GetLabels()
		return commit(tx, bkey, key, string(storedAcc.GetUID()), rv, enc)
	})
	if err != nil {
		return nil, err
	}
	s.publish(bkey, watch.Modified, enc, lbls)
	return result, nil
}

// Rollback restores the object identified by (meta, uid) to the historical
// revision whose resourceVersion is targetRV, writing it as a new current version
// with a fresh resourceVersion. Only the core state (metadata + spec) is rolled
// back; the current subresource fields (status, …) are preserved, mirroring the
// independent mutation paths of assets/ddl.sql. It fails if no such revision
// exists (including after Delete, which wipes history).
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

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var enc []byte
	var lbls map[string]string
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
		key := snapAcc.GetName()

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
		if e := setRawResourceVersion(snapMap, rv); e != nil {
			return e
		}
		enc, e = json.Marshal(snapMap)
		if e != nil {
			return e
		}
		result, e = s.decode(enc)
		if e != nil {
			return e
		}
		rAcc, e := meta.Accessor(result)
		if e != nil {
			return e
		}
		lbls = rAcc.GetLabels()
		return commit(tx, bkey, key, uid, rv, enc)
	})
	if err != nil {
		return nil, err
	}
	s.publish(bkey, watch.Modified, enc, lbls)
	return result, nil
}

func (s *DB) Delete(_ context.Context, m types.ObjectMeta) error {
	bkey, err := bucketKeyForMeta(m)
	if err != nil {
		return err
	}
	key := m.Name

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var raw []byte
	var lbls map[string]string
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
		lbls = acc.GetLabels()
		if e := b.Delete([]byte(key)); e != nil {
			return e
		}
		return deleteHistory(tx, bkey, string(acc.GetUID()))
	})
	if err != nil {
		return err
	}
	s.publish(bkey, watch.Deleted, raw, lbls)
	return nil
}

func (s *DB) Get(_ context.Context, m types.ObjectMeta) (types.Object, error) {
	bkey, err := bucketKeyForMeta(m)
	if err != nil {
		return nil, err
	}
	key := m.Name

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

	sub := &subscription{ch: make(chan metav1.WatchEvent, watchBuf), selector: sel}
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
func (s *DB) publish(bkey string, et watch.EventType, raw []byte, lbls map[string]string) {
	evt := metav1.WatchEvent{Type: string(et), Object: runtime.RawExtension{Raw: raw}}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sub := range s.subs[bkey] {
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
func commit(tx *bbolt.Tx, bkey, key, uid string, rv uint64, enc []byte) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bkey))
	if err != nil {
		return err
	}
	if err := b.Put([]byte(key), enc); err != nil {
		return err
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

// setRawResourceVersion stamps metadata.resourceVersion (a JSON string) directly
// into objMap's raw metadata, so a raw-JSON write carries a fresh rv without
// decoding and re-encoding the whole object.
func setRawResourceVersion(objMap map[string]json.RawMessage, rv uint64) error {
	metaMap := map[string]json.RawMessage{}
	if raw := objMap["metadata"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &metaMap); err != nil {
			return err
		}
	}
	rvJSON, err := json.Marshal(strconv.FormatUint(rv, 10))
	if err != nil {
		return err
	}
	metaMap["resourceVersion"] = rvJSON
	raw, err := json.Marshal(metaMap)
	if err != nil {
		return err
	}
	objMap["metadata"] = raw
	return nil
}

// coreField reports whether a top-level object field is core state (owned by
// Create/Update/Rollback) rather than a subresource (owned by UpdateSubresource).
func coreField(k string) bool {
	switch k {
	case "apiVersion", "kind", "metadata", "spec":
		return true
	default:
		return false
	}
}

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
