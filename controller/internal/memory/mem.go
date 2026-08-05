// Package memory is an in-memory storage.Storage for tests. It stores the objects
// it is given and hands them straight back — no persistence, no serialization,
// no backend — while reproducing the semantics the higher layers rely on:
// per-GVK monotonic resourceVersions, optimistic concurrency, metadata stamping,
// and a namespace/label-filtered watch bus. Namespaced kinds are keyed by
// "<namespace>/<name>" (matching the bolt store), so same-named objects in different
// namespaces do not collide.

package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"sync"

	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/api/utils"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

// Storage is an in-memory storage.Storage. Create it with New.
type Storage struct {
	mu   sync.Mutex
	seq  map[string]uint64                  // per-Kind ("group/kind") resourceVersion
	data map[string]map[string]types.Object // "group/kind" -> name -> object
	subs map[string][]*sub
	done chan struct{}
}

type sub struct {
	ch        chan metav1.WatchEvent
	selector  labels.Selector
	namespace string // empty = all namespaces
	closeOnce sync.Once
}

func (x *sub) close() { x.closeOnce.Do(func() { close(x.ch) }) }

var _ storage.Storage = (*Storage)(nil)

func New() *Storage {
	return &Storage{
		seq:  map[string]uint64{},
		data: map[string]map[string]types.Object{},
		subs: map[string][]*sub{},
		done: make(chan struct{}),
	}
}

func (s *Storage) Create(_ context.Context, obj types.Object) (types.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc, err := meta.Accessor(obj)
	if err != nil {
		return nil, err
	}
	bkey, err := bucketFromGVK(obj.GetObjectKind().GroupVersionKind())
	if err != nil {
		return nil, err
	}
	name := acc.GetName()
	if name == "" {
		return nil, fmt.Errorf("memory: metadata.name is required")
	}
	key := memKey(acc.GetNamespace(), name)
	if _, ok := s.data[bkey][key]; ok {
		return nil, storage.ErrAlreadyExists
	}
	acc.SetUID(apitypes.UID(utils.NewUIDv4()))
	acc.SetResourceVersion(strconv.FormatUint(s.next(bkey), 10))
	acc.SetGeneration(1) // spec revision counter; bumped only on spec writes, not on status
	acc.SetCreationTimestamp(metav1.Now())

	s.set(bkey, key, obj)
	s.publish(bkey, watch.Added, obj)
	return obj, nil
}

// Update replaces the object's core state and keeps the stored subresource fields, like the bolt
// store: a spec write must not carry a status back, least of all a stale one read before the node
// last reported. Without it a fake would hide the clobber the real store prevents.
func (s *Storage) Update(_ context.Context, obj types.Object) (types.Object, error) {
	return s.writeExisting(obj, true)
}

// UpdateSubresource stores the object WITHOUT advancing either metadata.generation or
// metadata.resourceVersion: a subresource is not a version of the object, so a status heartbeat
// neither wakes a spec-watcher nor invalidates a spec writer's optimistic-concurrency token. An
// unchanged subresource writes nothing at all.
//
// The one fidelity gap against bolt: this store replaces the whole object rather than merging
// only the named field, because nothing above it relies on the merge.
func (s *Storage) UpdateSubresource(_ context.Context, _ string, obj types.Object) (types.Object, error) {
	return s.writeExisting(obj, false)
}

// writeExisting is the shared update path: it rejects a stale resourceVersion and, for a core
// (spec) write, stamps a fresh resourceVersion and advances metadata.generation. A subresource
// write inherits both from the stored object, so the version line follows core state alone.
func (s *Storage) writeExisting(obj types.Object, specWrite bool) (types.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc, err := meta.Accessor(obj)
	if err != nil {
		return nil, err
	}
	bkey, err := bucketFromGVK(obj.GetObjectKind().GroupVersionKind())
	if err != nil {
		return nil, err
	}
	cur, ok := s.data[bkey][memKey(acc.GetNamespace(), acc.GetName())]
	if !ok {
		return nil, storage.ErrNotFound
	}
	curAcc, err := meta.Accessor(cur)
	if err != nil {
		return nil, err
	}
	if rv := acc.GetResourceVersion(); rv != "" && rv != curAcc.GetResourceVersion() {
		return nil, storage.ErrConflict
	}
	acc.SetUID(curAcc.GetUID())
	acc.SetCreationTimestamp(curAcc.GetCreationTimestamp())
	if specWrite {
		acc.SetGeneration(curAcc.GetGeneration() + 1)
		acc.SetResourceVersion(strconv.FormatUint(s.next(bkey), 10))
		merged, err := keepSubresources(obj, cur)
		if err != nil {
			return nil, err
		}
		obj = merged
	} else {
		acc.SetGeneration(curAcc.GetGeneration())
		acc.SetResourceVersion(curAcc.GetResourceVersion())
		// Identity and version now match the stored object, so what is left to compare IS the
		// change. No change, no write and no watch event — the node reports its status every
		// tick whether or not it moved.
		if sameObject(cur, obj) {
			return cur, nil
		}
	}

	s.set(bkey, memKey(acc.GetNamespace(), acc.GetName()), obj)
	s.publish(bkey, watch.Modified, obj)
	return obj, nil
}

// keepSubresources returns obj with every non-core top-level field (status and any other
// subresource) taken from stored. It round-trips through JSON and rebuilds the same concrete
// type, since this store holds typed objects and has no scheme to decode with.
func keepSubresources(obj, stored types.Object) (types.Object, error) {
	incMap, err := rawFields(obj)
	if err != nil {
		return nil, err
	}
	storedMap, err := rawFields(stored)
	if err != nil {
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
	merged, err := json.Marshal(incMap)
	if err != nil {
		return nil, err
	}
	out, ok := reflect.New(reflect.TypeOf(obj).Elem()).Interface().(types.Object)
	if !ok {
		return nil, fmt.Errorf("memory: %T is not a types.Object", obj)
	}
	if err := json.Unmarshal(merged, out); err != nil {
		return nil, err
	}
	return out, nil
}

func rawFields(obj types.Object) (map[string]json.RawMessage, error) {
	enc, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	return m, json.Unmarshal(enc, &m)
}

// coreField reports whether a top-level object field is core state (owned by Create/Update)
// rather than a subresource (owned by UpdateSubresource) — the same split the bolt store makes.
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

// sameObject reports whether two objects serialize identically.
func sameObject(a, b types.Object) bool {
	ea, err := json.Marshal(a)
	if err != nil {
		return false
	}
	eb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ea, eb)
}

// Rollback is unsupported: the memory keeps no revision history.
func (s *Storage) Rollback(context.Context, types.ObjectMeta, string, int64) (types.Object, error) {
	return nil, storage.ErrNotFound
}

// GetRevision is unsupported by the in-memory store (no history), matching Rollback.
func (s *Storage) GetRevision(context.Context, types.ObjectMeta, string, int64) (types.Object, error) {
	return nil, storage.ErrNotFound
}

func (s *Storage) Delete(_ context.Context, m types.ObjectMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bkey, err := bucketFromMeta(m)
	if err != nil {
		return err
	}
	obj, ok := s.data[bkey][memKey(m.Namespace, m.Name)]
	if !ok {
		return storage.ErrNotFound
	}
	delete(s.data[bkey], memKey(m.Namespace, m.Name))
	s.publish(bkey, watch.Deleted, obj)
	return nil
}

func (s *Storage) Get(_ context.Context, m types.ObjectMeta) (types.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bkey, err := bucketFromMeta(m)
	if err != nil {
		return nil, err
	}
	obj, ok := s.data[bkey][memKey(m.Namespace, m.Name)]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return obj, nil
}

func (s *Storage) List(_ context.Context, m types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bkey, err := bucketFromMeta(m)
	if err != nil {
		return nil, err
	}
	sel, err := parseSelector(opts.LabelSelector)
	if err != nil {
		return nil, err
	}
	bucket := s.data[bkey]
	names := make([]string, 0, len(bucket))
	for k := range bucket {
		names = append(names, k)
	}
	slices.Sort(names) // deterministic order

	var out []types.Object
	for _, name := range names {
		obj := bucket[name]
		if m.Namespace != "" {
			acc, err := meta.Accessor(obj)
			if err != nil {
				return nil, err
			}
			if acc.GetNamespace() != m.Namespace {
				continue // a namespaced list is scoped to its namespace
			}
		}
		if !sel.Empty() {
			acc, err := meta.Accessor(obj)
			if err != nil {
				return nil, err
			}
			if !sel.Matches(labels.Set(acc.GetLabels())) {
				continue
			}
		}
		out = append(out, obj)
	}
	return out, nil
}

func (s *Storage) Watch(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) (<-chan metav1.WatchEvent, error) {
	bkey, err := bucketFromMeta(m)
	if err != nil {
		return nil, err
	}
	sel, err := parseSelector(opts.LabelSelector)
	if err != nil {
		return nil, err
	}
	x := &sub{ch: make(chan metav1.WatchEvent, 64), selector: sel, namespace: m.Namespace}

	s.mu.Lock()
	s.subs[bkey] = append(s.subs[bkey], x)
	s.mu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
		case <-s.done:
		}
		s.mu.Lock()
		if i := slices.Index(s.subs[bkey], x); i >= 0 {
			s.subs[bkey] = slices.Delete(s.subs[bkey], i, i+1)
		}
		s.mu.Unlock()
		x.close()
	}()
	return x.ch, nil
}

func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	for _, subs := range s.subs {
		for _, x := range subs {
			x.close()
		}
	}
	s.subs = map[string][]*sub{}
	return nil
}

// publish delivers an event to matching subscribers. The caller holds s.mu, which
// serializes it with Watch/Close, so write order is delivery order and no send
// races a channel close. The object is marshaled once for the watch wire frame.
func (s *Storage) publish(bkey string, et watch.EventType, obj types.Object) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return
	}
	acc, err := meta.Accessor(obj)
	if err != nil {
		return
	}
	lbls := labels.Set(acc.GetLabels())
	evt := metav1.WatchEvent{Type: string(et), Object: runtime.RawExtension{Raw: raw}}
	for _, x := range s.subs[bkey] {
		if x.namespace != "" && x.namespace != acc.GetNamespace() {
			continue // a namespaced watch only sees its namespace's events
		}
		if x.selector != nil && !x.selector.Empty() && !x.selector.Matches(lbls) {
			continue
		}
		select {
		case x.ch <- evt:
		default:
		}
	}
}

func (s *Storage) next(bkey string) uint64 {
	s.seq[bkey]++
	return s.seq[bkey]
}

// memKey is the in-bucket key of an object: "<namespace>/<name>" (empty namespace for
// a cluster-scoped kind), matching the bolt store so namespaced objects with the same
// name in different namespaces don't collide.
func memKey(namespace, name string) string { return namespace + "/" + name }

func (s *Storage) set(bkey, name string, obj types.Object) {
	if s.data[bkey] == nil {
		s.data[bkey] = map[string]types.Object{}
	}
	s.data[bkey][name] = obj
}

func bucketFromGVK(gvk schema.GroupVersionKind) (string, error) {
	if gvk.Kind == "" {
		return "", fmt.Errorf("memory: object kind is required")
	}
	return gvk.Group + "/" + gvk.Kind, nil
}

func bucketFromMeta(m types.ObjectMeta) (string, error) {
	gv, err := schema.ParseGroupVersion(m.ApiVersion)
	if err != nil {
		return "", err
	}
	return bucketFromGVK(gv.WithKind(m.Kind))
}

func parseSelector(s string) (labels.Selector, error) {
	if s == "" {
		return labels.Everything(), nil
	}
	return labels.Parse(s)
}
