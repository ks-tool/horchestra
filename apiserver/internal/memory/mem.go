// Package memory is an in-memory storage.Storage for tests. It stores the objects
// it is given and hands them straight back — no persistence, no serialization,
// no backend — while reproducing the semantics the higher layers rely on:
// per-GVK monotonic resourceVersions, optimistic concurrency, metadata stamping,
// and a label-filtered watch bus. Namespaces are not modeled.

package memory

import (
	"context"
	"encoding/json"
	"fmt"
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
	if _, ok := s.data[bkey][name]; ok {
		return nil, storage.ErrAlreadyExists
	}
	acc.SetUID(apitypes.UID(utils.NewUIDv4()))
	acc.SetResourceVersion(strconv.FormatUint(s.next(bkey), 10))
	acc.SetCreationTimestamp(metav1.Now())

	s.set(bkey, name, obj)
	s.publish(bkey, watch.Added, obj)
	return obj, nil
}

func (s *Storage) Update(_ context.Context, obj types.Object) (types.Object, error) {
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
	cur, ok := s.data[bkey][acc.GetName()]
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
	acc.SetResourceVersion(strconv.FormatUint(s.next(bkey), 10))

	s.set(bkey, acc.GetName(), obj)
	s.publish(bkey, watch.Modified, obj)
	return obj, nil
}

// UpdateSubresource stores the whole object with a fresh resourceVersion; the
// in-memory memory does not model subresources separately.
func (s *Storage) UpdateSubresource(ctx context.Context, _ string, obj types.Object) (types.Object, error) {
	return s.Update(ctx, obj)
}

// Rollback is unsupported: the memory keeps no revision history.
func (s *Storage) Rollback(context.Context, types.ObjectMeta, string, int64) (types.Object, error) {
	return nil, storage.ErrNotFound
}

func (s *Storage) Delete(_ context.Context, m types.ObjectMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bkey, err := bucketFromMeta(m)
	if err != nil {
		return err
	}
	obj, ok := s.data[bkey][m.Name]
	if !ok {
		return storage.ErrNotFound
	}
	delete(s.data[bkey], m.Name)
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
	obj, ok := s.data[bkey][m.Name]
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
	x := &sub{ch: make(chan metav1.WatchEvent, 64), selector: sel}

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
