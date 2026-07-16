package bolt

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/LastPossum/kamino"
	"github.com/google/uuid"
	bbolt "go.etcd.io/bbolt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	"ks-tool.dev/horchestra/pkg/storage"
)

const (
	metaBucket = "._meta"
	rvKey      = "rv"
)

type Store struct {
	db    *bbolt.DB
	submu sync.RWMutex
	subs  map[string][]chan metav1.WatchEvent
}

var _ storage.Storage = (*Store)(nil)

func Open(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte(metaBucket))
		return e
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, subs: map[string][]chan metav1.WatchEvent{}}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// bucketKey ignores the version so all served versions of a kind share storage.
func bucketKey(gvk schema.GroupVersionKind) string { return gvk.Group + "/" + gvk.Kind }

// nextRV increments and returns the cluster-wide monotonic resource version.
func (s *Store) nextRV(tx *bbolt.Tx) (uint64, error) {
	b := tx.Bucket([]byte(metaBucket))
	var rv uint64
	if v := b.Get([]byte(rvKey)); v != nil {
		rv, _ = strconv.ParseUint(string(v), 10, 64)
	}
	rv++
	return rv, b.Put([]byte(rvKey), []byte(strconv.FormatUint(rv, 10)))
}

func (s *Store) Create(_ context.Context, gvk schema.GroupVersionKind, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	out, err := kamino.Clone(obj)
	if err != nil {
		return nil, err
	}
	uid, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	err = s.db.Update(func(tx *bbolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists([]byte(bucketKey(gvk)))
		if e != nil {
			return e
		}
		if b.Get([]byte(out.GetName())) != nil {
			return storage.ErrAlreadyExists
		}
		rv, e := s.nextRV(tx)
		if e != nil {
			return e
		}
		out.SetAPIVersion(gvk.GroupVersion().String())
		out.SetKind(gvk.Kind)
		out.SetUID(types.UID(uid.String()))
		out.SetResourceVersion(strconv.FormatUint(rv, 10))
		out.SetCreationTimestamp(metav1.NewTime(time.Now()))
		data, e := out.MarshalJSON()
		if e != nil {
			return e
		}
		return b.Put([]byte(out.GetName()), data)
	})
	if err != nil {
		return nil, err
	}
	s.publish(gvk, watch.Added, out)
	return out, nil
}

func (s *Store) Get(_ context.Context, gvk schema.GroupVersionKind, name string) (*unstructured.Unstructured, error) {
	out := &unstructured.Unstructured{}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketKey(gvk)))
		if b == nil {
			return storage.ErrNotFound
		}
		v := b.Get([]byte(name))
		if v == nil {
			return storage.ErrNotFound
		}
		return out.UnmarshalJSON(v)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) List(_ context.Context, gvk schema.GroupVersionKind) (*unstructured.UnstructuredList, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(gvk.GroupVersion().WithKind(gvk.Kind + "List"))
	listRV := "0"
	err := s.db.View(func(tx *bbolt.Tx) error {
		// The store-wide rv counter, read in the same snapshot as the items, is
		// the list resourceVersion: monotonic and never regressing on deletes
		// (unlike the max item version), so a client can start a watch from it.
		if m := tx.Bucket([]byte(metaBucket)); m != nil {
			if v := m.Get([]byte(rvKey)); v != nil {
				listRV = string(v)
			}
		}
		b := tx.Bucket([]byte(bucketKey(gvk)))
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			item := unstructured.Unstructured{}
			if e := item.UnmarshalJSON(v); e != nil {
				return e
			}
			list.Items = append(list.Items, item)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	list.SetResourceVersion(listRV)
	return list, nil
}

func (s *Store) Update(_ context.Context, gvk schema.GroupVersionKind, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	out, err := kamino.Clone(obj)
	if err != nil {
		return nil, err
	}
	err = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketKey(gvk)))
		if b == nil {
			return storage.ErrNotFound
		}
		cur := b.Get([]byte(out.GetName()))
		if cur == nil {
			return storage.ErrNotFound
		}
		old := &unstructured.Unstructured{}
		if e := old.UnmarshalJSON(cur); e != nil {
			return e
		}
		rv, e := s.nextRV(tx)
		if e != nil {
			return e
		}
		out.SetAPIVersion(gvk.GroupVersion().String())
		out.SetKind(gvk.Kind)
		out.SetUID(old.GetUID())
		out.SetCreationTimestamp(old.GetCreationTimestamp())
		out.SetResourceVersion(strconv.FormatUint(rv, 10))
		data, e := out.MarshalJSON()
		if e != nil {
			return e
		}
		return b.Put([]byte(out.GetName()), data)
	})
	if err != nil {
		return nil, err
	}
	s.publish(gvk, watch.Modified, out)
	return out, nil
}

func (s *Store) Delete(_ context.Context, gvk schema.GroupVersionKind, name string) error {
	deleted := &unstructured.Unstructured{}
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketKey(gvk)))
		if b == nil {
			return storage.ErrNotFound
		}
		cur := b.Get([]byte(name))
		if cur == nil {
			return storage.ErrNotFound
		}
		if e := deleted.UnmarshalJSON(cur); e != nil {
			return e
		}
		return b.Delete([]byte(name))
	})
	if err != nil {
		return err
	}
	s.publish(gvk, watch.Deleted, deleted)
	return nil
}

func (s *Store) Watch(ctx context.Context, gvk schema.GroupVersionKind) (<-chan metav1.WatchEvent, error) {
	ch := make(chan metav1.WatchEvent, 64)
	key := bucketKey(gvk)
	s.submu.Lock()
	s.subs[key] = append(s.subs[key], ch)
	s.submu.Unlock()
	go func() {
		<-ctx.Done()
		s.submu.Lock()
		subs := s.subs[key]
		for i, c := range subs {
			if c == ch {
				s.subs[key] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		s.submu.Unlock()
		close(ch)
	}()
	return ch, nil
}

// publish fans an event out to current subscribers, dropping on slow receivers.
func (s *Store) publish(gvk schema.GroupVersionKind, et watch.EventType, obj *unstructured.Unstructured) {
	evt := metav1.WatchEvent{Type: string(et), Object: runtime.RawExtension{Object: obj}}
	key := bucketKey(gvk)
	s.submu.RLock()
	defer s.submu.RUnlock()
	for _, ch := range s.subs[key] {
		select {
		case ch <- evt:
		default:
		}
	}
}
