package scheme

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/ks-tool/horchestra/api/types"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ObjectFunc func() types.Object

// Resource is the discovery/addressing metadata for an addressable Kind: its
// plural name (e.g. "applications"), its singular (defaults to the lowercased
// kind), short names (e.g. "app", "apps") and whether it is namespaced. List
// kinds are not resources and carry none of this.
type Resource struct {
	Plural     string
	Singular   string
	ShortNames []string
}

type Scheme struct {
	m    map[schema.GroupVersionKind]ObjectFunc
	res  map[schema.GroupVersionKind]Resource
	defs map[schema.GroupVersionKind]func(any)
}

func New() *Scheme {
	return &Scheme{
		m:    make(map[schema.GroupVersionKind]ObjectFunc),
		res:  make(map[schema.GroupVersionKind]Resource),
		defs: make(map[schema.GroupVersionKind]func(any)),
	}
}

// AddResource registers gvk's constructor (like AddKnownTypes) and its addressing
// metadata, marking it an addressable resource for discovery and error mapping.
// Plural is required; Singular defaults to the lowercased kind.
func (s *Scheme) AddResource(gvk schema.GroupVersionKind, o ObjectFunc, r Resource) {
	s.AddKnownTypes(gvk, o)
	if _, ok := s.m[gvk]; !ok {
		return
	}
	if r.Plural == "" {
		panic(fmt.Sprintf("resource plural is required: %s", gvk))
	}
	if r.Singular == "" {
		r.Singular = strings.ToLower(gvk.Kind)
	}
	s.res[gvk] = r
}

// Resource returns the addressing metadata registered for gvk via AddResource.
func (s *Scheme) Resource(gvk schema.GroupVersionKind) (Resource, bool) {
	r, ok := s.res[gvk]
	return r, ok
}

// Resources returns a copy of the addressable-resource registry.
func (s *Scheme) Resources() map[schema.GroupVersionKind]Resource {
	out := make(map[schema.GroupVersionKind]Resource, len(s.res))
	for gvk, r := range s.res {
		out[gvk] = r
	}
	return out
}

// GroupResource resolves gvk to its GroupResource, preferring the registered
// plural and falling back to apimachinery's kind->resource heuristic for kinds
// registered without resource metadata (e.g. error paths on odd GVKs).
func (s *Scheme) GroupResource(gvk schema.GroupVersionKind) schema.GroupResource {
	if r, ok := s.res[gvk]; ok {
		return schema.GroupResource{Group: gvk.Group, Resource: r.Plural}
	}
	gvr, _ := apimeta.UnsafeGuessKindToResource(gvk)
	return gvr.GroupResource()
}

func (s *Scheme) AddKnownTypes(gvk schema.GroupVersionKind, o ObjectFunc) {
	if o == nil {
		return
	}

	obj := o()
	if obj == nil {
		return
	}

	if v := reflect.ValueOf(obj); v.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("object must be a pointer: %s", v.Kind()))
	}

	if _, ok := s.m[gvk]; ok {
		panic(fmt.Sprintf("duplicate object kind: %s", gvk))
	}

	s.m[gvk] = o
}

func (s *Scheme) RegisterDefaults(o types.Object, fn func(any)) {
	gvk := o.GetObjectKind().GroupVersionKind()
	if _, ok := s.m[gvk]; ok {
		panic(fmt.Sprintf("duplicate defaulter object kind: %s", gvk))
	}

	s.defs[gvk] = fn
}

func (s *Scheme) New(gvk schema.GroupVersionKind) (types.Object, error) {
	f, ok := s.m[gvk]
	if !ok {
		return nil, fmt.Errorf("no type registered for %s", gvk)
	}

	obj := f()

	return obj, nil
}

func (s *Scheme) Decode(data []byte) (types.Object, error) {
	findKind := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}{}

	if err := json.Unmarshal(data, &findKind); err != nil {
		return nil, fmt.Errorf("decode object failed: %w", err)
	}

	if (len(findKind.Kind) == 0 && len(findKind.APIVersion) == 0) || len(findKind.Kind) == 0 {
		return nil, fmt.Errorf("couldn't get apiVersion/kind")
	}

	gv, err := schema.ParseGroupVersion(findKind.APIVersion)
	if err != nil {
		return nil, err
	}

	gvk := gv.WithKind(findKind.Kind)
	return s.New(gvk)
}

func (s *Scheme) KnownTypes(gv schema.GroupVersion) (objects []ObjectFunc) {
	for gvk, fn := range s.m {
		if gvk.GroupVersion() == gv {
			objects = append(objects, fn)
		}
	}
	return
}

func (s *Scheme) AllKnownTypes() []schema.GroupVersionKind {
	out := make([]schema.GroupVersionKind, 0, len(s.m))
	for gvk := range s.m {
		out = append(out, gvk)
	}
	return out
}
