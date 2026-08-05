package scheme

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"

	"github.com/ks-tool/horchestra/api/types"

	"github.com/santhosh-tekuri/jsonschema/v6"
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
	Namespaced bool
	// NoHistory forbids storage from retaining superseded revisions of this Kind. It is set on
	// Kinds whose old revisions are themselves the hazard — a Secret, whose pre-rotation
	// plaintext would otherwise sit in the copy-on-write history of any backup taken after the
	// operator believes the credential is dead. Rollback is not available for such a Kind.
	NoHistory bool
}

type Scheme struct {
	m    map[schema.GroupVersionKind]ObjectFunc
	res  map[schema.GroupVersionKind]Resource
	kind map[schema.GroupVersionKind]*kindSchema
	// defs are the custom defaulters registered per Kind (RegisterDefaults), run before that
	// Kind's declared defaults.
	defs map[schema.GroupVersionKind][]DefaultFunc
}

// kindSchema is everything derived from a Kind's Go type when it is registered: the compiled
// validator every write is checked against, the defaults an absent field is filled with, and
// the schema document itself — which the server publishes, so a client validates a manifest
// against the very rules the server will apply to it.
type kindSchema struct {
	validate *jsonschema.Schema
	defaults *defaultNode
	doc      map[string]any
}

func New() *Scheme {
	return &Scheme{
		m:    make(map[schema.GroupVersionKind]ObjectFunc),
		res:  make(map[schema.GroupVersionKind]Resource),
		kind: make(map[schema.GroupVersionKind]*kindSchema),
		defs: make(map[schema.GroupVersionKind][]DefaultFunc),
	}
}

// AddResource registers gvk's constructor (like AddKnownTypes) and its addressing
// metadata, marking it an addressable resource for discovery and error mapping.
// Plural is required; Singular defaults to the lowercased kind.
//
// It also compiles the Kind's input schema from its Go type. That happens here, at
// registration, rather than on first use: a type the reflector cannot render is a defect in the
// type, and it should stop the process at startup instead of turning every write of that Kind
// into a 500.
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

	k, err := inputSchema(gvk, o())
	if err != nil {
		panic(fmt.Sprintf("compile input schema for %s: %v", gvk, err))
	}
	s.kind[gvk] = k
}

// Resource returns the addressing metadata registered for gvk via AddResource.
func (s *Scheme) Resource(gvk schema.GroupVersionKind) (Resource, bool) {
	r, ok := s.res[gvk]
	return r, ok
}

// Resources returns a copy of the addressable-resource registry.
func (s *Scheme) Resources() map[schema.GroupVersionKind]Resource {
	out := make(map[schema.GroupVersionKind]Resource, len(s.res))
	maps.Copy(out, s.res)
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

	if v := reflect.ValueOf(obj); v.Kind() != reflect.Pointer {
		panic(fmt.Sprintf("object must be a pointer: %s", v.Kind()))
	}

	if _, ok := s.m[gvk]; ok {
		panic(fmt.Sprintf("duplicate object kind: %s", gvk))
	}

	s.m[gvk] = o
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
