package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	genschema "github.com/invopop/jsonschema"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// validators holds the compiled input schema for each built-in Kind, generated
// from its Go type at startup and kept in memory. Deriving the schema from the
// type keeps one source of truth: a field is required unless its json tag has
// ",omitempty"; a `jsonschema:"minLength=1"` tag forbids an empty value. The
// controller validates every create/update against these before admission.
var validators = buildValidators()

func buildValidators() map[schema.GroupVersionKind]*jsonschema.Schema {
	prototypes := map[schema.GroupVersionKind]any{
		ApplicationResource.GVK:      &Application{},
		NodeResource.GVK:             &Node{},
		PersistentVolumeResource.GVK: &PersistentVolume{},
		RoleResource.GVK:             &Role{},
		RoleBindingResource.GVK:      &RoleBinding{},
	}
	r := &genschema.Reflector{DoNotReference: true, ExpandedStruct: true, Mapper: mapType}
	c := jsonschema.NewCompiler()
	out := make(map[schema.GroupVersionKind]*jsonschema.Schema, len(prototypes))
	for gvk, proto := range prototypes {
		doc := reflectDoc(r, proto)
		id := "https://ks-tool.dev/schema/" + gvk.Group + "/" + gvk.Kind
		doc["$id"] = id
		raw, err := json.Marshal(doc)
		if err != nil {
			panic(fmt.Sprintf("marshal schema for %s: %v", gvk, err))
		}
		parsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			panic(fmt.Sprintf("parse schema for %s: %v", gvk, err))
		}
		if err := c.AddResource(id, parsed); err != nil {
			panic(fmt.Sprintf("add schema for %s: %v", gvk, err))
		}
		sch, err := c.Compile(id)
		if err != nil {
			panic(fmt.Sprintf("compile schema for %s: %v", gvk, err))
		}
		out[gvk] = sch
	}
	return out
}

// mapType overrides the schema for Kubernetes types that reflection cannot render
// on its own: metav1.Time and resource.Quantity marshal as strings, and the full
// ObjectMeta is reduced to the single field the controller enforces — a name.
func mapType(t reflect.Type) *genschema.Schema {
	switch t {
	case reflect.TypeOf(metav1.Time{}), reflect.TypeOf(resource.Quantity{}):
		return &genschema.Schema{Type: "string"}
	case reflect.TypeOf(metav1.ObjectMeta{}):
		props := genschema.NewProperties()
		props.Set("name", &genschema.Schema{Type: "string"})
		return &genschema.Schema{Type: "object", Properties: props, Required: []string{"name"}}
	}
	return nil
}

// reflectDoc reflects proto into a JSON-schema document (a generic map, so it can
// be normalized) and marks as required both metadata and a spec that declares
// required subfields, plus a non-empty metadata.name.
func reflectDoc(r *genschema.Reflector, proto any) map[string]any {
	raw, err := json.Marshal(r.Reflect(proto))
	if err != nil {
		panic(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(err)
	}
	props, ok := doc["properties"].(map[string]any)
	if !ok {
		return doc
	}
	req := stringSet(doc["required"])
	if _, ok := props["metadata"]; ok {
		req["metadata"] = struct{}{}
	}
	// Require spec only when the type declares required spec fields (e.g. an
	// Application's source/node); a Kind with a free-form spec stays permissive.
	if spec, ok := props["spec"].(map[string]any); ok {
		if sr, ok := spec["required"].([]any); ok && len(sr) > 0 {
			req["spec"] = struct{}{}
		}
	}
	doc["required"] = sortedKeys(req)
	// A present-but-empty name satisfies "required"; forbid it.
	if md, ok := props["metadata"].(map[string]any); ok {
		if mp, ok := md["properties"].(map[string]any); ok {
			if name, ok := mp["name"].(map[string]any); ok {
				name["minLength"] = 1
			}
		}
	}
	return doc
}

// Validate checks u against the in-memory input schema for its Kind. Kinds without
// a registered schema are not validated. A violation is returned as a single error
// so the service can surface it as HTTP 422 Invalid.
func Validate(gvk schema.GroupVersionKind, u *unstructured.Unstructured) error {
	v, ok := validators[gvk]
	if !ok {
		return nil
	}
	if err := v.Validate(u.Object); err != nil {
		return fmt.Errorf("%s", schemaError(err))
	}
	return nil
}

// schemaError condenses a jsonschema validation error to its actionable lines
// (e.g. "spec: missing property 'node'"), dropping the schema-URL preamble; it
// falls back to the raw error if the format is unrecognized.
func schemaError(err error) string {
	var msgs []string
	for _, line := range strings.Split(err.Error(), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "- at '")
		if !ok {
			continue
		}
		// rest is "/spec': missing property 'node'" (or "': …" at the root); turn
		// it into "spec: missing property 'node'".
		rest = strings.TrimPrefix(rest, "/")
		rest = strings.Replace(rest, "': ", ": ", 1)
		msgs = append(msgs, strings.TrimPrefix(rest, ": "))
	}
	if len(msgs) == 0 {
		return err.Error()
	}
	return strings.Join(msgs, "; ")
}

func stringSet(v any) map[string]struct{} {
	set := map[string]struct{}{}
	if list, ok := v.([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				set[s] = struct{}{}
			}
		}
	}
	return set
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
