package scheme

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/ks-tool/horchestra/api/types"

	genschema "github.com/invopop/jsonschema"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// printer renders a violation's message. The library localizes its diagnostics; the API speaks
// English, like every other error it returns.
var printer = message.NewPrinter(language.English)

// Validate checks a request body against the compiled input schema of its Kind — required
// fields, per-field bounds and unknown keys — and reports every violation, each pinned to the
// field that failed. A GVK registered without a schema (a List kind) is not validated.
//
// It runs on the raw bytes on purpose: by the time the body is a Go value, a misspelled key is
// indistinguishable from an absent one and an out-of-range number has already been truncated by
// the decoder.
func (s *Scheme) Validate(gvk schema.GroupVersionKind, data []byte) field.ErrorList {
	k, ok := s.kind[gvk]
	if !ok {
		return nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return field.ErrorList{field.Invalid(nil, nil, err.Error())}
	}
	var ve *jsonschema.ValidationError
	if err := k.validate.Validate(doc); err != nil {
		if !errors.As(err, &ve) {
			return field.ErrorList{field.Invalid(nil, nil, err.Error())}
		}
		return fieldErrors(ve, doc)
	}
	return nil
}

// DefaultFunc fills in what an author left out, working on the request body as it ARRIVED — the
// decoded JSON object, before anything types it. It is the escape hatch for a default no field
// tag can express: one field's value derived from another, or from the shape of the whole
// object. Registered per Kind with RegisterDefaults.
//
// It operates on the document rather than a typed value for the same reason everything else on
// this path does: after decoding, a field the author omitted and a field they wrote the zero
// value into are the same thing, and a defaulter cannot tell which it is looking at.
type DefaultFunc func(obj map[string]any)

// RegisterDefaults adds a custom defaulter for gvk. Several may be registered; they run in
// registration order, and all of them before the schema's own declared defaults.
func (s *Scheme) RegisterDefaults(gvk schema.GroupVersionKind, fn DefaultFunc) {
	if fn == nil {
		return
	}
	s.defs[gvk] = append(s.defs[gvk], fn)
}

// Default fills a request body's absent fields: first every custom DefaultFunc registered for
// the Kind, then the defaults DECLARED IN THE SCHEMA. It returns the completed body, or the body
// untouched when the Kind has neither.
//
// The order is the point. A custom defaulter exists to decide a value from what the author
// actually wrote, so it must see the object before anything has been filled in — otherwise every
// field it inspects is already set, and "the author asked for this" is indistinguishable from
// "the schema supplied it". The declared defaults then fill whatever is still absent, and
// validation runs last, over the completed body: a value this function supplied is checked
// exactly like an authored one, never trusted because the server wrote it.
//
// The declared default is the value the field's own `jsonschema:"default=…"` tag puts in the
// schema, so the shape the server publishes and the object it stores cannot say different
// things. A default fills a field, never the object that would hold it: an absent `spec` stays
// absent rather than being conjured from its children's defaults, so a body missing a required
// object is still reported as missing it.
func (s *Scheme) Default(gvk schema.GroupVersionKind, data []byte) ([]byte, error) {
	custom := s.defs[gvk]
	k := s.kind[gvk]
	declared := k != nil && k.defaults != nil
	if len(custom) == 0 && !declared {
		return data, nil
	}
	var doc map[string]any
	// UseNumber keeps every number exactly as it arrived: re-serializing through float64 would
	// silently round an int64 past 2^53 on a body this function may not even change.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return data, nil // not a JSON object; Validate reports it
	}
	for _, fn := range custom {
		fn(doc)
	}
	changed := declared && k.defaults.apply(doc)
	if !changed && len(custom) == 0 {
		return data, nil
	}
	return json.Marshal(doc)
}

// defaultNode mirrors one node of a compiled schema: the default declared for it, the defaults
// of its properties (an object), and of its elements (an array). Reading them off the schema
// rather than the Go type keeps one source: the same document the validator enforces states
// what an absent field means.
type defaultNode struct {
	value any
	props map[string]*defaultNode
	elem  *defaultNode
}

// collectDefaults walks a JSON Schema document and returns the defaults it declares, at every
// depth, or nil when it declares none. The schema is fully inlined (no $ref), so the walk is the
// schema's own shape.
func collectDefaults(doc map[string]any) *defaultNode {
	n := &defaultNode{}
	if props, ok := doc["properties"].(map[string]any); ok {
		for name, sub := range props {
			subDoc, ok := sub.(map[string]any)
			if !ok {
				continue
			}
			child := collectDefaults(subDoc)
			if v, ok := subDoc["default"]; ok {
				if child == nil {
					child = &defaultNode{}
				}
				child.value = v
			}
			if child == nil {
				continue
			}
			if n.props == nil {
				n.props = map[string]*defaultNode{}
			}
			n.props[name] = child
		}
	}
	if items, ok := doc["items"].(map[string]any); ok {
		n.elem = collectDefaults(items)
	}
	if n.props == nil && n.elem == nil {
		return nil
	}
	return n
}

// apply fills v's absent properties with this node's declared defaults, recursing into the
// objects and array elements that are present, and reports whether anything was filled. Maps and
// slices are filled in place — the caller holds the same containers.
func (n *defaultNode) apply(v any) bool {
	var changed bool
	switch t := v.(type) {
	case map[string]any:
		for name, child := range n.props {
			cur, present := t[name]
			if !present {
				if child.value != nil {
					t[name] = child.value
					changed = true
				}
				continue
			}
			changed = child.apply(cur) || changed
		}
	case []any:
		if n.elem == nil {
			break
		}
		for _, e := range t {
			changed = n.elem.apply(e) || changed
		}
	}
	return changed
}

// inputSchema compiles the input schema for one Kind out of its Go type. A field is required
// unless its json tag says omitempty/omitzero, a `jsonschema:"…"` tag carries the per-field
// bound (minLength=1 on an image, the enum on restartPolicy), and every struct is closed —
// additionalProperties: false — so a misspelled key is a 422 rather than a field that silently
// does nothing.
//
// Deriving the schema from the type is the whole point: one source of truth, so a renamed or
// deleted field cannot leave a hand-written rule behind that still validates the old shape.
func inputSchema(gvk schema.GroupVersionKind, proto types.Object) (*kindSchema, error) {
	r := &genschema.Reflector{
		DoNotReference: true, ExpandedStruct: true, Mapper: mapType,
		// The types' own doc comments, extracted at build time (internal/gencomments), become
		// each field's description — so the document the server publishes explains the API in
		// the same words the code does, and `kubectl explain` has something to print.
		CommentMap:    goComments,
		LookupComment: describeByType,
	}
	doc := r.Reflect(proto)
	// status is the server's, written through its own subresource by the node that observed it.
	// The Go field carries no omitempty (the server always serializes it), but requiring it of
	// an AUTHOR would make every create carry an empty one.
	doc.Required = slices.DeleteFunc(doc.Required, func(f string) bool { return f == "status" })
	doc.ID = genschema.ID("https://ks-tool.dev/schema/" + gvk.Group + "/" + gvk.Version + "/" + gvk.Kind)

	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return nil, err
	}
	parsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(string(doc.ID), parsed); err != nil {
		return nil, err
	}
	compiled, err := c.Compile(string(doc.ID))
	if err != nil {
		return nil, err
	}
	return &kindSchema{validate: compiled, defaults: collectDefaults(asMap), doc: asMap}, nil
}

// describeByType is the fallback for a field carrying no doc comment of its own: it is described
// by whatever its TYPE says. `spec` is the case that needs it — the field is one word, the
// documentation is all on ApplicationSpec — and without the fallback the reflector leaves it
// blank, because the tag pass wipes the type's description and only a field comment is put back.
//
// A field that does document itself keeps its own words: this returns nothing for it, and the
// comment map answers.
func describeByType(t reflect.Type, name string) string {
	if name == "" {
		return swaggerDoc(t, "") // a type of ours is described by its own comment, from the map
	}
	// A Kubernetes type documents itself: apimachinery generates SwaggerDoc() carrying the very
	// text Kubernetes publishes for its API, already prose and free of its codegen directives.
	// Reading it beats extracting those comments ourselves — it needs no source at build time,
	// it tracks the dependency automatically, and it is the text their own clients show.
	if d := swaggerDoc(t, name); d != "" {
		return d
	}
	if _, own := goComments[typeKey(t)+"."+name]; own {
		return ""
	}
	f, ok := t.FieldByName(name)
	if !ok {
		return ""
	}
	ft := f.Type
	for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
		ft = ft.Elem()
	}
	if ft.Kind() != reflect.Struct {
		return ""
	}
	if d := swaggerDoc(ft, ""); d != "" {
		return d
	}
	if d := wireDoc(ft); d != "" {
		return d
	}
	return goComments[typeKey(ft)]
}

// wireDoc describes a Go struct this schema renders as a scalar — what it is ON THE WIRE, which
// is the question an author has and not the one its Go doc answers: Quantity's own comment opens
// on marshaling and AsInt64 accessors, and neither type ships a generated description.
//
// It is stated once here because two callers need it: mapType, which builds the scalar schema,
// and the description fallback, since the tag pass wipes what mapType set.
func wireDoc(t reflect.Type) string {
	switch t {
	case reflect.TypeOf(metav1.Time{}):
		return "An RFC 3339 timestamp, e.g. 2026-08-03T09:15:00Z."
	case reflect.TypeOf(resource.Quantity{}):
		return "A quantity: a fixed-point number with an optional suffix — decimal SI (m, k, M, G, T) " +
			"or binary (Ki, Mi, Gi, Ti). 500m is half a CPU, 1Gi is 1024 MiB."
	}
	return ""
}

// swaggerDocumented is a type shipping its own generated field documentation, keyed by JSON
// field name with "" for the type itself. Every Kubernetes API type implements it.
type swaggerDocumented interface{ SwaggerDoc() map[string]string }

// swaggerDoc returns what t says about its field name — or about itself, for an empty name.
// The lookup is by JSON name, since that is how the generated documentation is keyed and what
// the schema calls the field anyway.
func swaggerDoc(t reflect.Type, name string) string {
	d, ok := reflect.New(t).Elem().Interface().(swaggerDocumented)
	if !ok {
		return ""
	}
	if name == "" {
		return d.SwaggerDoc()[""]
	}
	f, ok := t.FieldByName(name)
	if !ok {
		return ""
	}
	json, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	return d.SwaggerDoc()[json]
}

func typeKey(t reflect.Type) string { return t.PkgPath() + "." + t.Name() }

// mapType renders the types reflection cannot render on its own. metav1.Time and
// resource.Quantity are structs in Go and strings on the wire. ObjectMeta is reduced to the one
// field the server requires — a name — and left OPEN, because metadata is the one place the
// author is not the only writer: kubectl stamps its last-applied annotation there, the server
// stamps uid, resourceVersion and generation, and closing it would reject a body the server
// itself produced on the update and patch paths.
func mapType(t reflect.Type) *genschema.Schema {
	// A hand-built schema is outside the reflector's comment pass, so each one carries its own
	// description: ObjectMeta takes Kubernetes' generated words, the scalars take wireDoc's.
	switch t {
	case reflect.TypeOf(metav1.Time{}), reflect.TypeOf(resource.Quantity{}):
		return &genschema.Schema{Type: "string", Description: wireDoc(t)}
	case reflect.TypeOf(metav1.ObjectMeta{}):
		props := genschema.NewProperties()
		props.Set("name", &genschema.Schema{
			Type:        "string",
			MinLength:   new(uint64(1)),
			Description: swaggerDoc(t, "Name"),
		})
		return &genschema.Schema{
			Type:        "object",
			Properties:  props,
			Required:    []string{"name"},
			Description: swaggerDoc(t, ""),
		}
	}
	return nil
}

// fieldErrors turns a validation failure into one API field error per violation. Only the leaves
// of the failure tree say anything: every level above them repeats that the level below failed.
//
// Three kinds are re-pinned rather than reported where the library raises them, because it
// raises them on the OBJECT and the author needs the FIELD: a missing or unknown property is
// reported at the property, not at the object that lacks or carries it.
func fieldErrors(ve *jsonschema.ValidationError, doc any) field.ErrorList {
	var out field.ErrorList
	for _, leaf := range leaves(ve, nil) {
		p := fieldPath(leaf.InstanceLocation)
		switch k := leaf.ErrorKind.(type) {
		case *kind.Required:
			for _, name := range k.Missing {
				out = append(out, field.Required(p.Child(name), ""))
			}
		case *kind.AdditionalProperties:
			for _, name := range k.Properties {
				out = append(out, field.Forbidden(p.Child(name), "unknown field"))
			}
		case *kind.Enum:
			out = append(out, field.NotSupported(p, valueAt(doc, leaf.InstanceLocation), enumValues(k.Want)))
		default:
			// No bad value: the library's message already carries what it got where that
			// matters ("minimum: got -1, want 0"), and echoing the instance would put a
			// Secret's payload into the error and the audit log.
			out = append(out, field.Invalid(p, nil, k.LocalizedString(printer)))
		}
	}
	return out
}

// leaves collects the deepest errors of a validation tree — the ones naming a concrete instance
// location and keyword.
func leaves(e *jsonschema.ValidationError, out []*jsonschema.ValidationError) []*jsonschema.ValidationError {
	if len(e.Causes) == 0 {
		return append(out, e)
	}
	for _, c := range e.Causes {
		out = leaves(c, out)
	}
	return out
}

// fieldPath turns an instance location ("spec", "volumes", "0", "mountPath") into the API's
// field path (spec.volumes[0].mountPath), reading an all-digit token as an array index.
func fieldPath(tokens []string) *field.Path {
	var p *field.Path
	for _, t := range tokens {
		switch i, err := strconv.Atoi(t); {
		case err == nil && p != nil:
			p = p.Index(i)
		case p == nil:
			p = field.NewPath(t)
		default:
			p = p.Child(t)
		}
	}
	return p
}

// valueAt resolves an instance location against the decoded document, so an error can name what
// it actually got.
func valueAt(doc any, tokens []string) any {
	for _, t := range tokens {
		switch v := doc.(type) {
		case map[string]any:
			doc = v[t]
		case []any:
			i, err := strconv.Atoi(t)
			if err != nil || i < 0 || i >= len(v) {
				return nil
			}
			doc = v[i]
		default:
			return nil
		}
	}
	return doc
}

// enumValues renders an enum's permitted values for the "supported values: …" line.
func enumValues(want []any) []string {
	out := make([]string, 0, len(want))
	for _, v := range want {
		out = append(out, fmt.Sprint(v))
	}
	return out
}
