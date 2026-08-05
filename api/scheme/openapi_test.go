package scheme_test

import (
	"encoding/json"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// doc renders the OpenAPI document for the core group-version as generic JSON, the way a client
// reads it off the wire.
func doc(t *testing.T) map[string]any {
	t.Helper()
	s := newScheme(t)
	d, ok := s.OpenAPIV3(corev1.GroupVersion)
	if !ok {
		t.Fatal("no document for the core group-version")
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func schemas(t *testing.T, d map[string]any) map[string]any {
	t.Helper()
	comps, _ := d["components"].(map[string]any)
	out, _ := comps["schemas"].(map[string]any)
	if len(out) == 0 {
		t.Fatal("document carries no schemas")
	}
	return out
}

// TestOpenAPIPublishesTheEnforcedSchema is the property the whole document exists for: what a
// client validates against is the schema the server validates with, not a description of it
// maintained alongside. A field renamed in the Go type moves both or neither.
func TestOpenAPIPublishesTheEnforcedSchema(t *testing.T) {
	app, ok := schemas(t, doc(t))["io.horchestra.v1.Application"].(map[string]any)
	if !ok {
		t.Fatal("no schema for Application")
	}
	spec, _ := app["properties"].(map[string]any)["spec"].(map[string]any)
	if spec == nil {
		t.Fatal("Application schema has no spec")
	}
	// The three rules the enforced schema carries, as a client now sees them.
	if got := spec["additionalProperties"]; got != false {
		t.Errorf("spec.additionalProperties = %v, want false — an unknown field is refused", got)
	}
	image, _ := spec["properties"].(map[string]any)["image"].(map[string]any)
	if image == nil || image["minLength"] == nil {
		t.Errorf("spec.image lost its minLength: %v", image)
	}
	// A trait section is published inline, not behind a $ref: kubectl explain and every strict
	// client read the rules off the nested object, so a section that flattened to a reference
	// would take its children's enums and defaults out of the served schema.
	lifecycle, _ := spec["properties"].(map[string]any)["lifecycle"].(map[string]any)
	if lifecycle == nil {
		t.Fatalf("spec.lifecycle is not published: %v", spec["properties"])
	}
	policy, _ := lifecycle["properties"].(map[string]any)["restartPolicy"].(map[string]any)
	if policy == nil || policy["enum"] == nil || policy["default"] != corev1.RestartAlways {
		t.Errorf("spec.lifecycle.restartPolicy lost its enum/default: %v", policy)
	}
	// JSON Schema's own vocabulary is not OpenAPI's; a client handing this to a strict parser
	// must not meet $schema or $id.
	for _, k := range []string{"$schema", "$id"} {
		if _, ok := app[k]; ok {
			t.Errorf("%s leaked into the OpenAPI schema", k)
		}
	}
}

// TestOpenAPISchemasNameTheirKind: a client reads apiVersion/kind out of a manifest and needs to
// find the schema for it. The group-version-kind extension is that mapping — without it the
// document is a bag of anonymous shapes.
func TestOpenAPISchemasNameTheirKind(t *testing.T) {
	for name, v := range schemas(t, doc(t)) {
		sch, _ := v.(map[string]any)
		gvks, _ := sch["x-kubernetes-group-version-kind"].([]any)
		if len(gvks) != 1 {
			t.Errorf("%s: want exactly one group-version-kind, got %v", name, gvks)
			continue
		}
		gvk, _ := gvks[0].(map[string]any)
		if gvk["group"] != corev1.GroupName || gvk["version"] != "v1" || gvk["kind"] == "" {
			t.Errorf("%s: bad group-version-kind %v", name, gvk)
		}
	}
}

// TestOpenAPIDeclaresServerSideValidation locks the declaration that keeps validation on the
// server: each write operation names the fieldValidation parameter, which is how kubectl learns
// the server checks the object. Drop it and kubectl goes looking for a schema in a format this
// server does not serve, and refuses to send anything at all.
func TestOpenAPIDeclaresServerSideValidation(t *testing.T) {
	paths, _ := doc(t)["paths"].(map[string]any)
	const item = "/apis/horchestra.io/v1/namespaces/{namespace}/applications/{name}"
	ops, _ := paths[item].(map[string]any)
	if ops == nil {
		t.Fatalf("no write path for a namespaced Application; got %d paths", len(paths))
	}
	for _, verb := range []string{"put", "patch"} {
		op, _ := ops[verb].(map[string]any)
		if op == nil {
			t.Errorf("%s: no %s operation", item, verb)
			continue
		}
		gvk, _ := op["x-kubernetes-group-version-kind"].(map[string]any)
		if gvk["kind"] != "Application" {
			t.Errorf("%s %s: operation does not name its Kind: %v", item, verb, gvk)
		}
		params, _ := op["parameters"].([]any)
		if !declaresFieldValidation(params) {
			t.Errorf("%s %s: does not declare the fieldValidation query parameter", item, verb)
		}
	}
	// A cluster-scoped Kind takes no {namespace} segment.
	if _, ok := paths["/apis/horchestra.io/v1/nodes/{name}"]; !ok {
		t.Error("no write path for the cluster-scoped Node")
	}
}

func declaresFieldValidation(params []any) bool {
	for _, p := range params {
		m, _ := p.(map[string]any)
		if m["name"] == "fieldValidation" && m["in"] == "query" {
			return true
		}
	}
	return false
}

// TestOpenAPIOnlyForServedGroupVersions: a group-version this server does not serve has no
// document, so the index never points at one and a client is not told to expect it.
func TestOpenAPIOnlyForServedGroupVersions(t *testing.T) {
	s := newScheme(t)
	if _, ok := s.OpenAPIV3(schema.GroupVersion{Group: "example.com", Version: "v1"}); ok {
		t.Error("an unserved group-version must have no document")
	}
	gvs := s.OpenAPIGroupVersions()
	if len(gvs) != 1 || gvs[0] != corev1.GroupVersion {
		t.Errorf("group-versions = %v, want just the core one this scheme registers", gvs)
	}
}
