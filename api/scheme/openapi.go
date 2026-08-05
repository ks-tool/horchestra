package scheme

import (
	"maps"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// OpenAPIV3 returns the OpenAPI 3.0 document for one group-version, or false when nothing
// addressable is registered under it.
//
// The schemas in it are the SAME documents the server validates writes against — not a
// hand-maintained description of them. That is the property worth having: a client that
// downloads this and refuses a manifest refuses exactly what the server would have refused, and
// a field renamed in the Go type changes both at once or neither.
//
// Each schema carries `x-kubernetes-group-version-kind`, which is how a Kubernetes client maps
// the apiVersion/kind it read in a manifest onto the schema to check it against.
func (s *Scheme) OpenAPIV3(gv schema.GroupVersion) (map[string]any, bool) {
	schemas := map[string]any{}
	for gvk, k := range s.kind {
		if gvk.GroupVersion() != gv {
			continue
		}
		doc := maps.Clone(k.doc)
		// $schema and $id are JSON Schema's own vocabulary; an OpenAPI Schema Object carries
		// neither, and a client that hands the document to a strict parser chokes on them.
		delete(doc, "$schema")
		delete(doc, "$id")
		doc["x-kubernetes-group-version-kind"] = []map[string]string{
			{"group": gvk.Group, "version": gvk.Version, "kind": gvk.Kind},
		}
		schemas[openAPIName(gvk)] = doc
	}
	if len(schemas) == 0 {
		return nil, false
	}
	return map[string]any{
		"openapi":    "3.0.0",
		"info":       map[string]any{"title": "horchestra", "version": gv.Version},
		"paths":      s.writePaths(gv),
		"components": map[string]any{"schemas": schemas},
	}, true
}

// writePaths describes the WRITE surface of a group-version — create, replace, patch — and
// nothing else; what exists is already answered by discovery (/apis), and a schema is already
// answered by components.
//
// It exists for one property a client cannot get any other way: each operation declares the
// `fieldValidation` query parameter, which is how a Kubernetes client learns the SERVER
// validates a submitted object. Without that declaration kubectl assumes it must check the
// manifest itself, reaches for a schema in a format this server does not serve, and refuses to
// send anything at all.
func (s *Scheme) writePaths(gv schema.GroupVersion) map[string]any {
	paths := map[string]any{}
	for gvk, r := range s.res {
		if gvk.GroupVersion() != gv {
			continue
		}
		base := "/apis/" + gv.Group + "/" + gv.Version
		if r.Namespaced {
			base += "/namespaces/{namespace}"
		}
		collection := base + "/" + r.Plural
		paths[collection] = map[string]any{"post": writeOp(gvk, "create")}
		paths[collection+"/{name}"] = map[string]any{
			"put":   writeOp(gvk, "replace"),
			"patch": writeOp(gvk, "patch"),
		}
	}
	return paths
}

// writeOp is one write operation, carrying the Kind it writes and the validation parameter the
// server honours.
func writeOp(gvk schema.GroupVersionKind, verb string) map[string]any {
	return map[string]any{
		"x-kubernetes-group-version-kind": map[string]string{
			"group": gvk.Group, "version": gvk.Version, "kind": gvk.Kind,
		},
		"x-kubernetes-action": verb,
		"parameters": []map[string]any{{
			"name": "fieldValidation",
			"in":   "query",
			"description": "how the server treats unknown or duplicate fields. This server " +
				"always validates strictly: the parameter is declared so a client knows the " +
				"server checks the object, not so the check can be turned off.",
			"schema": map[string]any{"type": "string"},
		}},
		"responses": map[string]any{"200": map[string]any{"description": "OK"}},
	}
}

// OpenAPIGroupVersions returns every group-version that has an OpenAPI document, sorted, so the
// discovery index is stable across restarts.
func (s *Scheme) OpenAPIGroupVersions() []schema.GroupVersion {
	seen := map[schema.GroupVersion]struct{}{}
	for gvk := range s.kind {
		seen[gvk.GroupVersion()] = struct{}{}
	}
	out := slices.Collect(maps.Keys(seen))
	slices.SortFunc(out, func(a, b schema.GroupVersion) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// openAPIName is the schema's key in components.schemas: the group read back-to-front, then the
// version and the kind — "horchestra.io" + v1 + Application becomes io.horchestra.v1.Application.
// It mirrors Kubernetes' own naming (io.k8s.api.core.v1.Pod) because the clients reading this
// document are Kubernetes clients, and a familiar key is one less thing for them to be surprised
// by; nothing keys off it, since the group-version-kind extension is what a lookup uses.
func openAPIName(gvk schema.GroupVersionKind) string {
	if gvk.Group == "" {
		return "core." + gvk.Version + "." + gvk.Kind
	}
	parts := strings.Split(gvk.Group, ".")
	slices.Reverse(parts)
	return strings.Join(parts, ".") + "." + gvk.Version + "." + gvk.Kind
}
