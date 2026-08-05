package service

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestBindNamespaceIgnoresAFoldedSpelling is the cross-namespace write. The namespace used to be
// stamped by rewriting the raw JSON: probe metadata for the exact key "namespace", then set it and
// re-marshal. A map key is an exact string, but encoding/json folds FIELD names with a
// Unicode-aware comparison — so "nameſpace" (U+017F LATIN SMALL LETTER LONG S) was a different key
// to the probe and the SAME field to the decoder. Re-marshalling a map sorts its keys, which put
// that spelling after the honest one, where last-wins made it the value that took effect: a tenant
// holding rights in one namespace could write into any other.
//
// The bind now runs on the typed object. The fold is still real — the decoder does put
// "nameſpace" onto the Namespace field, which is exactly why the raw-map probe was blind — but the
// value it produces now meets a comparison against the namespace the CALLER is authoritative
// about, and disagreeing means refused. Either outcome is safe; what must never happen is the
// write landing in "victim".
func TestBindNamespaceIgnoresAFoldedSpelling(t *testing.T) {
	svc := newTestService(t)
	body := []byte(`{"metadata":{"name":"w","namespace":"mine","nameſpace":"victim"},"spec":{}}`)

	obj, err := svc.Create(t.Context(), widgetGVK, body, "mine")
	if err != nil {
		if !contains(err.Error(), "victim") {
			t.Fatalf("create failed for an unrelated reason: %v", err)
		}
		return // refused outright: the smuggled namespace never reached storage
	}
	meta, ok := obj.(metav1.Object)
	if !ok {
		t.Fatal("created object carries no metadata")
	}
	if got := meta.GetNamespace(); got != "mine" {
		t.Fatalf("object landed in namespace %q — a folded spelling must never place a write "+
			"outside the namespace the request addressed", got)
	}
}

// TestBindNamespaceRefusesADisagreeingBody: a body that names a different namespace than the
// caller is authoritative about is refused rather than silently rewritten, so a write can never
// land somewhere the request did not address.
func TestBindNamespaceRefusesADisagreeingBody(t *testing.T) {
	svc := newTestService(t)
	body := []byte(`{"metadata":{"name":"w","namespace":"theirs"},"spec":{}}`)
	if _, err := svc.Create(t.Context(), widgetGVK, body, "mine"); err == nil {
		t.Fatal("a body naming another namespace must be refused")
	}
}

// TestBindNamespaceRefusesANamespaceOnAClusterScopedWrite is the other half, and it is what closes
// the node-side hole: the gRPC status path passes "" because Node is cluster-scoped, so a node
// that puts a namespace in its own object is refused instead of creating an unaddressable
// namespaced shadow — an object no API route can reach, which takes cordon and delete away as
// containment levers.
func TestBindNamespaceRefusesANamespaceOnAClusterScopedWrite(t *testing.T) {
	svc := newTestService(t)
	body := []byte(`{"metadata":{"name":"w","namespace":"smuggled"},"spec":{}}`)
	_, err := svc.Create(t.Context(), widgetGVK, body, "")
	if err == nil {
		t.Fatal("a namespace on a cluster-scoped write must be refused")
	}
	if got := err.Error(); !contains(got, "cluster-scoped") {
		t.Errorf("the refusal must say why, got: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
