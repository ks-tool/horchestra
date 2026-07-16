package v1

import (
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func mustUnstructured(t *testing.T, body string) *unstructured.Unstructured {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("bad test body: %v", err)
	}
	return &unstructured.Unstructured{Object: m}
}

// TestApplicationSchema checks the input schema generated from the Application Go
// type: metadata.name, spec.image and spec.nodeName are required and non-empty,
// unknown spec fields are rejected, restartPolicy is an enum, and a volumeMount is
// exactly one of pv|tmpfs (the oneof_required union) — all derived from the struct
// tags, not a hand-written schema.
func TestApplicationSchema(t *testing.T) {
	gvk := ApplicationResource.GVK
	cases := []struct {
		name   string
		body   string
		reject string // substring the error must contain; "" means it must be accepted
	}{
		{"valid", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1"}}`, ""},
		{"valid with resources/env/volumeMounts", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","resources":{"requests":{"cpu":"500m","memory":"256Mi"}},"env":{"K":"V"},"volumeMounts":[{"pv":"d","path":"/d"}]}}`, ""},
		{"valid with tmpfs volumeMount", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","volumeMounts":[{"tmpfs":{"size":"64Mi"},"path":"/run"}]}}`, ""},
		{"valid with ports (name optional)", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","ports":[{"name":"http","port":8080},{"port":9090}]}}`, ""},
		{"valid restartPolicy", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","restartPolicy":"OnFailure"}}`, ""},
		{"valid securityContext", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","securityContext":{"runAsUser":70,"capabilities":{"drop":["ALL"]}}}}`, ""},
		{"ports missing port", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","ports":[{"name":"http"}]}}`, "port"},
		{"ports port out of range", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","ports":[{"port":0}]}}`, "port"},
		{"volumeMount both pv and tmpfs", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","volumeMounts":[{"path":"/d","pv":"d","tmpfs":{}}]}}`, "volumeMounts"},
		{"volumeMount neither pv nor tmpfs", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","volumeMounts":[{"path":"/d"}]}}`, "volumeMounts"},
		{"invalid restartPolicy", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","restartPolicy":"Sometimes"}}`, "restartPolicy"},
		{"missing nodeName", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1"}}`, "nodeName"},
		{"empty nodeName", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":""}}`, "nodeName"},
		{"missing image", `{"metadata":{"name":"demo"},"spec":{"nodeName":"n1"}}`, "image"},
		{"missing spec", `{"metadata":{"name":"demo"}}`, "spec"},
		{"missing name", `{"spec":{"image":"reg/app:v1","nodeName":"n1"}}`, "metadata"},
		{"unknown spec field", `{"metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"n1","bogus":1}}`, "bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(gvk, mustUnstructured(t, tc.body))
			if tc.reject == "" {
				if err != nil {
					t.Fatalf("want accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.reject) {
				t.Fatalf("want rejection mentioning %q, got %v", tc.reject, err)
			}
		})
	}
}

// TestNodeSchemaPermissive confirms a self-registering node passes: only a name
// is required, and status carries resource quantities as strings.
func TestNodeSchemaPermissive(t *testing.T) {
	body := `{"metadata":{"name":"n1"},"status":{"capacity":{"cpu":"8","memory":"16Gi"},"ready":true}}`
	if err := Validate(NodeResource.GVK, mustUnstructured(t, body)); err != nil {
		t.Fatalf("node self-registration should validate, got %v", err)
	}
	if err := Validate(NodeResource.GVK, mustUnstructured(t, `{"spec":{}}`)); err == nil {
		t.Fatal("a node without metadata.name must be rejected")
	}
}
