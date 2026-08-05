package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// TestTheSchedulerBindLands is here because the bind is a hand-written JSON literal
// (`{"spec":{"placement":{"nodeName":…}}}` in clientset.Assign) and a literal is exactly what a
// field rename does not touch. When nodeName moved into spec.placement, every Go reference moved
// with it and this one did not; the schema then refused the patch as an unknown field and the
// scheduler could place nothing at all — every workload stayed Pending, on a fleet where the
// only visible symptom was a status message.
//
// So this asserts the shape of that patch against the real schema and the real patch path,
// which is the only thing a compiler cannot do for it.
func TestTheSchedulerBindLands(t *testing.T) {
	s := startServer(t)
	if code, body := s.create(appPath(""), json.RawMessage(
		`{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"pending"},`+
			`"spec":{"image":"reg/x:v1"}}`)); code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", code, body)
	}

	code, body := s.merge(appPath("pending"), `{"spec":{"placement":{"nodeName":"node-1"}}}`)
	if code != http.StatusOK {
		t.Fatalf("bind patch = %d, body=%s — the scheduler cannot place anything", code, body)
	}
	var bound corev1.Application
	decode(t, body, &bound)
	if bound.Spec.Placement.NodeName != "node-1" {
		t.Errorf("nodeName after the bind = %q, want node-1", bound.Spec.Placement.NodeName)
	}
}
