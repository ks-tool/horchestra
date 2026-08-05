package apiserver

import (
	"encoding/json"
	"net/http"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/controller/admission"
	"github.com/ks-tool/horchestra/controller/internal/memory"
	"github.com/ks-tool/horchestra/controller/service"
)

// TestServerVersionIsAnswered: GET /version is the first thing a Kubernetes client asks and
// the only place it can learn what it is talking to. A 404 there is what makes `kubectl
// version` report the server's half as unknown.
func TestServerVersionIsAnswered(t *testing.T) {
	sch := scheme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	srv := New(sch, service.New(store, sch, admission.DefaultChain(nil, nil)))

	rec := get(t, srv, "/version", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var info struct {
		GitVersion string `json:"gitVersion"`
		GoVersion  string `json:"goVersion"`
		Platform   string `json:"platform"`
		Compiler   string `json:"compiler"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("the answer is not the shape a client reads: %v (%s)", err, rec.Body.String())
	}
	// Every field a client displays has to be populated: an empty gitVersion renders as a
	// server that was never built by anyone.
	for name, got := range map[string]string{
		"gitVersion": info.GitVersion, "goVersion": info.GoVersion,
		"platform": info.Platform, "compiler": info.Compiler,
	} {
		if got == "" {
			t.Errorf("%s is empty", name)
		}
	}
}
