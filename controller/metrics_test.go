package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/controller/admission"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
	"github.com/ks-tool/horchestra/controller/internal/memory"
	"github.com/ks-tool/horchestra/controller/service"
)

// fixedMetrics is a MetricsSource with one workload and one node measured.
type fixedMetrics struct {
	have  map[string]Sample
	nodes []Sample
}

func (f fixedMetrics) AllNodeMetrics() []Sample { return f.nodes }

func (f fixedMetrics) Metrics(ns, name string) (Sample, bool) {
	s, ok := f.have[ns+"/"+name]
	return s, ok
}

func (f fixedMetrics) AllMetrics() []Sample {
	out := make([]Sample, 0, len(f.have))
	for _, s := range f.have {
		out = append(out, s)
	}
	return out
}

// clusterListOnly authorizes exactly one thing: a cluster-wide list of applications.
type clusterListOnly struct{ allow bool }

func (c clusterListOnly) Authorize(_ context.Context, at authz.Attributes) (bool, error) {
	return c.allow && at.Verb == "list" && at.Resource == "applications" && at.Namespace == "", nil
}

func metricsServer(t *testing.T, az authz.Authorizer) *APIServer {
	t.Helper()
	sch := scheme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	srv := New(sch, service.New(store, sch, admission.DefaultChain(nil, nil)))
	srv.SetMetricsSource(fixedMetrics{nodes: []Sample{
		{Name: "node-1", Node: "node-1", CPUUsec: 900, MemoryBytes: 2 << 30, MemoryPeakBytes: 8 << 30, Received: time.Now()},
	}, have: map[string]Sample{
		"team-a/web": {
			Namespace: "team-a", Name: "web", Node: "node-1",
			CPUUsec: 1234, MemoryBytes: 5 << 20, MemoryPeakBytes: 9 << 20, PIDs: 7, OOMKills: 2,
			At: time.Unix(1700000000, 0), Received: time.Now(),
		},
	}})
	if az != nil {
		srv.SetAuthorizer(az)
	}
	return srv
}

func get(t *testing.T, srv *APIServer, path string, id *authn.Identity) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if id != nil {
		req = req.WithContext(authn.WithIdentity(req.Context(), id))
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// TestApplicationMetricsSubresource: the sample is served at the object's own subresource,
// which — now that subresources authorize as themselves — is a permission an operator can
// grant (`applications/metrics`, get) without handing over the Applications with it.
func TestApplicationMetricsSubresource(t *testing.T) {
	srv := metricsServer(t, nil)

	rec := get(t, srv, "/apis/horchestra.io/v1/namespaces/team-a/applications/web/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"memoryBytes":5242880`, `"memoryPeakBytes":9437184`, `"oomKills":2`, `"node":"node-1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s: %s", want, body)
		}
	}

	// A workload nobody has measured and one measured as idle are different facts, and only
	// one of them is a reason to go and look at the node.
	if rec := get(t, srv, "/apis/horchestra.io/v1/namespaces/team-a/applications/ghost/metrics", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unmeasured workload = %d, want 404", rec.Code)
	}
}

// TestExporterServesTheFleetsShape: /metrics is the whole fleet in one response. WHO may read
// it is a rule's nonResourceURLs, decided by the middleware before this handler runs (see the
// authz package) — the handler used to decide it itself, against a cluster-wide list permission
// standing in for a path nobody could grant directly. What is left to test here is the
// exposition.
func TestExporterServesTheFleetsShape(t *testing.T) {
	id := &authn.Identity{Name: "prometheus"}

	rec := get(t, metricsServer(t, clusterListOnly{allow: true}), "/metrics", id)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE horchestra_application_cpu_usec_total counter",
		"# TYPE horchestra_application_memory_bytes gauge",
		`horchestra_application_memory_bytes{namespace="team-a",application="web",node="node-1"} 5242880`,
		`horchestra_application_oom_kills_total{namespace="team-a",application="web",node="node-1"} 2`,
		// The machine itself, which no sum of its tenants would answer.
		"# TYPE horchestra_node_cpu_usec_total counter",
		`horchestra_node_memory_used_bytes{node="node-1"} 2147483648`,
		`horchestra_node_memory_total_bytes{node="node-1"} 8589934592`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition lacks %q:\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want the Prometheus text format", ct)
	}
}

// TestExporterWithoutASourceSaysSo: reporting an empty scrape would read as a fleet using
// nothing, which is a lie a monitoring system will act on.
func TestExporterWithoutASourceSaysSo(t *testing.T) {
	sch := scheme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	srv := New(sch, service.New(store, sch, admission.DefaultChain(nil, nil)))
	srv.SetAuthorizer(clusterListOnly{allow: true})

	if rec := get(t, srv, "/metrics", &authn.Identity{Name: "prometheus"}); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no source wired = %d, want 503", rec.Code)
	}
}
