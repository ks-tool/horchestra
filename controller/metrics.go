package apiserver

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// MetricsSource is the last measured consumption per workload, held by whatever received it
// — the node transport does. The apiserver only serves what it is given; it does no
// collection and keeps no history of its own.
type MetricsSource interface {
	Metrics(namespace, name string) (Sample, bool)
	AllMetrics() []Sample
	// AllNodeMetrics is what the MACHINES are consuming, which is not the sum of their
	// workloads: the system, the agent and everything else on the host are in it, and a
	// capacity is held against that total rather than against its tenants.
	AllNodeMetrics() []Sample
}

// Sample mirrors the node transport's measurement so this package does not import it — the
// dependency runs the other way, and a shared struct is cheaper than an interface per field.
type Sample struct {
	Namespace        string
	Name             string
	Node             string
	CPUUsec          int64
	CPUThrottledUsec int64
	MemoryBytes      int64
	MemoryPeakBytes  int64
	PIDs             int64
	OOMKills         int64
	At               time.Time
	Received         time.Time
}

// SetMetricsSource wires the backend that `applications/<name>/metrics` and the Prometheus
// exporter read. Without it both report that no measurement is available, rather than
// pretending a workload used nothing.
func (s *APIServer) SetMetricsSource(m MetricsSource) { s.metrics = m }

// ApplicationMetrics is what a single workload consumed, served at the application's own
// metrics subresource. The shape is deliberately not metrics.k8s.io: that API exists so
// `kubectl top` can find it, and faking a whole foreign group to borrow one command is a
// worse trade than a subresource of the object this control plane actually has — which, now
// that subresources authorize as themselves, is a permission an operator can grant on its
// own (`applications/metrics`, verb get) without handing over the Applications too.
type ApplicationMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Node is where the sample was taken; Timestamp is when, by the node's clock.
	Node      string      `json:"node,omitempty"`
	Timestamp metav1.Time `json:"timestamp,omitzero"`
	// Usage is cumulative since the workload started, so two samples give a rate over
	// whatever window the reader cares about — and one sample gives none, on purpose.
	CPUMicroseconds          int64 `json:"cpuMicroseconds"`
	CPUThrottledMicroseconds int64 `json:"cpuThrottledMicroseconds"`
	MemoryBytes              int64 `json:"memoryBytes"`
	MemoryPeakBytes          int64 `json:"memoryPeakBytes"`
	PIDs                     int64 `json:"pids"`
	OOMKills                 int64 `json:"oomKills"`
}

// registerMetrics binds the two readers of one sample: the per-application subresource and
// the Prometheus exporter.
func (s *APIServer) registerMetrics() {
	s.router.GET("/apis/"+corev1.GroupVersion.String()+"/namespaces/:namespace/applications/:name/metrics", s.applicationMetrics)
	s.router.GET("/metrics", s.prometheusMetrics)
}

func (s *APIServer) applicationMetrics(w http.ResponseWriter, req bunrouter.Request) error {
	if s.metrics == nil {
		return apierrors.NewServiceUnavailable("no metrics source is wired into this controller")
	}
	ns, name := req.Param("namespace"), req.Param("name")
	sample, ok := s.metrics.Metrics(ns, name)
	if !ok {
		// Not an empty sample: a workload nobody has measured and one measured as idle are
		// different facts, and only one of them is a reason to look at the node.
		return apierrors.NewNotFound(schema.GroupResource{Group: corev1.GroupName, Resource: "applications/metrics"}, name)
	}
	out := ApplicationMetrics{
		TypeMeta:                 metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "ApplicationMetrics"},
		ObjectMeta:               metav1.ObjectMeta{Namespace: sample.Namespace, Name: sample.Name},
		Node:                     sample.Node,
		Timestamp:                metav1.NewTime(sample.At),
		CPUMicroseconds:          sample.CPUUsec,
		CPUThrottledMicroseconds: sample.CPUThrottledUsec,
		MemoryBytes:              sample.MemoryBytes,
		MemoryPeakBytes:          sample.MemoryPeakBytes,
		PIDs:                     sample.PIDs,
		OOMKills:                 sample.OOMKills,
	}
	return writeJSON(w, http.StatusOK, out)
}

// prometheusMetrics serves every fresh sample in the text exposition format.
//
// On the CONTROLLER rather than on each node, which is the point. A node holds an outbound
// session and listens on nothing; an exporter per node would mean a port, a serving
// certificate and an authentication story on every machine in the fleet — a second trust
// relationship beside the one that already exists — to deliver numbers that are already
// arriving over the first. One scrape target here costs none of that, at the price of
// freshness bounded by the heartbeat, which for resource usage is not a price at all.
//
// It is authorized like any other path that addresses no object: a rule naming it in
// nonResourceURLs, decided by the middleware before the handler runs. It used to authorize
// ITSELF against a resource permission — cluster-wide list on applications — because the
// middleware's allowlist could not judge a path at all. That stood in for the real grant and
// could not be read off the path it guarded: a scraper denied at /metrics had to be told, out
// of band, that the fix was a permission on a different noun.
func (s *APIServer) prometheusMetrics(w http.ResponseWriter, req bunrouter.Request) error {
	if s.metrics == nil {
		return apierrors.NewServiceUnavailable("no metrics source is wired into this controller")
	}

	var b strings.Builder
	for _, m := range []struct {
		name, help, typ string
		value           func(Sample) int64
	}{
		{"horchestra_application_cpu_usec_total", "CPU time consumed by the workload, in microseconds.", "counter",
			func(s Sample) int64 { return s.CPUUsec }},
		{"horchestra_application_cpu_throttled_usec_total", "Time the workload was held back by its CPU quota, in microseconds.", "counter",
			func(s Sample) int64 { return s.CPUThrottledUsec }},
		{"horchestra_application_memory_bytes", "Current memory consumption of the workload.", "gauge",
			func(s Sample) int64 { return s.MemoryBytes }},
		{"horchestra_application_memory_peak_bytes", "High-water memory consumption since the workload started.", "gauge",
			func(s Sample) int64 { return s.MemoryPeakBytes }},
		{"horchestra_application_pids", "Processes and threads in the workload.", "gauge",
			func(s Sample) int64 { return s.PIDs }},
		{"horchestra_application_oom_kills_total", "Times the kernel OOM-killed something in the workload.", "counter",
			func(s Sample) int64 { return s.OOMKills }},
	} {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", m.name, m.help, m.name, m.typ)
		for _, sample := range s.metrics.AllMetrics() {
			fmt.Fprintf(&b, "%s{namespace=%q,application=%q,node=%q} %d\n",
				m.name, sample.Namespace, sample.Name, sample.Node, m.value(sample))
		}
	}
	// The machines themselves. Collected for `kubectl top node` and exported here too,
	// because the question a scrape asks first — is this host running out of anything — is
	// not answerable from its tenants' numbers.
	for _, m := range []struct {
		name, help, typ string
		value           func(Sample) int64
	}{
		{"horchestra_node_cpu_usec_total", "Busy CPU time across all cores of the node, in microseconds.", "counter",
			func(s Sample) int64 { return s.CPUUsec }},
		{"horchestra_node_memory_used_bytes", "Memory in use on the node (total minus available).", "gauge",
			func(s Sample) int64 { return s.MemoryBytes }},
		{"horchestra_node_memory_total_bytes", "Memory the node has.", "gauge",
			func(s Sample) int64 { return s.MemoryPeakBytes }},
	} {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", m.name, m.help, m.name, m.typ)
		for _, sample := range s.metrics.AllNodeMetrics() {
			fmt.Fprintf(&b, "%s{node=%q} %d\n", m.name, sample.Node, m.value(sample))
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
	return nil
}
