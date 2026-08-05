package apiserver

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// The metrics API `kubectl top` speaks. Serving it is a concession to one command, and it is
// worth making because the concession was already made: this control plane presents
// Applications as Pods under /api/v1 so `kubectl logs` resolves, and a workload's usage
// answered under the same fiction costs nothing new. Inventing a private shape instead would
// mean every operator learns a second way to ask the only question they were going to ask.
//
// It is READ-ONLY and derived: nothing here is stored, and every number comes from the last
// two samples a node reported.
const (
	metricsGroup   = "metrics.k8s.io"
	metricsVersion = "v1beta1"
	metricsGV      = metricsGroup + "/" + metricsVersion
)

// RateSource is consumption per unit time, which is what `kubectl top` displays — cores, not
// cumulative microseconds. A single counter cannot answer it, so the source only has one once
// two samples exist.
type RateSource interface {
	Rate(namespace, name string) (Rate, bool)
	AllRates() map[string]Rate
	NodeRate(node string) (Rate, bool)
	AllNodeRates() map[string]Rate
}

// Rate mirrors the node transport's derived rate; see Sample for why the shape is duplicated
// rather than imported.
type Rate struct {
	MilliCores  int64
	MemoryBytes int64
	Window      time.Duration
	At          time.Time
}

// SetRateSource wires what `kubectl top` reads.
func (s *APIServer) SetRateSource(r RateSource) { s.rates = r }

// PodMetrics and NodeMetrics are the metrics.k8s.io shapes, spelled out here rather than
// pulled from k8s.io/metrics: two structs are cheaper than a dependency whose only other
// content is a client this server does not use.
type PodMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Timestamp metav1.Time        `json:"timestamp"`
	Window    metav1.Duration    `json:"window"`
	Container []ContainerMetrics `json:"containers"`
}

// ContainerMetrics names the container the usage belongs to. An Application is one process,
// so there is exactly one entry and it takes the application's own name — the same identity
// the pods alias presents.
type ContainerMetrics struct {
	Name  string                       `json:"name"`
	Usage map[string]resource.Quantity `json:"usage"`
}

type NodeMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Timestamp metav1.Time                  `json:"timestamp"`
	Window    metav1.Duration              `json:"window"`
	Usage     map[string]resource.Quantity `json:"usage"`
}

type PodMetricsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []PodMetrics `json:"items"`
}

type NodeMetricsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []NodeMetrics `json:"items"`
}

// usage renders a rate as the quantities kubectl formats: CPU in cores (millis are the
// smallest unit it prints) and memory in bytes.
func usage(r Rate) map[string]resource.Quantity {
	return map[string]resource.Quantity{
		"cpu":    *resource.NewMilliQuantity(r.MilliCores, resource.DecimalSI),
		"memory": *resource.NewQuantity(r.MemoryBytes, resource.BinarySI),
	}
}

func (s *APIServer) registerMetricsAPI() {
	s.router.GET("/apis/"+metricsGroup, s.metricsAPIGroup)
	s.router.GET("/apis/"+metricsGV, s.metricsResourceList)
	s.router.GET("/apis/"+metricsGV+"/pods", s.podMetricsList)
	s.router.GET("/apis/"+metricsGV+"/namespaces/:namespace/pods", s.podMetricsList)
	s.router.GET("/apis/"+metricsGV+"/namespaces/:namespace/pods/:name", s.podMetricsGet)
	s.router.GET("/apis/"+metricsGV+"/nodes", s.nodeMetricsList)
	s.router.GET("/apis/"+metricsGV+"/nodes/:name", s.nodeMetricsGet)
}

func (s *APIServer) metricsAPIGroup(w http.ResponseWriter, _ bunrouter.Request) error {
	gv := metav1.GroupVersionForDiscovery{GroupVersion: metricsGV, Version: metricsVersion}
	return writeJSON(w, http.StatusOK, metav1.APIGroup{
		TypeMeta:         metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroup"},
		Name:             metricsGroup,
		Versions:         []metav1.GroupVersionForDiscovery{gv},
		PreferredVersion: gv,
	})
}

func (s *APIServer) metricsResourceList(w http.ResponseWriter, _ bunrouter.Request) error {
	return writeJSON(w, http.StatusOK, metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
		GroupVersion: metricsGV,
		APIResources: []metav1.APIResource{
			{Name: "pods", Namespaced: true, Kind: "PodMetrics", Verbs: metav1.Verbs{"get", "list"}},
			{Name: "nodes", Namespaced: false, Kind: "NodeMetrics", Verbs: metav1.Verbs{"get", "list"}},
		},
	})
}

// podMetrics builds one entry. The container carries the application's own name because an
// Application is one process — there is no containers[] to disambiguate.
func podMetrics(namespace, name string, r Rate) PodMetrics {
	return PodMetrics{
		TypeMeta:   metav1.TypeMeta{APIVersion: metricsGV, Kind: "PodMetrics"},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Timestamp:  metav1.NewTime(r.At),
		Window:     metav1.Duration{Duration: r.Window},
		Container:  []ContainerMetrics{{Name: name, Usage: usage(r)}},
	}
}

func (s *APIServer) podMetricsList(w http.ResponseWriter, req bunrouter.Request) error {
	if s.rates == nil {
		return apierrors.NewServiceUnavailable("no metrics source is wired into this controller")
	}
	ns := req.Param("namespace")
	all := s.rates.AllRates()
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys) // a listing that reshuffles between calls is one nobody can diff
	out := PodMetricsList{
		TypeMeta: metav1.TypeMeta{APIVersion: metricsGV, Kind: "PodMetricsList"},
		Items:    []PodMetrics{},
	}
	for _, k := range keys {
		namespace, name, ok := strings.Cut(k, "/")
		if !ok || (ns != "" && namespace != ns) {
			continue
		}
		out.Items = append(out.Items, podMetrics(namespace, name, all[k]))
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *APIServer) podMetricsGet(w http.ResponseWriter, req bunrouter.Request) error {
	if s.rates == nil {
		return apierrors.NewServiceUnavailable("no metrics source is wired into this controller")
	}
	ns, name := req.Param("namespace"), req.Param("name")
	r, ok := s.rates.Rate(ns, name)
	if !ok {
		// Absent until two samples exist, which is also metrics-server's answer: a rate off
		// one point would mean inventing a window, and the invented one is always wrong.
		return apierrors.NewNotFound(schema.GroupResource{Group: metricsGroup, Resource: "pods"}, name)
	}
	return writeJSON(w, http.StatusOK, podMetrics(ns, name, r))
}

func nodeMetrics(name string, r Rate) NodeMetrics {
	return NodeMetrics{
		TypeMeta:   metav1.TypeMeta{APIVersion: metricsGV, Kind: "NodeMetrics"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Timestamp:  metav1.NewTime(r.At),
		Window:     metav1.Duration{Duration: r.Window},
		Usage:      usage(r),
	}
}

func (s *APIServer) nodeMetricsList(w http.ResponseWriter, _ bunrouter.Request) error {
	if s.rates == nil {
		return apierrors.NewServiceUnavailable("no metrics source is wired into this controller")
	}
	all := s.rates.AllNodeRates()
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	out := NodeMetricsList{
		TypeMeta: metav1.TypeMeta{APIVersion: metricsGV, Kind: "NodeMetricsList"},
		Items:    []NodeMetrics{},
	}
	for _, n := range names {
		out.Items = append(out.Items, nodeMetrics(n, all[n]))
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *APIServer) nodeMetricsGet(w http.ResponseWriter, req bunrouter.Request) error {
	if s.rates == nil {
		return apierrors.NewServiceUnavailable("no metrics source is wired into this controller")
	}
	name := req.Param("name")
	r, ok := s.rates.NodeRate(name)
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Group: metricsGroup, Resource: "nodes"}, name)
	}
	return writeJSON(w, http.StatusOK, nodeMetrics(name, r))
}
