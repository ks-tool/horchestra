package nodeserver

import (
	"sort"
	"sync"
	"time"

	nodeapipb "github.com/ks-tool/horchestra/api/node"
)

// metricsRetention is how long a sample outlives the report that carried it. Past it a
// workload reads as unmeasured rather than as one using whatever it used last: a node that
// stopped reporting is exactly the case where a stale number is worse than none, because it
// looks like a healthy workload sitting still. It is also what reaps a deleted application —
// nothing reports it any more, so it ages out of the exporter on its own.
const metricsRetention = 2 * time.Minute

// Sample is one workload's measured consumption, as the node last reported it.
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
	// Received is the controller's own clock, and staleness is judged on it. The node's is
	// not trusted for the same reason its heartbeat timestamp is not: a value in the future
	// would make a sample permanently fresh.
	Received time.Time
}

// Rate is consumption per unit time, derived from two samples. `kubectl top` shows CORES,
// which a single cumulative counter cannot answer — the rate has to come from a difference,
// and Window says over what, so a reader can tell a number averaged over five seconds from
// one averaged over five minutes.
type Rate struct {
	MilliCores  int64
	MemoryBytes int64
	Window      time.Duration
	At          time.Time
}

// entry keeps the previous sample beside the current one, which is the whole reason the store
// is not a plain map of latest values: a rate needs two points, and the second one arrives a
// heartbeat after the first.
type entry struct{ prev, cur Sample }

// rate is nil until two samples exist. Reporting a rate off one point would mean inventing a
// window, and the invented one is always wrong on the first scrape after a restart.
func (e entry) rate() (Rate, bool) {
	if e.prev.At.IsZero() || !e.cur.At.After(e.prev.At) {
		return Rate{}, false
	}
	window := e.cur.At.Sub(e.prev.At)
	deltaCPU := e.cur.CPUUsec - e.prev.CPUUsec
	if deltaCPU < 0 {
		return Rate{}, false // the workload restarted: its counter began again
	}
	return Rate{
		MilliCores:  deltaCPU * 1000 / int64(window/time.Microsecond),
		MemoryBytes: e.cur.MemoryBytes,
		Window:      window,
		At:          e.cur.At,
	}, true
}

// metricsStore holds the last two samples per workload and per node, in memory only.
//
// In memory ON PURPOSE, which is the whole design decision here. These are samples of a
// moving quantity: persisting them would churn an object's resourceVersion on every
// heartbeat, wake every watcher of the Kind, and still leave no history worth querying —
// while the thing that DOES want history is a time-series database, scraping the exporter.
// metrics-server makes the same trade and says so: not for historical analysis.
type metricsStore struct {
	mu    sync.RWMutex
	now   func() time.Time
	by    map[string]entry // namespace/name
	nodes map[string]entry // node name
}

func newMetricsStore() *metricsStore {
	return &metricsStore{now: time.Now, by: map[string]entry{}, nodes: map[string]entry{}}
}

// advance slots a new sample in, keeping the one before it.
func advance(e entry, s Sample) entry {
	if !e.cur.At.IsZero() {
		e.prev = e.cur
	}
	e.cur = s
	return e
}

func (m *metricsStore) put(node string, am *nodeapipb.AppMetrics) {
	if am.GetNamespace() == "" || am.GetName() == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := am.GetNamespace() + "/" + am.GetName()
	m.by[key] = advance(m.by[key], Sample{
		Namespace: am.GetNamespace(), Name: am.GetName(), Node: node,
		CPUUsec: am.GetCpuUsec(), CPUThrottledUsec: am.GetCpuThrottledUsec(),
		MemoryBytes: am.GetMemoryBytes(), MemoryPeakBytes: am.GetMemoryPeakBytes(),
		PIDs: am.GetPids(), OOMKills: am.GetOomKills(),
		At: time.Unix(0, am.GetTimestampUnixNano()), Received: m.now(),
	})
}

// putNode records what the machine itself is consuming.
func (m *metricsStore) putNode(node string, nu *nodeapipb.NodeUsage) {
	if node == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node] = advance(m.nodes[node], Sample{
		Name: node, Node: node,
		CPUUsec: nu.GetCpuUsec(), MemoryBytes: nu.GetMemoryUsedBytes(), MemoryPeakBytes: nu.GetMemoryTotalBytes(),
		At: time.Unix(0, nu.GetTimestampUnixNano()), Received: m.now(),
	})
}

// Metrics is the last sample for one workload, if it is fresh enough to mean anything.
func (m *metricsStore) Metrics(namespace, name string) (Sample, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.by[namespace+"/"+name]
	if !ok || m.now().Sub(e.cur.Received) > metricsRetention {
		return Sample{}, false
	}
	return e.cur, true
}

// Rate is one workload's consumption per unit time; absent until two samples exist.
func (m *metricsStore) Rate(namespace, name string) (Rate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.by[namespace+"/"+name]
	if !ok || m.now().Sub(e.cur.Received) > metricsRetention {
		return Rate{}, false
	}
	return e.rate()
}

// NodeRate is the machine's own consumption per unit time.
func (m *metricsStore) NodeRate(node string) (Rate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.nodes[node]
	if !ok || m.now().Sub(e.cur.Received) > metricsRetention {
		return Rate{}, false
	}
	return e.rate()
}

// AllNodeRates is every node whose consumption is known, ordered by name.
func (m *metricsStore) AllNodeRates() map[string]Rate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]Rate{}
	for name, e := range m.nodes {
		if m.now().Sub(e.cur.Received) > metricsRetention {
			continue
		}
		if r, ok := e.rate(); ok {
			out[name] = r
		}
	}
	return out
}

// AllNodeMetrics is the latest sample per node, ordered by name.
func (m *metricsStore) AllNodeMetrics() []Sample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Sample, 0, len(m.nodes))
	for _, e := range m.nodes {
		if m.now().Sub(e.cur.Received) <= metricsRetention {
			out = append(out, e.cur)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// AllRates is every workload whose consumption is known.
func (m *metricsStore) AllRates() map[string]Rate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]Rate{}
	for key, e := range m.by {
		if m.now().Sub(e.cur.Received) > metricsRetention {
			continue
		}
		if r, ok := e.rate(); ok {
			out[key] = r
		}
	}
	return out
}

// AllMetrics is every fresh sample, ordered so the exporter's output is stable — a scrape
// that reshuffles its lines every time is a diff nobody can read.
func (m *metricsStore) AllMetrics() []Sample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Sample, 0, len(m.by))
	for _, e := range m.by {
		if m.now().Sub(e.cur.Received) <= metricsRetention {
			out = append(out, e.cur)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Metrics and AllMetrics expose the store on the Server, which is what the composition root
// hands to the apiserver.
func (s *Server) Metrics(namespace, name string) (Sample, bool) {
	return s.metrics.Metrics(namespace, name)
}
func (s *Server) AllMetrics() []Sample                     { return s.metrics.AllMetrics() }
func (s *Server) Rate(namespace, name string) (Rate, bool) { return s.metrics.Rate(namespace, name) }
func (s *Server) AllNodeMetrics() []Sample                 { return s.metrics.AllNodeMetrics() }
func (s *Server) AllRates() map[string]Rate                { return s.metrics.AllRates() }
func (s *Server) NodeRate(node string) (Rate, bool)        { return s.metrics.NodeRate(node) }
func (s *Server) AllNodeRates() map[string]Rate            { return s.metrics.AllNodeRates() }
