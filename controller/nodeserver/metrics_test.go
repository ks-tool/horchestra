package nodeserver

import (
	"testing"
	"time"

	nodeapipb "github.com/ks-tool/horchestra/api/node"
)

func sampleMsg(ns, name string, mem int64) *nodeapipb.AppMetrics {
	return &nodeapipb.AppMetrics{
		Namespace: ns, Name: name, MemoryBytes: mem, CpuUsec: 42,
		TimestampUnixNano: time.Now().UnixNano(),
	}
}

// TestSamplesGoStaleRatherThanLinger: a node that stops reporting is exactly the case where
// the last number is worse than none — a workload frozen at whatever it used last looks
// healthy and idle, which is the opposite of what happened. It is also what reaps a deleted
// application, since nothing reports it any more.
func TestSamplesGoStaleRatherThanLinger(t *testing.T) {
	m := newMetricsStore()
	base := time.Now()
	m.now = func() time.Time { return base }
	m.put("node-1", sampleMsg("team", "web", 1<<20))

	if s, ok := m.Metrics("team", "web"); !ok || s.MemoryBytes != 1<<20 || s.Node != "node-1" {
		t.Fatalf("fresh sample = %+v, %v", s, ok)
	}
	if len(m.AllMetrics()) != 1 {
		t.Fatal("a fresh sample must appear in the fleet view")
	}

	m.now = func() time.Time { return base.Add(metricsRetention + time.Second) }
	if _, ok := m.Metrics("team", "web"); ok {
		t.Error("a sample past its retention must read as unmeasured, not as idle")
	}
	if len(m.AllMetrics()) != 0 {
		t.Error("a stale sample is still being exported")
	}
}

// TestFleetViewIsOrdered: an exporter whose lines reshuffle between scrapes produces a diff
// nobody can read, and map iteration would do exactly that.
func TestFleetViewIsOrdered(t *testing.T) {
	m := newMetricsStore()
	m.put("node-1", sampleMsg("team-b", "web", 1))
	m.put("node-1", sampleMsg("team-a", "zebra", 1))
	m.put("node-2", sampleMsg("team-a", "alpha", 1))

	for range 8 {
		got := m.AllMetrics()
		if len(got) != 3 {
			t.Fatalf("got %d samples", len(got))
		}
		if got[0].Name != "alpha" || got[1].Name != "zebra" || got[2].Name != "web" {
			t.Fatalf("order = %s/%s %s/%s %s/%s",
				got[0].Namespace, got[0].Name, got[1].Namespace, got[1].Name, got[2].Namespace, got[2].Name)
		}
	}
}

// TestUnnamedSampleIsDropped: a message with no workload behind it would occupy a cache slot
// keyed on "/" and show up in the exporter as a metric for nothing.
func TestUnnamedSampleIsDropped(t *testing.T) {
	m := newMetricsStore()
	m.put("node-1", &nodeapipb.AppMetrics{MemoryBytes: 5})
	m.put("node-1", &nodeapipb.AppMetrics{Namespace: "team", MemoryBytes: 5})
	if got := len(m.AllMetrics()); got != 0 {
		t.Errorf("%d nameless samples were kept", got)
	}
}
