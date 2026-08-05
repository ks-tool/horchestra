package agent

import "testing"

// TestSameHost pins the comparison: exact, or the same first label (a short hostname against an
// FQDN, in either direction), case-insensitively.
func TestSameHost(t *testing.T) {
	yes := [][2]string{
		{"node-1", "node-1"},
		{"NODE-1", "node-1"},
		{"node-1", "node-1.internal"},
		{"node-1.internal", "node-1"},
		{"node-1.a.example", "node-1.b.example"},
	}
	for _, p := range yes {
		if !sameHost(p[0], p[1]) {
			t.Errorf("sameHost(%q, %q) = false, want true", p[0], p[1])
		}
	}
	no := [][2]string{
		{"node-1", "node-2"},
		{"node-1", "node-11"},
		{"node-1", ""},
	}
	for _, p := range no {
		if sameHost(p[0], p[1]) {
			t.Errorf("sameHost(%q, %q) = true, want false", p[0], p[1])
		}
	}
}
