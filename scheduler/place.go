package scheduler

import (
	"sort"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// pending returns the Applications with no assigned node, oldest first (then by
// name) so scheduling order is stable.
func pending(apps []corev1.Application) []corev1.Application {
	var out []corev1.Application
	for _, a := range apps {
		if a.Spec.NodeName == "" {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := out[i].CreationTimestamp.Time, out[j].CreationTimestamp.Time
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

type nodeFit struct {
	name        string
	capacity    corev1.ResourceAmounts
	allocated   corev1.ResourceAmounts
	schedulable bool
}

type fitState struct {
	nodes  []*nodeFit
	byName map[string]*nodeFit
}

// newFitState builds the per-node capacity/allocation view. Allocation is computed
// live from the sum of the effective requests of the Applications already assigned
// to each node — never the agent-reported Node.Status.Allocated, which lags.
func newFitState(nodes []corev1.Node, apps []corev1.Application, now time.Time, readyTimeout time.Duration) *fitState {
	alloc := map[string]corev1.ResourceAmounts{}
	for _, a := range apps {
		if a.Spec.NodeName == "" {
			continue
		}
		alloc[a.Spec.NodeName] = alloc[a.Spec.NodeName].Add(a.Spec.Resources.EffectiveRequests())
	}
	fs := &fitState{byName: make(map[string]*nodeFit, len(nodes))}
	for _, n := range nodes {
		nf := &nodeFit{
			name:        n.Name,
			capacity:    n.Status.Capacity,
			allocated:   alloc[n.Name],
			schedulable: schedulable(n, now, readyTimeout),
		}
		fs.nodes = append(fs.nodes, nf)
		fs.byName[n.Name] = nf
	}
	sort.Slice(fs.nodes, func(i, j int) bool { return fs.nodes[i].name < fs.nodes[j].name })
	return fs
}

// schedulable reports whether a node can take new work: not cordoned, self-reported
// Ready with a fresh heartbeat, and reporting a capacity in both dimensions (a zero
// capacity is a node that has not measured itself yet — placing there would
// over-commit blindly).
func schedulable(n corev1.Node, now time.Time, readyTimeout time.Duration) bool {
	if n.Spec.Unschedulable {
		return false
	}
	if !n.Status.Ready {
		return false
	}
	if n.Status.Capacity.CPU.IsZero() || n.Status.Capacity.Memory.IsZero() {
		return false
	}
	hb := n.Status.Heartbeat.Time
	return !hb.IsZero() && now.Sub(hb) <= readyTimeout
}

// choose picks the best node the app fits on under the policy, or false if none.
// Nodes are visited in name order, so ties resolve deterministically.
func (f *fitState) choose(app corev1.Application, policy Policy) (string, bool) {
	req := app.Spec.Resources.EffectiveRequests()
	best := ""
	var bestScore float64
	for _, n := range f.nodes {
		if !n.schedulable || !fits(n.capacity, n.allocated, req) {
			continue
		}
		score := dominant(n.capacity, n.allocated.Add(req))
		if best == "" || preferred(policy, score, bestScore) {
			best, bestScore = n.name, score
		}
	}
	return best, best != ""
}

// place debits a node's allocation by an app's requests, so the next placement in
// the same pass accounts for the room already taken.
func (f *fitState) place(node string, app corev1.Application) {
	if n := f.byName[node]; n != nil {
		n.allocated = n.allocated.Add(app.Spec.Resources.EffectiveRequests())
	}
}

// fits reports whether req still fits in capacity given the current allocation.
func fits(capacity, allocated, req corev1.ResourceAmounts) bool {
	after := allocated.Add(req)
	return after.CPU.Cmp(capacity.CPU) <= 0 && after.Memory.Cmp(capacity.Memory) <= 0
}

// dominant is a node's dominant resource utilization — the max of its per-resource
// used/capacity ratios — the scalar the policy optimizes. Capacity is non-zero in
// both dimensions here (schedulable already excluded zero-capacity nodes).
func dominant(capacity, used corev1.ResourceAmounts) float64 {
	cpu := float64(used.CPU.MilliValue()) / float64(capacity.CPU.MilliValue())
	mem := float64(used.Memory.Value()) / float64(capacity.Memory.Value())
	if cpu > mem {
		return cpu
	}
	return mem
}

// preferred reports whether score a beats the incumbent b under the policy: spread
// minimizes resulting utilization (balance), binpack maximizes it (pack).
func preferred(policy Policy, a, b float64) bool {
	if policy == Binpack {
		return a > b
	}
	return a < b
}
