package plugins

import (
	"context"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// WorkloadAffinityName is the plugin's registry name.
const WorkloadAffinityName = "WorkloadAffinity"

const workloadAffinityScoresKey = "WorkloadAffinity.scores"

// WorkloadAffinity places an app relative to OTHER Applications in its own namespace,
// within a topology domain (topologyKey = a Node label whose shared value defines the
// domain). Required co-location (workloadAffinity) and required spreading
// (workloadAntiAffinity, enforced symmetrically) gate feasibility (Filter); preferred
// terms rank a feasible node (a normalized Score). Its Reserve records the placed app on
// the node so a same-cycle placement is visible to a later app's Filter (mirroring
// NodeResourcesFit's resource debit).
type WorkloadAffinity struct{ handle framework.Handle }

// NewWorkloadAffinity builds the plugin bound to the per-pass snapshot via the Handle.
func NewWorkloadAffinity(h framework.Handle) *WorkloadAffinity { return &WorkloadAffinity{handle: h} }

func (*WorkloadAffinity) Name() string { return WorkloadAffinityName }

func (p *WorkloadAffinity) Filter(_ context.Context, _ *framework.CycleState, app *corev1.Application, node *framework.NodeInfo) *framework.Status {
	snap := p.handle.Snapshot()
	aff := workloadAff(app)
	if aff.affinity != nil {
		for _, t := range aff.affinity.Required {
			if !domainHasMatch(snap, node.Node.Name, app.Namespace, t) {
				return framework.NewStatus(framework.Unschedulable, "no matching workload in the required affinity topology domain")
			}
		}
	}
	if aff.antiAffinity != nil {
		for _, t := range aff.antiAffinity.Required {
			if domainHasMatch(snap, node.Node.Name, app.Namespace, t) {
				return framework.NewStatus(framework.Unschedulable, "a workload the app repels is already in the topology domain")
			}
		}
	}
	// Symmetry: placing app here must not violate an already-placed app's anti-affinity.
	// Domain membership uses the same notion as the forward path (Snapshot.Domain): a node
	// lacking the topologyKey is its own singleton domain, so same-node repulsion still holds.
	for _, ni := range snap.List() {
		for _, placed := range ni.Apps {
			if placed.Namespace != app.Namespace {
				continue
			}
			for _, t := range placed.AntiAffinity {
				if subsetMatch(t.LabelSelector, app.Labels) && nodeInDomain(snap, node.Node.Name, ni.Node.Name, t.TopologyKey) {
					return framework.NewStatus(framework.Unschedulable, "placement would violate an already-placed workload's anti-affinity")
				}
			}
		}
	}
	return nil
}

func (p *WorkloadAffinity) PreScore(_ context.Context, state *framework.CycleState, app *corev1.Application, nodes []*framework.NodeInfo) *framework.Status {
	aff := workloadAff(app)
	affPreferred := aff.affinity != nil && len(aff.affinity.Preferred) > 0
	antiPreferred := aff.antiAffinity != nil && len(aff.antiAffinity.Preferred) > 0
	if !affPreferred && !antiPreferred {
		return nil
	}
	snap := p.handle.Snapshot()
	raw := make(map[string]int64, len(nodes))
	for _, ni := range nodes {
		var s int64
		if affPreferred {
			for _, w := range aff.affinity.Preferred {
				if domainHasMatch(snap, ni.Node.Name, app.Namespace, w.Term) {
					s += int64(w.Weight)
				}
			}
		}
		if antiPreferred {
			for _, w := range aff.antiAffinity.Preferred {
				if domainHasMatch(snap, ni.Node.Name, app.Namespace, w.Term) {
					s -= int64(w.Weight)
				}
			}
		}
		raw[ni.Node.Name] = s
	}
	state.Write(workloadAffinityScoresKey, normalize(raw))
	return nil
}

func (p *WorkloadAffinity) Score(_ context.Context, state *framework.CycleState, _ *corev1.Application, node *framework.NodeInfo) (int64, *framework.Status) {
	return scoreFromState(state, workloadAffinityScoresKey, node.Node.Name), nil
}

func (p *WorkloadAffinity) Reserve(_ context.Context, _ *framework.CycleState, app *corev1.Application, node string) *framework.Status {
	if ni, ok := p.handle.Snapshot().Get(node); ok {
		ni.AddApp(framework.PlacedFromApp(*app))
	}
	return nil
}

func (p *WorkloadAffinity) Unreserve(_ context.Context, _ *framework.CycleState, app *corev1.Application, node string) {
	if ni, ok := p.handle.Snapshot().Get(node); ok {
		ni.RemoveApp(app.Namespace, app.Name)
	}
}

// domainHasMatch reports whether any app in node's topology domain and the given
// namespace matches the term's label selector.
func domainHasMatch(snap *framework.Snapshot, node, namespace string, t corev1.WorkloadAffinityTerm) bool {
	for _, ni := range snap.Domain(node, t.TopologyKey) {
		for _, a := range ni.Apps {
			if a.Namespace == namespace && subsetMatch(t.LabelSelector, a.Labels) {
				return true
			}
		}
	}
	return false
}

// nodeInDomain reports whether candidate node shares domainOf's topology domain for
// topologyKey — the same domain notion as domainHasMatch, so the two anti-affinity
// directions agree (a keyless node is its own singleton domain).
func nodeInDomain(snap *framework.Snapshot, node, domainOf, topologyKey string) bool {
	for _, ni := range snap.Domain(domainOf, topologyKey) {
		if ni.Node.Name == node {
			return true
		}
	}
	return false
}

type workloadAffinities struct {
	affinity     *corev1.WorkloadAffinity
	antiAffinity *corev1.WorkloadAffinity
}

func workloadAff(app *corev1.Application) workloadAffinities {
	if app.Spec.Placement.Affinity == nil {
		return workloadAffinities{}
	}
	return workloadAffinities{app.Spec.Placement.Affinity.WorkloadAffinity, app.Spec.Placement.Affinity.WorkloadAntiAffinity}
}
