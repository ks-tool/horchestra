package plugins

import (
	"context"
	"slices"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// NodeAffinityName is the plugin's registry name.
const NodeAffinityName = "NodeAffinity"

const nodeAffinityScoresKey = "NodeAffinity.scores"

// NodeAffinity filters and scores nodes by their scheduling labels against the app's
// spec.nodeSelector (sugar) and spec.affinity.nodeAffinity: required terms gate
// feasibility (Filter), preferred terms rank a feasible node (a normalized Score).
type NodeAffinity struct{}

// NewNodeAffinity builds the plugin (stateless).
func NewNodeAffinity() *NodeAffinity { return &NodeAffinity{} }

func (*NodeAffinity) Name() string { return NodeAffinityName }

func (*NodeAffinity) Filter(_ context.Context, _ *framework.CycleState, app *corev1.Application, node *framework.NodeInfo) *framework.Status {
	labels := node.Node.SchedulingLabels()
	if !subsetMatch(app.Spec.Placement.NodeSelector, labels) {
		return framework.NewStatus(framework.Unschedulable, "node labels do not match spec.nodeSelector")
	}
	if na := nodeAffinity(app); na != nil && na.Required != nil && !nodeSelectorMatches(*na.Required, labels) {
		return framework.NewStatus(framework.Unschedulable, "node labels do not match required nodeAffinity")
	}
	return nil
}

func (*NodeAffinity) PreScore(_ context.Context, state *framework.CycleState, app *corev1.Application, nodes []*framework.NodeInfo) *framework.Status {
	na := nodeAffinity(app)
	if na == nil || len(na.Preferred) == 0 {
		return nil
	}
	raw := make(map[string]int64, len(nodes))
	for _, ni := range nodes {
		var s int64
		for _, t := range na.Preferred {
			if nodeSelectorMatches(t.Preference, ni.Node.SchedulingLabels()) {
				s += int64(t.Weight)
			}
		}
		raw[ni.Node.Name] = s
	}
	state.Write(nodeAffinityScoresKey, normalize(raw))
	return nil
}

func (*NodeAffinity) Score(_ context.Context, state *framework.CycleState, _ *corev1.Application, node *framework.NodeInfo) (int64, *framework.Status) {
	return scoreFromState(state, nodeAffinityScoresKey, node.Node.Name), nil
}

func nodeAffinity(app *corev1.Application) *corev1.NodeAffinity {
	if app.Spec.Placement.Affinity == nil {
		return nil
	}
	return app.Spec.Placement.Affinity.NodeAffinity
}

// --- shared affinity helpers (used by NodeAffinity + WorkloadAffinity) ---

// subsetMatch reports whether every selector entry equals have's; an empty selector
// matches anything.
func subsetMatch(selector, have map[string]string) bool {
	for k, v := range selector {
		if have[k] != v {
			return false
		}
	}
	return true
}

// nodeSelectorMatches reports whether have satisfies every MatchLabels entry AND every
// MatchExpressions requirement. An unknown operator never matches (fail-closed).
func nodeSelectorMatches(sel corev1.NodeSelector, have map[string]string) bool {
	if !subsetMatch(sel.MatchLabels, have) {
		return false
	}
	for _, r := range sel.MatchExpressions {
		v, ok := have[r.Key]
		switch r.Operator {
		case corev1.NodeSelectorOpIn:
			if !ok || !slices.Contains(r.Values, v) {
				return false
			}
		case corev1.NodeSelectorOpNotIn:
			if ok && slices.Contains(r.Values, v) {
				return false
			}
		case corev1.NodeSelectorOpExists:
			if !ok {
				return false
			}
		case corev1.NodeSelectorOpDoesNotExist:
			if ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// normalize maps raw per-node scores linearly onto [0, MaxNodeScore]; all-equal yields
// all-zero (no differentiation between nodes).
func normalize(raw map[string]int64) map[string]int64 {
	if len(raw) == 0 {
		return raw
	}
	var lo, hi int64
	first := true
	for _, v := range raw {
		if first {
			lo, hi, first = v, v, false
			continue
		}
		lo, hi = min(lo, v), max(hi, v)
	}
	out := make(map[string]int64, len(raw))
	if hi == lo {
		return out
	}
	for k, v := range raw {
		out[k] = (v - lo) * framework.MaxNodeScore / (hi - lo)
	}
	return out
}

// scoreFromState reads a normalized per-node score a PreScore pass stashed (0 if none).
func scoreFromState(state *framework.CycleState, key, node string) int64 {
	v, ok := state.Read(key)
	if !ok {
		return 0
	}
	m, ok := v.(map[string]int64)
	if !ok {
		return 0
	}
	return m[node]
}
