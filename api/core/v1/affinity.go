package v1

// LabelDomain is reserved for the Node labels the control plane DERIVES from what a node
// reports. Keys under it are refused in spec.labels, and the derived set is recomputed on
// every heartbeat, so a placement rule reading one of them reads a measured fact about the
// machine rather than something an operator typed or a node claimed.
//
// The split is the point. spec.labels is intent an operator authors (tier=secure,
// zone=dc3); these are observation, and letting either overwrite the other would make a
// nodeAffinity match mean two different things depending on which write landed last.
const LabelDomain = "horchestra.io/"

// The derived Node labels. Each is a fact the node already reports for other reasons, so
// none of them adds a thing a node can assert that it could not assert before.
const (
	// LabelHostname is the node's own name, so per-host (anti-)affinity — topologyKey:
	// horchestra.io/hostname — works out of the box (the analog of kubernetes.io/hostname).
	// The name is the node certificate's CN, which registration has already proven.
	LabelHostname = LabelDomain + "hostname"
	// LabelOS and LabelArch are the node's platform as the Go runtime names it ("linux",
	// "amd64") — the same vocabulary an OCI image manifest selects on, which is what makes
	// them the labels an app pins its placement with when its image is not multi-arch.
	LabelOS   = LabelDomain + "os"
	LabelArch = LabelDomain + "arch"
)

// Node selector operators (a subset of Kubernetes').
const (
	NodeSelectorOpIn           = "In"
	NodeSelectorOpNotIn        = "NotIn"
	NodeSelectorOpExists       = "Exists"
	NodeSelectorOpDoesNotExist = "DoesNotExist"
)

// Affinity groups the placement constraints the scheduler honors: node affinity (which
// hosts a workload may/should run on) and workload (anti-)affinity (co-locate with /
// spread away from other Applications within a topology domain). Honored by the
// scheduler only — an author-pinned spec.nodeName skips it.
type Affinity struct {
	NodeAffinity         *NodeAffinity     `json:"nodeAffinity,omitempty"`
	WorkloadAffinity     *WorkloadAffinity `json:"workloadAffinity,omitempty"`
	WorkloadAntiAffinity *WorkloadAffinity `json:"workloadAntiAffinity,omitempty"`
}

// NodeAffinity constrains placement by Node labels. Required must match for a node to
// be feasible (a Filter predicate); Preferred only ranks feasible nodes (a Score).
type NodeAffinity struct {
	Required  *NodeSelector       `json:"requiredDuringScheduling,omitempty"`
	Preferred []PreferredNodeTerm `json:"preferredDuringScheduling,omitempty"`
}

// NodeSelector matches a Node's scheduling labels — spec.labels the operator authored plus
// the derived status.labels: every MatchLabels entry must equal and every MatchExpressions
// requirement must hold (AND across both; empty matches any).
type NodeSelector struct {
	MatchLabels      map[string]string         `json:"matchLabels,omitempty"`
	MatchExpressions []NodeSelectorRequirement `json:"matchExpressions,omitempty"`
}

// NodeSelectorRequirement is one label constraint. Operator is In, NotIn, Exists or
// DoesNotExist; Values is used by In/NotIn and must be empty for Exists/DoesNotExist.
type NodeSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator" jsonschema:"enum=In,enum=NotIn,enum=Exists,enum=DoesNotExist"`
	Values   []string `json:"values,omitempty"`
}

// PreferredNodeTerm is a soft node preference; Weight (conventionally 1..100) ranks a
// feasible node when its Preference matches.
type PreferredNodeTerm struct {
	Weight     int32        `json:"weight"`
	Preference NodeSelector `json:"preference"`
}

// WorkloadAffinity constrains placement relative to OTHER Applications in the same
// namespace, within a topology domain. Required must hold (a Filter); Preferred ranks
// (a Score). One type serves both co-location (workloadAffinity) and spreading
// (workloadAntiAffinity).
type WorkloadAffinity struct {
	Required  []WorkloadAffinityTerm         `json:"requiredDuringScheduling,omitempty"`
	Preferred []WeightedWorkloadAffinityTerm `json:"preferredDuringScheduling,omitempty"`
}

// WorkloadAffinityTerm selects peer Applications by label (same namespace ONLY — there
// is deliberately no cross-namespace selector) and a topology domain: TopologyKey is a
// Node label whose shared value defines the domain (horchestra.io/hostname = per-host).
type WorkloadAffinityTerm struct {
	LabelSelector map[string]string `json:"labelSelector,omitempty"`
	TopologyKey   string            `json:"topologyKey"`
}

// WeightedWorkloadAffinityTerm is a soft workload (anti-)affinity preference.
type WeightedWorkloadAffinityTerm struct {
	Weight int32                `json:"weight"`
	Term   WorkloadAffinityTerm `json:"term"`
}
