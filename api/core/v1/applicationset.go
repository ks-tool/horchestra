package v1

import (
	"maps"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ApplicationSet is a bundle: an explicit list of named Applications created, updated and
// deleted as one unit, plus a typed nodeSpread mode (one child per matching Node = a
// DaemonSet). It fully owns its children's lifecycle (drift on a child is reverted); an
// Application also stays a first-class, directly-authorable Kind. The reconcile lives in
// controller/loops/appset. (§0/L3 — supersedes the withdrawn Argo generators/templates.)

// Reserved labels stamped on every child — the fast List selector. The AUTHORITY for
// ownership is the child's controller ownerReference, not these labels (a bare Application
// could set a label; it cannot forge the controller ownerReference the appset stamps).
const (
	LabelApplicationSet = "horchestra.io/application-set"

	// AnnAppsetSpecHash records the digest of the spec the ApplicationSet controller rendered
	// for a child. The controller compares THIS, not the spec itself, to decide whether a child
	// needs rewriting: the stored spec has been through admission (defaulted securityContext and
	// the rest) while the freshly rendered one has not, so comparing specs directly never agrees
	// and the controller rewrites every child on every pass. The annotation round-trips through
	// admission untouched, so a converged set produces no writes at all.
	AnnAppsetSpecHash = "horchestra.io/appset-spec-hash"
	LabelComponent    = "horchestra.io/component"
)

// AppsetOwner returns the controller ownerReference naming the ApplicationSet that owns app, or
// nil when app is not a set's child. It is the ONE definition of appset ownership: the loop's
// adoption/GC guard and the admission rule that keeps the reference controller-owned must not be
// able to disagree about what "owned" means. APIVersion is part of the match, so a reference to
// some other group's ApplicationSet kind is not ownership.
func AppsetOwner(app *Application) *metav1.OwnerReference {
	return AppsetOwnerOf(app.OwnerReferences)
}

// AppsetOwnerOf is the same question asked of any object's references — a set owns the Services it
// renders as well as its children, and one definition of ownership has to answer for both.
func AppsetOwnerOf(refs []metav1.OwnerReference) *metav1.OwnerReference {
	if i := appsetOwnerIndex(refs); i >= 0 {
		return &refs[i]
	}
	return nil
}

// appsetOwnerIndex is where that definition actually lives, so recognising ownership and giving
// it up cannot drift apart.
func appsetOwnerIndex(refs []metav1.OwnerReference) int {
	for i := range refs {
		if r := &refs[i]; r.Kind == "ApplicationSet" &&
			r.APIVersion == GroupVersion.String() && r.Controller != nil && *r.Controller {
			return i
		}
	}
	return -1
}

// ReservedChildLabels are the labels an ApplicationSet stamps on the children it renders. They
// are not the ownership authority — the controller ownerReference is — but they are reserved
// from clients all the same, so nothing can be made to LOOK like a set's child.
//
// A function rather than a package-level slice: a caller cannot append to the list every other
// caller reads.
func ReservedChildLabels() []string { return []string{LabelApplicationSet, LabelComponent} }

// ReleaseAppsetChild strips every mark a set leaves on a child — the controller ownerReference,
// the reserved labels and the render digest — leaving an object no set claims.
//
// All of it, not just the ownerReference. The reference alone decides ownership, so dropping it
// is enough to make the child survive; but the marks that stay behind are reserved to the
// controller, which means the released object could not be created from its own manifest, and
// they would go on naming a set that no longer exists. A released child is a hand-authored
// Application in every respect or it is not released.
//
// The maps are cloned before the deletes: the caller's copy of the object shares them with the
// list it was read from, and a release must not reach backwards into that.
func ReleaseAppsetChild(app *Application) { ReleaseAppsetMeta(&app.ObjectMeta) }

// ReleaseAppsetMeta is that stripping applied to any object a set rendered — a child, or one of
// the Services beside them. A handover that let go of the workloads and kept the name they
// register under would leave a directory nobody owns and no manifest could recreate.
func ReleaseAppsetMeta(meta *metav1.ObjectMeta) {
	if i := appsetOwnerIndex(meta.OwnerReferences); i >= 0 {
		meta.OwnerReferences = slices.Delete(slices.Clone(meta.OwnerReferences), i, i+1)
	}
	meta.Labels = maps.Clone(meta.Labels)
	for _, key := range ReservedChildLabels() {
		delete(meta.Labels, key)
	}
	meta.Annotations = maps.Clone(meta.Annotations)
	delete(meta.Annotations, AnnAppsetSpecHash)
}

// FinalizerChildTeardown holds an ApplicationSet's object until its children are gone. It is the
// cascade half of the node-teardown hold: without it a set was erased FIRST and its children were
// reaped by a later sweep keyed on the missing owner, so between those two moments the children
// were orphans — running, with nothing pointing at them — and if the loop was down in between,
// they stayed that way. With it the set outlives its own delete, and an operator watching one go
// sees what is left.
const FinalizerChildTeardown = "horchestra.io/child-teardown"

// Deleting reports whether this set has been asked to go and is waiting on its children.
func (s ApplicationSet) Deleting() bool { return s.DeletionTimestamp != nil }

// ApplicationSet declares a bundle of component Applications.
type ApplicationSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   ApplicationSetSpec   `json:"spec"`
	Status ApplicationSetStatus `json:"status"`
}

// ApplicationSetSpec is the bundle: an explicit list of named component Applications plus
// shared config projected onto every child.
type ApplicationSetSpec struct {
	Applications []NamedApplicationSpec `json:"applications"`
	Common       CommonMeta             `json:"common,omitzero"`
	// Placement and Rollout are the set's own traits, in the same two sections a component
	// carries: where the children go, and how they get there. They differ from a component's
	// only in what they can say — a set's placement is a RELATION between children, which no
	// single one of them could state about itself.
	Placement SetPlacement `json:"placement,omitzero"`
	Rollout   Rollout      `json:"rollout,omitzero"`
}

// Placement modes for a set's children.
const (
	// PlacementSameNode co-locates every child of the set on one node: the first child
	// (by name) is the anchor the scheduler places freely, and the rest are created
	// pinned to the node it landed on. The set therefore creates the anchor FIRST and the
	// siblings only once it is placed — pinning after the fact would mean moving a running
	// workload. A sibling that does not fit is refused by the capacity admission like any
	// other pinned app, which is the known capacity race (its real fix is gang scheduling).
	PlacementSameNode = "sameNode"
)

// SetPlacement constrains where the set's children run relative to each other. It is a
// separate type from a component's Placement rather than a superset of it because the two
// answer different questions: a component says which nodes suit IT, a set says how its
// children stand to one another, and a field that meant one thing at one level and another
// at the next would be the sort of thing nobody could read off a manifest.
type SetPlacement struct {
	// Mode is empty (each child placed independently) or PlacementSameNode.
	Mode string `json:"mode,omitempty"`
}

// Rollout is how the set converges its children to a changed spec, as opposed to what it
// converges them to: how much may be disrupted at once, and whether a child the set no longer
// renders is deleted.
//
// What happens to the children when the SET is deleted is deliberately NOT here: that is a fact
// about one removal rather than about the set, so it rides on the delete request
// (`kubectl delete --cascade=orphan`) where the person deciding it is the person deleting.
type Rollout struct {
	// MaxUnavailable caps how many children may be un-Running simultaneously while the set
	// rolls a change. Updates are applied to at most that many children per pass and resume
	// only as the updated ones report Running again, so a broken version stalls the rollout
	// instead of reaching every child. It bounds UPDATES only: creating a child that does
	// not exist yet and pruning one the set no longer renders are not disruptions of a
	// running workload. Unset (or 0) converges every changed child at once.
	MaxUnavailable int32 `json:"maxUnavailable,omitempty"`
	// Prune deletes children the set no longer lists. Default true. It belongs here rather
	// than in a policy block of its own because it is the same question the rest of this
	// section answers — what the set is allowed to do to a running child to reach the spec.
	Prune *bool `json:"prune,omitempty"`
}

// SameNode reports whether the set co-locates its children.
func (s ApplicationSetSpec) SameNode() bool { return s.Placement.Mode == PlacementSameNode }

// RolloutBudget is the effective maxUnavailable: 0 means unlimited (converge everything at
// once), which is also the behaviour when no rollout is declared.
func (s ApplicationSetSpec) RolloutBudget() int {
	if s.Rollout.MaxUnavailable < 0 {
		return 0
	}
	return int(s.Rollout.MaxUnavailable)
}

// NamedApplicationSpec is one component of the bundle: a name, an optional per-child
// metadata overlay, a typed ApplicationSpec, and the scale trait — at most one fan-out mode.
type NamedApplicationSpec struct {
	Name     string          `json:"name"`
	Metadata ChildMeta       `json:"metadata,omitzero"`
	Spec     ApplicationSpec `json:"spec"`
	// Scale is how many of this component the set renders. It sits on the component and not
	// inside its spec because it is the one trait an Application cannot carry: a spec
	// describes one workload, and there is no count of itself to put in it.
	Scale Scale `json:"scale,omitzero"`
}

// Scale fans a component out — into N identical children (Replicas) or one child per matching
// Node (NodeSpread). At most one mode; neither is a fan-out of one.
type Scale struct {
	// Replicas fans the component out into N children named <set>-<component>-<i>, i in
	// [0,N). The ONLY per-child variation is the index — there is no templating, so every
	// replica carries a byte-identical spec and the scheduler places each independently.
	//
	// Setting it (even to 1) switches the component to indexed names, so toggling it on or
	// off RENAMES the children: the old names are pruned and the new ones created. That
	// matters for storage — a pv volume with no name is provisioned per child from the
	// child's name, so each replica gets its own volume (and a rename abandons the old
	// one, keeping its data). A pv volume WITH a name is one shared volume, which is why
	// admission refuses that combination for replicas > 1.
	Replicas   *int32      `json:"replicas,omitempty"`
	NodeSpread *NodeSpread `json:"nodeSpread,omitempty"`
}

// NodeSpread turns a component into a DaemonSet: one child per Node whose spec.labels
// match NodeSelector (empty = every Node), with spec.nodeName injected. The ONLY per-node
// variation is the node identity — no templating. A nodeSpread component must leave
// spec.nodeName empty (the set assigns it and owns placement).
type NodeSpread struct {
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// ChildMeta is an optional per-child metadata overlay (merged over common; child wins).
type ChildMeta struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// CommonMeta is projected into every child: labels/annotations merged (child wins), env
// appended UNDER the child's own env (a child var with the same Name wins — config only, no
// secrets), and volumes appended deduplicated by mountPath (the child's own mount at a path wins).
type CommonMeta struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Env         []EnvVar          `json:"env,omitempty"`
	Volumes     []VolumeMount     `json:"volumes,omitempty"`
}

// Prune reports the effective prune policy (default true).
func (s ApplicationSetSpec) Prune() bool { return s.Rollout.Prune == nil || *s.Rollout.Prune }

// ApplicationSet rollup phases. A holding phase is the reason of the condition that holds
// the set, so Phase never invents a state the conditions do not already describe.
const (
	AppSetPhaseReady       = "Ready"       // every rendered child exists and is running
	AppSetPhaseProgressing = "Progressing" // converging: children missing or not yet running
	// AppSetPhaseTerminating is a set whose object has been deleted and whose children are
	// still going. It is the set-level twin of an Application's Terminating, and it exists
	// for the same reason: the gap between "deleted" and "gone" is where an operator looks.
	AppSetPhaseTerminating = "Terminating"
)

// ApplicationSetStatus is the observed rollup, written through the status subresource.
type ApplicationSetStatus struct {
	// Phase is the one-word rollup an operator reads first. It is not a second vocabulary:
	// when something holds the set back it IS that condition's reason (RenderError,
	// AwaitingAnchor, RolloutHeld), so the summary and the detail can never disagree;
	// otherwise Ready when every rendered child exists and runs, else Progressing.
	Phase                   string        `json:"phase,omitempty"`
	ObservedResourceVersion string        `json:"observedResourceVersion,omitempty"`
	Desired                 int           `json:"desired"`
	Current                 int           `json:"current"`
	Scheduled               int           `json:"scheduled"`
	Running                 int           `json:"running"`
	Children                []ChildStatus `json:"children,omitempty"`
	Conditions              []Condition   `json:"conditions,omitempty"`
}

// ChildStatus is one child's observed placement and phase.
type ChildStatus struct {
	Name  string `json:"name"`
	Node  string `json:"node,omitempty"`
	Phase string `json:"phase,omitempty"`
}

// Condition is a status condition (e.g. a render or name-conflict error).
type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// ApplicationSetList is a list of ApplicationSets.
type ApplicationSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ApplicationSet `json:"items"`
}
