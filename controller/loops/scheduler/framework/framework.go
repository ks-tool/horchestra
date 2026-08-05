// Package framework is horchestra's scheduling framework, modelled on kube-scheduler:
// scheduling one Application is a pipeline of extension points — PreFilter, Filter,
// Score, Reserve, PreBind, Bind — and each point is served by pluggable plugins
// registered in a Registry and selected by a Profile. The scheduler builds a
// Framework from a profile and runs the points; the concrete predicates and priorities
// (resource fit, node schedulability, volume binding, the binder) live in plugins, so
// scheduling policy is changed by swapping plugins, not editing the engine.
//
// The full extension-point set is modelled: QueueSort orders the pending queue, then per
// app PreFilter, Filter, PostFilter (when no node is feasible), PreScore, Score, Reserve,
// Permit, PreBind, Bind and PostBind. A point with no plugin enabled is a no-op, so the
// profile enables only the handful it needs.
package framework

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// MaxNodeScore is the upper bound a Score plugin returns for a node (kube's convention).
const MaxNodeScore int64 = 100

// Code is a plugin outcome.
type Code int

const (
	// Success means the plugin approves (a Filter passes, a Bind handled the app).
	Success Code = iota
	// Unschedulable is an expected "not now" — a node is infeasible, or the app can't
	// be placed this cycle. It leaves the app pending, not an error.
	Unschedulable
	// Error is an internal failure that aborts the cycle for this app.
	Error
	// Skip is returned by a Bind plugin that does not handle the app, so the next
	// binder is tried.
	Skip
)

// Status is a plugin result. A nil *Status is Success.
type Status struct {
	code   Code
	reason string
	err    error
}

// NewStatus builds a non-success status with a human reason.
func NewStatus(code Code, reason string) *Status { return &Status{code: code, reason: reason} }

// AsError wraps err as an Error status (nil err → nil status).
func AsError(err error) *Status {
	if err == nil {
		return nil
	}
	return &Status{code: Error, err: err}
}

func (s *Status) IsSuccess() bool { return s == nil || s.code == Success }
func (s *Status) Code() Code {
	if s == nil {
		return Success
	}
	return s.code
}
func (s *Status) Message() string {
	switch {
	case s == nil:
		return ""
	case s.err != nil:
		return s.err.Error()
	default:
		return s.reason
	}
}
func (s *Status) AsError() error {
	if s == nil || s.code != Error {
		return nil
	}
	return s.err
}

// CycleState is per-Application scratch shared across the plugins of one cycle — the
// place a PreFilter plugin stashes work for its own Filter/PreBind to read back.
type CycleState struct {
	mu sync.Mutex
	m  map[string]any
}

func NewCycleState() *CycleState { return &CycleState{m: map[string]any{}} }

func (c *CycleState) Write(key string, val any) {
	c.mu.Lock()
	c.m[key] = val
	c.mu.Unlock()
}

func (c *CycleState) Read(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	return v, ok
}

// PlacedApp is an Application already assigned to a node — the facts the affinity
// plugins need: its namespace+name, its labels (matched by other apps' affinity
// selectors), and its own required anti-affinity terms (matched for symmetric
// enforcement — placing a new app must not violate an already-placed app's repulsion).
type PlacedApp struct {
	Namespace    string
	Name         string
	Labels       map[string]string
	AntiAffinity []corev1.WorkloadAffinityTerm
}

// NodeInfo is a candidate node plus the resources already requested on it this pass
// (the live allocation the resource-fit plugin filters and scores against, and the
// Reserve point debits so same-cycle placements don't overcommit) and the apps already
// placed on it (what the affinity plugins filter/score against, and their Reserve
// records so a same-cycle placement is visible to a later app).
type NodeInfo struct {
	Node      corev1.Node
	Requested corev1.ResourceAmounts
	Apps      []PlacedApp
}

// AddApp records app as placed on this node (the affinity Reserve point); RemoveApp
// drops it by namespace+name (the Unreserve rollback). Mirrors Reserve/Unreserve for
// resources, so a same-cycle placement is seen by a later app's Filter.
func (n *NodeInfo) AddApp(a PlacedApp) { n.Apps = append(n.Apps, a) }
func (n *NodeInfo) RemoveApp(namespace, name string) {
	for i := range n.Apps {
		if n.Apps[i].Namespace == namespace && n.Apps[i].Name == name {
			n.Apps = slices.Delete(n.Apps, i, i+1)
			return
		}
	}
}

// PlacedFromApp projects a placed Application into a PlacedApp (labels + its required
// anti-affinity terms), shared by the snapshot builder and the affinity Reserve point.
func PlacedFromApp(app corev1.Application) PlacedApp {
	pa := PlacedApp{Namespace: app.Namespace, Name: app.Name, Labels: app.Labels}
	if app.Spec.Placement.Affinity != nil && app.Spec.Placement.Affinity.WorkloadAntiAffinity != nil {
		pa.AntiAffinity = app.Spec.Placement.Affinity.WorkloadAntiAffinity.Required
	}
	return pa
}

// Reserve/Unreserve debit and credit the node's requested resources in place.
func (n *NodeInfo) Reserve(r corev1.ResourceAmounts) {
	n.Requested.CPU.Add(r.CPU)
	n.Requested.Memory.Add(r.Memory)
}
func (n *NodeInfo) Unreserve(r corev1.ResourceAmounts) {
	n.Requested.CPU.Sub(r.CPU)
	n.Requested.Memory.Sub(r.Memory)
}

// Snapshot is the per-pass view of the cluster's nodes, ordered by name so ties resolve
// deterministically.
type Snapshot struct {
	byName  map[string]*NodeInfo
	ordered []*NodeInfo
}

// NewSnapshot indexes and name-orders the node infos.
func NewSnapshot(infos []*NodeInfo) *Snapshot {
	slices.SortFunc(infos, func(a, b *NodeInfo) int { return strings.Compare(a.Node.Name, b.Node.Name) })
	s := &Snapshot{byName: make(map[string]*NodeInfo, len(infos)), ordered: infos}
	for _, ni := range infos {
		s.byName[ni.Node.Name] = ni
	}
	return s
}

func (s *Snapshot) List() []*NodeInfo { return s.ordered }
func (s *Snapshot) Get(name string) (*NodeInfo, bool) {
	ni, ok := s.byName[name]
	return ni, ok
}

// Domain returns the NodeInfos sharing node's topology domain: those whose scheduling
// label for topologyKey equals node's value for that key (node itself included). A
// node that lacks the key is its own singleton domain. An unknown node yields nil.
func (s *Snapshot) Domain(node, topologyKey string) []*NodeInfo {
	self, ok := s.byName[node]
	if !ok {
		return nil
	}
	want, has := self.Node.SchedulingLabel(topologyKey)
	out := []*NodeInfo{self}
	if !has {
		return out
	}
	for _, ni := range s.ordered {
		if ni.Node.Name == node {
			continue
		}
		if v, ok := ni.Node.SchedulingLabel(topologyKey); ok && v == want {
			out = append(out, ni)
		}
	}
	return out
}

// Handle is what a plugin is given at construction: read access to the per-pass node
// and volume snapshots and the scheduler clock, and the control-plane writes a plugin
// performs (implicit volume provisioning, volume co-scheduling, and the app bind). It
// is horchestra's analogue of kube-scheduler's framework.Handle (SharedLister +
// ClientSet); the writes go through the control plane so admission re-validates them.
type Handle interface {
	Snapshot() *Snapshot
	Clock() time.Time
	// PV returns the current (per-pass) view of a PersistentVolume by namespace+name.
	PV(namespace, name string) (corev1.PersistentVolume, bool)
	// CreatePV implicitly provisions a nodeless PersistentVolume of the given size in namespace.
	CreatePV(ctx context.Context, namespace, name string, size resource.Quantity) error
	// BindPV pins a PersistentVolume (addressed by namespace+name) to a node.
	BindPV(ctx context.Context, namespace, name, node string) error
	// BindApp pins an Application (addressed by namespace+name) to a node.
	BindApp(ctx context.Context, namespace, name, node string) error
}

// Plugin is the base every extension-point plugin satisfies.
type Plugin interface{ Name() string }

// QueueSortPlugin orders the pending Applications within a scheduling pass. At most one
// may be enabled (as in kube-scheduler); Less reports whether app a is attempted before b.
type QueueSortPlugin interface {
	Plugin
	Less(a, b *corev1.Application) bool
}

// PreFilterPlugin pre-processes the app (and may reject it) before node fitting.
type PreFilterPlugin interface {
	Plugin
	PreFilter(ctx context.Context, state *CycleState, app *corev1.Application) *Status
}

// FilterPlugin reports whether a node is feasible for the app.
type FilterPlugin interface {
	Plugin
	Filter(ctx context.Context, state *CycleState, app *corev1.Application, node *NodeInfo) *Status
}

// ScorePlugin ranks a feasible node in [0, MaxNodeScore]; higher is better.
type ScorePlugin interface {
	Plugin
	Score(ctx context.Context, state *CycleState, app *corev1.Application, node *NodeInfo) (int64, *Status)
}

// ReservePlugin claims (and on failure releases) resources on the chosen node.
type ReservePlugin interface {
	Plugin
	Reserve(ctx context.Context, state *CycleState, app *corev1.Application, node string) *Status
	Unreserve(ctx context.Context, state *CycleState, app *corev1.Application, node string)
}

// PreBindPlugin does work that must complete before the bind (e.g. co-scheduling volumes).
type PreBindPlugin interface {
	Plugin
	PreBind(ctx context.Context, state *CycleState, app *corev1.Application, node string) *Status
}

// BindPlugin binds the app to the node (or returns Skip to defer to the next binder).
type BindPlugin interface {
	Plugin
	Bind(ctx context.Context, state *CycleState, app *corev1.Application, node string) *Status
}

// PostFilterPlugin runs when Filter left no feasible node. It may make room (e.g.
// preemption) and nominate a node to retry on: a Success status names that node. filtered
// maps each infeasible node to why Filter rejected it. No PostFilter plugin ships (there is
// no preemption), so the point is a no-op that leaves the app pending.
type PostFilterPlugin interface {
	Plugin
	PostFilter(ctx context.Context, state *CycleState, app *corev1.Application, filtered map[string]*Status) (nominatedNode string, status *Status)
}

// PreScorePlugin pre-processes the feasible node set before Score (e.g. to precompute
// shared state a Score plugin reads from CycleState).
type PreScorePlugin interface {
	Plugin
	PreScore(ctx context.Context, state *CycleState, app *corev1.Application, nodes []*NodeInfo) *Status
}

// PermitPlugin runs after Reserve and before PreBind; it can approve or reject the
// placement (gang scheduling / quota gates). The Wait code is not modelled — a Permit
// plugin either succeeds or rejects.
type PermitPlugin interface {
	Plugin
	Permit(ctx context.Context, state *CycleState, app *corev1.Application, node string) *Status
}

// PostBindPlugin runs after a successful Bind — a notification hook (metrics, cleanup); it
// cannot fail the cycle.
type PostBindPlugin interface {
	Plugin
	PostBind(ctx context.Context, state *CycleState, app *corev1.Application, node string)
}

// PluginFactory constructs a plugin bound to a Handle.
type PluginFactory func(h Handle) (Plugin, error)

// Registry maps plugin names to their factories.
type Registry map[string]PluginFactory

// Register adds a factory (last write wins), so a caller can override a built-in.
func (r Registry) Register(name string, f PluginFactory) { r[name] = f }

// Profile selects which plugins are enabled (in order) and the weight of each Score
// plugin (default 1).
type Profile struct {
	Plugins      []string
	ScoreWeights map[string]int64
}

// Framework is a built, ready-to-run set of plugins bucketed by extension point.
type Framework struct {
	queueSort  QueueSortPlugin // at most one
	preFilter  []PreFilterPlugin
	filter     []FilterPlugin
	postFilter []PostFilterPlugin
	preScore   []PreScorePlugin
	score      []ScorePlugin
	reserve    []ReservePlugin
	permit     []PermitPlugin
	preBind    []PreBindPlugin
	bind       []BindPlugin
	postBind   []PostBindPlugin
	weights    map[string]int64
}

// New builds a Framework: it constructs each enabled plugin from the registry and files
// it under every extension point it implements.
func New(r Registry, p Profile, h Handle) (*Framework, error) {
	fw := &Framework{weights: map[string]int64{}}
	for _, name := range p.Plugins {
		factory, ok := r[name]
		if !ok {
			return nil, fmt.Errorf("framework: unknown plugin %q", name)
		}
		pl, err := factory(h)
		if err != nil {
			return nil, fmt.Errorf("framework: init plugin %q: %w", name, err)
		}
		if v, ok := pl.(QueueSortPlugin); ok {
			if fw.queueSort != nil {
				return nil, fmt.Errorf("framework: more than one QueueSort plugin enabled (%q and %q)", fw.queueSort.Name(), name)
			}
			fw.queueSort = v
		}
		if v, ok := pl.(PreFilterPlugin); ok {
			fw.preFilter = append(fw.preFilter, v)
		}
		if v, ok := pl.(FilterPlugin); ok {
			fw.filter = append(fw.filter, v)
		}
		if v, ok := pl.(PostFilterPlugin); ok {
			fw.postFilter = append(fw.postFilter, v)
		}
		if v, ok := pl.(PreScorePlugin); ok {
			fw.preScore = append(fw.preScore, v)
		}
		if v, ok := pl.(ScorePlugin); ok {
			fw.score = append(fw.score, v)
			w := int64(1)
			if pw, ok := p.ScoreWeights[name]; ok {
				w = pw
			}
			fw.weights[name] = w
		}
		if v, ok := pl.(ReservePlugin); ok {
			fw.reserve = append(fw.reserve, v)
		}
		if v, ok := pl.(PermitPlugin); ok {
			fw.permit = append(fw.permit, v)
		}
		if v, ok := pl.(PreBindPlugin); ok {
			fw.preBind = append(fw.preBind, v)
		}
		if v, ok := pl.(BindPlugin); ok {
			fw.bind = append(fw.bind, v)
		}
		if v, ok := pl.(PostBindPlugin); ok {
			fw.postBind = append(fw.postBind, v)
		}
	}
	return fw, nil
}

// Sort orders the pending apps in place with the configured QueueSort plugin (a stable
// sort, so equal apps keep their input order). With no QueueSort plugin the order is left
// unchanged.
func (fw *Framework) Sort(apps []corev1.Application) {
	if fw.queueSort == nil {
		return
	}
	slices.SortStableFunc(apps, func(a, b corev1.Application) int {
		switch {
		case fw.queueSort.Less(&a, &b):
			return -1
		case fw.queueSort.Less(&b, &a):
			return 1
		default:
			return 0
		}
	})
}

// RunPreFilter runs the PreFilter plugins; the first non-success short-circuits.
func (fw *Framework) RunPreFilter(ctx context.Context, state *CycleState, app *corev1.Application) *Status {
	for _, p := range fw.preFilter {
		if st := p.PreFilter(ctx, state, app); !st.IsSuccess() {
			return st
		}
	}
	return nil
}

// RunFilter runs the Filter plugins for one node; all must pass (AND).
func (fw *Framework) RunFilter(ctx context.Context, state *CycleState, app *corev1.Application, node *NodeInfo) *Status {
	for _, p := range fw.filter {
		if st := p.Filter(ctx, state, app, node); !st.IsSuccess() {
			return st
		}
	}
	return nil
}

// RunPostFilter runs the PostFilter plugins when no node was feasible; the first that
// succeeds (having made room) returns its nominated node. With no PostFilter plugin the
// app stays Unschedulable.
func (fw *Framework) RunPostFilter(ctx context.Context, state *CycleState, app *corev1.Application, filtered map[string]*Status) (string, *Status) {
	for _, p := range fw.postFilter {
		if node, st := p.PostFilter(ctx, state, app, filtered); st.IsSuccess() {
			return node, st
		}
	}
	return "", NewStatus(Unschedulable, "no PostFilter plugin could make room")
}

// RunPreScore runs the PreScore plugins; the first non-success short-circuits.
func (fw *Framework) RunPreScore(ctx context.Context, state *CycleState, app *corev1.Application, nodes []*NodeInfo) *Status {
	for _, p := range fw.preScore {
		if st := p.PreScore(ctx, state, app, nodes); !st.IsSuccess() {
			return st
		}
	}
	return nil
}

// RunScore scores every feasible node, summing each plugin's weighted score.
func (fw *Framework) RunScore(ctx context.Context, state *CycleState, app *corev1.Application, nodes []*NodeInfo) (map[string]int64, *Status) {
	total := make(map[string]int64, len(nodes))
	for _, ni := range nodes {
		total[ni.Node.Name] = 0
	}
	for _, p := range fw.score {
		w := fw.weights[p.Name()]
		for _, ni := range nodes {
			s, st := p.Score(ctx, state, app, ni)
			if !st.IsSuccess() {
				return nil, st
			}
			total[ni.Node.Name] += s * w
		}
	}
	return total, nil
}

// RunReserve reserves on every Reserve plugin; on the first failure it unreserves the
// ones that already succeeded and returns the failure.
func (fw *Framework) RunReserve(ctx context.Context, state *CycleState, app *corev1.Application, node string) *Status {
	for i, p := range fw.reserve {
		if st := p.Reserve(ctx, state, app, node); !st.IsSuccess() {
			for j := range i {
				fw.reserve[j].Unreserve(ctx, state, app, node)
			}
			return st
		}
	}
	return nil
}

// RunUnreserve rolls back every Reserve plugin (called when a later point fails).
func (fw *Framework) RunUnreserve(ctx context.Context, state *CycleState, app *corev1.Application, node string) {
	for _, p := range fw.reserve {
		p.Unreserve(ctx, state, app, node)
	}
}

// RunPermit runs the Permit plugins after Reserve; the first non-success short-circuits
// (the caller then unreserves). None are enabled, so it is a no-op success.
func (fw *Framework) RunPermit(ctx context.Context, state *CycleState, app *corev1.Application, node string) *Status {
	for _, p := range fw.permit {
		if st := p.Permit(ctx, state, app, node); !st.IsSuccess() {
			return st
		}
	}
	return nil
}

// RunPreBind runs the PreBind plugins; the first non-success short-circuits.
func (fw *Framework) RunPreBind(ctx context.Context, state *CycleState, app *corev1.Application, node string) *Status {
	for _, p := range fw.preBind {
		if st := p.PreBind(ctx, state, app, node); !st.IsSuccess() {
			return st
		}
	}
	return nil
}

// RunBind tries each Bind plugin in order; the first that does not Skip is authoritative.
func (fw *Framework) RunBind(ctx context.Context, state *CycleState, app *corev1.Application, node string) *Status {
	if len(fw.bind) == 0 {
		return NewStatus(Error, "no bind plugin configured")
	}
	for _, p := range fw.bind {
		st := p.Bind(ctx, state, app, node)
		if st.Code() == Skip {
			continue
		}
		return st
	}
	return NewStatus(Error, "all bind plugins skipped")
}

// RunPostBind runs the PostBind notification hooks after a successful bind; they cannot
// fail the cycle.
func (fw *Framework) RunPostBind(ctx context.Context, state *CycleState, app *corev1.Application, node string) {
	for _, p := range fw.postBind {
		p.PostBind(ctx, state, app, node)
	}
}
