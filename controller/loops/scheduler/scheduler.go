// Package scheduler assigns a node to each Application that has no spec.nodeName and
// co-schedules its storage. It is built on a kube-scheduler-style plugin framework
// (see ./framework and ./plugins): scheduling one app runs a pipeline of extension
// points — PreFilter, Filter, Score, Reserve, PreBind, Bind — served by pluggable
// plugins selected in a profile. The built-in profile is NodeSchedulable +
// NodeResourcesFit + VolumeBinding + DefaultBinder; a deployment can register more
// plugins or drop one without touching the engine.
//
// It also owns storage placement. A pv volume declared inline on an Application is
// materialized on demand by the VolumeBinding plugin: if no matching PersistentVolume
// exists, one is created (implicit provisioning), then pinned to the node the app lands
// on; a PersistentVolume already backed by a node constrains its app to run there. So a
// stateful app can be authored with neither the app's nodeName nor a separate
// PersistentVolume — the scheduler creates and places both.
//
// It is level-driven: it re-lists Applications, Nodes and PersistentVolumes on every
// change and on a resync timer, so a lossy watch or a missed event self-corrects. Every
// placement is written back THROUGH the control plane (Cluster.Assign / AssignVolume /
// CreateVolume), so admission re-validates it — a node that filled up between the
// decision and the write is rejected and the app stays pending for the next cycle.
//
// It is the ONLY scheduler: there is no spec.schedulerName and no multi-scheduler model, so
// every Application with no nodeName is this loop's to place, and an author who pins one takes
// it out of scheduling entirely. Node capacity counts every placed app either way — pinned or
// scheduled — since what a node is running does not depend on who decided it (see buildSnapshot).
package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"k8s.io/apimachinery/pkg/api/resource"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"
	"github.com/ks-tool/horchestra/controller/loops/scheduler/plugins"
)

// Cluster is the control-plane access the scheduler needs.
type Cluster interface {
	// Applications, Nodes and Volumes return the current objects.
	Applications(ctx context.Context) ([]corev1.Application, error)
	Nodes(ctx context.Context) ([]corev1.Node, error)
	Volumes(ctx context.Context) ([]corev1.PersistentVolume, error)
	// Assign pins app to node by setting spec.nodeName THROUGH the control plane,
	// so admission (capacity, node-exists) re-validates the placement. An error
	// (e.g. the node filled up) leaves the app pending for the next cycle.
	Assign(ctx context.Context, namespace, app, node string) error
	// AssignVolume pins a PersistentVolume (in namespace) to a node by setting spec.node
	// THROUGH the control plane. Used to co-schedule a nodeless volume onto the node its
	// Application runs on.
	AssignVolume(ctx context.Context, namespace, pv, node string) error
	// CreateVolume implicitly creates a nodeless PersistentVolume with the given name and
	// size in namespace THROUGH the control plane, when an Application declares a pv volume
	// inline and no matching PersistentVolume exists yet.
	CreateVolume(ctx context.Context, namespace, name string, size resource.Quantity) error
	// UpdateAppStatus writes an Application's status THROUGH the status subresource, which is
	// what lets the scheduler say why it could not place a workload without bumping the
	// generation every spec-watcher gates on.
	UpdateAppStatus(ctx context.Context, app *corev1.Application) error
}

// Policy is how a node is chosen among those an Application fits.
type Policy string

const (
	// Spread (the default) balances load: the node left least utilized wins.
	Spread Policy = "spread"
	// Binpack packs tight: the node left most utilized that still fits wins.
	Binpack Policy = "binpack"
)

// Config tunes a Scheduler; the zero value is usable (Spread, 30s resync, 45s
// node-ready timeout, no logging).
type Config struct {
	Policy       Policy
	Resync       time.Duration
	ReadyTimeout time.Duration
	Logger       *zerolog.Logger
}

// Scheduler places pending Applications onto nodes through the plugin framework.
type Scheduler struct {
	cluster      Cluster
	policy       Policy
	resync       time.Duration
	readyTimeout time.Duration
	log          zerolog.Logger
	now          func() time.Time
	fw           *framework.Framework

	// per-pass state — the reconcile loop is a single goroutine, so the framework.Handle
	// reads these without locking. Rebuilt at the top of every scheduleOnce.
	snap *framework.Snapshot
	pvs  map[string]corev1.PersistentVolume
}

// New builds a Scheduler over cluster, filling defaults for the zero Config and
// constructing the framework from the built-in plugin profile.
func New(cluster Cluster, cfg Config) *Scheduler {
	s := &Scheduler{
		cluster:      cluster,
		policy:       cfg.Policy,
		resync:       cfg.Resync,
		readyTimeout: cfg.ReadyTimeout,
		now:          time.Now,
		pvs:          map[string]corev1.PersistentVolume{},
	}
	if s.policy == "" {
		s.policy = Spread
	}
	if s.resync <= 0 {
		s.resync = 30 * time.Second
	}
	if s.readyTimeout <= 0 {
		s.readyTimeout = 45 * time.Second
	}
	if cfg.Logger != nil {
		s.log = *cfg.Logger
	} else {
		s.log = zerolog.Nop()
	}
	fw, err := framework.New(s.registry(), defaultProfile(), s)
	if err != nil {
		// The built-in registry and profile are static and consistent, so this cannot
		// fail; a panic here would only ever mean a programming error in the wiring.
		panic(fmt.Sprintf("scheduler: build framework: %v", err))
	}
	s.fw = fw
	return s
}

// registry maps the built-in plugin names to factories, each capturing the scheduler
// (its clock, policy and control-plane writer via the Handle).
func (s *Scheduler) registry() framework.Registry {
	r := framework.Registry{}
	r.Register(plugins.PrioritySortName, func(framework.Handle) (framework.Plugin, error) {
		return plugins.NewPrioritySort(), nil
	})
	r.Register(plugins.NodeSchedulableName, func(h framework.Handle) (framework.Plugin, error) {
		return plugins.NewNodeSchedulable(s.readyTimeout, h), nil
	})
	r.Register(plugins.RuntimeClassName, func(framework.Handle) (framework.Plugin, error) {
		return plugins.NewRuntimeClass(), nil
	})
	r.Register(plugins.RoutedNetworkName, func(framework.Handle) (framework.Plugin, error) {
		return plugins.NewRoutedNetwork(), nil
	})
	r.Register(plugins.NodeAffinityName, func(framework.Handle) (framework.Plugin, error) {
		return plugins.NewNodeAffinity(), nil
	})
	r.Register(plugins.WorkloadAffinityName, func(h framework.Handle) (framework.Plugin, error) {
		return plugins.NewWorkloadAffinity(h), nil
	})
	r.Register(plugins.NodeResourcesFitName, func(h framework.Handle) (framework.Plugin, error) {
		return plugins.NewNodeResourcesFit(s.policy == Binpack, h), nil
	})
	r.Register(plugins.VolumeBindingName, func(h framework.Handle) (framework.Plugin, error) {
		return plugins.NewVolumeBinding(h), nil
	})
	r.Register(plugins.DefaultBinderName, func(h framework.Handle) (framework.Plugin, error) {
		return plugins.NewDefaultBinder(h), nil
	})
	return r
}

// defaultProfile is the built-in scheduling profile.
func defaultProfile() framework.Profile {
	return framework.Profile{
		Plugins: []string{
			plugins.PrioritySortName,
			plugins.NodeSchedulableName,
			plugins.RuntimeClassName,
			plugins.RoutedNetworkName,
			plugins.NodeAffinityName,
			plugins.WorkloadAffinityName,
			plugins.NodeResourcesFitName,
			plugins.VolumeBindingName,
			plugins.DefaultBinderName,
		},
		ScoreWeights: map[string]int64{
			plugins.NodeResourcesFitName: 1,
			plugins.NodeAffinityName:     1,
			plugins.WorkloadAffinityName: 1,
		},
	}
}

// Name identifies the scheduler to the controller loop.Manager.
func (s *Scheduler) Name() string { return "scheduler" }

// Watches lists the Kinds whose changes re-run scheduling: Applications (new pending
// work), Nodes (capacity and readiness) and PersistentVolumes (binding state).
func (s *Scheduler) Watches() []types.ObjectMeta {
	v := corev1.GroupVersion.String()
	return []types.ObjectMeta{
		{ApiVersion: v, Kind: "Application"},
		{ApiVersion: v, Kind: "Node"},
		{ApiVersion: v, Kind: "PersistentVolume"},
	}
}

// ReconcileOnce runs one scheduling pass. It is the loop.Reconciler entry point; the
// Manager owns the wake, resync timer and leader gate, so the scheduler keeps no loop
// of its own.
func (s *Scheduler) ReconcileOnce(ctx context.Context) { s.scheduleOnce(ctx) }

// scheduleOnce refreshes the per-pass snapshots, co-schedules the volumes of already
// placed apps, and runs the scheduling cycle for every pending app.
func (s *Scheduler) scheduleOnce(ctx context.Context) {
	apps, err := s.cluster.Applications(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("scheduler: list applications")
		return
	}
	nodes, err := s.cluster.Nodes(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("scheduler: list nodes")
		return
	}
	pvs, err := s.cluster.Volumes(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("scheduler: list volumes")
		return
	}
	s.pvs = indexPVs(pvs)
	s.snap = buildSnapshot(nodes, apps)

	// Already-placed apps: run only the volume points (PreFilter provisions implicit
	// PVs, PreBind co-schedules the nodeless ones onto the app's node). This covers an
	// author who pinned the app but left an inline volume unbacked.
	for i := range apps {
		if apps[i].Spec.Placement.NodeName == "" {
			continue
		}
		state := framework.NewCycleState()
		if st := s.fw.RunPreFilter(ctx, state, &apps[i]); !st.IsSuccess() {
			continue
		}
		if st := s.fw.RunPreBind(ctx, state, &apps[i], apps[i].Spec.Placement.NodeName); !st.IsSuccess() {
			s.log.Warn().Str("app", apps[i].Name).Str("reason", st.Message()).
				Msg("scheduler: co-schedule volumes for placed app failed")
		}
	}

	// Pending apps: order them with the QueueSort plugin, then run the full cycle.
	pend := pending(apps)
	s.fw.Sort(pend)
	for i := range pend {
		s.scheduleApp(ctx, &pend[i])
	}
}

// scheduleApp runs one Application through the framework pipeline. A non-success at any
// point leaves the app pending for the next cycle; a failure after Reserve rolls the
// reservation back so the node isn't left debited.
func (s *Scheduler) scheduleApp(ctx context.Context, app *corev1.Application) {
	state := framework.NewCycleState()
	if st := s.fw.RunPreFilter(ctx, state, app); !st.IsSuccess() {
		s.log.Info().Str("app", app.Name).Str("reason", st.Message()).Msg("scheduler: prefilter; leaving pending")
		s.unschedulable(ctx, app, "not schedulable: "+st.Message())
		return
	}
	var feasible []*framework.NodeInfo
	filtered := map[string]*framework.Status{}
	for _, ni := range s.snap.List() {
		if st := s.fw.RunFilter(ctx, state, app, ni); st.IsSuccess() {
			feasible = append(feasible, ni)
		} else {
			filtered[ni.Node.Name] = st
		}
	}

	var node string
	if len(feasible) == 0 {
		// No feasible node: PostFilter may make room (preemption) and nominate one. No
		// PostFilter plugin is enabled, so this leaves the app pending.
		nominated, st := s.fw.RunPostFilter(ctx, state, app, filtered)
		if !st.IsSuccess() {
			s.log.Info().Str("app", app.Name).Msg("scheduler: no node fits; leaving pending")
			s.unschedulable(ctx, app, noNodeFits(len(s.snap.List()), filtered))
			return
		}
		node = nominated
	} else {
		if st := s.fw.RunPreScore(ctx, state, app, feasible); !st.IsSuccess() {
			s.log.Warn().Str("app", app.Name).Str("reason", st.Message()).Msg("scheduler: prescore failed; leaving pending")
			s.unschedulable(ctx, app, "not schedulable: "+st.Message())
			return
		}
		scores, st := s.fw.RunScore(ctx, state, app, feasible)
		if !st.IsSuccess() {
			s.log.Warn().Str("app", app.Name).Str("reason", st.Message()).Msg("scheduler: scoring failed; leaving pending")
			s.unschedulable(ctx, app, "not schedulable: "+st.Message())
			return
		}
		node = pickBest(feasible, scores)
	}

	if st := s.fw.RunReserve(ctx, state, app, node); !st.IsSuccess() {
		s.log.Warn().Str("app", app.Name).Str("node", node).Str("reason", st.Message()).Msg("scheduler: reserve failed; leaving pending")
		s.unschedulable(ctx, app, "not placed on "+node+": "+st.Message())
		return
	}
	if st := s.fw.RunPermit(ctx, state, app, node); !st.IsSuccess() {
		s.fw.RunUnreserve(ctx, state, app, node)
		s.log.Warn().Str("app", app.Name).Str("node", node).Str("reason", st.Message()).Msg("scheduler: permit rejected; leaving pending")
		s.unschedulable(ctx, app, "not placed on "+node+": "+st.Message())
		return
	}
	if st := s.fw.RunPreBind(ctx, state, app, node); !st.IsSuccess() {
		s.fw.RunUnreserve(ctx, state, app, node)
		s.log.Warn().Str("app", app.Name).Str("node", node).Str("reason", st.Message()).Msg("scheduler: prebind failed; leaving pending")
		s.unschedulable(ctx, app, "not placed on "+node+": "+st.Message())
		return
	}
	if st := s.fw.RunBind(ctx, state, app, node); !st.IsSuccess() {
		s.fw.RunUnreserve(ctx, state, app, node)
		s.log.Warn().Str("app", app.Name).Str("node", node).Str("reason", st.Message()).Msg("scheduler: bind rejected; leaving pending")
		s.unschedulable(ctx, app, "not placed on "+node+": "+st.Message())
		return
	}
	s.fw.RunPostBind(ctx, state, app, node)
	s.scheduled(ctx, app)
	s.log.Info().Str("app", app.Name).Str("node", node).Msg("scheduler: scheduled")
}

// --- framework.Handle: the reads and writes the built-in plugins use ---

func (s *Scheduler) Snapshot() *framework.Snapshot { return s.snap }
func (s *Scheduler) Clock() time.Time              { return s.now() }

func (s *Scheduler) PV(namespace, name string) (corev1.PersistentVolume, bool) {
	pv, ok := s.pvs[corev1.WorkloadID(namespace, name)]
	return pv, ok
}

func (s *Scheduler) CreatePV(ctx context.Context, namespace, name string, size resource.Quantity) error {
	if err := s.cluster.CreateVolume(ctx, namespace, name, size); err != nil {
		return err
	}
	// nodeless; keyed by namespace-qualified ID so same-named PVs across namespaces are distinct
	s.pvs[corev1.WorkloadID(namespace, name)] = corev1.PersistentVolume{Spec: corev1.PersistentVolumeSpec{Size: size}}
	s.log.Info().Str("namespace", namespace).Str("volume", name).Msg("scheduler: created implicit volume")
	return nil
}

func (s *Scheduler) BindPV(ctx context.Context, namespace, name, node string) error {
	if err := s.cluster.AssignVolume(ctx, namespace, name, node); err != nil {
		return err
	}
	id := corev1.WorkloadID(namespace, name)
	pv := s.pvs[id]
	pv.Spec.Node = node
	s.pvs[id] = pv // reflect it so a later app in this pass sees the volume bound
	return nil
}

func (s *Scheduler) BindApp(ctx context.Context, namespace, name, node string) error {
	return s.cluster.Assign(ctx, namespace, name, node)
}

// --- per-pass builders ---

// pending returns the unplaced Applications (no assigned node). The scheduling order is not
// decided here — the caller applies the QueueSort plugin.
func pending(apps []corev1.Application) []corev1.Application {
	var out []corev1.Application
	for _, a := range apps {
		if a.Spec.Placement.NodeName == "" {
			out = append(out, a)
		}
	}
	return out
}

// indexPVs keys PersistentVolumes by name for lookup during placement.
func indexPVs(pvs []corev1.PersistentVolume) map[string]corev1.PersistentVolume {
	m := make(map[string]corev1.PersistentVolume, len(pvs))
	for _, pv := range pvs {
		m[pv.ID()] = pv // namespace-qualified so same-named PVs across namespaces stay distinct
	}
	return m
}

// buildSnapshot builds the per-node view: capacity plus the live allocation summed from
// the effective requests of the applications already assigned to each node.
//
// A workload that has run to completion is not on the node in any sense that matters here: it
// occupies no resource, so counting its requests would retire a slice of the node with every job
// that ever ran there, and it is no longer a neighbour, so leaving it among the placed apps would
// have an anti-affinity rule repel new work from a job that finished last week.
func buildSnapshot(nodes []corev1.Node, apps []corev1.Application) *framework.Snapshot {
	alloc := map[string]corev1.ResourceAmounts{}
	placed := map[string][]framework.PlacedApp{}
	for _, a := range apps {
		if a.Spec.Placement.NodeName == "" || a.Finished() {
			continue
		}
		alloc[a.Spec.Placement.NodeName] = alloc[a.Spec.Placement.NodeName].Add(a.Spec.Resources.EffectiveRequests())
		placed[a.Spec.Placement.NodeName] = append(placed[a.Spec.Placement.NodeName], framework.PlacedFromApp(a))
	}
	infos := make([]*framework.NodeInfo, 0, len(nodes))
	for _, n := range nodes {
		infos = append(infos, &framework.NodeInfo{Node: n, Requested: alloc[n.Name], Apps: placed[n.Name]})
	}
	return framework.NewSnapshot(infos)
}

// pickBest is the highest-scoring node; feasible is in name order, so ties resolve to
// the lowest name.
func pickBest(feasible []*framework.NodeInfo, scores map[string]int64) string {
	best := ""
	var bestScore int64
	for _, ni := range feasible {
		if sc := scores[ni.Node.Name]; best == "" || sc > bestScore {
			best, bestScore = ni.Node.Name, sc
		}
	}
	return best
}
