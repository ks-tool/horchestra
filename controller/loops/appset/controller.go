package appset

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"

	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Cluster is the control-plane surface the ApplicationSet loop drives — reads of the sets,
// nodes and their child Applications, and the writes that converge the children. Every write
// goes through the control plane, so admission re-validates each child.
type Cluster interface {
	ApplicationSets(ctx context.Context) ([]corev1.ApplicationSet, error)
	Nodes(ctx context.Context) ([]corev1.Node, error)
	Applications(ctx context.Context) ([]corev1.Application, error)
	CreateApplication(ctx context.Context, app *corev1.Application) error
	UpdateApplication(ctx context.Context, app *corev1.Application) error
	DeleteApplication(ctx context.Context, namespace, name string) error
	// The Services a set renders for its components are converged by the same diff as the
	// children, and read whole because a name this set does not own must not be written to.
	Services(ctx context.Context) ([]corev1.Service, error)
	CreateService(ctx context.Context, svc *corev1.Service) error
	UpdateService(ctx context.Context, svc *corev1.Service) error
	DeleteService(ctx context.Context, namespace, name string) error
	UpdateSetStatus(ctx context.Context, set *corev1.ApplicationSet) error
	// UpdateSet and DeleteSet exist for the cascade alone: releasing the child-teardown
	// finalizer once the set's children are gone, and erasing the set that was waiting on them.
	UpdateSet(ctx context.Context, set *corev1.ApplicationSet) error
	DeleteSet(ctx context.Context, namespace, name string) error
}

// Config holds the loop's tunables.
type Config struct {
	Resync time.Duration
	Logger *zerolog.Logger
}

// Controller expands ApplicationSets into child Applications and keeps them converged. It is a
// loop.Reconciler: the Manager owns the wake, resync and leader gate, so it runs single-
// goroutine and needs no locking.
type Controller struct {
	cluster Cluster
	log     zerolog.Logger
}

// New builds the controller over cluster.
func New(cluster Cluster, cfg Config) *Controller {
	log := zerolog.Nop()
	if cfg.Logger != nil {
		log = *cfg.Logger
	}
	return &Controller{cluster: cluster, log: log}
}

// Name identifies the loop to the Manager.
func (*Controller) Name() string { return "applicationset" }

// Watches wakes the loop on ApplicationSet changes (new/edited sets), Node changes (a
// nodeSpread component re-renders as nodes join/leave) and Application changes (a hand-deleted
// child is recreated).
func (*Controller) Watches() []types.ObjectMeta {
	return []types.ObjectMeta{
		{ApiVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet"},
		{ApiVersion: corev1.GroupVersion.String(), Kind: "Node"},
		{ApiVersion: corev1.GroupVersion.String(), Kind: "Application"},
	}
}

// ReconcileOnce is the loop.Reconciler entry point.
func (c *Controller) ReconcileOnce(ctx context.Context) { c.reconcileOnce(ctx) }

func (c *Controller) reconcileOnce(ctx context.Context) {
	sets, err := c.cluster.ApplicationSets(ctx)
	if err != nil {
		c.log.Error().Err(err).Msg("appset: list applicationsets")
		return
	}
	nodes, err := c.cluster.Nodes(ctx)
	if err != nil {
		c.log.Error().Err(err).Msg("appset: list nodes")
		return
	}
	apps, err := c.cluster.Applications(ctx)
	if err != nil {
		c.log.Error().Err(err).Msg("appset: list applications")
		return
	}
	// GC-first: delete a child whose owning ApplicationSet no longer exists — a cascade keyed on
	// the child's controller ownerReference (not the user-writable label) that survives
	// parent-gone without finalizers; the child-keyed sweep runs every reconcile.
	live := make(map[string]*corev1.ApplicationSet, len(sets))
	for i := range sets {
		live[sets[i].Namespace+"/"+sets[i].Name] = &sets[i]
	}
	for i := range apps {
		a := apps[i]
		ref := corev1.AppsetOwner(&a)
		if ref == nil {
			continue
		}
		// Keep iff the child is still owned by a live set — the same predicate as the
		// adoption/prune guard (ownedBySet), so the GC cascade can never diverge from it.
		if s, ok := live[a.Namespace+"/"+ref.Name]; !ok || !ownedBySet(a, s) {
			if err := c.cluster.DeleteApplication(ctx, a.Namespace, a.Name); err != nil {
				c.log.Warn().Err(err).Str("child", a.Name).Msg("appset: gc orphaned child")
				continue
			}
			// This delete runs with no request identity and leaves no RequestLog entry, so it
			// is the only record that the control plane destroyed a tenant's object.
			c.log.Info().Str("namespace", a.Namespace).Str("child", a.Name).
				Str("set", ref.Name).Msg("appset: deleted orphaned child")
		}
	}
	for i := range sets {
		c.reconcileSet(ctx, &sets[i], nodes, apps)
	}
}

// cascade takes a deleted set the rest of the way down: delete every child it still owns, and
// once none are left, release the finalizer that has been holding the set's own object.
//
// Doing it in this order is the whole point. The set used to be erased FIRST and its children
// reaped afterwards by the orphan sweep, so in between they were running with nothing pointing at
// them — and with the loop down in between, they stayed that way. Now the set is the record of an
// unfinished cascade for as long as one is unfinished, and it says so: an operator reads
// Terminating and the children still standing.
//
// A child's own delete is itself a request — it carries the node-teardown finalizer — so
// "no children left" means every node confirmed its workload gone, not that the deletes were
// issued. The set therefore outlives the last workload it owns, which is exactly what it is for.
// `kubectl delete appset X --cascade=orphan` makes it a handover instead: the children are let go
// rather than taken down, and the hold ends as soon as every one of them has been released. What
// the hold waits for there is the RELEASE, not a teardown — nothing on any node changes, so there
// is nothing for a node to confirm.
func (c *Controller) cascade(ctx context.Context, set *corev1.ApplicationSet, existing map[string]corev1.Application) {
	if orphanRequested(set) {
		if !c.releaseServices(ctx, set) || !c.release(ctx, set, existing) {
			// Some child could not be let go. The set keeps its hold and says so, and the
			// release is retried next pass — it is idempotent, one that already went through
			// is no longer owned and is not seen here again.
			c.holdTerminating(ctx, set, existing)
			return
		}
		c.finishCascade(ctx, set)
		return
	}
	for name := range existing {
		child := existing[name]
		if child.Deleting() {
			continue // already asked; its node is what finishes it
		}
		if err := c.cluster.DeleteApplication(ctx, child.Namespace, child.Name); err != nil {
			c.log.Warn().Err(err).Str("set", set.Name).Str("child", child.Name).
				Msg("appset: cascade delete")
		}
	}
	if len(existing) > 0 {
		c.holdTerminating(ctx, set, existing)
		return
	}
	c.finishCascade(ctx, set)
}

// release hands the children over: each is stripped of every mark that made it a set's, so the
// GC-first orphan sweep no longer reaches it and no set — not even one recreated under the same
// name — can adopt, rewrite or reap it. It reports whether every child made it.
//
// The stripping runs through the ordinary Application update path, and the loop carries no authn
// identity, which is exactly why it is allowed to write metadata reserved from clients.
func (c *Controller) release(ctx context.Context, set *corev1.ApplicationSet, existing map[string]corev1.Application) bool {
	released := true
	for name := range existing {
		child := existing[name]
		corev1.ReleaseAppsetChild(&child)
		if err := c.cluster.UpdateApplication(ctx, &child); err != nil {
			c.log.Warn().Err(err).Str("set", set.Name).Str("child", child.Name).
				Msg("appset: release child on set deletion")
			released = false
			continue
		}
		// The counterpart of the orphan-GC line below: the control plane disowning a tenant's
		// object leaves as little trace in RequestLog as destroying one, and an operator asking
		// later why a workload answers to nothing has only this to find.
		c.log.Info().Str("namespace", child.Namespace).Str("child", child.Name).
			Str("set", set.Name).Msg("appset: released child (--cascade=orphan)")
	}
	return released
}

// orphanRequested reports whether this deletion asked for the children to be left running. The
// caller said so on the DELETE request; the service recorded it as the orphan finalizer, because
// that request is long gone by the time this runs and the object is the only thing that outlived
// it. It is Kubernetes' own marker, so `--cascade=orphan` needs nothing taught to any client.
func orphanRequested(set *corev1.ApplicationSet) bool {
	return slices.Contains(set.Finalizers, metav1.FinalizerOrphanDependents)
}

// holdTerminating keeps the deleted set standing as the record of an unfinished cascade, with the
// children it is still waiting on.
func (c *Controller) holdTerminating(ctx context.Context, set *corev1.ApplicationSet, existing map[string]corev1.Application) {
	status := terminatingPhase(buildStatus(set, existing, set.Status.Desired, nil))
	if statusEqual(set.Status, status) {
		return
	}
	set.Status = status
	if err := c.cluster.UpdateSetStatus(ctx, set); err != nil {
		c.log.Warn().Err(err).Str("set", set.Name).Msg("appset: update terminating status")
	}
}

// releaseServices hands the rendered Services over with the children, stripped of every mark that
// made them a set's. It reports whether every one made it.
func (c *Controller) releaseServices(ctx context.Context, set *corev1.ApplicationSet) bool {
	owned, err := c.ownedServices(ctx, set)
	if err != nil {
		return false
	}
	released := true
	for i := range owned {
		svc := owned[i]
		corev1.ReleaseAppsetMeta(&svc.ObjectMeta)
		if err := c.cluster.UpdateService(ctx, &svc); err != nil {
			c.log.Warn().Err(err).Str("set", set.Name).Str("service", svc.Name).
				Msg("appset: release service on set deletion")
			released = false
			continue
		}
		c.log.Info().Str("namespace", svc.Namespace).Str("service", svc.Name).
			Str("set", set.Name).Msg("appset: released service (--cascade=orphan)")
	}
	return released
}

// ownedServices is the set's own Services, read whole from the namespace so a name it does not own
// is never mistaken for one it does.
func (c *Controller) ownedServices(ctx context.Context, set *corev1.ApplicationSet) ([]corev1.Service, error) {
	all, err := c.cluster.Services(ctx)
	if err != nil {
		c.log.Error().Err(err).Str("set", set.Name).Msg("appset: list services")
		return nil, err
	}
	var out []corev1.Service
	for i := range all {
		if ownedRefs(all[i].OwnerReferences, all[i].Namespace, set) {
			out = append(out, all[i])
		}
	}
	return out, nil
}

// finishCascade drops the child-teardown hold and erases the set the hold was keeping alive.
func (c *Controller) finishCascade(ctx context.Context, set *corev1.ApplicationSet) {
	// The Services go LAST, after the children they front are gone: a Service its members still
	// declare is refused, the same interlock a mounted PV has. On the orphan path there is nothing
	// left to delete — they were released with the children.
	if !orphanRequested(set) {
		owned, err := c.ownedServices(ctx, set)
		if err != nil {
			return // the hold stands; retried next pass
		}
		for i := range owned {
			if err := c.cluster.DeleteService(ctx, owned[i].Namespace, owned[i].Name); err != nil {
				c.log.Warn().Err(err).Str("set", set.Name).Str("service", owned[i].Name).
					Msg("appset: delete service on set deletion")
				return
			}
		}
	}
	// Both of the cascade's own holds go together: the teardown hold that kept the set standing
	// while its children were dealt with, and the orphan marker that said HOW to deal with them.
	// Leaving the marker behind would hang the object on a finalizer nothing else removes.
	kept := slices.DeleteFunc(slices.Clone(set.Finalizers), func(f string) bool {
		return f == corev1.FinalizerChildTeardown || f == metav1.FinalizerOrphanDependents
	})
	if len(kept) < len(set.Finalizers) {
		set.Finalizers = kept
		if err := c.cluster.UpdateSet(ctx, set); err != nil {
			c.log.Warn().Err(err).Str("set", set.Name).Msg("appset: release cascade hold")
			return
		}
	}
	if len(kept) > 0 {
		return // something else still holds it
	}
	if err := c.cluster.DeleteSet(ctx, set.Namespace, set.Name); err != nil {
		c.log.Warn().Err(err).Str("set", set.Name).Msg("appset: erase a set whose children are gone")
	}
}

// reconcileSet converges one ApplicationSet: expand it, create/update the children it renders,
// prune the ones it no longer does, then write a guarded status.
func (c *Controller) reconcileSet(ctx context.Context, set *corev1.ApplicationSet, nodes []corev1.Node, apps []corev1.Application) {
	existing := ownedChildren(set, apps) // adoption guard: only children carrying our owner label
	if set.Deleting() {
		c.cascade(ctx, set, existing)
		return
	}
	desired, err := Expand(set, nodes)
	if err != nil {
		// An expand error leaves the existing children untouched (never a destructive prune on a
		// bad set); surface it as a status condition and preserve the last-known desired count
		// (expand failed, so the target can't be recomputed).
		c.writeStatus(ctx, set, existing, set.Status.Desired, nodes, corev1.Condition{
			Type: "Rendered", Status: "False", Reason: "RenderError", Message: err.Error(),
		})
		return
	}

	// Before the children, and the order is load-bearing: a child declares the service it joins,
	// and a declaration naming nothing is refused by admission — so a set whose Services arrived
	// second would fail every create on its first pass.
	c.convergeServices(ctx, set, apps)

	desiredByName := make(map[string]corev1.Application, len(desired))
	for i := range desired {
		desiredByName[desired[i].Name] = desired[i]
	}
	// Init steps first: a set's run-to-completion components gate its services, so the services
	// are not created until every step has succeeded. Applied BEFORE co-location, so the anchor
	// is chosen among the children that may actually be created.
	desiredByName, initCond := initGate(set, desiredByName, existing)
	serviceCount := len(desired) - initChildCount(set, desired)
	// Whole-set placement: co-locate the children on the node the anchor landed on. Until it
	// is placed the siblings are not created at all — creating them unpinned would let the
	// scheduler scatter them, and pinning them afterwards would MOVE running workloads.
	converge := corev1.Condition{Type: "Converged", Status: "True", Reason: "Converged"}
	if set.Spec.SameNode() {
		var held bool
		desiredByName, held = pinSameNode(desiredByName, existing, anchorChild(set, desiredByName))
		if held {
			converge = corev1.Condition{Type: "Converged", Status: "False", Reason: "AwaitingAnchor",
				Message: "co-located set: waiting for the anchor child to be scheduled"}
		}
	}
	// Deterministic order: a budgeted rollout must pick the same children each pass, or a
	// held-back change would rotate between them and never finish.
	ready := readyNodes(nodes)
	budget := set.Spec.RolloutBudget()
	unavailable := 0
	if budget > 0 {
		for name, cur := range existing {
			if _, wanted := desiredByName[name]; wanted && !childRunning(cur, ready) {
				unavailable++
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(desiredByName)) {
		d := desiredByName[name]
		cur, ok := existing[name]
		if !ok {
			// Creates are not part of the disruption budget: a child that does not exist yet is
			// not a running workload the rollout could take down.
			if err := c.cluster.CreateApplication(ctx, new(d)); err != nil {
				c.log.Warn().Err(err).Str("child", name).Msg("appset: create child")
			}
			continue
		}
		merged, changed := mergeManaged(cur, d)
		if !changed {
			continue
		}
		// The budget protects LIVE children only. Updating one that is already not running
		// costs no availability — and refusing to would deadlock the set: once every child is
		// broken the budget is spent, and the very change that fixes them could never land
		// (found on a live node, rolling a bad image and then being unable to roll it back).
		available := childRunning(cur, ready)
		if available && budget > 0 && unavailable >= budget {
			// Hold the rest of the rollout: a change lands only as earlier children come back
			// Running, so a version that never does stops here instead of reaching the whole set.
			converge = corev1.Condition{Type: "Converged", Status: "False", Reason: "RolloutHeld",
				Message: fmt.Sprintf("rolling update held at maxUnavailable=%d", budget)}
			break
		}
		if err := c.cluster.UpdateApplication(ctx, new(merged)); err != nil {
			c.log.Warn().Err(err).Str("child", name).Msg("appset: update child")
			continue
		}
		if available && budget > 0 {
			unavailable++ // a running child was just taken down; it costs budget until it is back
		}
	}
	if set.Spec.Prune() {
		for name, e := range existing {
			if _, ok := desiredByName[name]; !ok {
				if err := c.cluster.DeleteApplication(ctx, e.Namespace, name); err != nil {
					c.log.Warn().Err(err).Str("child", name).Msg("appset: prune child")
				}
			}
		}
	}
	// Desired stays the FULL rendered count of the set's SERVICES even while sameNode or an init
	// step holds children back, so status expresses "5 wanted, 1 exists" rather than pretending
	// the set is smaller than it is. Init children are not in that count — a finished job is not
	// a missing replica, and counting one would leave a set with an init step permanently short.
	conds := []corev1.Condition{{Type: "Rendered", Status: "True", Reason: "Expanded"}, converge}
	if initCond != nil {
		conds = append(conds, *initCond)
	}
	c.writeStatus(ctx, set, existing, serviceCount, nodes, conds...)
}

// initChildCount is how many of the rendered children are init steps.
func initChildCount(set *corev1.ApplicationSet, rendered []corev1.Application) int {
	isInit := initComponents(set)
	n := 0
	for _, app := range rendered {
		if isInit[componentOf(app)] {
			n++
		}
	}
	return n
}

// pinSameNode co-locates the set: the lexically first child is the anchor the scheduler
// places, and every sibling is pinned to the node it landed on. Until the anchor has a node
// the siblings are withheld (the returned set holds the anchor alone, held=true) — pinning
// them later would move running workloads, and leaving them unpinned would scatter them.
func pinSameNode(desired, existing map[string]corev1.Application, anchor string) (map[string]corev1.Application, bool) {
	names := slices.Sorted(maps.Keys(desired))
	if len(names) == 0 || anchor == "" {
		return desired, false
	}
	node := ""
	if cur, ok := existing[anchor]; ok {
		node = cur.Spec.Placement.NodeName
	}
	if node == "" {
		return map[string]corev1.Application{anchor: desired[anchor]}, true
	}
	out := make(map[string]corev1.Application, len(desired))
	for _, name := range names {
		child := desired[name]
		// Only an unpinned sibling is co-located: a child that already carries a node is one
		// the set placed for another reason, and silently moving it would be a surprise.
		// (Admission refuses sameNode together with nodeSpread, the one way that arises.)
		if name != anchor && child.Spec.Placement.NodeName == "" {
			child.Spec.Placement.NodeName = node
		}
		out[name] = child
	}
	return out, false
}

// readyNodes indexes node readiness (a fresh heartbeat is what keeps Ready true).
func readyNodes(nodes []corev1.Node) map[string]bool {
	ready := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		ready[n.Name] = n.Status.Ready
	}
	return ready
}

// childRunning is the readiness signal a rollout gates on: the child is placed, its node is
// alive, the node reports the workload as Running, AND the generation it reports converging
// is the one currently stored. That last term is what makes the gate real — it NAMES the
// version. Phase alone says only that some workload is up, and when a node cannot apply a
// new spec (an unpullable image, a refused mount) the PREVIOUS one keeps running and keeps
// reporting Running: a rollout gated on phase alone would read that as success and walk the
// broken spec across the whole set. Verified the hard way on a live node.
func childRunning(app corev1.Application, readyNode map[string]bool) bool {
	return app.Spec.Placement.NodeName != "" && readyNode[app.Spec.Placement.NodeName] &&
		app.Status.Phase == corev1.AppPhaseRunning &&
		app.Status.ObservedGeneration == app.Generation
}

// writeStatus computes the rollup and writes it only when it differs from the stored status
// (the loop watches ApplicationSet, so an unconditional write would busy-loop).
func (c *Controller) writeStatus(ctx context.Context, set *corev1.ApplicationSet, existing map[string]corev1.Application, desired int, nodes []corev1.Node, conds ...corev1.Condition) {
	status := buildStatus(set, existing, desired, nodes, conds...)
	if statusEqual(set.Status, status) {
		return
	}
	set.Status = status
	if err := c.cluster.UpdateSetStatus(ctx, set); err != nil {
		c.log.Warn().Err(err).Str("set", set.Name).Msg("appset: update status")
	}
}

// ownedChildren indexes the Applications this set owns by name — the adoption guard. Ownership
// keys on the child's controller ownerReference (name, and UID when both carry one), NOT the
// user-writable label: a bare Application could squat the label, so a label-only guard would
// let the set clobber or prune a foreign object.
// convergeServices creates, updates and prunes the Services this set renders.
//
// It touches only what it OWNS. A desired name that already exists as somebody else's object is
// left alone — the component still joins it, which is the "front an existing service" case — because
// a loop that adopted a name it did not create could rewrite a tenant's ports or reap the object on
// the next prune.
func (c *Controller) convergeServices(ctx context.Context, set *corev1.ApplicationSet, apps []corev1.Application) {
	all, err := c.cluster.Services(ctx)
	if err != nil {
		c.log.Error().Err(err).Str("set", set.Name).Msg("appset: list services")
		return
	}
	byName := map[string]corev1.Service{}
	owned := map[string]corev1.Service{}
	for i := range all {
		if all[i].Namespace != set.Namespace {
			continue
		}
		byName[all[i].Name] = all[i]
		if ownedRefs(all[i].OwnerReferences, all[i].Namespace, set) {
			owned[all[i].Name] = all[i]
		}
	}

	desired := map[string]corev1.Service{}
	for _, svc := range ExpandServices(set) {
		desired[svc.Name] = svc
	}
	for _, name := range slices.Sorted(maps.Keys(desired)) {
		want := desired[name]
		cur, exists := byName[name]
		if !exists {
			if err := c.cluster.CreateService(ctx, &want); err != nil {
				c.log.Warn().Err(err).Str("set", set.Name).Str("service", name).Msg("appset: create service")
			}
			continue
		}
		if _, ours := owned[name]; !ours {
			c.log.Debug().Str("set", set.Name).Str("service", name).
				Msg("appset: a service of that name exists and is not this set's — joining it, not writing it")
			continue
		}
		if slices.Equal(cur.Spec.Ports, want.Spec.Ports) {
			continue
		}
		// The address is not ours to move: it is declared by whoever knows what answers on it, or
		// allocated once at create. Only the ports are rendered.
		cur.Spec.Ports = want.Spec.Ports
		if err := c.cluster.UpdateService(ctx, &cur); err != nil {
			c.log.Warn().Err(err).Str("set", set.Name).Str("service", name).Msg("appset: update service")
		}
	}
	if !set.Spec.Prune() {
		return
	}
	for name, svc := range owned {
		if _, wanted := desired[name]; wanted || serviceHasMembers(apps, svc) {
			// A Service its members still declare is refused by admission (the same interlock a
			// mounted PV has), so it is not even attempted: the members go first, and the next
			// pass takes the empty name away.
			continue
		}
		if err := c.cluster.DeleteService(ctx, svc.Namespace, name); err != nil {
			c.log.Warn().Err(err).Str("set", set.Name).Str("service", name).Msg("appset: prune service")
		}
	}
}

// serviceHasMembers reports whether any Application still declares this Service — any, not just
// this set's, since membership is self-declared and a foreign workload may have joined.
func serviceHasMembers(apps []corev1.Application, svc corev1.Service) bool {
	for i := range apps {
		if apps[i].Namespace == svc.Namespace && apps[i].Spec.ServiceName == svc.Name {
			return true
		}
	}
	return false
}

func ownedChildren(set *corev1.ApplicationSet, apps []corev1.Application) map[string]corev1.Application {
	out := map[string]corev1.Application{}
	for i := range apps {
		if ownedBySet(apps[i], set) {
			out[apps[i].Name] = apps[i]
		}
	}
	return out
}

// ownedBySet reports whether app's controller ownerReference names set — same namespace, same
// name, same UID. The UID must match exactly: buildChild stamps the set's UID into the reference
// it renders, so a child naming a same-named set that has since been deleted and recreated is an
// orphan of the old set, not a child of the new one. An EMPTY ref.UID used to satisfy it too,
// and that is metadata a client writes.
func ownedBySet(app corev1.Application, set *corev1.ApplicationSet) bool {
	return ownedRefs(app.OwnerReferences, app.Namespace, set)
}

// ownedRefs is the same test for anything a set renders — its children and the Services beside
// them — so one definition answers for both.
func ownedRefs(refs []metav1.OwnerReference, namespace string, set *corev1.ApplicationSet) bool {
	ref := corev1.AppsetOwnerOf(refs)
	return ref != nil && namespace == set.Namespace && ref.Name == set.Name && ref.UID == set.UID
}

// mergeManaged writes the set-owned fields onto the current child but PRESERVES the
// scheduler-assigned spec.nodeName whenever the desired child leaves it empty (a bundle child;
// a nodeSpread child instead carries a non-empty nodeName the set owns) — else the appset and
// the scheduler ping-pong the placement. It reports whether anything the appset owns changed.
func mergeManaged(cur, desired corev1.Application) (corev1.Application, bool) {
	spec := desired.Spec
	if spec.Placement.NodeName == "" {
		spec.Placement.NodeName = cur.Spec.Placement.NodeName // preserve the scheduler's placement
	}
	// Compare the stamped render digest, not the spec: cur.Spec came back through admission
	// (securityContext defaulted, flags forced) while desired.Spec has not been admitted, so a
	// direct DeepEqual is never equal — the controller rewrote every child on every pass, each
	// write published a Modified event that re-woke this same loop, and one ordinary
	// ApplicationSet became an unbounded write/watch storm that also bumped metadata.generation
	// each time and so defeated the node push loop's dedup.
	changed := cur.Annotations[corev1.AnnAppsetSpecHash] != desired.Annotations[corev1.AnnAppsetSpecHash] ||
		!reflect.DeepEqual(cur.Labels, desired.Labels) ||
		(desired.Spec.Placement.NodeName != "" && cur.Spec.Placement.NodeName != desired.Spec.Placement.NodeName)
	merged := cur // keep the stored metadata (resourceVersion, uid) for the update
	merged.Spec = spec
	merged.Labels = desired.Labels
	merged.Annotations = desired.Annotations
	merged.OwnerReferences = desired.OwnerReferences
	return merged, changed
}

// buildStatus rolls up the set's observed children: Desired is the count the set renders,
// Current the count that exist, so status can express partial convergence. "running" is the
// same signal a rolling update gates on — the child is placed on a Ready node AND the node
// reports the workload itself as Running (childRunning), so the rollup cannot claim a set is
// healthy while its workloads crash-loop on live nodes.
func buildStatus(set *corev1.ApplicationSet, existing map[string]corev1.Application, desired int, nodes []corev1.Node, conds ...corev1.Condition) corev1.ApplicationSetStatus {
	ready := readyNodes(nodes)
	isInit := initComponents(set)
	st := corev1.ApplicationSetStatus{Desired: desired, Conditions: conds}
	for name, a := range existing {
		child := corev1.ChildStatus{Name: name, Node: a.Spec.Placement.NodeName}
		// An init step is listed but not counted. It is a thing that happened, not a replica
		// that is missing: counting one would leave every set with an init step one short of
		// Ready forever, and its own phase says more than Scheduled ever could.
		if isInit[componentOf(a)] {
			child.Phase = a.Status.Phase
			if child.Phase == "" {
				child.Phase = "Pending"
			}
			st.Children = append(st.Children, child)
			continue
		}
		st.Current++
		switch {
		case a.Spec.Placement.NodeName == "":
			child.Phase = "Pending"
		case childRunning(a, ready):
			st.Scheduled++
			st.Running++
			child.Phase = "Running"
		default:
			st.Scheduled++
			child.Phase = "Scheduled"
		}
		st.Children = append(st.Children, child)
	}
	st.Phase = rollupPhase(st, conds)
	return st
}

// rollupPhase summarises the set in one word: whatever condition is holding it back (so the
// summary is always the detail's own reason), else Ready when every rendered child exists and
// runs, else Progressing.
func rollupPhase(st corev1.ApplicationSetStatus, conds []corev1.Condition) string {
	for _, c := range conds {
		if c.Status == "False" && c.Reason != "" {
			return c.Reason
		}
	}
	if st.Desired == st.Current && st.Desired == st.Running {
		return corev1.AppSetPhaseReady
	}
	return corev1.AppSetPhaseProgressing
}

// terminatingPhase overrides the rollup for a set on its way out. Progressing would be a lie in
// the one direction that matters: a set whose children are being destroyed reads as one that is
// still trying to bring them up.
func terminatingPhase(st corev1.ApplicationSetStatus) corev1.ApplicationSetStatus {
	st.Phase = corev1.AppSetPhaseTerminating
	return st
}

// statusEqual compares two statuses ignoring the child ordering (map iteration is unordered).
func statusEqual(a, b corev1.ApplicationSetStatus) bool {
	if a.Phase != b.Phase {
		return false
	}
	if a.Desired != b.Desired || a.Current != b.Current || a.Scheduled != b.Scheduled || a.Running != b.Running {
		return false
	}
	if !reflect.DeepEqual(a.Conditions, b.Conditions) {
		return false
	}
	return childSetEqual(a.Children, b.Children)
}

func childSetEqual(a, b []corev1.ChildStatus) bool {
	if len(a) != len(b) {
		return false
	}
	index := make(map[string]corev1.ChildStatus, len(a))
	for _, c := range a {
		index[c.Name] = c
	}
	for _, c := range b {
		if index[c.Name] != c {
			return false
		}
	}
	return true
}
