package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"time"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	netdapi "github.com/ks-tool/horchestra/api/netd"
	nodeapipb "github.com/ks-tool/horchestra/api/node"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"

	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Reconcile brings this node in line with the desired set the controller pushed. It
// is pure orchestration over the two mechanisms: the Volumes port provisions this
// node's PersistentVolumes and resolves each app's mounts; the Runtime port runs the
// wanted applications and tears down the rest. Actual state is read from the runtime
// itself (Runtime.List), never a persisted record, so it self-heals across crashes
// and reboots. Every failure is collected, never fatal: one failing app, volume
// provision or volume reclaim never stops the others, and all of them surface in the
// returned (joined) error for the caller to log.
func (a *Agent) Reconcile(ctx context.Context, applications []corev1.Application, pvList []corev1.PersistentVolume, secrets []corev1.Secret, stores []secretsv1.SecretStore, tokens map[string]map[string]string, networks map[string]*nodeapipb.WorkloadNetwork) error {
	apps := make([]workload.App, 0, len(applications))
	for i := range applications {
		wa := workload.FromApplication(applications[i])
		// The pushed identity tokens join the in-memory desired state here — never inside
		// FromApplication, which builds from the API object alone.
		wa.Tokens = tokens[wa.ID()]
		// The routed address the control plane chose, delivered with the push rather than stored
		// on the object — the same way the identity tokens above arrive, and for the same reason:
		// a workload's object is its author's manifest.
		if n := networks[wa.ID()]; n != nil {
			wa.Address, wa.Gateway, wa.MTU = n.GetAddress(), n.GetGateway(), int(n.GetMtu())
		}
		apps = append(apps, wa)
	}

	// Key PVs by their namespace-qualified ID so two same-named PVs in different namespaces,
	// both pushed to this node, do not collide on disk.
	myPVs := map[string]corev1.PersistentVolume{}
	allPVs := map[string]bool{}
	for i := range pvList {
		allPVs[pvList[i].ID()] = true
		if pvList[i].Spec.Node == a.node {
			myPVs[pvList[i].ID()] = pvList[i]
		}
	}
	var errs []error
	if err := a.volumes.Provision(ctx, myPVs); err != nil {
		errs = append(errs, err)
	}

	want := appsForNode(apps, a.node)
	a.stateMu.Lock()
	a.want = want
	a.stateMu.Unlock()
	errs = append(errs, a.reconcileApps(ctx, want, myPVs, secrets, stores)...)
	if err := a.volumes.Reclaim(ctx, allPVs, want); err != nil {
		errs = append(errs, err)
	}
	// The network's leftovers go the same way, and by the same rule: what the node no longer wants
	// is what is reclaimed. Only isolated workloads are named — a workload on the host network has
	// nothing on the node to take back — and the list is total, so a veth whose workload vanished
	// while the agent was down is swept on the first pass after it returns.
	if a.network != nil {
		if err := a.network.GC(ctx, isolatedIDs(want)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// reconcileApps converges the wanted applications and tears down the rest. What is
// actually running is read from the runtime (Runtime.List), so a workload wiped by a
// reboot, stopped, or drifted is repaired. An app whose volumes this node does not
// back is skipped silently (another node backs it); a resolve or apply failure is
// collected.
func (a *Agent) reconcileApps(ctx context.Context, want map[string]workload.App, myPVs map[string]corev1.PersistentVolume, secrets []corev1.Secret, stores []secretsv1.SecretStore) []error {
	var errs []error
	for name, app := range want {
		// A workload whose object is being deleted is torn down here rather than converged.
		// It reaches this loop at all — instead of simply vanishing from desired state — so the
		// node still has the spec, and with it the grace period the author asked for; the old
		// shape learned of a deletion by ABSENCE and had nothing left to read.
		if app.Deleting {
			if err := a.runtime.Remove(ctx, name, app.Lifecycle.GracePeriod()); err != nil {
				errs = append(errs, fmt.Errorf("tear down %s: %w", name, err))
			}
			delete(a.applied, name)
			continue
		}
		if !a.volumes.Fits(app, myPVs) {
			continue // this node does not back all of the app's volumes
		}
		vols, err := a.volumes.Resolve(app, myPVs)
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve %s: %w", name, err))
			continue
		}
		secVols, err := a.secrets.Materialize(ctx, app, secrets, stores)
		if err != nil {
			// Fail-closed: never start an app whose non-optional secret is absent; leave it
			// pending (a later push re-reconciles). An app already running keeps running —
			// this only skips the Apply, it does not tear the workload down (keep-last-good).
			errs = append(errs, fmt.Errorf("materialize secrets %s: %w", name, err))
			continue
		}
		// Same fail-closed rule for the env references: an app must not start with a variable
		// its spec says comes from a Secret silently unset.
		app.SecretEnv, err = a.secrets.MaterializeEnv(ctx, app, secrets, stores)
		if err != nil {
			errs = append(errs, fmt.Errorf("materialize secret env %s: %w", name, err))
			continue
		}
		if err := a.runtime.Apply(ctx, app, append(vols, secVols...)); err != nil {
			errs = append(errs, fmt.Errorf("converge %s: %w", name, err))
			continue
		}
		// Converged: record WHICH spec is now running. Only a successful Apply advances it,
		// so a node that cannot start a new spec keeps reporting the generation it actually
		// runs — the signal a rollout gates on.
		if a.applied == nil {
			a.applied = map[string]int64{}
		}
		a.applied[name] = app.Generation
	}
	// Every workload the runtime holds, in whatever state: a finished job and a failed unit are
	// as much this node's to tear down as a running one, so the teardown reads the ids and not
	// the phases.
	held, _ := a.runtime.States(ctx)
	for _, s := range held {
		if _, ok := want[s.ID]; !ok {
			_ = a.runtime.Remove(ctx, s.ID, 0) // no spec: this workload is not in desired state at all
			delete(a.applied, s.ID)
		}
	}
	// Image GC is deliberately NOT run on the reconcile path: it is a manual, operator-driven
	// operation (the `purge` command) performed in a maintenance window, so reclaiming blobs
	// never races a live workload's converge.
	return errs
}

// appsForNode keys the applications pinned to node by workload id. spec.nodeName pins each
// application to exactly one node, so a node runs only the applications naming it.
//
// An application with no metadata.uid is dropped rather than keyed under "": the storage layer
// stamps a uid on every create, so an empty one is a malformed push, and two of them would
// collide on the empty key — one workload silently displacing the other, then both naming the
// same unit and the same config file.
func appsForNode(apps []workload.App, node string) map[string]workload.App {
	want := make(map[string]workload.App, len(apps))
	for _, a := range apps {
		if a.Node != node {
			continue
		}
		if a.ID() == "" {
			log.Warn().Str("app", corev1.WorkloadID(a.Namespace, a.Name)).
				Msg("application has no metadata.uid: it has no identity on this node and is not run")
			continue
		}
		want[a.ID()] = a
	}
	return want
}

// nodeStatus is the node's reported status: measured capacity (capped by the
// -config limits) and the allocation summed from the effective requests of the
// applications this node is actually carrying.
//
// TERMINAL workloads are left out — a job that has finished holds a unit and nothing else, and
// counting it would retire a slice of the node with every job that ever ran there. Everything
// else stays in, including workloads that are starting, restarting or failed-and-restartable:
// they are load the node has committed to, and dropping them the moment nothing is running
// would let the scheduler place against capacity that is about to be taken back.
func (a *Agent) nodeStatus() corev1.NodeStatus {
	capacity, osName := nodeCapacity(a.limits)
	var alloc corev1.ResourceAmounts
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	for id, app := range a.want {
		if corev1.TerminalPhase(a.observed[id].Phase, app.Lifecycle, a.observed[id].Attempts) {
			continue
		}
		alloc = alloc.Add(app.EffectiveRequests())
	}
	return corev1.NodeStatus{
		Capacity:  capacity,
		Allocated: alloc,
		OS:        osName,
		IP:        nodeIP(a.controller),
		Ready:     true,
		Heartbeat: metav1.Now(),
		Runtimes:  []string{a.runtime.Name()},
		Platform:  corev1.Platform{OS: runtime.GOOS, Arch: runtime.GOARCH},
		// Asked of the helper, not assumed from the fact that a network port exists: a node whose
		// helper is missing, misconfigured or short a capability advertises false, and the
		// scheduler keeps isolated workloads off it instead of letting them fail at start.
		RoutedNetwork: a.canRouteWorkloads(),
	}
}

// nodeIP returns this node's source IP toward the controller — the address it
// reaches the control plane on. A UDP "connect" sends no packets; it just resolves
// the route and yields the local address. Empty if it cannot be determined.
func nodeIP(controller string) string {
	u, err := url.Parse(controller)
	if err != nil {
		return ""
	}
	host, port := u.Hostname(), u.Port()
	if len(port) == 0 {
		port = "443"
	}
	conn, err := net.Dial("udp", net.JoinHostPort(host, port))
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// isolatedIDs is every workload on this node with a network of its own — the keep-list the helper
// reclaims against. Empty is meaningful and correct: a node whose workloads are all on the host
// network has nothing wired, and the helper should hold nothing for it.
func isolatedIDs(apps map[string]workload.App) []string {
	var out []string
	for _, app := range apps {
		if !app.HostNetwork {
			out = append(out, app.ID())
		}
	}
	return out
}

// canRouteWorkloads is whether this node can give a workload a network of its own, as the helper
// itself reports it. Any failure is a no: a node that cannot be asked cannot be counted on, and
// advertising a capability on the strength of a call that did not answer is how a workload ends up
// scheduled onto a node that then refuses it.
func (a *Agent) canRouteWorkloads() bool {
	if a.network == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), networkStatusTimeout)
	defer cancel()
	st, err := a.network.Status(ctx)
	return err == nil && st.GetRoutedNetwork()
}

// networkStatusTimeout bounds that question. It rides the heartbeat, so a slow answer must not
// hold the node's status behind it.
const networkStatusTimeout = 3 * time.Second

// networkConfigureTimeout bounds the other one. It is longer because what it carries is the whole
// fleet's addressing rather than one bit, and it is still bounded because a helper that has stopped
// answering must not hold the reconcile loop that feeds every workload on the node.
const networkConfigureTimeout = 15 * time.Second

// configureNetwork replaces this node's forwarding state with what the control plane just pushed:
// where every workload address in the fleet lives, and what every ClusterIP balances onto.
//
// It is asked on EVERY push and always in full, because it is a replace and not a delta — neither
// side keeps a record of what was programmed last time, which is what makes an agent restart, a
// helper restart and a reboot all converge the same way. An empty set is meaningful and is sent:
// a fleet whose last isolated workload went away has an empty table, not a stale one.
//
// A node with no datapath is skipped rather than asked and refused. The shortfall is already
// reported once per heartbeat in the node's own status, and asking anyway would write a failure
// into the log on every push for the life of a node that is working exactly as configured.
//
// That bit is one bit for two programs, so a node that loaded only one of them programs neither.
// Deliberate while the two are all-or-nothing in practice — a kernel either runs BPF or does not —
// and visible when it is not: the helper's status names which half is missing.
func (a *Agent) configureNetwork(ctx context.Context, routes []*netdapi.Route, services []*netdapi.ServiceRule) {
	if a.network == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, networkConfigureTimeout)
	defer cancel()
	st, err := a.network.Status(ctx)
	if err != nil || !st.GetDatapath() {
		return
	}
	if err := a.network.Configure(ctx, routes, services); err != nil {
		log.Error().Err(err).Int("routes", len(routes)).Int("services", len(services)).
			Msg("program this node's forwarding state")
	}
}
