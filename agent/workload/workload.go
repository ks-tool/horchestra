// Package workload holds the reconcile-facing desired-state types the two node
// mechanisms share — the Runtime (agent/runtime) that runs a workload and the Volumes
// (agent/volume) that back its storage. It is the leaf both mechanisms and the agent
// core depend on, so neither mechanism imports the other or the agent core: the
// dependency direction is agent → {runtime, volume, workload} and runtime, volume → workload.
package workload

import corev1 "github.com/ks-tool/horchestra/api/core/v1"

// App is a desired application, projected from an Application the controller pushed
// — the form the Runtime and Volumes mechanisms operate on. It carries both the
// runtime fields (image/command/env/security, consumed by the Runtime) and the
// volume fields (Volumes, consumed by the Volumes).
type App struct {
	// UID is the API object's metadata.uid, and it is this workload's identity on the node:
	// the reconcile key, the unit name, the config file name and the state directories all
	// derive from it. It is assigned once at create, survives every update, and is NEW after
	// a delete/recreate — so an application recreated under the same name is a different
	// workload here too, torn down and started clean rather than mistaken for the old one.
	UID       string
	Name      string
	Namespace string
	// Generation is the API object's metadata.generation (spec writes only). The agent
	// reports back the generation it converged, which is how the control plane tells
	// "running the new spec" from "still running the old one".
	Generation int64
	Node       string
	Image      string
	Command    []string
	Args       []string
	Requests   corev1.ResourceAmounts
	Limits     corev1.ResourceAmounts
	Env        []string // literal "KEY=VALUE", in declared order (flattened from spec.env once)
	// EnvRefs are the spec.env entries that source their value from a Secret, in declared
	// order. They are references, not values: the Secrets mechanism resolves them into
	// SecretEnv at converge time.
	EnvRefs []corev1.EnvVar
	// SecretEnv is the resolved "KEY=VALUE" form of EnvRefs, filled by the reconciler after
	// the Secrets mechanism materializes them — never by FromApplication, which only ever sees
	// the reference. It is plaintext and stays in memory, like Volume.Content; the Runtime
	// decides how to hand it to the workload without putting it in the unit's own text.
	SecretEnv []string
	// Lifecycle is the app's spec section verbatim, unset fields included: the runtime applies
	// each field's default where the value is consumed, so an unset one keeps following the
	// default rather than being frozen into this projection.
	Lifecycle corev1.Lifecycle
	// Attempts is how many times this job has already been run, carried down from
	// status.attempts. The node spends the retry budget against it, so a job that used its
	// budget before a reboot does not get a fresh one after.
	Attempts int32
	// Deleting is the object's metadata.deletionTimestamp: this workload has been asked to go
	// and its node is what has to make that true. It arrives as desired state rather than as an
	// absence — which is what a delete used to be — so the spec, and with it the grace period
	// the author wrote, is still here when the teardown needs it.
	Deleting        bool
	SecurityContext *corev1.SecurityContext
	Volumes         []corev1.VolumeMount
	// Tokens are this workload's controller-minted identity JWTs, keyed by AUDIENCE (pushed
	// beside desired state): the vault one the client exchanges at a jwt-method SecretStore,
	// and one per token volume the workload mounts. Keyed by audience because a token is worth
	// exactly the door it names — one credential presented at the wrong one is not a credential.
	//
	// They are in-memory CREDENTIALS, set by the reconciler — never by FromApplication — and the
	// json:"-" tag keeps any serialization of an App from ever writing them down.
	Tokens map[string]string `json:"-"`
	// HostNetwork is whether this workload shares the node's network namespace. Today every
	// workload does; when the control plane starts leasing addresses, a false here is what makes
	// the trampoline create a namespace of its own and ask for it to be wired.
	HostNetwork bool
	// Address, Gateway and MTU are what the control plane leased for an isolated workload:
	// the address in CIDR form, the node-side gateway its default route points at, and the MTU
	// an overlay's overhead may lower. All empty on the host network — and an isolated workload
	// with no address is refused rather than started, because a namespace with nothing in it
	// fails as a bug in the workload rather than as a network that was not built.
	Address string
	Gateway string
	MTU     int
}

// Token is the workload's JWT for one audience, empty when the controller minted none.
func (a App) Token(audience string) string { return a.Tokens[audience] }

// VaultToken is the token the vault client exchanges at a jwt-method SecretStore.
func (a App) VaultToken() string { return a.Tokens[corev1.TokenAudienceVault] }

// VolumeKind is how a resolved volume attaches to the workload: a host-path bind (a
// shared-kernel runtime mounts a host directory), a block device or filesystem image
// (a microVM or block driver attaches virtio-block), or an ephemeral tmpfs. The
// Runtime interprets the kind; the Volumes driver only states it.
type VolumeKind int

const (
	VolumeHostPath    VolumeKind = iota // Ref is a host directory, bind-mounted at MountPath
	VolumeBlockDevice                   // Ref is a host device node, attached at MountPath
	VolumeImage                         // Ref is a filesystem-image file, attached at MountPath
	VolumeTmpfs                         // ephemeral in-memory mount at MountPath (Ref empty)
	VolumeSecret                        // per-key files under MountPath, materialized in RAM from Content
)

// Volume is one resolved mount: the single backend-neutral seam between the two
// mechanisms. The Volumes (CSI) port produces a Volume from an App's declared mounts —
// stating what it is (Kind + Ref) and where it goes (MountPath) — and the Runtime (CRI)
// port attaches it however its model requires: a bind for a shared-kernel runtime, a
// virtio-block device for a microVM. Neither the overlay/systemd model nor any single
// storage backend leaks through it.
type Volume struct {
	Kind      VolumeKind
	Ref       string // host path | device node | image file; empty for VolumeTmpfs/VolumeSecret
	MountPath string // path inside the workload's root filesystem
	FsType    string // filesystem for VolumeBlockDevice/VolumeImage (e.g. "ext4"); empty otherwise
	Size      string // VolumeTmpfs size cap / provisioned size (e.g. "64Mi"); empty = backend default
	ReadOnly  bool
	// Content is a VolumeSecret's materialized payload: relative file path within MountPath
	// → raw bytes. The runtime renders each entry as a read-only in-RAM file (systemd
	// service credential), so the secret value never touches persistent disk.
	Content map[string][]byte
}

// ID is the workload's identity on the node — the reconcile key and the basis of its
// unit, config and rootfs names.
//
// It is the object's UID rather than its namespace-qualified name because a name is not an
// identity: two distinct names can sanitize to the same string, a name is reused the moment
// an application is deleted and recreated, and the node would carry the old workload's
// overlay upperdir and config into the new one. A uid does none of that, and it needs no
// separator convention to stay parseable out of a unit name.
func (a App) ID() string { return a.UID }

// FromApplication projects a pushed Application into the reconciler's App form.
func FromApplication(it corev1.Application) App {
	return App{
		UID:             string(it.UID),
		Name:            it.Name,
		Namespace:       it.Namespace,
		Generation:      it.Generation,
		Node:            it.Spec.Placement.NodeName,
		Image:           it.Spec.Image,
		Command:         it.Spec.Command,
		Args:            it.Spec.Args,
		Requests:        it.Spec.Resources.Requests,
		Limits:          it.Spec.Resources.Limits,
		Env:             envStrings(it.Spec.Env),
		EnvRefs:         envRefs(it.Spec.Env),
		Lifecycle:       it.Spec.Lifecycle,
		Attempts:        it.Status.Attempts,
		Deleting:        it.Deleting(),
		SecurityContext: it.Spec.SecurityContext,
		Volumes:         it.Spec.Volumes,
		HostNetwork:     it.OnHostNetwork(),
	}
}

// envStrings flattens the LITERAL entries of an ordered spec.env into "KEY=VALUE" strings,
// preserving declared order so the projection is deterministic (the runtime's converge hash
// depends on it). An entry with a secretRef carries no value here — flattening it would emit an
// empty "NAME=" that silently shadows the resolved one.
func envStrings(vars []corev1.EnvVar) []string {
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		if v.IsSecret() {
			continue
		}
		out = append(out, v.Name+"="+v.Value)
	}
	return out
}

// envRefs keeps the secret-sourced entries, in declared order, for the Secrets mechanism.
func envRefs(vars []corev1.EnvVar) []corev1.EnvVar {
	var out []corev1.EnvVar
	for _, v := range vars {
		if v.IsSecret() {
			out = append(out, v)
		}
	}
	return out
}

// EffectiveRequests are the resources this app reserves on its node.
func (a App) EffectiveRequests() corev1.ResourceAmounts {
	return corev1.ResourceRequirements{Requests: a.Requests, Limits: a.Limits}.EffectiveRequests()
}
