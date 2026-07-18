package v1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Application struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec ApplicationSpec `json:"spec"`
}

type ApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Application `json:"items"`
}

type Node struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   NodeSpec   `json:"spec"`
	Status NodeStatus `json:"status,omitempty"`
}

type NodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Node `json:"items"`
}

// RestartPolicy values. Never marks a run-to-completion job (one-shot); Always
// (the default) and OnFailure are long-running services.
const (
	RestartAlways    = "Always"
	RestartOnFailure = "OnFailure"
	RestartNever     = "Never"
)

// ApplicationSpec uses Kubernetes Pod vocabulary on a flat, single-container shape
// (one application = one process = one systemd unit, so there is no containers[]
// list). It stays inside horchestra's invariants: NodeName is author-supplied and
// required (no scheduler fills it); Env is a plain map with no valueFrom, so a
// secret cannot be referenced through it; Ports are a pure declaration (no
// in-node data-plane); storage is a separate PersistentVolume Kind, referenced by
// name.
type ApplicationSpec struct {
	// Image is a plain OCI image reference, e.g. reg.io/ns/app:v1 (no scheme).
	Image string `json:"image" jsonschema:"minLength=1"`
	// NodeName pins the application to a single node: one application runs on
	// exactly one node. Required and author-supplied on create/update.
	NodeName string `json:"nodeName" jsonschema:"minLength=1"`
	// Command overrides the image ENTRYPOINT and Args overrides its CMD (Kubernetes
	// semantics). Both are literal argv — never interpolated with values.
	Command []string `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	// Env are environment variables layered over the image's own. Plain config only
	// (e.g. POSTGRES_HOST_AUTH_METHOD); secrets belong in a mounted file. The map
	// shape has no valueFrom, so a secret cannot be referenced here by construction.
	Env map[string]string `json:"env,omitempty"`
	// Ports the application listens on — a pure declaration for an external edge/LB
	// (the orchestrator runs no data-plane of its own). Absent = not routed.
	Ports     []Port               `json:"ports,omitempty"`
	Resources ResourceRequirements `json:"resources,omitempty"`
	// RestartPolicy is Always (default), OnFailure or Never; Never marks a
	// run-to-completion job. Filled by Default() when empty.
	RestartPolicy string `json:"restartPolicy,omitempty" jsonschema:"enum=Always,enum=OnFailure,enum=Never,default=Always"`
	// SecurityContext sets the workload's identity and confinement. When unset, the
	// image's own USER is used; the hardened floor (NoNewPrivileges, ProtectSystem,
	// read-only rootfs) always applies regardless of this field.
	SecurityContext *SecurityContext `json:"securityContext,omitempty"`
	// VolumeMounts mount storage into the container at a path — each entry is
	// exactly one of a PersistentVolume (by name) or an ephemeral tmpfs.
	VolumeMounts []VolumeMount `json:"volumeMounts,omitempty"`
	// Values is free-form horchestra-native config (no Pod analog).
	Values map[string]any `json:"values,omitempty"`
}

// Port is one network port the application listens on, for an external edge to
// route to. Name is an optional label ("http", "metrics", …), free to omit for a
// single-port app; Port is the TCP port and is required.
type Port struct {
	Name string `json:"name,omitempty"`
	Port int    `json:"port" jsonschema:"minimum=1,maximum=65535"`
}

// VolumeMount mounts storage into the container at Path. It is a discriminated
// union: exactly one of PV (a PersistentVolume referenced by name) or Tmpfs (an
// ephemeral in-memory mount). The "exactly one" is enforced at validation time by
// the `oneof_required` tags below — invopop emits a schema oneOf and santhosh
// rejects an entry that sets both or neither, so no admission code is needed. PV's
// storage and lifecycle live in the separate PersistentVolume Kind, not here.
type VolumeMount struct {
	Path  string      `json:"path" jsonschema:"minLength=1"`
	PV    string      `json:"pv,omitempty" jsonschema:"oneof_required=pv"`
	Tmpfs *TmpfsMount `json:"tmpfs,omitempty" jsonschema:"oneof_required=tmpfs"`
}

// TmpfsMount is an ephemeral in-memory mount (systemd TemporaryFileSystem=) for
// temporary paths (pid files, sockets, caches) that need no data on disk, e.g.
// /run. It needs no PersistentVolume; its memory is charged to the app's limit.
type TmpfsMount struct {
	// Size caps the tmpfs (e.g. "64Mi"); systemd's default (half of RAM) when empty.
	Size string `json:"size,omitempty"`
}

// SecurityContext is the pod-level security configuration. Identity fields
// (RunAsUser/RunAsGroup) fall back to the image when unset; the confinement floor
// is always on, so an unset field never weakens security.
type SecurityContext struct {
	RunAsUser                *int64        `json:"runAsUser,omitempty"`
	RunAsGroup               *int64        `json:"runAsGroup,omitempty"`
	RunAsNonRoot             *bool         `json:"runAsNonRoot,omitempty"`
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation,omitempty"`
	Capabilities             *Capabilities `json:"capabilities,omitempty"`
}

// Capabilities lists Linux capabilities to drop from the workload (rendered as a
// systemd CapabilityBoundingSet=). Add is deliberately absent — capabilities can
// only be dropped, never granted, so a workload cannot gain a privilege it was not
// built with.
type Capabilities struct {
	Drop []string `json:"drop,omitempty"`
}

// PersistentVolume is a directory of storage on a node's disk, with a lifecycle
// independent of the Applications that mount it: deleting an Application leaves
// the volume and its data; deleting the PersistentVolume reclaims the data from
// disk on the next reconcile.
type PersistentVolume struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec PersistentVolumeSpec `json:"spec"`
}

type PersistentVolumeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []PersistentVolume `json:"items"`
}

type PersistentVolumeSpec struct {
	// Size is the requested storage as a Kubernetes quantity ("10Gi"). It is
	// advisory in this skeleton (a host directory, not a quota-enforced volume).
	Size resource.Quantity `json:"size,omitempty"`
	// Node is the node whose disk backs the volume; only that node provisions it.
	Node string `json:"node,omitempty"`
	// Mode is the directory's octal permission, e.g. "0755" (default) or "1777"
	// for a shared writable directory such as a socket dir.
	Mode string `json:"mode,omitempty"`
}

type NodeSpec struct {
	Labels        map[string]string `json:"labels,omitempty"`
	Networks      []string          `json:"networks,omitempty"`
	Unschedulable bool              `json:"unschedulable,omitempty"`
}

// NodeStatus is reported by the node-agent every reconcile. Capacity is the
// resource the node offers (its total, capped by any -config limit); Allocated
// is the sum of the requests of the applications running on it, subtracted from
// capacity as apps are placed. `kubectl get nodes` shows the Allocated/Capacity
// ratio as a percentage, and -o wide the raw amounts.
type NodeStatus struct {
	Capacity  ResourceAmounts `json:"capacity,omitempty"`
	Allocated ResourceAmounts `json:"allocated,omitempty"`
	// OS is a human-readable identifier — distro, kernel and CPU architecture,
	// e.g. "Ubuntu 24.04.2 LTS (6.8.0-85-generic, amd64)".
	OS string `json:"os,omitempty"`
	// IP is the node's address as it reaches the controller (its source IP toward
	// the control plane), shown in `kubectl get nodes -o wide`.
	IP string `json:"ip,omitempty"`
	// Ready is the agent's self-reported readiness, refreshed every reconcile
	// together with Heartbeat. A node counts as ready only while its heartbeat is
	// fresh, so a stopped agent becomes NotReady on its own — without a separate
	// liveness controller. Not omitempty: a genuine false must overwrite a stale
	// true through the status merge patch.
	Ready     bool        `json:"ready"`
	Heartbeat metav1.Time `json:"heartbeat,omitempty"`
}

// ResourceAmounts is a set of compute resources — CPU and memory — as Kubernetes
// resource quantities, decoded and printed the standard way ("500m", "2",
// "512Mi", "8Gi"). It is both a node's capacity/allocation and an application's
// requests/limits. Disk is deliberately absent: per-application storage is
// requested through Storage []VolumeClaim, not as a compute resource.
type ResourceAmounts struct {
	CPU    resource.Quantity `json:"cpu,omitempty"`
	Memory resource.Quantity `json:"memory,omitempty"`
}

// IsZero reports whether no resource is set.
func (a ResourceAmounts) IsZero() bool { return a.CPU.IsZero() && a.Memory.IsZero() }

// Add returns the field-wise sum of two resource amounts.
func (a ResourceAmounts) Add(b ResourceAmounts) ResourceAmounts {
	cpu := a.CPU.DeepCopy()
	cpu.Add(b.CPU)
	mem := a.Memory.DeepCopy()
	mem.Add(b.Memory)
	return ResourceAmounts{CPU: cpu, Memory: mem}
}

// ResourceRequirements are an application's resource requests and limits.
// Requests are subtracted from a node's available capacity when the app is
// placed (the allocation); limits cap what it may use. A request left unset
// defaults to the corresponding limit.
type ResourceRequirements struct {
	Requests ResourceAmounts `json:"requests,omitempty"`
	Limits   ResourceAmounts `json:"limits,omitempty"`
}

// EffectiveRequests are the resources an app reserves on its node: its requests,
// with a field left unset defaulting to the corresponding limit (the same
// fallback kube-scheduler applies).
func (r ResourceRequirements) EffectiveRequests() ResourceAmounts {
	req := ResourceAmounts{CPU: r.Requests.CPU, Memory: r.Requests.Memory}
	if req.CPU.IsZero() {
		req.CPU = r.Limits.CPU
	}
	if req.Memory.IsZero() {
		req.Memory = r.Limits.Memory
	}
	return req
}
