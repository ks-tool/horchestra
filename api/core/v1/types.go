package v1

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Application is the unit of work: one application is one process, run from an OCI image as a
// hardened supervised unit on one node. There is no containers[] list and no pod — the flat,
// single-container shape is the model, not a simplification of it. An author states the desired
// spec; the node that owns the workload reports what it observed into status, and never the
// other way round.
type Application struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   ApplicationSpec   `json:"spec"`
	Status ApplicationStatus `json:"status,omitzero"`
}

// Application phases reported by the node-agent from the workload's actual runtime state.
const (
	AppPhasePending = "Pending" // placed on a node but the runtime is not yet running it
	AppPhaseRunning = "Running" // the runtime reports the workload as running on its node
	// AppPhaseSucceeded is a run-to-completion workload that ran and exited zero. It exists
	// because "Running" was the only other answer: a finished job kept reporting Running for
	// as long as its unit was held, so nothing could tell a job that had done its work from
	// one still doing it — which is the only question anybody asks about a job.
	AppPhaseSucceeded = "Succeeded"
	AppPhaseFailed    = "Failed" // pinned to a node but the runtime is not running it (crash/converge error)
	// AppPhaseTerminating is a workload whose object has been deleted and whose node is still
	// taking it down. It exists because "deleted" and "gone" are not the same moment and the gap
	// is exactly where an operator looks: a workload that will not stop used to disappear from
	// the API while its unit ran on, with no state anywhere saying so.
	AppPhaseTerminating = "Terminating"
	// AppPhaseTerminated is the node saying the workload is gone — no unit, nothing left to
	// stop. It is a wire signal rather than something to read on an object: it is what releases
	// the node-teardown finalizer, and the object is erased in the same pass.
	AppPhaseTerminated = "Terminated"
)

// FinalizerNodeTeardown holds an Application's object until the node that runs its workload says
// the workload is gone. It is what turns a delete from an erase into a request: the object stays,
// carrying the spec — and therefore the author's terminationGracePeriodSeconds, which the node
// otherwise no longer has by the time it needs it — until the teardown is confirmed rather than
// assumed.
const FinalizerNodeTeardown = "horchestra.io/node-teardown"

// Deleting reports whether this object has been asked to go and is waiting on something.
func (a Application) Deleting() bool { return a.DeletionTimestamp != nil }

// OnHostNetwork reports whether this workload binds the node's own addresses rather than having a
// network namespace of its own. Unset means yes, because the host's network is the only mode there
// is — see HostNetwork for why the field is a pointer.
//
// It exists so that everything deciding "is the node's address this workload's address" asks one
// question: the catalog registers a host-network instance under its node, and the day an isolated
// workload is possible, that registration has to stop rather than publish a port nothing on the
// node is listening on.
func (a Application) OnHostNetwork() bool {
	return a.Spec.HostNetwork == nil || *a.Spec.HostNetwork
}

// TerminalPhase reports whether a phase means the workload will never run again on its node
// without a new spec. The phase alone does not decide it, which is why the lifecycle and the
// attempt count come too: a Failed service is restarted and is still that node's load, and a
// Failed job is over only once its retry budget is spent.
//
// An unreported attempts (0) is read as one run, because a workload cannot have reached Failed
// without running. Reading it as zero would make a job with no retries budgeted look like one
// that still had a run coming, and it would be retried forever — the exact failure the count
// exists to bound.
func TerminalPhase(phase string, lifecycle Lifecycle, attempts int32) bool {
	if phase == AppPhaseSucceeded {
		return true
	}
	if phase != AppPhaseFailed || !lifecycle.RunToCompletion() {
		return false
	}
	return max(attempts, 1) > lifecycle.Retries()
}

// Finished reports whether this Application has already run to completion on the spec it
// carries now. It is the one definition of "done", and it is here rather than beside any of
// its three readers because they must not be able to drift: the node transport withholds a
// finished workload from the node, and the scheduler and the capacity admission stop counting
// it against the node. Two of those agreeing and one not would either leak capacity or block
// placements against room nothing occupies.
//
// Both terms are load-bearing. Without the phase a running workload would be treated as done;
// without observedGeneration a job would be done FOREVER, and editing its spec — the one way
// anything else in this system is re-triggered — could never run it again.
func (a Application) Finished() bool {
	return TerminalPhase(a.Status.Phase, a.Spec.Lifecycle, a.Status.Attempts) &&
		a.Status.ObservedGeneration == a.Generation
}

// ApplicationStatus is the node-observed status of an Application, reported by the node-agent
// each reconcile and persisted through the status subresource. It is authoritative only for an
// app pinned to a node (the reporting node); an unplaced app has an empty phase.
type ApplicationStatus struct {
	// ObservedGeneration is the metadata.generation the node reports having converged to.
	// It is what names the RUNNING version: phase says a workload is up, this says which
	// spec it is up on, so a node that cannot apply a new spec (an unpullable image, a
	// rejected mount) keeps reporting the old generation instead of looking converged.
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	Phase              string `json:"phase,omitempty"`
	Message            string `json:"message,omitempty"`
	// Address is the routed address the node WIRED this workload at, in CIDR form
	// (10.244.1.7/32). Empty on the host network, which is every workload until an operator
	// turns routing on.
	//
	// The node reports it, the control plane does not write it — the same arrangement Kubernetes
	// has for podIP, and for the same reason: it is an observation of what exists on a machine.
	// The control plane CHOOSES the address and sends it in the desired-state push (beside the
	// workload tokens, which are per-workload decisions delivered the same way); what comes back
	// here is the node saying it is so, which is also what tells a restarted control plane which
	// addresses are in use.
	Address string `json:"address,omitempty"`
	// ExitCode is what the workload's main process returned, once it has finished. A pointer
	// because zero is the interesting value: an absent field is a workload that has not
	// finished, and a plain int would report every running workload as having succeeded.
	ExitCode *int32 `json:"exitCode,omitempty"`
	// FinishedAt is when the workload's main process left, by the node's clock.
	FinishedAt metav1.Time `json:"finishedAt,omitzero"`
	// Attempts is how many times this job's node has run it, counted against
	// spec.lifecycle.backoffLimit. It is on the object because that is the only durable place:
	// the unit is transient, so a node that rebooted mid-budget would otherwise start counting
	// from zero. Only a job counts — a service's restarts are systemd's and are not budgeted.
	Attempts int32 `json:"attempts,omitempty"`
}

// IsZero reports whether the status is unset, so it is omitted from serialization until a node
// reports a phase.
func (s ApplicationStatus) IsZero() bool {
	return s.Phase == "" && s.Message == ""
}

type ApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Application `json:"items"`
}

// Node is a member of the fleet: a Linux host running the agent. It is created when the agent
// first registers with a certificate the controller trusts, and its identity is that
// certificate's CN — nothing an agent sends can name a different node. The agent owns status
// (capacity, readiness, its heartbeat) and may write nothing else; spec is the operator's, which
// is what makes a cordon something a node cannot lift for itself.
type Node struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   NodeSpec   `json:"spec"`
	Status NodeStatus `json:"status"`
}

type NodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Node `json:"items"`
}

// RestartPolicy values. Never marks a run-to-completion job (one-shot); Always
// (the default) and OnFailure are long-running services.
const (
	RestartAlways    = "Always"
	RestartOnFailure = "OnFailure"
	RestartNever     = "Never"
)

// DefaultTerminationGracePeriodSeconds is the grace period an Application that names none gets:
// long enough for an image that handles SIGTERM to flush, short enough that one which does not
// is not the pace of the node's converge loop.
//
// The value that REACHES a node comes from the field's own schema default, filled in at the
// write boundary; this constant is the node runtime's fallback for an object that never passed
// through it. The two must agree, and api/scheme's TestDefaultsComeFromTheSchema is what keeps
// them agreeing.
const DefaultTerminationGracePeriodSeconds int64 = 30

// EnvVar is one environment variable layered over the image's own, in declared order
// (Kubernetes/OCI shape). The ordered list (not a map) keeps the projected environment
// deterministic, which the node runtime's converge hash relies on. Exactly one source is
// allowed: a literal Value, or a SecretRef the node resolves.
type EnvVar struct {
	// Name is the variable name. Required for a literal or a single-key SecretRef; it must
	// be EMPTY for a wildcard SecretRef, whose names come from the Secret's own keys.
	Name string `json:"name,omitempty"`
	// Value is the literal value. It is stored in the object and rendered into the unit, so
	// it is plain config only — never a credential.
	Value string `json:"value,omitempty"`
	// SecretRef sources the value from a Secret instead of carrying it here. Only the
	// reference is stored; the node resolves it at converge time.
	SecretRef *EnvSecretRef `json:"secretRef,omitempty"`
}

// EnvSecretAllKeys is the Key value that imports EVERY key of a Secret as its own variable.
const EnvSecretAllKeys = "*"

// EnvSecretRef sources an environment variable — or, with Key "*", one variable per key —
// from a Secret in the Application's OWN namespace. There is no namespace field, so a
// cross-namespace reference is not expressible.
//
// Delivery is REAL PROCESS ENVIRONMENT, Kubernetes-style: the workload sees the variable at
// execve, nothing must be sourced. The resolved values never touch persistent storage — they
// would otherwise outlive the agent that fetched them: survive a reboot with nothing to
// re-authorize them, and be copied into every backup of the node. So the agent writes them to a
// RAM-backed (tmpfs) carrier file, which the systemd runtime hands to PID1 via EnvironmentFile=
// (read at spawn; only the PATH is a unit property) and the rootless runtime's sandbox folds
// into the execve envp: only the file's path is ever written down. Nothing about the value
// reaches the unit's text or its Environment=, which systemd exports as a bus property any
// local caller can read with `systemctl show`. The usual env-variable caveats apply — the
// values are visible in the workload's own /proc/self/environ and inherited by its children;
// mount a secret volume instead where that is unacceptable.
//
// Because the values exist only while the agent holds them, a workload that sources any is bound
// to the agent's own unit (Requires=/After=) and is never enabled into a boot target: it starts
// when the agent has the values, and stops when the agent does.
//
// AN ENV-SOURCED SECRET DOES NOT ROTATE. Environment is spawn-time state: nothing can replace it
// in a running process, so the only way to deliver a new value this way is to restart the
// workload — and restarting a workload because a credential rotated is a worse answer than not
// rotating it. The node writes the new value regardless, so the next start for any other reason
// uses it, and a CHANGED SET of variables does restart, because that is a different workload.
// A credential that must rotate under a running process is mounted as a file: a `type: secret`
// volume is the agent's own RAM-backed directory, bound into the workload, so a rewrite there is
// live immediately. This is the same split Kubernetes makes, for the same reason.
type EnvSecretRef struct {
	// Name is the Secret in the Application's namespace.
	Name string `json:"name" jsonschema:"minLength=1"`
	// Key is the data key to read, or "*" (EnvSecretAllKeys) to import every key: each
	// becomes an assignment named after the key, in sorted key order, so the projection is
	// deterministic. A key that is not a valid environment-variable name — a Secret key may
	// be any file basename, e.g. "ca.pem" — fails the converge with that key named, rather
	// than being skipped silently; so does a value carrying a newline, which the file's
	// one-assignment-per-line shape cannot express. Mount such keys instead.
	Key string `json:"key" jsonschema:"minLength=1"`
	// Prefix is prepended to every variable name of a wildcard import (e.g. "PG_"). It must
	// itself be a valid environment-variable name prefix. Ignored for a single key.
	Prefix string `json:"prefix,omitempty"`
	// Optional lets the application start when the Secret (or the named key) is absent.
	// Absent or false is fail-closed: the app is held rather than started without the value,
	// and an already-running one keeps running.
	Optional *bool `json:"optional,omitempty"`
}

// IsWildcard reports whether the reference imports every key of the Secret.
func (r EnvSecretRef) IsWildcard() bool { return r.Key == EnvSecretAllKeys }

// IsOptional reports whether the application may start without the referenced value.
func (r EnvSecretRef) IsOptional() bool { return r.Optional != nil && *r.Optional }

// IsSecret reports whether the variable is sourced from a Secret.
func (v EnvVar) IsSecret() bool { return v.SecretRef != nil }

// ApplicationSpec uses Kubernetes Pod vocabulary on a flat, single-container shape
// (one application = one process = one systemd unit, so there is no containers[]
// list). It stays inside horchestra's invariants: NodeName is author-supplied and
// required (no scheduler fills it); Env is an ordered list whose only indirection is a
// Secret reference in the app's own namespace (see EnvSecretRef); Ports are a pure
// declaration (no in-node data-plane); storage is a separate PersistentVolume Kind,
// referenced by name.
type ApplicationSpec struct {
	// Image is a plain OCI image reference, e.g. reg.io/ns/app:v1 (no scheme).
	Image string `json:"image" jsonschema:"minLength=1"`
	// Command overrides the image ENTRYPOINT and Args overrides its CMD (Kubernetes
	// semantics). Both are literal argv — never interpolated with values.
	Command []string `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	// Env are environment variables layered over the image's own, in declared order. An entry
	// carries either a literal value (plain config — a literal is stored in the object and
	// rendered into the unit) or a secretRef the node resolves, including "key: *" to import
	// every key of a Secret. A credential is still better mounted as a file: read
	// EnvSecretRef's doc comment for what env costs you.
	Env []EnvVar `json:"env,omitempty"`
	// Ports the application listens on — a pure declaration for an external edge/LB
	// (the orchestrator runs no data-plane of its own). Absent = not routed.
	Ports     []Port               `json:"ports,omitempty"`
	Resources ResourceRequirements `json:"resources,omitzero"`
	// Lifecycle is how this workload is run and stopped; Placement is where it may run. Both
	// are traits: policy stated ABOUT a workload that says nothing about what the workload is,
	// which is what separates them from the fields above and lets one be authored, reviewed and
	// (for placement) ignored by the node entirely.
	Lifecycle Lifecycle `json:"lifecycle,omitzero"`
	Placement Placement `json:"placement,omitzero"`
	// HostNetwork runs the workload in the HOST's network namespace: it binds the node's own
	// addresses, its declared ports are real host ports, and it reaches whatever the node
	// reaches — including the node's loopback and every other workload's ports.
	//
	// Today it is the only mode there is, so an unset field means it and an explicit `false` is
	// REFUSED rather than accepted and quietly ignored: a field that reports isolation nobody
	// implements is worse than no field, because it is read as a guarantee. When the pod network
	// lands, unset flips to meaning isolation and this becomes the privileged exception it is
	// meant to be — an edge, a node exporter — rather than the rule.
	//
	// A pointer so that "said nothing" and "asked for isolation" are different states. They have
	// to be: the first is every manifest written so far and the second is a request the tree
	// cannot honour, and answering them the same way would either refuse everything or promise
	// something false.
	HostNetwork *bool `json:"hostNetwork,omitempty"`
	// ServiceName joins this workload to a Service, and joining is DECLARED here rather than
	// selected there: an instance says which service it belongs to, the way a Consul instance
	// registers under a service name, and the Service asserts nothing about a fleet it cannot
	// see. The spelling is StatefulSet's; the meaning is Consul's — in Kubernetes the field only
	// names a headless Service for a DNS subdomain and the selector is what confers membership,
	// so nothing here should be read across from it.
	//
	// It is a reference to a Service in this namespace, validated like any other reference, so a
	// typo cannot conjure a service nobody can find. Empty means the workload is in no catalog
	// and has no virtual address — which is the right answer for the edge itself and for
	// anything else that is reached rather than reaching.
	ServiceName string `json:"serviceName,omitempty" jsonschema:"maxLength=253"`
	// RuntimeClassName selects which node runtime executes this workload (a RuntimeClass
	// analog). Empty selects the node's default runtime. The scheduler places the app only on
	// nodes whose status.runtimes advertises the requested class (a Filter predicate), so a
	// class no node supports leaves the app pending rather than failing at start. Optional.
	RuntimeClassName string `json:"runtimeClassName,omitempty"`
	// SecurityContext sets the workload's identity and confinement. When unset, the
	// image's own USER is used; the hardened floor (NoNewPrivileges, ProtectSystem,
	// read-only rootfs) always applies regardless of this field.
	SecurityContext *SecurityContext `json:"securityContext,omitempty"`
	// Volumes are the storage this workload mounts — each entry is an inline volume
	// (a PersistentVolume or an ephemeral tmpfs) mounted at a path. A pv volume's
	// PersistentVolume is created implicitly on demand when none exists.
	Volumes []VolumeMount `json:"volumes,omitempty"`
	// Values is free-form horchestra-native config (no Pod analog).
	Values map[string]any `json:"values,omitempty"`
}

// Lifecycle is the run-and-stop policy of a workload: whether it is a service the node keeps
// up or a job that is allowed to end, and how long a stop waits before it is not a stop any
// more. It says nothing about what the workload is, which is why it is a section and not more
// fields on the spec — and why a set of them can be authored once and stated about many
// workloads.
type Lifecycle struct {
	// RestartPolicy is Always (default), OnFailure or Never; Never marks a run-to-completion
	// job, which the node keeps in its terminal state instead of starting again. An absent one
	// is filled with the default DECLARED HERE before the object is stored, so what a reader
	// sees is what the node will do — including when the author omits the whole section, which
	// is why the section itself is conjured before the declared defaults run.
	RestartPolicy string `json:"restartPolicy,omitempty" jsonschema:"enum=Always,enum=OnFailure,enum=Never,default=Always"`
	// TerminationGracePeriodSeconds is how long a stop waits for the workload to exit on its own
	// before it is killed. Unset means DefaultTerminationGracePeriodSeconds; 0 kills immediately.
	//
	// It is a pointer so "unset" stays distinguishable from an explicit 0, and it is worth setting
	// deliberately: the workload is PID 1 of its own namespace, where the kernel drops any signal
	// it has installed no handler for, so an image that ignores SIGTERM spends this whole period
	// running before it is killed — on every stop, and therefore on every restart a changed spec
	// causes. Raise it for a workload that needs to flush; lower it for one that cannot shut down
	// gracefully anyway.
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty" jsonschema:"minimum=0,default=30"`
	// ActiveDeadlineSeconds bounds a JOB's whole run — from the moment the node starts it to the
	// moment its process leaves — after which the workload is killed and reported Failed with
	// DeadlineExceeded. Unset means no deadline: a job may run as long as it likes.
	//
	// It has no meaning for a service and admission refuses it there. A service that must not run
	// past some age is not a service, and the field that would express it (systemd's RuntimeMaxSec)
	// does nothing on the unit shape a job uses, so honouring it for one shape and silently
	// ignoring it for the other is the one thing this must not do.
	ActiveDeadlineSeconds *int64 `json:"activeDeadlineSeconds,omitempty" jsonschema:"minimum=1"`
	// BackoffLimit is how many times a failed JOB is retried before it is Failed for good
	// (reason BackoffLimitExceeded). Unset or 0 is no retry, which is what restartPolicy: Never
	// says on its own; 2 means up to three runs in total.
	//
	// The count is status.attempts and it lives on the OBJECT, not on the node: a job's unit is
	// transient and a reboot forgets it, so a node-local counter would hand every job a fresh
	// budget every time its host came back. Like activeDeadlineSeconds it is refused on a service,
	// whose retries are systemd's Restart= and are not counted at all.
	BackoffLimit *int32 `json:"backoffLimit,omitempty" jsonschema:"minimum=0"`
}

// GracePeriod is how long a stop of this workload waits before the kill. The default is applied
// where the value is consumed rather than stamped onto the object, so an app that names no period
// keeps following the default if it ever changes. A negative value cannot reach here — admission
// refuses it — and is clamped anyway rather than becoming a nonsense timeout.
func (l Lifecycle) GracePeriod() time.Duration {
	secs := DefaultTerminationGracePeriodSeconds
	if s := l.TerminationGracePeriodSeconds; s != nil && *s >= 0 {
		secs = *s
	}
	return time.Duration(secs) * time.Second
}

// RunToCompletion reports whether this is a job rather than a service.
func (l Lifecycle) RunToCompletion() bool { return l.RestartPolicy == RestartNever }

// Retries is the effective backoffLimit: how many times a failed job is started again. Unset is 0.
func (l Lifecycle) Retries() int32 {
	if l.BackoffLimit == nil || *l.BackoffLimit < 0 {
		return 0
	}
	return *l.BackoffLimit
}

// Placement is where a workload may run: constraints the SCHEDULER honors, and nothing the node
// ever reads. That is the whole reason it is one section — every field here is spent by the time
// the workload reaches a node, so an operator can retune placement without touching anything the
// runtime acts on.
//
// NodeName is the exception to that and belongs here for exactly that reason: it is the one
// placement statement the SCHEDULER may also write, and it overrides every other field in the
// section, so an author reading a pin and the constraints it silences reads them together.
type Placement struct {
	// NodeName pins the application to a single node: one application runs on exactly one
	// node. Optional, and the one field of this section a node ever sees — it is what the
	// desired-state push is keyed on. When empty the scheduler assigns a node by fitting the
	// app against the rest of this section and writes it here; when the author sets it the app
	// is pinned there and the scheduler leaves it, and the rest of the section, alone.
	NodeName string `json:"nodeName,omitempty"`
	// NodeSelector is placement sugar: the app is placed only on nodes whose scheduling
	// labels match every entry (a subset match) — equivalent to a nodeAffinity.required with
	// these matchLabels. Optional.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Affinity constrains placement by node labels and by proximity to other Applications
	// (co-locate / spread across a topology). It is a scheduler-time constraint, not
	// re-evaluated after placement. Optional.
	Affinity *Affinity `json:"affinity,omitempty"`
	// Priority is an optional scheduling priority (higher = placed and kept first). The
	// built-in scheduler does not read it: it is carried on the object so a queue/preemption
	// engine can be plugged in without a schema change.
	Priority *int32 `json:"priority,omitempty"`
}

// Port is one network port the application listens on, for an external edge to
// route to. Name is an optional label ("http", "metrics", …), free to omit for a
// single-port app; Port is the TCP port and is required.
type Port struct {
	Name string `json:"name,omitempty"`
	Port int    `json:"port" jsonschema:"minimum=1,maximum=65535"`
}

// VolumeMount mounts a Volume into the container at MountPath.
type VolumeMount struct {
	Volume    VolumeSource `json:"volume"`
	MountPath string       `json:"mountPath" jsonschema:"minLength=1"`
	// ReadOnly mounts a pv volume read-only (a read-only bind under ProtectSystem=strict).
	// tmpfs mounts are always writable ephemeral scratch, so it is ignored for them.
	ReadOnly bool `json:"readOnly,omitempty"`
	// SubPath mounts a subdirectory of the volume instead of its root (pv only) — e.g. a
	// per-app subdir of a shared PV. It must be a relative path within the volume (no "..",
	// not absolute); the subdirectory is created on demand.
	SubPath string `json:"subPath,omitempty"`
}

// Volume type discriminators.
const (
	VolumeTypePV     = "pv"     // backed by a PersistentVolume
	VolumeTypeTmpfs  = "tmpfs"  // ephemeral in-memory mount
	VolumeTypeSecret = "secret" // populated from a Secret's data, mounted read-only in RAM
	VolumeTypeToken  = "token"  // the workload's own identity token, minted per audience, in RAM
)

// TokenAudienceAPI is the audience of a workload token addressed at THIS control plane — the one
// a workload presents to read the service-discovery catalog or anything else it is granted.
//
// An audience is what keeps one credential from being every credential. A token minted for Vault
// is a login at Vault and nothing here; this one is a caller at this API and nothing at Vault. A
// workload that holds one has not been handed the other, and a stolen token is worth exactly the
// one door it opens.
const TokenAudienceAPI = "horchestra"

// TokenAudienceVault is the audience of a token addressed at Vault/OpenBao, which pins it through
// the role's bound_audiences. It sits here beside the API one because an audience is a fact about
// the model — who a credential is for — and the two are only meaningful against each other.
const TokenAudienceVault = "vault"

// VolumeSource describes a volume inline on an Application, in one shape for every kind
// (so persistent, ephemeral and secret storage read alike). Type selects the kind: a "pv"
// is backed by a PersistentVolume — created implicitly from Name and Size when none exists,
// though one may also be created separately and is then used as-is; a "tmpfs" is an
// ephemeral systemd TemporaryFileSystem= with no data on disk, its memory charged to the
// app's limit; a "secret" is populated from a Secret's Data and mounted read-only in RAM.
type VolumeSource struct {
	// Type is "pv", "tmpfs", "secret" or "token".
	Type string `json:"type" jsonschema:"enum=pv,enum=tmpfs,enum=secret,enum=token"`
	// Name is the referenced object's name: the PersistentVolume (pv) or Secret (secret).
	// For a pv it is optional and defaults to the Application's name; for a secret it is
	// required (admission rejects a nameless secret mount).
	Name string `json:"name,omitempty"`
	// Size is a pv's requested storage or a tmpfs's memory cap (e.g. "10Gi", "64Mi").
	// Advisory for a pv in this skeleton; an empty tmpfs size is systemd's default
	// (half of RAM). Rejected for a secret.
	Size resource.Quantity `json:"size,omitzero"`
	// Items selects and remaps specific keys of a Secret into the mount (secret only);
	// empty projects every key at its own basename.
	Items []KeyToPath `json:"items,omitempty"`
	// DefaultMode is the file mode for secret keys lacking a per-item Mode (secret only);
	// defaults to 0400.
	DefaultMode *int32 `json:"defaultMode,omitempty"`
	// Optional, when true, lets the app start even if the referenced Secret is absent
	// (secret only); otherwise a missing secret holds the app pending (fail-closed).
	Optional *bool `json:"optional,omitempty"`
	// Audience is who a token volume's token is FOR (token only); empty means this control
	// plane (TokenAudienceAPI). The claim is checked by whoever the token is presented to, so
	// the field is what stops one credential from being every credential — a workload reading
	// the catalog holds a caller at this API, not a login at Vault.
	Audience string `json:"audience,omitempty"`
}

// RoutedGateway is the address every isolated workload routes through, and it is the same on every
// node because it is not an address in the fleet's range at all: it is link-local, it lives on the
// host end of that workload's own veth pair, and it exists to be the next hop of a default route
// and to answer one ARP.
//
// A constant rather than an address carved out of the workload range — the shape Calico uses, and
// the reason a per-node slice is unnecessary: nothing about a workload's address says where it
// runs, so nothing has to be renumbered when it moves.
const RoutedGateway = "169.254.1.1"

// KeyToPath projects one Secret key to a relative path within a secret mount, optionally
// with its own file mode (else the volume's DefaultMode applies).
type KeyToPath struct {
	Key  string `json:"key"`
	Path string `json:"path"`
	Mode *int32 `json:"mode,omitempty"`
}

// IsPV reports whether the mount is a PersistentVolume; IsTmpfs whether it is a tmpfs;
// IsSecret whether it projects a Secret; IsToken whether it projects the workload's own
// identity token.
func (m VolumeMount) IsPV() bool     { return m.Volume.Type == VolumeTypePV }
func (m VolumeMount) IsTmpfs() bool  { return m.Volume.Type == VolumeTypeTmpfs }
func (m VolumeMount) IsSecret() bool { return m.Volume.Type == VolumeTypeSecret }
func (m VolumeMount) IsToken() bool  { return m.Volume.Type == VolumeTypeToken }

// TokenAudience is who this token mount's token is for: the declared audience, or this control
// plane when none is named. The default is the useful one — a workload asking for "a token" wants
// to talk to the API that gave it to it — and it is resolved here rather than defaulted into the
// stored object so that an audience the operator DID write is the only one anything reads back.
func (m VolumeMount) TokenAudience() string {
	if m.Volume.Audience != "" {
		return m.Volume.Audience
	}
	return TokenAudienceAPI
}

// TokenAudiences is every distinct audience an Application asks for, sorted, so the controller
// mints one token per audience and no more.
func (a Application) TokenAudiences() []string {
	seen := map[string]struct{}{}
	for _, m := range a.Spec.Volumes {
		if m.IsToken() {
			seen[m.TokenAudience()] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// SecretName is the Secret a secret mount projects: the explicit Volume.Name (admission
// requires it for a secret mount, so there is no app-name fallback as for a pv).
func (m VolumeMount) SecretName() string { return m.Volume.Name }

// PVName is the PersistentVolume a pv mount resolves to: the explicit Volume.Name, or
// the owning Application's name when unset.
func (m VolumeMount) PVName(appName string) string {
	if m.Volume.Name != "" {
		return m.Volume.Name
	}
	return appName
}

// SecurityContext is the workload's identity on its node. Both fields are assigned by the
// control plane out of the namespace's id block — they are its output, not the author's input —
// and both are pinned for the object's life, because everything the workload writes is owned by
// them.
//
// The confinement floor is not represented here at all, and deliberately so: no-root and
// no-escalation are not settings. They are enforced by ValidRunAsID at admission and again on the
// node, and by NoNewPrivileges plus an empty CapabilityBoundingSet that every unit carries
// unconditionally. A field that could only ever hold one value would advertise a choice that does
// not exist.
type SecurityContext struct {
	// RunAsUser is the workload's own uid, distinct from every other workload's. That is what
	// makes it a boundary: workloads share the host PID namespace, so a shared uid would let one
	// reach another's rootfs, volume data and materialized secrets through /proc/<pid>/root.
	RunAsUser *int64 `json:"runAsUser,omitempty"`
	// RunAsGroup is the group the whole namespace shares, and the workload's primary group. With
	// distinct uids a uid can no longer be what lets two workloads use the same PersistentVolume
	// — this is. Volumes are chgrp'd to it and carry setgid, so what one workload writes stays in
	// the group and stays reachable by the next one that mounts the same volume. It is the
	// primary group rather than a supplementary one because systemd accepts an allocated primary
	// gid for a workload with no account on the node, while a supplementary group must already
	// exist there.
	RunAsGroup *int64 `json:"runAsGroup,omitempty"`
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
	metav1.ListMeta `json:"metadata"`

	Items []PersistentVolume `json:"items"`
}

// Secret Type discriminators.
const (
	// SecretTypeOpaque is an arbitrary user-defined secret (the default).
	SecretTypeOpaque = "Opaque"
	// SecretTypeVault names a secret whose value lives in an external Vault/OpenBao
	// SecretStore: the manifest carries no inline Data, and the node fetches the value
	// directly at materialization.
	SecretTypeVault = "horchestra.io/vault"
)

// Vault-secret annotation keys: a vault secret carries its backing store, path and
// keys as annotations rather than inline Data.
const (
	AnnExternalSecretStore = "secrets.horchestra.io/store"
	AnnExternalSecretPath  = "secrets.horchestra.io/path"
	AnnExternalSecretKeys  = "secrets.horchestra.io/keys"
	// AnnExternalSecretStaticRole names a database static role, "<mount>/<role>", INSTEAD of
	// a KV path: the node reads the credential Vault currently holds for that role rather
	// than a value someone wrote. Mutually exclusive with the path annotation, and admitted
	// only where the VaultStaticRoles feature gate is on. See StaticRoleRef.
	AnnExternalSecretStaticRole = "secrets.horchestra.io/static-role"
	// AnnExternalSecretDynamicRole names a database DYNAMIC role, "<mount>/<role>": Vault
	// creates a user per request and binds it to a lease the node holds, renews and releases.
	// Each consumer is then its own database identity, so revoking one touches nobody else —
	// which a static role, shared by every reader, cannot offer. Mutually exclusive with the
	// other two sources, and admitted only where the VaultDynamicSecrets gate is on.
	AnnExternalSecretDynamicRole = "secrets.horchestra.io/dynamic-role"
)

// Secret holds sensitive key/value data (credentials, keys, config) projected into an
// Application through a type:secret volume. It is namespaced and never crosses namespaces.
// Data values are raw bytes — base64-encoded on the JSON wire, matching Kubernetes — so the
// agent materializes them verbatim into a read-only in-RAM mount.
type Secret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Immutable, when true, forbids any change to the data after creation (metadata may
	// still change), letting the control plane and agent treat the content as stable.
	Immutable *bool `json:"immutable,omitempty"`
	// Type classifies the secret (SecretTypeOpaque by default, or SecretTypeVault for a
	// reference whose value is fetched from a SecretStore rather than carried inline).
	Type string `json:"type,omitempty"`
	// Data is the secret payload: raw bytes per key (base64 on the JSON wire). Keys must be
	// valid path basenames.
	Data map[string][]byte `json:"data,omitempty"`
	// StringData is a write-only convenience for supplying values as UTF-8 strings; the
	// secretPolicy admission plugin merges it into Data and clears it, so a stored Secret
	// only ever carries Data.
	StringData map[string]string `json:"stringData,omitempty"`
}

// ID is the Secret's namespace-qualified key.
func (s Secret) ID() string { return WorkloadID(s.Namespace, s.Name) }

// SecretList is a list of Secrets.
type SecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Secret `json:"items"`
}

type PersistentVolumeSpec struct {
	// Size is the requested storage as a Kubernetes quantity ("10Gi"). It is
	// advisory in this skeleton (a host directory, not a quota-enforced volume).
	Size resource.Quantity `json:"size,omitzero"`
	// Node is the node whose disk backs the volume; only that node provisions it.
	Node string `json:"node,omitempty"`
	// Mode is the directory's octal permission, e.g. "0755" (default) or "1777"
	// for a shared writable directory such as a socket dir.
	Mode string `json:"mode,omitempty"`
	// ReclaimPolicy decides the fate of the data when the PersistentVolume is deleted:
	// "Delete" (ReclaimDelete, the default) reclaims the backing store; "Retain"
	// (ReclaimRetain) keeps the data on disk for manual recovery and the agent stops
	// managing it. The agent records this at provision time, since a deleted PV's spec is
	// gone by the time its data would be reclaimed.
	ReclaimPolicy string `json:"reclaimPolicy,omitempty" jsonschema:"enum=Delete,enum=Retain"`
	// Shared lets more than one Application mount this volume at once. Without it a volume
	// belongs to exactly one Application, and a second one naming it is refused.
	//
	// Exclusive is the default because concurrent writers are a property of the DATA, not of
	// the mount: two apps on one directory is safe for a content-addressed store and silent
	// corruption for a database, and nothing in a volume's declaration tells the two apart.
	// Whoever authored the volume knows which it holds, so the decision is theirs.
	//
	// It lives here and nowhere else on purpose. An Application's inline pv volume has no
	// equivalent field: a workload cannot opt itself into sharing another workload's storage,
	// and a volume created implicitly from an inline mount is exclusive with no way to ask
	// otherwise. Turning it off again is refused while more than one Application still mounts
	// the volume — the invariant would be false the moment the write landed.
	Shared bool `json:"shared,omitempty"`
}

// ID is the PersistentVolume's namespace-qualified identity — the key the agent uses for
// its backing directory and reclaim ledger, so two same-named PVs in different namespaces
// do not collide on a node (mirrors an Application's ID()).
func (pv PersistentVolume) ID() string { return WorkloadID(pv.Namespace, pv.Name) }

// PersistentVolume reclaim policies. There is no driver field: a volume is a directory on the
// node named by spec.node, which is the only backend there is.
const (
	// ReclaimDelete reclaims a PV's backing store when the PV is deleted (the default).
	ReclaimDelete = "Delete"
	// ReclaimRetain keeps a deleted PV's data on disk for manual recovery.
	ReclaimRetain = "Retain"
)

// WorkloadID is the node-unique identity of an Application's workload across
// namespaces: "<namespace>_<name>", or just "<name>" when the namespace is empty. It
// names the app's systemd unit, its rootfs and its reconcile key, so two same-named
// applications in different namespaces do not collide on a node. "_" is not a valid
// namespace/name character (DNS-1123), so it is an unambiguous separator.
func WorkloadID(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "_" + name
}

// Namespace is the soft-multi-tenancy scope: an Application, PersistentVolume, Role or
// RoleBinding lives inside exactly one Namespace, addressed as
// .../namespaces/<ns>/<resource>. The Namespace object is itself cluster-scoped, and the
// set of them is flat — there is no grouping above it.
type Namespace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
}

type NamespaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Namespace `json:"items"`
}

type NodeSpec struct {
	Unschedulable bool `json:"unschedulable,omitempty"`
}

// Platform is a node's operating system and CPU architecture as the Go runtime and an OCI
// image manifest both name them ("linux", "amd64"). It is the machine-readable half of
// NodeStatus.OS, which is prose for a human column and nothing should parse.
type Platform struct {
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
}

// NodeStatus is reported by the node-agent every reconcile. Capacity is the
// resource the node offers (its total, capped by any -config limit); Allocated
// is the sum of the requests of the applications running on it, subtracted from
// capacity as apps are placed. `kubectl get nodes` shows the Allocated/Capacity
// ratio as a percentage, and -o wide the raw amounts.
type NodeStatus struct {
	Capacity  ResourceAmounts `json:"capacity"`
	Allocated ResourceAmounts `json:"allocated"`
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
	Heartbeat metav1.Time `json:"heartbeat,omitzero"`
	// Runtimes are the workload runtimes this node's agent supports (e.g. ["systemd"]). The
	// scheduler filters an Application's runtimeClassName against this set; an empty set means
	// the node advertises only its unnamed default runtime.
	Runtimes []string `json:"runtimes,omitempty"`
	// Platform is the node's OS and CPU architecture, reported by its agent.
	Platform Platform `json:"platform,omitzero"`
	// RoutedNetwork is whether this node can give a workload a network of its own — it has the
	// privileged helper, and that helper holds the capabilities the job needs. Reported by the
	// node because it is a fact about the machine, and the only place it can be known.
	//
	// The scheduler filters on it. Without that, an isolated workload lands wherever it fits and
	// then refuses to start on a node that cannot wire it — a failure at the far end of the
	// system from the decision that caused it.
	RoutedNetwork bool `json:"routedNetwork,omitempty"`
	// Labels are the placement labels the CONTROL PLANE derives from the rest of this status
	// (see DerivedNodeLabels), recomputed on every heartbeat and never taken from the node's
	// own report. They sit beside spec.labels rather than in it because they are observation,
	// not intent — and because the write path that carries them is the node's status
	// subresource, which nodeRestriction confines a node to precisely so it cannot label
	// itself into a placement pool it was never granted.
	Labels map[string]string `json:"labels,omitempty"`
}

// DerivedNodeLabels is the placement labels the control plane computes from a node's
// reported status. It is the ONE definition of that set: the controller stamps it on every
// heartbeat and the scheduler reads the result, so a label cannot mean one thing where it is
// written and another where it is matched.
//
// A field the node has not reported yields no label at all, rather than an empty-valued one:
// a nodeAffinity with the DoesNotExist operator is then answerable, and an Exists term does
// not match a node that reported nothing.
func DerivedNodeLabels(n *Node) map[string]string {
	out := map[string]string{LabelHostname: n.Name}
	if n.Status.Platform.OS != "" {
		out[LabelOS] = n.Status.Platform.OS
	}
	if n.Status.Platform.Arch != "" {
		out[LabelArch] = n.Status.Platform.Arch
	}
	return out
}

// SchedulingLabels is what a placement rule matches against: the operator's spec.labels
// plus the derived status.labels. Every nodeSelector, nodeAffinity and topologyKey lookup
// goes through here, so the two sets are one namespace of keys with one lookup — the
// alternative being a rule that silently matches half the labels a node has.
//
// The derived half wins a collision, which admission also refuses at the source; both,
// because a Node stored before the refusal existed must still not be able to claim an
// architecture it does not have.
//
// The result is READ-ONLY: a node with no derived labels yet (created by an operator, not
// heard from since) gets spec.labels itself rather than a copy of it.
func (n *Node) SchedulingLabels() map[string]string {
	if len(n.Status.Labels) == 0 {
		return n.Labels
	}
	out := make(map[string]string, len(n.Labels)+len(n.Status.Labels))
	maps.Copy(out, n.Labels)
	maps.Copy(out, n.Status.Labels)
	return out
}

// SchedulingLabel is SchedulingLabels for a single key, for the topology lookups that want
// one label and would otherwise build a merged map per node per term.
func (n *Node) SchedulingLabel(key string) (string, bool) {
	if v, ok := n.Status.Labels[key]; ok {
		return v, true
	}
	v, ok := n.Labels[key]
	return v, ok
}

// ResourceAmounts is a set of compute resources — CPU and memory — as Kubernetes
// resource quantities, decoded and printed the standard way ("500m", "2",
// "512Mi", "8Gi"). It is both a node's capacity/allocation and an application's
// requests/limits. Disk is deliberately absent: per-application storage is
// requested through Storage []VolumeClaim, not as a compute resource.
type ResourceAmounts struct {
	CPU    resource.Quantity `json:"cpu,omitzero"`
	Memory resource.Quantity `json:"memory,omitzero"`
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

// Exceeds reports, per resource, where a (a node's summed requests) is over capacity,
// as human-readable "cpu 5 > 4" strings; an empty result means a fits. A resource whose
// capacity is zero is governed by unconstrainedZero: true — the admission create-time
// backstop — treats a zero capacity as unconstrained (never an overage), so an app pinned
// to a node that has not reported capacity is admitted and waits; false — the scheduler's
// Filter predicate — treats a zero capacity as fitting nothing, so any positive request
// overflows and the node is unschedulable. The two callers share this one comparison so
// the admission backstop and the scheduler predicate can never disagree on the same node.
func (a ResourceAmounts) Exceeds(capacity ResourceAmounts, unconstrainedZero bool) []string {
	var over []string
	if overResource(a.CPU, capacity.CPU, unconstrainedZero) {
		over = append(over, fmt.Sprintf("cpu %s > %s", a.CPU.String(), capacity.CPU.String()))
	}
	if overResource(a.Memory, capacity.Memory, unconstrainedZero) {
		over = append(over, fmt.Sprintf("memory %s > %s", a.Memory.String(), capacity.Memory.String()))
	}
	return over
}

// overResource reports whether requested is over capacity for one resource, honoring the
// zero-capacity polarity: an unconstrained zero capacity is never exceeded; a strict zero
// capacity is exceeded by any positive request.
func overResource(requested, capacity resource.Quantity, unconstrainedZero bool) bool {
	if capacity.IsZero() {
		return !unconstrainedZero && !requested.IsZero()
	}
	return requested.Cmp(capacity) > 0
}

// ResourceRequirements are an application's resource requests and limits.
// Requests are subtracted from a node's available capacity when the app is
// placed (the allocation); limits cap what it may use. A request left unset
// defaults to the corresponding limit.
type ResourceRequirements struct {
	Requests ResourceAmounts `json:"requests,omitzero"`
	Limits   ResourceAmounts `json:"limits,omitzero"`
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
