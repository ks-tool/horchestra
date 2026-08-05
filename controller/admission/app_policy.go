package admission

import (
	"context"
	"fmt"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// appPolicy enforces Application spec invariants that need cross-field reasoning the
// per-field JSON schema cannot express: a resource request must not exceed its limit
// (rejected however it arose — a direct submission or a limits-only patch that drops the
// limit below an already-defaulted request), so the node accounting stays consistent; and a
// volume mount must name a known volume type with a mountPath. The no-root securityContext
// floor is enforced separately by policyEnforcement.
// maxVolumesPerApp caps the volumes one Application may declare. Each pv entry becomes a
// PersistentVolume the scheduler creates and binds on its behalf, so the list is a write
// amplifier and needs a ceiling; generous for any real workload.
const maxVolumesPerApp = 64

// appPolicy also holds the one deployment fact a workload's shape depends on: whether this cluster
// can give a workload a network of its own. A field rather than a global, so a test states the
// answer it means instead of mutating something another test is reading.
type appPolicy struct{ routedNetwork bool }

// jobFieldsAreForJobs refuses the two lifecycle fields that only a run-to-completion workload can
// obey. Neither has a meaning for a service, and neither has a systemd property that would give
// it one on the unit shape a service uses — so accepting them would store a field the node
// silently ignores, which is the worst of the three possible answers.
func jobFieldsAreForJobs(lc corev1.Lifecycle) error {
	if lc.RunToCompletion() {
		return nil
	}
	for _, f := range []struct {
		path string
		set  bool
	}{
		{"activeDeadlineSeconds", lc.ActiveDeadlineSeconds != nil},
		{"backoffLimit", lc.BackoffLimit != nil},
	} {
		if f.set {
			return fmt.Errorf("spec.lifecycle.%s: only a run-to-completion workload has one — set restartPolicy: %s",
				f.path, corev1.RestartNever)
		}
	}
	return nil
}

func (appPolicy) Admit(context.Context, *Attributes) error { return nil }

func (p appPolicy) Validate(_ context.Context, a *Attributes) error {
	if a.Operation == Delete || a.IsSubresource() {
		return nil
	}
	app, ok := a.Object.(*corev1.Application)
	if !ok {
		return nil
	}
	// The host network is the only mode the tree implements: nothing gives a workload a network
	// namespace of its own yet. Accepting `false` would hand back a promise of isolation that no
	// code keeps, and a field read as a guarantee is worse than an absent one. The refusal is
	// also where the check will live when the pod network arrives behind its gate — an author
	// asking for isolation a DISABLED datapath cannot provide must meet the same answer, not a
	// workload that quietly runs flat.
	if app.Spec.HostNetwork != nil && !*app.Spec.HostNetwork && !p.routedNetwork {
		return fmt.Errorf("spec.hostNetwork: this cluster has no routed network — start the controller with " +
			"--routed-cidr and give the nodes a network helper, or leave the workload on the host's network. " +
			"Accepting `false` here would promise an isolation nothing on any node provides")
	}
	if err := jobFieldsAreForJobs(app.Spec.Lifecycle); err != nil {
		return err
	}
	r := app.Spec.Resources
	if r.Requests.CPU.Sign() < 0 || r.Requests.Memory.Sign() < 0 || r.Limits.CPU.Sign() < 0 || r.Limits.Memory.Sign() < 0 {
		return fmt.Errorf("spec.resources: requests and limits must not be negative")
	}
	if !r.Limits.CPU.IsZero() && r.Requests.CPU.Cmp(r.Limits.CPU) > 0 {
		return fmt.Errorf("spec.resources: cpu request %s exceeds limit %s", &r.Requests.CPU, &r.Limits.CPU)
	}
	if !r.Limits.Memory.IsZero() && r.Requests.Memory.Cmp(r.Limits.Memory) > 0 {
		return fmt.Errorf("spec.resources: memory request %s exceeds limit %s", &r.Requests.Memory, &r.Limits.Memory)
	}
	// Each pv volume is implicitly provisioned as a PersistentVolume by the scheduler's
	// VolumeBinding plugin — one Create and one Bind per entry, each an fsynced write, with no
	// budget of its own. An unbounded list therefore turns a single Application into tens of
	// thousands of durable writes and permanent fleet-wide state, so the cardinality is bounded
	// here, where the list first arrives.
	if n := len(app.Spec.Volumes); n > maxVolumesPerApp {
		return fmt.Errorf("spec.volumes: %d volumes is more than the %d an application may declare", n, maxVolumesPerApp)
	}
	for i, v := range app.Spec.Volumes {
		switch v.Volume.Type {
		case corev1.VolumeTypePV, corev1.VolumeTypeTmpfs:
		case corev1.VolumeTypeToken:
			// Nothing to name and nothing to select: the token is the workload's own, minted for
			// it by this control plane, and it is one value. A name or an items list would be a
			// field the node has nothing to do with — accepted and silently ignored, which is the
			// worst of the three possible answers.
			if v.Volume.Name != "" {
				return fmt.Errorf("spec.volumes[%d]: a token volume names no object — the token is this workload's own", i)
			}
			if len(v.Volume.Items) > 0 {
				return fmt.Errorf("spec.volumes[%d]: a token volume has no keys to select", i)
			}
			if !v.Volume.Size.IsZero() {
				return fmt.Errorf("spec.volumes[%d]: a token volume must not set size", i)
			}
			if a := v.Volume.Audience; a != "" && corev1.ValidBaseName(a, "volume.audience") != nil {
				return fmt.Errorf("spec.volumes[%d]: %q is not a usable audience", i, a)
			}
		case corev1.VolumeTypeSecret:
			if v.Volume.Name == "" {
				return fmt.Errorf("spec.volumes[%d]: a secret volume requires volume.name", i)
			}
			if !v.Volume.Size.IsZero() {
				return fmt.Errorf("spec.volumes[%d]: a secret volume must not set size", i)
			}
			// items[].path is a tenant-controlled destination that flows into the node's
			// systemd bind directives and filesystem joins; reject injection/traversal.
			for j, it := range v.Volume.Items {
				if err := corev1.ValidRelPath(it.Path); err != nil {
					return fmt.Errorf("spec.volumes[%d].items[%d]: %w", i, j, err)
				}
			}
		default:
			return fmt.Errorf("spec.volumes[%d]: unknown volume type %q (want %q, %q, %q or %q)",
				i, v.Volume.Type, corev1.VolumeTypePV, corev1.VolumeTypeTmpfs, corev1.VolumeTypeSecret, corev1.VolumeTypeToken)
		}
		// mountPath reaches the node's systemd mount directives (space/':'-separated lists) and
		// overlay/join paths; a space, ':' or '..' would inject a bind or escape the mount root.
		if err := corev1.ValidMountPath(v.MountPath); err != nil {
			return fmt.Errorf("spec.volumes[%d]: %w", i, err)
		}
	}
	return validateEnv(app.Spec.Env)
}

// maxEnvPerApp caps the entries one Application may declare. A wildcard secretRef expands on
// the node into one variable per key, so the declared list is not the final count; the Secret's
// own 1 MiB cap bounds that side.
const maxEnvPerApp = 256

// validateEnv enforces the env invariants that can be decided from the Application alone: one
// source per entry, a name the node can express, and no two entries claiming the same name. The
// names a wildcard import derives from a Secret's keys cannot be checked here — the Secret may
// not exist yet, and its keys may change afterwards — so the node re-validates every resolved
// name and value and fails the converge with the offending key named.
func validateEnv(env []corev1.EnvVar) error {
	if n := len(env); n > maxEnvPerApp {
		return fmt.Errorf("spec.env: %d entries is more than the %d an application may declare", n, maxEnvPerApp)
	}
	claimed := map[string]struct{}{}
	for i, v := range env {
		switch {
		case v.SecretRef == nil:
			if err := corev1.ValidEnvName(v.Name, "name"); err != nil {
				return fmt.Errorf("spec.env[%d]: %w", i, err)
			}
			if err := corev1.ValidEnvValue(v.Name, v.Value); err != nil {
				return fmt.Errorf("spec.env[%d]: %w", i, err)
			}
		case v.Value != "":
			// Two sources for one variable is a mistake with a silent winner; refuse it rather
			// than pick.
			return fmt.Errorf("spec.env[%d]: set either value or secretRef, not both", i)
		default:
			ref := v.SecretRef
			if ref.Name == "" {
				return fmt.Errorf("spec.env[%d]: secretRef requires name", i)
			}
			if ref.Key == "" {
				return fmt.Errorf("spec.env[%d]: secretRef requires key (a data key, or %q for every key)", i, corev1.EnvSecretAllKeys)
			}
			if err := corev1.ValidEnvPrefix(ref.Prefix); err != nil {
				return fmt.Errorf("spec.env[%d]: %w", i, err)
			}
			if ref.IsWildcard() {
				// The variable names come from the Secret's keys, so a name here would be
				// silently ignored — and a wildcard claims no single name to check for
				// collisions.
				if v.Name != "" {
					return fmt.Errorf("spec.env[%d]: a wildcard secretRef must not set name; its names come from the secret's keys (use prefix to scope them)", i)
				}
				continue
			}
			if err := corev1.ValidEnvName(v.Name, "name"); err != nil {
				return fmt.Errorf("spec.env[%d]: %w", i, err)
			}
			if err := corev1.ValidBaseName(ref.Key, "secretRef.key"); err != nil {
				return fmt.Errorf("spec.env[%d]: %w", i, err)
			}
			if ref.Prefix != "" {
				return fmt.Errorf("spec.env[%d]: secretRef.prefix applies only to a wildcard key (%q)", i, corev1.EnvSecretAllKeys)
			}
		}
		if _, dup := claimed[v.Name]; dup {
			return fmt.Errorf("spec.env[%d]: %q is declared twice", i, v.Name)
		}
		claimed[v.Name] = struct{}{}
	}
	return nil
}
