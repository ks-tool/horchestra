package admission

import (
	"context"
	"strings"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// restrictedFloorUID is the non-root uid/gid the compiled no-root floor defaults an
// Application's securityContext to when RunAsUser/RunAsGroup are left unset.
const restrictedFloorUID = corev1.DefaultRunAsID

// policyEnforcement is the compiled no-root floor: every Application runs as a non-root
// user with privilege escalation disabled, regardless of storage, lister, or
// authorizer (the floor is a Go constant needing no storage). It intentionally holds
// no lister and reads no policy objects — the configurable ClusterPolicy/Policy layer was
// removed pending its redesign (fixed-rules + CEL, docs/ng-architecture.md §0/L4); the
// floor stands on its own until then.
type policyEnforcement struct{}

func (policyEnforcement) Admit(_ context.Context, a *Attributes) error {
	if a.Operation == Delete {
		return nil
	}
	app, ok := a.Object.(*corev1.Application)
	if !ok {
		return nil
	}
	if app.Spec.SecurityContext == nil {
		app.Spec.SecurityContext = &corev1.SecurityContext{}
	}
	sc := app.Spec.SecurityContext
	if sc.RunAsUser == nil {
		sc.RunAsUser = new(restrictedFloorUID)
	}
	if sc.RunAsGroup == nil {
		sc.RunAsGroup = new(restrictedFloorUID)
	}
	return nil
}

func (policyEnforcement) Validate(_ context.Context, a *Attributes) error {
	if a.Operation == Delete {
		return nil
	}
	app, ok := a.Object.(*corev1.Application)
	if !ok {
		return nil
	}
	sc := app.Spec.SecurityContext
	// Fail closed on anything still asking to run as uid/gid 0 — including the ids that only
	// BECOME 0 on the node: the range check is part of the floor, not input hygiene, because
	// the kernel reads a uid in uid_t and 2^32 truncates to root (see corev1.ValidRunAsID).
	if sc == nil || sc.RunAsUser == nil {
		return Forbidden("spec.securityContext.runAsUser: the no-root floor forbids running as uid 0 — set a non-zero runAsUser")
	}
	if err := corev1.ValidRunAsID("spec.securityContext.runAsUser", *sc.RunAsUser); err != nil {
		return Forbidden("%s", err)
	}
	if sc.RunAsGroup != nil {
		if err := corev1.ValidRunAsID("spec.securityContext.runAsGroup", *sc.RunAsGroup); err != nil {
			return Forbidden("%s", err)
		}
	}
	// Field shape — the restartPolicy enum, a non-negative terminationGracePeriodSeconds, a
	// non-empty image — is the input schema's, enforced on the raw body before anything decodes
	// it (api/scheme). What stays here is what a per-field schema cannot state: the no-root
	// floor above, and the exec guards below, which read three fields together against what
	// systemd does with them.
	return validateExecInputs(app.Spec)
}

// execModifiers are the leading characters systemd reads as ExecStart modifiers; '+' and '!'
// run the command with full privileges, bypassing User= and the hardened floor.
const execModifiers = "@-:+!"

// validateExecInputs is a defense-in-depth guard for the node renderer's no-root guarantee: it
// rejects user-supplied command/args/env that could bypass User= at the systemd layer — a leading
// ExecStart privilege modifier on the program (argv[0] = command[0]; '+'/'!' run as root), or a
// newline/CR/NUL that would inject a directive line such as "User=0". Image-sourced command/env
// are not visible here, so the node-render guards (pkg/systemd) remain authoritative; this is the
// earlier, clearer 403 for the manifest path. Only command[0] takes a modifier — args legitimately
// start with '-'.
func validateExecInputs(spec corev1.ApplicationSpec) error {
	if c := spec.Command; len(c) > 0 && c[0] != "" && strings.ContainsRune(execModifiers, rune(c[0][0])) {
		return Forbidden("spec.command[0] %q: a leading %q is a systemd ExecStart modifier ('+'/'!' run as root) — use an absolute or bare program path", c[0], c[0][:1])
	}
	for i, v := range spec.Command {
		if strings.ContainsAny(v, "\n\r\x00") {
			return Forbidden("spec.command[%d]: control characters are not allowed (they can inject a systemd directive)", i)
		}
	}
	for i, v := range spec.Args {
		if strings.ContainsAny(v, "\n\r\x00") {
			return Forbidden("spec.args[%d]: control characters are not allowed (they can inject a systemd directive)", i)
		}
	}
	seenEnv := make(map[string]bool, len(spec.Env))
	for i, e := range spec.Env {
		if strings.ContainsAny(e.Name, "\n\r\x00") || strings.ContainsAny(e.Value, "\n\r\x00") {
			return Forbidden("spec.env[%d] (%q): control characters are not allowed (they can inject a systemd directive)", i, e.Name)
		}
		// Reject duplicate names: a repeated Name resolves inconsistently across runtimes
		// (systemd Environment= is last-wins; execve+glibc getenv is first-wins).
		if seenEnv[e.Name] {
			return Forbidden("spec.env[%d]: duplicate name %q", i, e.Name)
		}
		seenEnv[e.Name] = true
	}
	return nil
}
