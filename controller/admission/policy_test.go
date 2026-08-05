package admission

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

func TestPolicyEnforcement(t *testing.T) {
	ctx := context.Background()

	// Admit defaults an absent securityContext to the non-root floor.
	app := &corev1.Application{ObjectMeta: metav1.ObjectMeta{Name: "web"}}
	a := &Attributes{Operation: Create, Object: app}
	if err := (policyEnforcement{}).Admit(ctx, a); err != nil {
		t.Fatalf("admit: %v", err)
	}
	sc := app.Spec.SecurityContext
	if sc == nil || sc.RunAsUser == nil || *sc.RunAsUser != restrictedFloorUID {
		t.Fatalf("admit must default runAsUser to %d, got %+v", restrictedFloorUID, sc)
	}
	// No-root and no-escalation are not fields to assert on: they are enforced by the range check
	// below, by the node-side backstop, and by the NoNewPrivileges + empty CapabilityBoundingSet
	// every unit carries unconditionally.
	if sc.RunAsGroup == nil || *sc.RunAsGroup != restrictedFloorUID {
		t.Fatalf("admit must default runAsGroup to %d, got %+v", restrictedFloorUID, sc)
	}
	if err := (policyEnforcement{}).Validate(ctx, a); err != nil {
		t.Fatalf("a defaulted app must validate, got %v", err)
	}

	// An explicit root request is not silently rewritten by Admit and is rejected by Validate.
	zero := int64(0)
	rootApp := &corev1.Application{Spec: corev1.ApplicationSpec{SecurityContext: &corev1.SecurityContext{RunAsUser: &zero}}}
	ra := &Attributes{Operation: Create, Object: rootApp}
	_ = (policyEnforcement{}).Admit(ctx, ra)
	// The message names the offending field rather than a fixed "uid 0" phrase: the check is
	// shared with runAsGroup and with the out-of-range ids that truncate to 0 on the node.
	if err := (policyEnforcement{}).Validate(ctx, ra); err == nil ||
		!strings.Contains(err.Error(), "runAsUser") || !strings.Contains(err.Error(), "0") {
		t.Fatalf("explicit uid 0 must be rejected, got %v", err)
	}

	// Wired into the DefaultChain: a plain app comes out defaulted to the floor and valid.
	app2 := &corev1.Application{ObjectMeta: metav1.ObjectMeta{Name: "web2"}}
	err := DefaultChain(nil, nil).Run(ctx, &Attributes{GVK: corev1.GroupVersion.WithKind("Application"), Operation: Create, Object: app2})
	if err != nil {
		t.Fatalf("DefaultChain must accept + default a plain app, got %v", err)
	}
	if app2.Spec.SecurityContext == nil || app2.Spec.SecurityContext.RunAsUser == nil {
		t.Error("DefaultChain must default the securityContext via policyEnforcement")
	}
}

// TestPolicyEnforcementExecInputs checks the defense-in-depth guard on user-supplied
// command/args/env: a leading systemd ExecStart modifier on command[0], or a control char that
// could inject a "User=0" directive, is rejected (the node-render guards stay authoritative for
// image-sourced values).
func TestPolicyEnforcementExecInputs(t *testing.T) {
	ctx := context.Background()
	validate := func(spec corev1.ApplicationSpec) error {
		app := &corev1.Application{Spec: spec}
		a := &Attributes{Operation: Create, Object: app}
		_ = (policyEnforcement{}).Admit(ctx, a) // default the securityContext so we reach the exec guard
		return (policyEnforcement{}).Validate(ctx, a)
	}
	reject := []struct {
		name, want string
		spec       corev1.ApplicationSpec
	}{
		{"command + modifier", "command[0]", corev1.ApplicationSpec{Command: []string{"+/bin/sh", "-c", "id"}}},
		{"command ! modifier", "command[0]", corev1.ApplicationSpec{Command: []string{"!/bin/sh"}}},
		{"command @ modifier", "command[0]", corev1.ApplicationSpec{Command: []string{"@/bin/sh"}}},
		{"command : modifier", "command[0]", corev1.ApplicationSpec{Command: []string{":/bin/sh"}}},
		{"command newline", "command[0]", corev1.ApplicationSpec{Command: []string{"/bin/sh\nUser=0"}}},
		{"args newline", "args[1]", corev1.ApplicationSpec{Command: []string{"/bin/sh"}, Args: []string{"-c", "x\nUser=0"}}},
		{"env value newline", "env", corev1.ApplicationSpec{Env: []corev1.EnvVar{{Name: "X", Value: "y\nUser=0"}}}},
		{"env key newline", "env", corev1.ApplicationSpec{Env: []corev1.EnvVar{{Name: "X\nUser=0", Value: "y"}}}},
		{"duplicate env name", "duplicate", corev1.ApplicationSpec{Env: []corev1.EnvVar{{Name: "X", Value: "a"}, {Name: "X", Value: "b"}}}},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			if err := validate(tc.spec); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
	// A clean command (absolute), args (a leading '-' is fine), and env must pass.
	ok := corev1.ApplicationSpec{Command: []string{"/bin/sh"}, Args: []string{"-c", "echo hi"}, Env: []corev1.EnvVar{{Name: "LANG", Value: "C"}}}
	if err := validate(ok); err != nil {
		t.Fatalf("a clean command/args/env must pass: %v", err)
	}
}

// The restartPolicy enum and a non-negative terminationGracePeriodSeconds are the input schema's
// rules now, checked on the raw body before it decodes — see api/scheme's TestInputSchema*. They
// were tested here while admission restated them in Go.
