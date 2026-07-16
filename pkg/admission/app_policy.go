package admission

import (
	"context"
	"fmt"

	v1 "ks-tool.dev/horchestra/api/v1"
)

// appPolicy enforces Application spec invariants that need cross-field reasoning
// the per-field JSON schema cannot express:
//
//   - a resource request must not exceed its limit (rejected however it arose — a
//     direct submission or a limits-only patch that drops the limit below an
//     already-defaulted request), so the node accounting stays consistent;
//   - runAsNonRoot must be backed by an explicit non-zero runAsUser. The image's
//     USER is not introspectable at admission, so asserting non-root without a uid
//     is rejected fail-closed rather than trusted.
type appPolicy struct{}

func (appPolicy) Admit(context.Context, *Attributes) error { return nil }

func (appPolicy) Validate(_ context.Context, a *Attributes) error {
	if a.Operation == Delete {
		return nil
	}
	app, ok := a.Object.(*v1.Application)
	if !ok {
		return nil
	}
	r := app.Spec.Resources
	if !r.Limits.CPU.IsZero() && r.Requests.CPU.Cmp(r.Limits.CPU) > 0 {
		return fmt.Errorf("spec.resources: cpu request %s exceeds limit %s", &r.Requests.CPU, &r.Limits.CPU)
	}
	if !r.Limits.Memory.IsZero() && r.Requests.Memory.Cmp(r.Limits.Memory) > 0 {
		return fmt.Errorf("spec.resources: memory request %s exceeds limit %s", &r.Requests.Memory, &r.Limits.Memory)
	}
	if sc := app.Spec.SecurityContext; sc != nil && sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
		if sc.RunAsUser == nil || *sc.RunAsUser == 0 {
			return fmt.Errorf("spec.securityContext: runAsNonRoot requires a non-zero runAsUser")
		}
	}
	return nil
}
