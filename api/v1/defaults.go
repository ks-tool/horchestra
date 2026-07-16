package v1

// Defaulter is implemented by Kinds that fill in defaults for unset fields. The
// service calls Default() on a decoded object before admission, so the stored
// object carries its defaults explicitly. This is the Kubernetes defaulting model
// (the SetDefaults_* / webhook.Defaulter functions): arbitrary Go, run as a
// mutation before validation — able to express conditional and computed defaults
// that a static schema `default` keyword cannot.
type Defaulter interface {
	Default()
}

// Default fills in the Application's defaults.
//
//   - Static: RestartPolicy defaults to Always. (The schema also carries this via
//     a `default=` tag for discovery/UI-form pre-fill, but the behavioral source of
//     truth is here.)
//   - Computed: an unset resource request falls back to the matching limit — the
//     same rule the scheduler applies via EffectiveRequests, materialized here so
//     the reservation accounted for on the node is explicit in the stored spec.
//     This is exactly the kind of default that cannot be a static tag.
func (a *Application) Default() {
	if a.Spec.RestartPolicy == "" {
		a.Spec.RestartPolicy = RestartAlways
	}
	req, lim := &a.Spec.Resources.Requests, a.Spec.Resources.Limits
	if req.CPU.IsZero() && !lim.CPU.IsZero() {
		req.CPU = lim.CPU.DeepCopy()
	}
	if req.Memory.IsZero() && !lim.Memory.IsZero() {
		req.Memory = lim.Memory.DeepCopy()
	}
}
