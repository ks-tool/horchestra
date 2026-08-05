// Package features is the feature-gate registry: the named capabilities a deployment opts
// into, each off until an operator turns it on with --feature-gates.
//
// A gate is for something BUILT that not every cluster should carry by default: a capability
// whose shape may still move, or a hardening whose cost an operator should choose to accept.
// It is not a configuration knob — a gate has exactly two states and no tuning — and a
// capability that has settled loses its gate rather than gaining a default of true forever.
//
// Default-off is never the less safe side. Where a gate governs a safety/convenience trade,
// the CONVENIENCE is what a cluster opts into, so a deployment that sets no gates at all gets
// the careful behaviour rather than inheriting a default someone chose for ergonomics.
//
// Gates are a VALUE, not a package-global. Every component that consults one is handed the
// set it runs with, the same way it is handed its Lister or its Storage — so a test states
// the gates it means instead of mutating a global another test is also reading.
package features

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Feature is a gate's name, as it appears in --feature-gates.
type Feature string

const (
	// VaultStaticRoles admits a Secret that names a Vault/OpenBao database STATIC ROLE
	// instead of a KV path: Vault owns one fixed database user and rotates its password on
	// its own schedule, and the node re-reads the current password as it turns over.
	//
	// It is gated because it puts a rotating value under a running workload, which only one
	// of the two delivery shapes survives: a type:secret volume is the agent's RAM carrier
	// bound into the workload, so a rewrite there is live, while an env secretRef is
	// spawn-time state that cannot change without a restart. A deployment turns this on
	// once it knows which of its workloads read credentials from a file.
	VaultStaticRoles Feature = "VaultStaticRoles"

	// AutoNodeCertRotation lets the control plane sign a node's renewal of its OWN
	// certificate without an operator. Off — the default — every renewal waits Pending until
	// someone approves it.
	//
	// It is off by default because a node certificate is otherwise self-renewing, and that
	// makes a leaked one permanent: the check guarding the automatic path is a verified
	// system:nodes caller re-issuing a certificate for its own name, which is satisfied by
	// whoever holds the key. Nothing here can tell the thief from the owner. A live session
	// proves only that SOMEONE is connected, and it is the legitimate agent's session that
	// would satisfy any test for one — so there is no check to add that would make the
	// automation safe, only a human to put in the path or not.
	//
	// Turning it on is a real choice, not laziness: a fleet large enough that per-node
	// approval is not operable is a fleet where the automation is worth its risk. What it
	// costs when off is that a certificate expiring unattended drops that node out of the
	// fleet until someone approves — its workloads keep running, since systemd supervises
	// them and not the agent; what stops is managing them.
	AutoNodeCertRotation Feature = "AutoNodeCertRotation"

	// VaultDynamicSecrets admits a Secret naming a Vault/OpenBao database DYNAMIC role: Vault
	// creates a database user per request and binds it to a lease, so each consumer is its
	// own identity and revoking one touches nobody else.
	//
	// It is gated separately from static roles because it puts the node in a holding
	// relationship it was not in before. A lease has to be RENEWED before it expires and
	// RELEASED when the workload it belongs to goes away; an agent that stops renewing costs
	// a workload its database access, and one that fails to release leaks a live credential
	// until Vault's max_ttl. None of that exists for a static role, whose password Vault
	// rotates whether anyone is listening or not. Turn it on where per-consumer identity —
	// an audit log that names the caller, revocation that touches one workload — is worth
	// that.
	VaultDynamicSecrets Feature = "VaultDynamicSecrets"

	// NodeLogs serves a node agent's own unit journal at
	// /apis/horchestra.io/v1/nodes/<name>/log, readable with `kubectl get --raw`.
	//
	// It is gated because a node's journal is not a tenant's object: it is the log of the
	// process that runs every workload on that host, and reading it is an operator action, not
	// an application one. Off, the route is NOT REGISTERED — the answer is the router's
	// ordinary 404, indistinguishable from any unknown path, so nothing about the fleet can be
	// probed by asking. There is no handler behind a permission check to get past.
	//
	// On, it is authorized like any other subresource of a cluster-scoped Kind (`nodes/log`),
	// because the path is a real /apis path and the middleware classifies it as one. Nobody
	// holding namespace-scoped rights comes near it.
	//
	// What it serves is deliberately the AGENT'S unit, not the host journal: the host journal
	// carries every workload's output, and one call to it would bypass the per-workload
	// permission check pods/log makes.
	NodeLogs Feature = "NodeLogs"
)

// Stages a gate can be at. Alpha is "the shape may still change"; Beta is "the shape is
// settled, the default is not".
const (
	StageAlpha = "alpha"
	StageBeta  = "beta"
)

// Spec is what is known about a gate: whether it is on when nobody says otherwise, how
// settled it is, and one line an operator can read in --help.
type Spec struct {
	Default bool
	Stage   string
	Doc     string
}

// registry is every gate this build knows. A name outside it is a typo, and Parse says so
// rather than accepting a gate that silently does nothing.
var registry = map[Feature]Spec{
	VaultStaticRoles: {
		Default: false,
		Stage:   StageAlpha,
		Doc:     "admit Secrets naming a Vault database static role, whose password Vault rotates on a schedule",
	},
	VaultDynamicSecrets: {
		Default: false,
		Stage:   StageAlpha,
		Doc:     "admit Secrets naming a Vault database dynamic role: a per-consumer credential the node holds a lease on",
	},
	AutoNodeCertRotation: {
		Default: false,
		Stage:   StageBeta,
		Doc:     "sign a node's renewal of its own certificate without an operator (off: every renewal waits for approval)",
	},
	NodeLogs: {
		Default: false,
		Stage:   StageAlpha,
		Doc:     "serve a node agent's own unit journal at /apis/horchestra.io/v1/nodes/<name>/log (off: the route does not exist)",
	},
}

// Gates is the set a component runs with: an explicit entry overrides the registry default,
// and a nil map is every gate at its default — which is what a caller that has no opinion
// (a unit test, a tool) should pass.
type Gates map[Feature]bool

// Enabled reports whether f is on. An unknown feature is off: the only way one reaches here
// is a build where it was removed, and a removed capability is not on.
func (g Gates) Enabled(f Feature) bool {
	if v, ok := g[f]; ok {
		return v
	}
	return registry[f].Default
}

// Parse reads the --feature-gates form, "Name=true,Other=false". An unknown name or a
// non-boolean value is an error naming what is known, because a mistyped gate would
// otherwise read as a working one that does nothing.
func Parse(s string) (Gates, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	g := Gates{}
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("feature gate %q: want Name=true or Name=false", part)
		}
		f := Feature(strings.TrimSpace(name))
		if _, known := registry[f]; !known {
			return nil, fmt.Errorf("unknown feature gate %q; this build knows: %s", f, strings.Join(Names(), ", "))
		}
		on, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("feature gate %q: %q is not a boolean", f, value)
		}
		g[f] = on
	}
	return g, nil
}

// String renders the set back in the flag's own form, sorted so it is stable in logs.
func (g Gates) String() string {
	if len(g) == 0 {
		return ""
	}
	out := make([]string, 0, len(g))
	for _, f := range slices.Sorted(maps.Keys(g)) {
		out = append(out, string(f)+"="+strconv.FormatBool(g[f]))
	}
	return strings.Join(out, ",")
}

// Names is every gate this build knows, sorted — for --help and for the error a typo gets.
func Names() []string {
	out := make([]string, 0, len(registry))
	for f := range registry {
		out = append(out, string(f))
	}
	slices.Sort(out)
	return out
}

// Describe is what is known about one gate. It exists so a command can GENERATE a flag per gate —
// its name, its default and its help — instead of restating the registry in a second place that can
// fall behind it. Unknown reports false rather than returning a zero Spec that reads as a real gate
// which is off.
func Describe(f Feature) (Spec, bool) {
	s, ok := registry[f]
	return s, ok
}

// Usage is the one-line-per-gate text a command puts in its --feature-gates help.
func Usage() string {
	out := make([]string, 0, len(registry))
	for _, name := range Names() {
		s := registry[Feature(name)]
		out = append(out, fmt.Sprintf("%s=true|false (%s, default %t): %s", name, s.Stage, s.Default, s.Doc))
	}
	return strings.Join(out, "; ")
}
