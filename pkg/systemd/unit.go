//go:build linux

package systemd

import (
	"io"
	"strings"

	"github.com/coreos/go-systemd/v22/unit"
)

type Unit struct {
	Description      string
	ExecStart        []string
	RootDirectory    string
	WorkingDirectory string
	User             string
	Group            string
	// DynamicUser makes systemd take the numeric User=/Group= as given instead of resolving it
	// in the node's user database. Without it a uid with no account there kills the unit at
	// 217/USER before the workload's first instruction — and per-namespace ids are allocated by
	// the control plane, so no account for them can exist on the node. systemd registers the id
	// transiently for the unit's lifetime, which is also why two units may not share one.
	DynamicUser bool
	Environment []string
	// EnvironmentFiles are EnvironmentFile= paths PID1 reads at spawn. Unlike Environment=
	// (a bus property any local caller reads via `systemctl show`), only the PATH is ever
	// visible — which is why Secret-sourced variables travel this way and never inline.
	EnvironmentFiles []string
	// Type is the systemd service Type= (default "simple"; "oneshot" for a
	// run-to-completion job).
	Type string
	// RemainAfterExit keeps a successfully-finished unit in the "active (exited)"
	// state instead of "inactive" — set for a oneshot job so a completed run is not
	// seen as stopped and re-executed by the reconciler's self-heal.
	RemainAfterExit bool
	Restart         string
	// WantedBy is the [Install] target the unit enables into. Empty defaults to
	// "multi-user.target" (a system unit); a per-user unit uses "default.target".
	WantedBy string
	// NoInstall omits the [Install] section entirely, so the unit can never be enabled into a
	// boot target. It is set for a unit that carries secret material: its credentials only exist
	// while the agent is there to hand them over, so a boot-time start without the agent would
	// come up without them.
	NoInstall bool
	// Requires and After are [Unit] dependencies. A secret-bearing workload requires the agent
	// unit: the values live in RAM only, so the workload must not outlive the process that can
	// re-materialize them, and must be ordered after it.
	Requires []string
	After    []string
	// StartLimitIntervalSec / StartLimitBurst bound the restart rate (a [Unit] backstop):
	// more than Burst starts within the interval drops the unit to "failed" instead of
	// flapping forever and spinning the CPU. Empty leaves systemd's default.
	StartLimitIntervalSec string
	StartLimitBurst       string
	// StateDirectory is the systemd StateDirectory= name: systemd creates
	// /var/lib/<name> owned by User= (recursively re-owning an existing one) and
	// exempts it from ProtectSystem=strict — the service's writable data root.
	StateDirectory string
	Hardened       bool
	// Resource limits, applied to the unit's cgroup (empty = unset). CPUWeight and
	// MemoryLow express the application's requests (relative share, reclaim
	// protection); CPUQuota and MemoryMax express its limits (hard caps).
	CPUWeight string
	CPUQuota  string
	MemoryLow string
	MemoryMax string
	// BindPaths are "source:destination" writable bind mounts (host dir into the
	// RootDirectory); ReadWritePaths exempt those destinations from
	// ProtectSystem=strict so the workload can write to its volumes.
	BindPaths []string
	// BindReadOnlyPaths are "source:destination" read-only bind mounts; their destinations
	// are deliberately NOT added to ReadWritePaths, so they stay read-only under
	// ProtectSystem=strict.
	BindReadOnlyPaths []string
	ReadWritePaths    []string
	// TemporaryFileSystems are "path[:options]" ephemeral in-memory mounts (writable
	// tmpfs), for temporary paths that need no PersistentVolume.
	TemporaryFileSystems []string
	// SetCredentials are "id:value" service credentials: systemd places each in the unit's
	// private, in-RAM credentials directory (%d, 0700, files 0400) owned by the service
	// user, from where a BindReadOnlyPaths=%d/id:… projects it into the workload — so a
	// secret value lives only in RAM and never in the workload's writable space.
	SetCredentials []string
}

// Options returns the unit as ordered go-systemd unit options, grouped by
// section ([Unit]/[Service]/[Install]).
func (u Unit) Options() []*unit.UnitOption {
	var opts []*unit.UnitOption
	if len(u.Description) > 0 {
		opts = append(opts, unit.NewUnitOption("Unit", "Description", u.Description))
	}
	for _, r := range u.Requires {
		opts = append(opts, unit.NewUnitOption("Unit", "Requires", r))
	}
	for _, a := range u.After {
		opts = append(opts, unit.NewUnitOption("Unit", "After", a))
	}
	if len(u.StartLimitIntervalSec) > 0 {
		opts = append(opts, unit.NewUnitOption("Unit", "StartLimitIntervalSec", u.StartLimitIntervalSec))
	}
	if len(u.StartLimitBurst) > 0 {
		opts = append(opts, unit.NewUnitOption("Unit", "StartLimitBurst", u.StartLimitBurst))
	}
	svcType := u.Type
	if len(svcType) == 0 {
		svcType = "simple"
	}
	opts = append(opts, unit.NewUnitOption("Service", "Type", svcType))
	if len(u.RootDirectory) > 0 {
		opts = append(opts, unit.NewUnitOption("Service", "RootDirectory", u.RootDirectory))
	}
	if len(u.WorkingDirectory) > 0 {
		opts = append(opts, unit.NewUnitOption("Service", "WorkingDirectory", u.WorkingDirectory))
	}
	if u.DynamicUser {
		// Emitted before User=, so the numeric id that follows is taken rather than looked up.
		opts = append(opts, unit.NewUnitOption("Service", "DynamicUser", "yes"))
	}
	if len(u.User) > 0 {
		opts = append(opts, unit.NewUnitOption("Service", "User", u.User))
	}
	if len(u.Group) > 0 {
		opts = append(opts, unit.NewUnitOption("Service", "Group", u.Group))
	}
	if len(u.StateDirectory) > 0 {
		opts = append(opts, unit.NewUnitOption("Service", "StateDirectory", u.StateDirectory))
	}
	for _, e := range u.Environment {
		opts = append(opts, unit.NewUnitOption("Service", "Environment", quoteEnv(e)))
	}
	for _, f := range u.EnvironmentFiles {
		opts = append(opts, unit.NewUnitOption("Service", "EnvironmentFile", f))
	}
	opts = append(opts, unit.NewUnitOption("Service", "ExecStart", execStartLine(u.ExecStart)))
	if u.RemainAfterExit {
		opts = append(opts, unit.NewUnitOption("Service", "RemainAfterExit", "yes"))
	}
	if len(u.Restart) > 0 {
		opts = append(opts, unit.NewUnitOption("Service", "Restart", u.Restart))
	}
	for _, r := range []struct{ key, val string }{
		{"CPUWeight", u.CPUWeight}, {"CPUQuota", u.CPUQuota},
		{"MemoryLow", u.MemoryLow}, {"MemoryMax", u.MemoryMax},
	} {
		if len(r.val) > 0 {
			opts = append(opts, unit.NewUnitOption("Service", r.key, r.val))
		}
	}
	if u.Hardened {
		// The always-on hardening floor (the R6–R10 confinement of the no-root policy). buildUnit
		// sets Hardened for EVERY workload, so NoNewPrivileges (which stops a workload regaining
		// privilege via a setuid/file-caps binary or a user namespace) and the rest never depend on
		// a per-call decision — yet it stays OFF the agent/daemon units (Hardened=false), which must
		// exec setuid helpers like newuidmap (userns) and fusermount3 (fuse). An empty
		// CapabilityBoundingSet= drops ALL capabilities: the MVP has no workload that needs one (a
		// privileged edge LB is external / service-discovery based), and real-root workloads go to a
		// future Firecracker runtime. Still deliberately NOT here: SystemCallFilter=@system-service
		// (must be validated against real workloads with io_uring/unusual syscalls first).
		opts = append(opts,
			unit.NewUnitOption("Service", "NoNewPrivileges", "yes"),
			unit.NewUnitOption("Service", "CapabilityBoundingSet", ""),
			unit.NewUnitOption("Service", "ProtectSystem", "strict"),
			unit.NewUnitOption("Service", "ProtectHome", "yes"),
			unit.NewUnitOption("Service", "PrivateTmp", "yes"),
			unit.NewUnitOption("Service", "PrivateDevices", "yes"),
			unit.NewUnitOption("Service", "ProtectKernelTunables", "yes"),
			unit.NewUnitOption("Service", "ProtectKernelModules", "yes"),
			unit.NewUnitOption("Service", "ProtectKernelLogs", "yes"),
			unit.NewUnitOption("Service", "ProtectControlGroups", "yes"),
			unit.NewUnitOption("Service", "ProtectClock", "yes"),
			unit.NewUnitOption("Service", "ProtectHostname", "yes"),
			unit.NewUnitOption("Service", "RestrictSUIDSGID", "yes"),
			unit.NewUnitOption("Service", "RestrictRealtime", "yes"),
			unit.NewUnitOption("Service", "RestrictNamespaces", "yes"),
			unit.NewUnitOption("Service", "LockPersonality", "yes"),
			unit.NewUnitOption("Service", "SystemCallArchitectures", "native"),
		)
	}
	for _, p := range u.ReadWritePaths {
		opts = append(opts, unit.NewUnitOption("Service", "ReadWritePaths", p))
	}
	for _, b := range u.BindPaths {
		opts = append(opts, unit.NewUnitOption("Service", "BindPaths", b))
	}
	for _, b := range u.BindReadOnlyPaths {
		opts = append(opts, unit.NewUnitOption("Service", "BindReadOnlyPaths", b))
	}
	for _, t := range u.TemporaryFileSystems {
		opts = append(opts, unit.NewUnitOption("Service", "TemporaryFileSystem", t))
	}
	for _, c := range u.SetCredentials {
		opts = append(opts, unit.NewUnitOption("Service", "SetCredential", c))
	}
	if !u.NoInstall {
		wantedBy := u.WantedBy
		if len(wantedBy) == 0 {
			wantedBy = "multi-user.target"
		}
		opts = append(opts, unit.NewUnitOption("Install", "WantedBy", wantedBy))
	}
	return opts
}

// quoteEnv double-quotes a "KEY=VALUE" assignment whose value contains
// whitespace, so systemd parses it as one variable rather than splitting it into
// separate (invalid) tokens — as happens with image env like a multi-word
// build-dependency list. A backslash triggers quoting too: unquoted, a trailing one
// line-continues the unit file and swallows the following directive, and quoting
// escapes it rather than rejecting an env value that may legitimately contain one.
func quoteEnv(e string) string {
	if !strings.ContainsAny(e, " \t\\") {
		return e
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(e) + `"`
}

// execStartLine renders an argv into a systemd ExecStart command line. systemd
// splits the line on unquoted whitespace, so each argument is quoted individually
// — otherwise an image CMD argument that itself contains a space (e.g. nginx's
// `nginx -g "daemon off;"`, whose "daemon off;" is one argument) would be re-split
// into separate tokens and the program would see a bogus extra argument.
func execStartLine(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = quoteExecArg(a)
	}
	return strings.Join(quoted, " ")
}

// quoteExecArg quotes one ExecStart argument for systemd's command-line parser.
// A literal '%' is doubled so it is not read as a specifier and a literal '$' so
// it is not read as a variable reference; an argument that is empty or holds
// whitespace, a quote, a backslash or a semicolon is wrapped in double quotes
// with backslashes and double quotes escaped. Plain arguments pass through
// unchanged so the common ExecStart stays readable.
//
// The '$' doubling is correctness rather than confinement — expansion draws on
// this unit's own Environment=, which belongs to the same principal as the
// command, and it happens after the command lines have been parsed, so it can
// neither add one nor re-parse a privilege modifier. Left raw, though, systemd
// eats the argument: an unset "$5" expands to ZERO arguments, so an image whose
// CMD carries a literal '$' silently loses it before the program is exec'd. It
// also matches Kubernetes semantics, where a '$' in command/args reaches the
// process rather than being expanded by whatever supervises it.
//
// The semicolon is the load-bearing one. systemd concatenates SEVERAL command
// lines in one ExecStart= when they are separated by a bare ";" word, and it
// re-parses the '@-:+!' privilege modifiers for each line — so an argv of
// {"/bin/true", ";", "+/bin/sh", "-c", payload} renders a second command line
// that runs FULLY PRIVILEGED, ignoring User=, CapabilityBoundingSet= and the
// rest of the hardened floor. systemd's separator test runs on the still-quoted
// text, so quoting turns the token into a literal argument the program receives
// as ";" — which is also what `find … -exec … ;` legitimately needs.
func quoteExecArg(arg string) string {
	arg = strings.ReplaceAll(arg, "%", "%%")
	arg = strings.ReplaceAll(arg, "$", "$$")
	if arg != "" && !strings.ContainsAny(arg, " \t\n\"';\\") {
		return arg
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(arg) + `"`
}

// Render serializes the unit to systemd unit-file text.
func (u Unit) Render() (string, error) {
	opts := u.Options()
	// go-systemd serializes each option as "Name=Value" verbatim, so a newline in a value would
	// inject a following directive line — e.g. an image env "X=y\nUser=0" (or a WorkingDirectory /
	// BindPaths mountPath carrying one) would emit a spurious "User=0" that runs the service as
	// root. Refuse any control char in a rendered value, closing that injection at the one
	// serialization point.
	// A trailing backslash is the same injection by the other end: systemd joins a line ending
	// in an odd number of backslashes with the line that follows, so a value like `-/app\`
	// SWALLOWS the next directive instead of adding one. WorkingDirectory= is emitted directly
	// before User=, and its value comes from the image config, so an image can erase its own
	// User= line — and a service with no User= runs as root, defeating the no-root backstop.
	for _, o := range opts {
		if err := validateOptionValue(o.Name, o.Value); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(unit.Serialize(opts))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
