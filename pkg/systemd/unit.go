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
	Environment      []string
	// Type is the systemd service Type= (default "simple"; "oneshot" for a
	// run-to-completion job).
	Type string
	// RemainAfterExit keeps a successfully-finished unit in the "active (exited)"
	// state instead of "inactive" — set for a oneshot job so a completed run is not
	// seen as stopped and re-executed by the reconciler's self-heal.
	RemainAfterExit bool
	Restart         string
	Hardened        bool
	// CapabilityBoundingSet, when non-nil, is emitted verbatim as
	// CapabilityBoundingSet= (an empty value drops all capabilities; a "~CAP_X …"
	// value drops the listed ones). nil leaves systemd's default untouched.
	CapabilityBoundingSet *string
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
	BindPaths      []string
	ReadWritePaths []string
	// TemporaryFileSystems are "path[:options]" ephemeral in-memory mounts (writable
	// tmpfs), for temporary paths that need no PersistentVolume.
	TemporaryFileSystems []string
}

// Options returns the unit as ordered go-systemd unit options, grouped by
// section ([Unit]/[Service]/[Install]).
func (u Unit) Options() []*unit.UnitOption {
	opts := []*unit.UnitOption{}
	if len(u.Description) > 0 {
		opts = append(opts, unit.NewUnitOption("Unit", "Description", u.Description))
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
	if len(u.User) > 0 {
		opts = append(opts, unit.NewUnitOption("Service", "User", u.User))
	}
	if len(u.Group) > 0 {
		opts = append(opts, unit.NewUnitOption("Service", "Group", u.Group))
	}
	for _, e := range u.Environment {
		opts = append(opts, unit.NewUnitOption("Service", "Environment", quoteEnv(e)))
	}
	opts = append(opts, unit.NewUnitOption("Service", "ExecStart", execStartLine(u.ExecStart)))
	if u.RemainAfterExit {
		opts = append(opts, unit.NewUnitOption("Service", "RemainAfterExit", "yes"))
	}
	if len(u.Restart) > 0 {
		opts = append(opts, unit.NewUnitOption("Service", "Restart", u.Restart))
	}
	if u.CapabilityBoundingSet != nil {
		opts = append(opts, unit.NewUnitOption("Service", "CapabilityBoundingSet", *u.CapabilityBoundingSet))
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
		opts = append(opts,
			unit.NewUnitOption("Service", "NoNewPrivileges", "yes"),
			unit.NewUnitOption("Service", "ProtectSystem", "strict"),
			unit.NewUnitOption("Service", "ProtectHome", "yes"),
			unit.NewUnitOption("Service", "PrivateTmp", "yes"),
		)
	}
	for _, p := range u.ReadWritePaths {
		opts = append(opts, unit.NewUnitOption("Service", "ReadWritePaths", p))
	}
	for _, b := range u.BindPaths {
		opts = append(opts, unit.NewUnitOption("Service", "BindPaths", b))
	}
	for _, t := range u.TemporaryFileSystems {
		opts = append(opts, unit.NewUnitOption("Service", "TemporaryFileSystem", t))
	}
	opts = append(opts, unit.NewUnitOption("Install", "WantedBy", "multi-user.target"))
	return opts
}

// quoteEnv double-quotes a "KEY=VALUE" assignment whose value contains
// whitespace, so systemd parses it as one variable rather than splitting it into
// separate (invalid) tokens — as happens with image env like a multi-word
// build-dependency list.
func quoteEnv(e string) string {
	if !strings.ContainsAny(e, " \t") {
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
// A literal '%' is doubled so it is not read as a specifier; an argument that is
// empty or holds whitespace, a quote or a backslash is wrapped in double quotes
// with backslashes and double quotes escaped. Plain arguments pass through
// unchanged so the common ExecStart stays readable.
func quoteExecArg(arg string) string {
	arg = strings.ReplaceAll(arg, "%", "%%")
	if arg != "" && !strings.ContainsAny(arg, " \t\n\"'\\") {
		return arg
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(arg) + `"`
}

// Render serializes the unit to systemd unit-file text.
func (u Unit) Render() (string, error) {
	b, err := io.ReadAll(unit.Serialize(u.Options()))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
