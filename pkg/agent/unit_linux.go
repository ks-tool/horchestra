//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/systemd"
)

// Unit builds a hardened systemd service unit that runs the application from the
// assembled rootfs: the app's env layered over the image's, its command/args
// overriding the image entrypoint/cmd (Kubernetes semantics), its restartPolicy
// and securityContext mapped onto systemd, its volumes bind-mounted writable, and
// its requests/limits applied as cgroup limits. It lives in a linux-only file so
// the cross-platform parts of this package do not pull in the systemd package.
func Unit(a App, spec *LaunchSpec, binds, tmpfs []string) systemd.Unit {
	// Kubernetes command/args semantics: Command overrides the image ENTRYPOINT
	// (and drops its CMD unless Args is given); Args overrides the image CMD.
	entry, cmd := spec.Entrypoint, spec.Cmd
	if len(a.Command) > 0 {
		entry, cmd = a.Command, nil
	}
	if len(a.Args) > 0 {
		cmd = a.Args
	}
	argv := append(append([]string{}, entry...), cmd...)

	restart, svcType := restartDirectives(a.RestartPolicy)
	user, group := spec.User, ""
	var capBounding *string
	if sc := a.SecurityContext; sc != nil {
		if sc.RunAsUser != nil {
			user = strconv.FormatInt(*sc.RunAsUser, 10)
		}
		if sc.RunAsGroup != nil {
			group = strconv.FormatInt(*sc.RunAsGroup, 10)
		}
		if sc.Capabilities != nil && len(sc.Capabilities.Drop) > 0 {
			v := capabilityBoundingSet(sc.Capabilities.Drop)
			capBounding = &v
		}
	}

	u := systemd.Unit{
		Description:      "host orchestrator " + a.Name,
		Type:             svcType,
		RemainAfterExit:  svcType == "oneshot", // a completed job stays active(exited), not re-run
		RootDirectory:    spec.Rootfs,
		WorkingDirectory: spec.WorkingDir,
		User:             user,
		Group:            group,
		Environment:      append(append([]string{}, spec.Env...), envList(a.Env)...),
		ExecStart:        resolveExec(spec.Rootfs, argv, spec.Env),
		Hardened:         true,
		Restart:          restart,
		// securityContext.capabilities.drop is rendered so the declared confinement
		// is actually applied (the hardened floor does not drop capabilities itself,
		// so workloads needing one still work unless the app opts into dropping).
		CapabilityBoundingSet: capBounding,
		CPUWeight:             cpuWeight(a.Requests.CPU),
		CPUQuota:              cpuQuota(a.Limits.CPU),
		MemoryLow:             memBytes(a.Requests.Memory),
		MemoryMax:             memBytes(a.Limits.Memory),
		BindPaths:             binds,
		TemporaryFileSystems:  tmpfs,
	}
	// Each volume destination must stay writable under ProtectSystem=strict.
	for _, b := range binds {
		if _, dest, ok := strings.Cut(b, ":"); ok {
			u.ReadWritePaths = append(u.ReadWritePaths, dest)
		}
	}
	return u
}

// restartDirectives maps a RestartPolicy to systemd's (Restart=, Type=). Never is
// a run-to-completion job (Type=oneshot, no restart); Always (the default when
// empty, though Default() normally fills it) and OnFailure are long-running
// services.
func restartDirectives(policy string) (restart, svcType string) {
	switch policy {
	case v1.RestartOnFailure:
		return "on-failure", "simple"
	case v1.RestartNever:
		return "no", "oneshot"
	default: // RestartAlways
		return "always", "simple"
	}
}

// capabilityBoundingSet renders securityContext.capabilities.drop into a systemd
// CapabilityBoundingSet= value: dropping ALL yields an empty set (every capability
// removed), otherwise the listed capabilities are removed with the "~" prefix.
func capabilityBoundingSet(drop []string) string {
	for _, c := range drop {
		if strings.EqualFold(c, "ALL") {
			return "" // empty bounding set = drop every capability
		}
	}
	caps := make([]string, 0, len(drop))
	for _, c := range drop {
		caps = append(caps, normalizeCap(c))
	}
	return "~" + strings.Join(caps, " ")
}

// normalizeCap turns a Kubernetes-style capability name ("NET_ADMIN") into the
// systemd/kernel form ("CAP_NET_ADMIN"), leaving an already-prefixed name as is.
func normalizeCap(c string) string {
	c = strings.ToUpper(c)
	if !strings.HasPrefix(c, "CAP_") {
		c = "CAP_" + c
	}
	return c
}

// tmpfsSpec builds a systemd TemporaryFileSystem= spec for a tmpfs volume at path,
// applying a size cap (bytes) when the app requested one (systemd's default,
// half of RAM, otherwise — the app's memory limit caps it either way).
func tmpfsSpec(path, size string) string {
	if q, err := resource.ParseQuantity(size); err == nil && q.Value() > 0 {
		return path + ":size=" + strconv.FormatInt(q.Value(), 10)
	}
	return path
}

// cpuQuota maps a CPU limit to systemd CPUQuota — a hard cap as a percentage of
// one CPU (500m -> "50%", 2 -> "200%"). Empty when unset.
func cpuQuota(q resource.Quantity) string {
	m := q.MilliValue()
	if m <= 0 {
		return ""
	}
	pct := m / 10
	if pct < 1 {
		pct = 1
	}
	return strconv.FormatInt(pct, 10) + "%"
}

// cpuWeight maps a CPU request to a systemd CPUWeight (relative share): one core
// is the default weight of 100, scaled linearly and clamped to systemd's [1,10000].
func cpuWeight(q resource.Quantity) string {
	m := q.MilliValue()
	if m <= 0 {
		return ""
	}
	w := m / 10 // 1000m -> 100 (systemd's default weight)
	if w < 1 {
		w = 1
	}
	if w > 10000 {
		w = 10000
	}
	return strconv.FormatInt(w, 10)
}

// memBytes renders a memory quantity as a byte count for systemd's Memory* knobs,
// which take bytes (not the Ki/Mi suffixes resource.Quantity prints). Empty when
// unset.
func memBytes(q resource.Quantity) string {
	if b := q.Value(); b > 0 {
		return strconv.FormatInt(b, 10)
	}
	return ""
}

// envList renders an env map as sorted "K=V" entries so a unit re-renders
// identically for the same input (systemd Environment= — later wins over the
// image's own, which are emitted first).
func envList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(env))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// resolveExec makes argv[0] absolute if it isn't already, by finding it in the
// image's PATH within rootfs. systemd requires an absolute ExecStart, but OCI
// entrypoints are commonly bare (e.g. "docker-entrypoint.sh"); left unresolved
// the unit would fail to exec.
func resolveExec(rootfs string, argv, imageEnv []string) []string {
	if len(argv) == 0 || strings.HasPrefix(argv[0], "/") {
		return argv
	}
	for _, dir := range execPath(imageEnv) {
		abs := filepath.Join(dir, argv[0])
		if fi, err := os.Stat(filepath.Join(rootfs, abs)); err == nil && !fi.IsDir() {
			return append([]string{abs}, argv[1:]...)
		}
	}
	return argv // leave as-is; systemd surfaces a clear "not absolute"/exec error
}

// execPath is the image's PATH split into directories, or the conventional
// default when the image sets none.
func execPath(imageEnv []string) []string {
	for _, e := range imageEnv {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			return strings.Split(v, ":")
		}
	}
	return []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
}
