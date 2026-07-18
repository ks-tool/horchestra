//go:build linux

// Package units is the node-side agent.Units adapter: it runs and supervises
// application services as hardened systemd units over D-Bus, rendering each unit
// with the generic pkg/systemd renderer. It imports the agent module (for the
// port types), so it is linked only into the node binary — never the control
// plane, which must not pull in agent/nodeapi alongside apiserver/nodeapi.
package units

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ks-tool/horchestra/agent"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/pkg/systemd"

	"github.com/coreos/go-systemd/v22/dbus"
	"k8s.io/apimachinery/pkg/api/resource"
)

// unitPrefix namespaces application units so they can be enumerated on the node
// (the actual-state source) and never collide with a system unit of the same
// name.
const unitPrefix = "horchestra-app-"

// unitName is the systemd unit name for an application.
func unitName(app string) string { return unitPrefix + app + ".service" }

// Units runs and supervises application services as hardened systemd units under
// unitDir, managed over D-Bus. It implements agent.Units.
type Units struct {
	unitDir string
}

// New binds a Units to the directory unit files are written to (e.g.
// /run/systemd/system or /etc/systemd/system).
func New(unitDir string) *Units { return &Units{unitDir: unitDir} }

var _ agent.Units = (*Units)(nil)

// Apply renders name's unit for the app and installs it only when it differs
// from the on-disk file, daemon-reloading after a write; it reports whether the
// definition changed. It does not start the service.
func (u *Units) Apply(ctx context.Context, name string, app agent.App, spec *agent.LaunchSpec, binds []agent.Bind, tmpfs []agent.Tmpfs) (bool, error) {
	desired, err := buildUnit(app, spec, binds, tmpfs).Render()
	if err != nil {
		return false, err
	}
	path := filepath.Join(u.unitDir, unitName(name))
	if onDisk, _ := os.ReadFile(path); string(onDisk) == desired {
		return false, nil
	}
	if err := os.WriteFile(path, []byte(desired), 0o644); err != nil {
		return false, err
	}
	if err := daemonReload(ctx); err != nil {
		return true, err
	}
	return true, nil
}

// Start activates the named service; a no-op if already active.
func (u *Units) Start(ctx context.Context, name string) error {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	ch := make(chan string, 1)
	if _, err := conn.StartUnitContext(ctx, unitName(name), "replace", ch); err != nil {
		return err
	}
	if res := <-ch; res != "done" {
		return fmt.Errorf("start %s: %s", unitName(name), res)
	}
	return nil
}

// Restart daemon-reloads systemd and (re)starts the named service — used after
// its definition changed.
func (u *Units) Restart(ctx context.Context, name string) error {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.ReloadContext(ctx); err != nil {
		return err
	}
	ch := make(chan string, 1)
	if _, err := conn.RestartUnitContext(ctx, unitName(name), "replace", ch); err != nil {
		return err
	}
	if res := <-ch; res != "done" {
		return fmt.Errorf("restart %s: %s", unitName(name), res)
	}
	return nil
}

// Stop deactivates the named service.
func (u *Units) Stop(ctx context.Context, name string) error {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	ch := make(chan string, 1)
	if _, err := conn.StopUnitContext(ctx, unitName(name), "replace", ch); err != nil {
		return err
	}
	if res := <-ch; res != "done" {
		return fmt.Errorf("stop %s: %s", unitName(name), res)
	}
	return nil
}

// Remove stops the named service, deletes its unit file and daemon-reloads.
func (u *Units) Remove(ctx context.Context, name string) error {
	_ = u.Stop(ctx, name)
	if err := os.Remove(filepath.Join(u.unitDir, unitName(name))); err != nil && !os.IsNotExist(err) {
		return err
	}
	return daemonReload(ctx)
}

// IsActive reports whether the named service is running (or coming up). A unit
// systemd does not know, or one it cannot report on, reads as not active.
func (u *Units) IsActive(ctx context.Context, name string) bool {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return false
	}
	defer conn.Close()
	prop, err := conn.GetUnitPropertyContext(ctx, unitName(name), "ActiveState")
	if err != nil {
		return false
	}
	switch prop.Value.Value() {
	case "active", "activating", "reloading":
		return true
	default:
		return false
	}
}

// List returns the names of the application services installed on this node,
// read from the unit directory — the node's own record of what it runs.
func (u *Units) List(_ context.Context) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(u.unitDir, unitPrefix+"*.service"))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), unitPrefix), ".service"))
	}
	return names, nil
}

// Logs streams the named service's journal via journalctl; follow tails it, tail
// bounds the backlog. The returned reader kills journalctl and releases the pipe
// on Close.
func (u *Units) Logs(ctx context.Context, name string, follow bool, tail int64) (io.ReadCloser, error) {
	args := []string{"-u", unitName(name), "-o", "cat", "--no-pager"}
	if tail > 0 {
		args = append(args, "-n", strconv.FormatInt(tail, 10))
	}
	if follow {
		args = append(args, "-f")
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &journalReader{cmd: cmd, out: stdout}, nil
}

// journalReader adapts a running journalctl process into an io.ReadCloser:
// reads come from its stdout, and Close kills the process so a follow stream
// stops when the caller is done.
type journalReader struct {
	cmd *exec.Cmd
	out io.ReadCloser
}

func (j *journalReader) Read(p []byte) (int, error) { return j.out.Read(p) }

func (j *journalReader) Close() error {
	if j.cmd.Process != nil {
		_ = j.cmd.Process.Kill()
	}
	_ = j.out.Close()
	_ = j.cmd.Wait()
	return nil
}

// daemonReload reloads the systemd manager configuration.
func daemonReload(ctx context.Context) error {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.ReloadContext(ctx)
}

// buildUnit renders a hardened systemd service unit that runs the application
// from the assembled rootfs: the app's env layered over the image's, its
// command/args overriding the image entrypoint/cmd (Kubernetes semantics), its
// restartPolicy and securityContext mapped onto systemd, its volumes
// bind-mounted writable, and its requests/limits applied as cgroup limits.
func buildUnit(a agent.App, spec *agent.LaunchSpec, binds []agent.Bind, tmpfs []agent.Tmpfs) systemd.Unit {
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
	}
	// Each PersistentVolume is bind-mounted writable; its destination must stay
	// writable under ProtectSystem=strict.
	for _, b := range binds {
		u.BindPaths = append(u.BindPaths, b.HostPath+":"+b.MountPath)
		u.ReadWritePaths = append(u.ReadWritePaths, b.MountPath)
	}
	for _, t := range tmpfs {
		u.TemporaryFileSystems = append(u.TemporaryFileSystems, tmpfsSpec(t.Path, t.Size))
	}
	return u
}

// restartDirectives maps a RestartPolicy to systemd's (Restart=, Type=). Never is
// a run-to-completion job (Type=oneshot, no restart); Always (the default when
// empty) and OnFailure are long-running services.
func restartDirectives(policy string) (restart, svcType string) {
	switch policy {
	case corev1.RestartOnFailure:
		return "on-failure", "simple"
	case corev1.RestartNever:
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
