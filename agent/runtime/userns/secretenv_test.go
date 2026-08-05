//go:build linux

package userns

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ks-tool/horchestra/agent/runtime"
	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// TestSandboxConfigCarriesNoSecretValues is the regression test for the leak this feature shipped
// with once: the resolved values were serialized into the sandbox config, which the agent leaves on
// persistent disk for the trampoline to read. A credential there outlives the agent that fetched
// it — it survives a reboot with nothing left to re-authorize it and is copied into every backup of
// the node. The config may name the RAM-backed carrier file; it may never hold what is in it.
func TestSandboxConfigCarriesNoSecretValues(t *testing.T) {
	runtimeDir := t.TempDir()
	r := &Runtime{stateDir: t.TempDir(), runtimeDir: runtimeDir, sandboxCmd: []string{"/usr/local/bin/horchestra", "sandbox"}}
	app := workload.App{
		UID: "b4e95624-75d6-4639-9f6d-2a4aa651df6f", Name: "web", Namespace: "team-a",
		SecretEnv: []string{"PGPASSWORD=s3cr3t", "PG_host=db.internal"},
	}
	id := app.ID()

	envFile, err := runtime.WriteSecretEnvFile(runtimeDir, id, app.SecretEnv)
	if err != nil {
		t.Fatalf("WriteSecretEnvFile: %v", err)
	}
	cfg := r.buildConfig(id, &runtime.LaunchSpec{LayerDirs: []string{"/img/l1"}}, app, nil, envFile, nil)
	if cfg.SecretEnvFile != envFile {
		t.Fatalf("SecretEnvFile = %q, want %q", cfg.SecretEnvFile, envFile)
	}

	configPath := filepath.Join(t.TempDir(), "sandbox.json")
	rendered, _, err := marshalSandboxConfig(cfg)
	if err != nil {
		t.Fatalf("marshalSandboxConfig: %v", err)
	}
	if err := ensureSandboxConfig(configPath, rendered); err != nil {
		t.Fatalf("ensureSandboxConfig: %v", err)
	}
	blob, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "s3cr3t") {
		t.Fatalf("the sandbox config carries the secret:\n%s", blob)
	}
	// The values are in the RAM-backed carrier, and only there.
	content, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read the env file: %v", err)
	}
	if want := "PGPASSWORD=s3cr3t\nPG_host=db.internal\n"; string(content) != want {
		t.Fatalf("carrier content = %q, want %q", content, want)
	}
	if found := grepDir(t, r.stateDir, "s3cr3t"); found != "" {
		t.Fatalf("the secret value reached the persistent state dir at %s", found)
	}
}

// TestTransientUnitCannotStartWithoutTheAgent replaces the old [Install]/Requires= pair. A
// transient unit exists only in the manager's memory: it cannot be enabled into a boot target,
// and a reboot leaves nothing behind for systemd to start. So "never comes up without the agent"
// now holds by construction for EVERY workload, not just the secret-bearing ones, and the agent
// owns the order things come back in.
func TestTransientUnitCannotStartWithoutTheAgent(t *testing.T) {
	r := &Runtime{stateDir: t.TempDir(), runtimeDir: t.TempDir(), sandboxCmd: []string{"/usr/local/bin/horchestra", "sandbox"}}
	app := testApp()
	app.SecretEnv = []string{"PGPASSWORD=s3cr3t"}

	props := r.unitProperties(app.ID(), "cfgsum", app)

	var names []string
	for _, pr := range props {
		names = append(names, pr.Name)
		if strings.Contains(fmt.Sprint(pr.Value), "s3cr3t") {
			t.Fatalf("property %s carries the secret value", pr.Name)
		}
	}
	// Nothing here can enable the unit, and nothing needs to: there is no [Install] to omit.
	for _, forbidden := range []string{"WantedBy", "Requires", "After"} {
		if slices.Contains(names, forbidden) {
			t.Errorf("a transient unit must not need %s — it cannot be boot-enabled at all", forbidden)
		}
	}
	for _, want := range []string{"Description", "ExecStart", "CollectMode"} {
		if !slices.Contains(names, want) {
			t.Errorf("missing property %s; got %v", want, names)
		}
	}
}

// testApp is the workload the unit-shaping tests are written against: a uid distinct from the
// namespace/name pair, so a test cannot pass by accident when the two are confused.
func testApp() workload.App {
	return workload.App{UID: "b4e95624-75d6-4639-9f6d-2a4aa651df6f", Name: "web", Namespace: "team-a"}
}

// TestWorkloadIsNamedByUID: the unit and the config file are named by the object's uid, and the
// description is a label with no data in it.
//
// A name is not an identity. Two distinct application names can sanitize to the same string, and
// a name is reused the instant an application is deleted and recreated — at which point a
// name-keyed node would hand the new workload the old one's overlay upperdir and config, or
// consider it already converged. The uid also needs no separator convention: the '_' join that
// let unitID split a namespace out of a unit name is gone with it.
func TestWorkloadIsNamedByUID(t *testing.T) {
	r := &Runtime{stateDir: "/state", runtimeDir: t.TempDir(), sandboxCmd: []string{"/usr/local/bin/horchestra", "sandbox"}}
	app := testApp()

	unit := r.UnitName(app.ID())
	if want := app.UID + ".service"; unit != want {
		t.Fatalf("unit = %q, want %q — the uid alone names it", unit, want)
	}
	if got, ok := unitID(unit); !ok || got != app.UID {
		t.Fatalf("unitID(%q) = %q, %v; want the uid back", unit, got, ok)
	}
	// List selects our units off the user bus by this glob alone, so it has to match the names
	// UnitName produces. The agent runs as a dedicated user whose systemd --user manager holds
	// little besides these units, and a uid is already unique — hence no vendor prefix.
	if ok, err := filepath.Match(unitGlob, unit); err != nil || !ok {
		t.Fatalf("unit %q is not selected by unitGlob %q (err %v) — List would not see it", unit, unitGlob, err)
	}
	if got, want := r.configPath(app.ID()), "/state/config/"+app.UID+".json"; got != want {
		t.Fatalf("configPath = %q, want %q", got, want)
	}

	// The description is the only thing that maps a uid-named unit back to an application for a
	// human reading `systemctl --user list-units`, so it must carry the namespace/name form — and
	// nothing else: the spec hash it used to end in was read by nobody and observed stale.
	d := unitDescription(app)
	if !strings.Contains(d, "team-a/web") {
		t.Fatalf("description %q must name the workload as namespace/name, the form kubectl shows", d)
	}
	if strings.Contains(d, "spec=") {
		t.Fatalf("description %q still carries a hash nothing reads", d)
	}
}

// TestConfigDigestIsTheConvergeSignal: a spec change must reach the node.
//
// The unit's ExecStart names the config by PATH, and that path is the same string for the life of
// a workload — so changing env, argv or volumes leaves every unit property byte-identical and the
// workload keeps running the old config while the control plane reports it converged. The digest
// of the rendered config is what closes that: it changes with any byte of the config, and it
// doubles as the integrity check the sandbox applies to the file it reads.
func TestConfigDigestIsTheConvergeSignal(t *testing.T) {
	r := &Runtime{stateDir: t.TempDir(), runtimeDir: t.TempDir(), sandboxCmd: []string{"/usr/local/bin/horchestra", "sandbox"}}
	app := testApp()
	ls := &runtime.LaunchSpec{LayerDirs: []string{"/img/l1"}}

	base := app
	base.Env = []string{"MODE=old"}
	_, sumBefore, err := marshalSandboxConfig(r.buildConfig(app.ID(), ls, base, nil, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	changed := app
	changed.Env = []string{"MODE=new"}
	_, sumAfter, err := marshalSandboxConfig(r.buildConfig(app.ID(), ls, changed, nil, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if sumBefore == sumAfter {
		t.Fatal("an env change must change the config digest, or the restart never happens")
	}

	// Rendering the same desired state twice must give the same digest, or every tick reads as
	// drift and restarts a healthy workload forever.
	_, again, err := marshalSandboxConfig(r.buildConfig(app.ID(), ls, base, nil, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if again != sumBefore {
		t.Fatalf("the digest is not stable across renders: %s then %s", sumBefore, again)
	}

	// The digest rides in the argv, and the argv is what convergence compares. A unit systemd
	// still reports as running the OLD config must not read as converged, or the restart that
	// carries the new spec to the workload never happens.
	if !slices.Contains(r.sandboxArgv(app.ID(), sumBefore), sumBefore) {
		t.Fatal("the config digest must ride in the ExecStart argv")
	}
	running := appliedExecStart(r.sandboxArgv(app.ID(), sumBefore))
	if !execStartMatches(running, r.sandboxArgv(app.ID(), sumBefore)) {
		t.Fatal("a unit running the config we asked for must read as converged")
	}
	if execStartMatches(running, r.sandboxArgv(app.ID(), sumAfter)) {
		t.Fatal("a unit still running the old config must not read as converged")
	}
}

// appliedExecStart builds an ExecStart value shaped the way systemd reports it — a(sasbttttuii):
// path, argv, ignore-errors, four timestamps, pid, code, status. The field count is the part
// worth pinning: getting it wrong makes the decode FAIL rather than mismatch, which reads as
// drift on every tick and restarts a healthy workload forever.
func appliedExecStart(argv []string) any {
	return [][]any{{
		argv[0], argv, false,
		uint64(0), uint64(0), uint64(0), uint64(0),
		uint32(0), int32(0), int32(0),
	}}
}

// grepDir returns the first regular file under dir whose contents carry needle, or "".
func grepDir(t *testing.T, dir, needle string) string {
	t.Helper()
	var found string
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if b, rerr := os.ReadFile(path); rerr == nil && strings.Contains(string(b), needle) {
			found = path
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return found
}

// TestUnitExecStartsTheSandboxBinary: a workload's supervisor path must exec the TRAMPOLINE, and
// name it explicitly.
//
// It has been wrong twice, in opposite directions. It was once `<self> __sandbox` — a hidden
// subcommand of whatever binary happened to be running, so systemd ran the whole control plane to
// start a process. It then became a separate `horchestra-sandbox` file, and is now the node
// binary's own `sandbox` subcommand: one build for a node's three roles, and the control plane is
// no longer in it. What must never come back is an ExecStart that reaches the trampoline by
// accident rather than by name.
func TestUnitExecStartsTheSandboxBinary(t *testing.T) {
	r := &Runtime{stateDir: t.TempDir(), runtimeDir: t.TempDir(), sandboxCmd: []string{"/usr/local/bin/horchestra", "sandbox"}}
	app := testApp()

	var exec string
	for _, pr := range r.unitProperties(app.ID(), "cfgsum", app) {
		if pr.Name == "ExecStart" {
			exec = fmt.Sprint(pr.Value)
		}
	}
	for _, want := range []string{"/usr/local/bin/horchestra", "sandbox", "--config", r.configPath(app.ID()), "--config-sha256"} {
		if !strings.Contains(exec, want) {
			t.Fatalf("ExecStart is missing %q: %s", want, exec)
		}
	}
	if strings.Contains(exec, "__sandbox") {
		t.Fatalf("the retired hidden subcommand must not appear: %s", exec)
	}
	// The subcommand is what selects the trampoline, so it has to be an argument rather than part
	// of the path: a unit that execs the binary bare starts the AGENT under a workload's name.
	if !strings.Contains(exec, `"/usr/local/bin/horchestra", "sandbox"`) {
		t.Fatalf("the sandbox subcommand is not the argument right after the binary: %s", exec)
	}
}

// TestConvergenceComparesAppliedNotTheLabel: the description is plain text anything able to start
// a transient unit under the same user can reproduce, so trusting it meant a forged unit running
// a different ExecStart looked converged forever. Convergence must rest on what systemd applied.
func TestConvergenceComparesAppliedNotTheLabel(t *testing.T) {
	r := &Runtime{stateDir: t.TempDir(), runtimeDir: t.TempDir(), sandboxCmd: []string{"/usr/local/bin/horchestra", "sandbox"}}
	app := testApp()
	want := r.unitProperties(app.ID(), "cfgsum", app)

	applied := map[string]any{
		"Description": unitDescription(app),
		"Restart":     "always", // testApp names no policy, and an unset policy is Always
	}
	if !appliedMatches(applied, want, r.sandboxArgv(app.ID(), "cfgsum")) {
		t.Fatal("a unit matching what we asked for must read as converged")
	}

	// Same description, different supervision — the forgery the old check could not see.
	forged := map[string]any{"Description": unitDescription(app), "Restart": "no"}
	if appliedMatches(forged, want, r.sandboxArgv(app.ID(), "cfgsum")) {
		t.Fatal("a unit carrying our description but a different Restart must not read as converged")
	}
}

// TestUnitBoundsItsOwnStop: the stop timeout is always set, comes from the spec, and falls back
// to the shared default.
//
// A workload is PID 1 of its own namespace, and the kernel drops a signal PID 1 has no handler
// for — so an image that ignores SIGTERM always runs the period out, and the period becomes the
// latency of every restart. Left at the manager's default that is 90 seconds per spec change, and
// on Fedora a service.d drop-in turns the expiry into a crash rather than a quiet kill.
func TestUnitBoundsItsOwnStop(t *testing.T) {
	r := &Runtime{stateDir: t.TempDir(), runtimeDir: t.TempDir(), sandboxCmd: []string{"/usr/local/bin/horchestra", "sandbox"}}

	stopUSec := func(app workload.App) uint64 {
		t.Helper()
		for _, p := range r.unitProperties(app.ID(), "cfgsum", app) {
			if p.Name == "TimeoutStopUSec" {
				v, _ := p.Value.Value().(uint64)
				return v
			}
		}
		t.Fatal("no TimeoutStopUSec: a workload that ignores SIGTERM would pace the whole converge loop")
		return 0
	}

	// Unset: the default is applied by the runtime, not stamped on the object.
	want := uint64(corev1.DefaultTerminationGracePeriodSeconds) * uint64(time.Second/time.Microsecond)
	if got := stopUSec(testApp()); got != want {
		t.Fatalf("default TimeoutStopUSec = %d, want %d", got, want)
	}

	// Set: the spec wins, including an explicit 0, which means kill immediately and must not be
	// confused with "unset" — that is what the pointer is for.
	for _, secs := range []int64{0, 5, 120} {
		app := testApp()
		app.Lifecycle.TerminationGracePeriodSeconds = &secs
		if got, want := stopUSec(app), uint64(secs)*uint64(time.Second/time.Microsecond); got != want {
			t.Errorf("TerminationGracePeriodSeconds=%d gave TimeoutStopUSec %d, want %d", secs, got, want)
		}
	}

	// It has to be compared too, or the check is one-sided: relaxing it out of band to something
	// unbounded would stall every later restart and nothing would notice. Changing the spec value
	// must likewise read as drift — the config digest cannot see it, since it is a unit property
	// and never reaches the sandbox config.
	app := testApp()
	props := r.unitProperties(app.ID(), "cfgsum", app)
	longer := int64(120)
	app.Lifecycle.TerminationGracePeriodSeconds = &longer
	applied := map[string]any{"TimeoutStopUSec": stopUSec(app)}
	if appliedMatches(applied, props, r.sandboxArgv(app.ID(), "cfgsum")) {
		t.Fatal("a unit whose stop timeout differs from the spec must not read as converged")
	}
}

// TestRestartPolicyDrivesTheUnit: spec.restartPolicy has to reach systemd, and the
// run-to-completion case has to survive the converge loop.
//
// A job is the interesting one. Its unit is not active once it has finished, and the converge
// pass restarts anything wanted that is not active — so without the pair below (RemainAfterExit
// keeps a finished job loaded and "active (exited)"; a narrower CollectMode keeps a failed one
// loaded) a Never workload is re-run on every heartbeat, which is the exact opposite of Never.
func TestRestartPolicyDrivesTheUnit(t *testing.T) {
	r := &Runtime{stateDir: t.TempDir(), runtimeDir: t.TempDir(), sandboxCmd: []string{"/usr/local/bin/horchestra", "sandbox"}}
	prop := func(app workload.App, name string) (any, bool) {
		for _, p := range r.unitProperties(app.ID(), "cfgsum", app) {
			if p.Name == name {
				return p.Value.Value(), true
			}
		}
		return nil, false
	}
	for _, tc := range []struct{ policy, restart, collect string }{
		{"", "always", "inactive-or-failed"}, // unset means Always, the documented default
		{corev1.RestartAlways, "always", "inactive-or-failed"},
		{corev1.RestartOnFailure, "on-failure", "inactive-or-failed"},
		{corev1.RestartNever, "no", "inactive"},
	} {
		t.Run("policy="+tc.policy, func(t *testing.T) {
			app := testApp()
			app.Lifecycle.RestartPolicy = tc.policy
			if got, _ := prop(app, "Restart"); got != tc.restart {
				t.Errorf("Restart = %v, want %q", got, tc.restart)
			}
			if got, _ := prop(app, "CollectMode"); got != tc.collect {
				t.Errorf("CollectMode = %v, want %q", got, tc.collect)
			}
			remain, set := prop(app, "RemainAfterExit")
			if want := tc.policy == corev1.RestartNever; set != want {
				t.Errorf("RemainAfterExit present = %v, want %v", set, want)
			} else if set && remain != true {
				t.Errorf("RemainAfterExit = %v, want true", remain)
			}
		})
	}

	// A change of policy must land: it moves no byte of the sandbox config, so only the unit
	// property comparison can see it.
	svc, job := testApp(), testApp()
	job.Lifecycle.RestartPolicy = corev1.RestartNever
	if appliedMatches(map[string]any{"Restart": "always", "CollectMode": "inactive-or-failed"},
		r.unitProperties(job.ID(), "cfgsum", job), r.sandboxArgv(job.ID(), "cfgsum")) {
		t.Fatal("a unit still running the previous restart policy must not read as converged")
	}
	if _, set := prop(svc, "RemainAfterExit"); set {
		t.Fatal("a long-running service must not remain after exit — it would never be restarted")
	}
}
