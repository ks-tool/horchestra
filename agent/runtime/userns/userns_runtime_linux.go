//go:build linux

package userns

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ks-tool/horchestra/agent/network"
	"github.com/ks-tool/horchestra/agent/runtime"
	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	netdapi "github.com/ks-tool/horchestra/api/netd"
	apisandbox "github.com/ks-tool/horchestra/api/sandbox"
	"github.com/ks-tool/horchestra/api/utils"
	"github.com/rs/zerolog/log"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/api/resource"
)

// RuntimeName is the class name of the rootless user-namespace runtime — what a node advertises
// in status.runtimes and an Application targets via spec.runtimeClassName.
const RuntimeName = "userns"

// unitGlob selects horchestra's own workload units on the user bus. A workload's unit is named
// by the application's uid alone — <uid>.service — so this is the shape of a canonical UUID:
// 8-4-4-4-12 hex, which is what both storage backends stamp (api/utils.NewUIDv4).
//
// The population this can confuse is not "units on the host" but TRANSIENT units on this user's
// bus, and that set is ours by construction: a transient unit exists only because something
// called StartTransientUnit on this bus, the agent runs as its own dedicated user, and nothing
// else on that account makes the call. So the shape is all the scoping the glob needs — no vendor
// prefix on top of an already-unique name.
const unitGlob = "????????-????-????-????-????????????.service"

// Runtime is a runtime.Runtime that runs each workload in a rootless user namespace supervised by
// the user's systemd manager (systemd --user), NOT by the agent. Each workload is a TRANSIENT
// --user service, started over the bus and living only in the manager's memory: no unit file is
// written anywhere, and a transient unit cannot be enabled into a boot target, so nothing comes
// back after a reboot until the agent converges. That is the point — startup order is the agent's
// to decide, and a workload never starts without the secrets the agent resolves for it.
//
// The agent drives the user manager over go-systemd/dbus (podman's rootless private-socket
// connection), and the unit's ExecStart is the horchestra-sandbox trampoline (own userns + overlay
// + pivot_root + read-only rootfs + dropPrivileges + seccomp). The agent only converges: it reads
// actual state back off the bus and restarts drift, level-driven — so a workload survives the
// agent crashing or restarting, and the running unit is the only record there is.
type Runtime struct {
	images   runtime.Images
	stateDir string
	// sandboxCmd is what the unit ExecStarts to reach the trampoline: the node binary and its
	// `sandbox` subcommand. Argv rather than a path because the trampoline stopped being a file of
	// its own — a workload's unit now starts `<node binary> sandbox`, and the two words have to
	// travel together or the unit execs the agent.
	// A DEDICATED binary, not this one: the workload's supervisor path should run the trampoline
	// and nothing else — not the agent, and certainly not the monolith's control plane.
	sandboxCmd []string
	// runtimeDir is RAM-backed (tmpfs: $XDG_RUNTIME_DIR/horchestra for a user agent). The
	// workload's Secret-sourced environment is assembled there as an overlay layer and stacked
	// into the sandbox's rootfs, so a resolved secret never reaches persistent storage — not the
	// unit, not the sandbox config, nothing that outlives the agent that fetched it.
	runtimeDir string
	// subUID/subGID are the node's subordinate ranges: the ids this agent may hand to a workload,
	// and the ones its own namespace maps. Both views of a workload's identity are derived from
	// them (workload.HostID for the sandbox's map, workload.AgentID for file ownership).
	subUID, subGID corev1.IDRange
	// flap rate-limits restarting a workload that will not stay up. It lives here because this
	// is where the decision to restart is made, and nothing below can make it any more: a
	// transient unit's own start limit is reset on every converge (see flapGuard).
	flap *flapGuard
	// runs is the retry ledger of the jobs on this node — how many times each has been started
	// and what budget it was given. It sits beside flap because the two pace the same decision
	// from opposite ends: flap decides how SOON a failed workload may be started again, this
	// decides whether it may be started again at all.
	runs *runLedger
	// net is what gives an isolated workload an address. Nil is the ordinary node: every workload
	// shares the host's network, which is also what a fleet running no privileged helper keeps
	// doing forever.
	net network.Network
}

// workloadIDs is the identity this workload's files must belong to, expressed the way the agent's
// own user namespace addresses it. The sandbox is told the in-namespace id; the agent has to write
// files the process holding that id can read, and those are two views of one mapping.
func (r *Runtime) workloadIDs(app workload.App) runtime.IDs {
	uid, gid := workloadRunAs(app)
	return runtime.IDs{
		UID: int(workload.AgentID(r.subUID, uid)),
		GID: int(workload.AgentID(r.subGID, gid)),
	}
}

// workloadRunAs is the uid/gid the workload runs as inside its namespace, with the compiled floor
// standing in for anything missing or out of range.
//
// An out-of-range id falls back to the floor rather than narrowing: int(uid) is the last place the
// full int64 is still visible, and on a 32-bit build the conversion itself would truncate 2^32 to 0
// before dropPrivileges could ever see it. Reaching here with a bad id means admission was
// bypassed, so refuse the tenant's value instead of trusting it.
func workloadRunAs(app workload.App) (uid, gid int64) {
	uid, gid = restrictedFloorUID, restrictedFloorUID
	if sc := app.SecurityContext; sc != nil {
		if sc.RunAsUser != nil && corev1.ValidRunAsID("runAsUser", *sc.RunAsUser) == nil {
			uid = *sc.RunAsUser
		}
		if sc.RunAsGroup != nil && corev1.ValidRunAsID("runAsGroup", *sc.RunAsGroup) == nil {
			gid = *sc.RunAsGroup
		}
	}
	return uid, gid
}

// New builds the rootless runtime over the image store, the state dir it assembles per-workload
// overlay upperdirs, merged roots and sandbox configs under, and the path of the
// horchestra-sandbox binary each workload's unit ExecStarts.
func New(images runtime.Images, stateDir, runtimeDir string, sandboxCmd []string, subUID, subGID corev1.IDRange) *Runtime {
	return &Runtime{
		images: images, stateDir: stateDir, sandboxCmd: sandboxCmd,
		runtimeDir: runtimeDir, subUID: subUID, subGID: subGID,
		flap: newFlapGuard(), runs: newRunLedger(),
	}
}

// WithNetwork gives the runtime the port that wires an isolated workload. Without it a workload
// that asks for its own network is REFUSED rather than started flat: isolation asked for and
// silently not given is the one failure that looks like the workload's own bug.
func (r *Runtime) WithNetwork(n network.Network) *Runtime {
	r.net = n
	return r
}

var _ runtime.Runtime = (*Runtime)(nil)

// Name returns the runtime's class name.
func (*Runtime) Name() string { return RuntimeName }

// UnitName is the systemd --user service backing the workload with this id — surfaced in
// ApplicationStatus.Unit so an operator can inspect it on the node (systemctl/journalctl --user).
func (*Runtime) UnitName(id string) string { return id + ".service" }

// Apply converges one workload: ensure its image, render its sandbox config, and — only when what
// systemd is actually running differs from what that config and the app's limits ask for — restart
// the transient unit. An already-converged workload is left alone, so an agent restart does not
// disturb it.
func (r *Runtime) Apply(ctx context.Context, app workload.App, volumes []workload.Volume) error {
	id := app.ID()
	if err := runtime.ValidateVolumes(volumes); err != nil {
		return err
	}
	if err := supportedVolumes(volumes); err != nil {
		return err
	}
	ls, err := runtime.EnsureImage(ctx, r.images, app.Namespace, app.Image)
	if err != nil {
		return err
	}
	unit := r.UnitName(id)

	// Write the RAM-backed secret-environment file before anything can start: the sandbox
	// folds it into the workload's execve environment, so it has to exist when systemd runs
	// the trampoline. A rotated value moves no byte of the unit, so the change is caught
	// here and forces the restart.
	// A CHANGED SET of variables is a different workload and restarts; a changed VALUE is not.
	// Environment is spawn-time state — nothing can replace it in a running process — so the
	// only way to "rotate" an env secret is to restart the workload, and restarting a workload
	// because a credential rotated is a worse answer than not rotating it. The new value is
	// written anyway: whenever the workload next restarts for a reason of its own, it starts
	// with the current one. A credential that must rotate under a running process is mounted as
	// a file, which is exactly what the secret volume below is for.
	rotated := runtime.SecretEnvShapeChanged(r.runtimeDir, id, app.SecretEnv)
	envFile, err := runtime.WriteSecretEnvFile(r.runtimeDir, id, app.SecretEnv)
	if err != nil {
		return err
	}
	// Secret volumes need no restart at all: the sandbox binds this carrier directly, so
	// rewriting it here IS the rotation, live under the running workload.
	secretMounts, err := runtime.WriteSecretVolumes(r.runtimeDir, id, volumes, r.workloadIDs(app))
	if err != nil {
		return err
	}

	// Render the config before deciding anything: its digest rides in the unit's ExecStart, so
	// what convergence is decided on is the CONTENT the workload would run — not a path, which
	// stays identical while everything behind it changes. Reassembling it is pure computation
	// over already-resolved inputs, so doing it every tick costs a marshal.
	blob, sum, err := marshalSandboxConfig(r.buildConfig(id, ls, app, volumes, envFile, secretMounts))
	if err != nil {
		return err
	}
	// Repaired every tick, independently of the unit: the file is what the trampoline reads at
	// the next start, and it sits under a directory the agent's own user can write. A config
	// edited out of band is put back here, and refused by the sandbox in the window before that
	// (it verifies this digest against the bytes it read).
	if err := ensureSandboxConfig(r.configPath(id), blob); err != nil {
		return err
	}

	// The running unit IS the record: convergence is asked of systemd rather than of a file the
	// agent left on disk. Nothing durable is written for the unit at all — a transient unit lives
	// in the manager's memory and is gone after a reboot, which is the point: the agent decides
	// what comes back up, and in what order.
	// The retry ledger is seeded from what the OBJECT says before anything reads it, so a job
	// that spent runs before this agent started (or before this node rebooted) is not handed
	// them again. It is a floor, never a reset.
	if runToCompletion(app) {
		r.runs.seed(id, app.Attempts, app.Lifecycle.Retries())
	}
	props := r.unitProperties(id, sum, app)
	st := r.inspect(ctx, unit, id, sum, app, props)
	if st.converged && !rotated {
		// Clear the flap count only once the start has HELD. A crash-looping unit is briefly
		// active between systemd's own retries, and a tick landing in that sliver would
		// otherwise reset the count and the backoff would never engage.
		if st.activeFor >= flapWindow {
			r.flap.forget(id)
		}
		return nil
	}
	switch {
	case rotated || st.running:
		// A rotated secret is new content, and drift on a unit that is UP is a correction we
		// asked for. Neither is a workload failing to stay up, so neither is rate-limited and
		// both start the count over.
		r.flap.forget(id)
	default:
		// It is not running. Restart it unless it has been failing, in which case the backoff
		// paces the attempts — nothing is hidden either way: the unit stays failed and the node
		// reports the app as not running, which is exactly what is true.
		allow, wait := r.flap.mayStart(id, sum)
		if !allow {
			log.Debug().Str("unit", unit).Dur("retry_in", wait).Msg("userns: restart held off")
			return nil
		}
		if wait > 0 {
			log.Info().Str("unit", unit).Dur("next_retry_after", wait).
				Msg("userns: restarting a workload that is not staying up")
		}
	}
	return withUserConn(ctx, func(c *sddbus.Conn) error {
		// "replace" swaps a running unit's definition in one job. A unit that failed earlier
		// still occupies its name until reset, so clear it first — CollectMode handles the
		// ordinary case, this covers the one it does not.
		_ = c.ResetFailedUnitContext(ctx, unit)
		if err := stopUnit(ctx, c, unit, terminationGracePeriod(app)); err != nil {
			log.Debug().Err(err).Str("unit", unit).Msg("userns: nothing to stop before (re)start")
		}

		// An isolated workload is wired while it starts: the trampoline makes its own network
		// namespace and holds the workload until this says it has an address. Prepared here —
		// BEFORE the start, because the trampoline writes the moment it is up, and AFTER the stop,
		// which is the part that had to be learned.
		//
		// The handshake carries a deadline, and preparing before the stop meant that deadline ran
		// while the PREVIOUS workload was being terminated: a grace period of 40 seconds against a
		// handshake of 30 left the reader gone before the new trampoline had started. It then wrote
		// its pid to a FIFO nobody was reading and waited for an answer nobody would give, systemd
		// restarted it, and the same thing happened again — a workload stuck restarting forever,
		// with both halves reporting a timeout and neither of them at fault. Seen three times on a
		// stand before the order was the suspect.
		wired, err := r.prepareNetwork(ctx, id, app)
		if err != nil {
			return err
		}
		defer wired.stop()

		start := func(ch chan<- string) (int, error) {
			return c.StartTransientUnitContext(ctx, unit, "replace", props, ch)
		}
		if !runToCompletion(app) {
			return runJob(ctx, "start "+unit, start)
		}
		// A oneshot unit's start job does NOT complete when the workload is up — it completes
		// when the workload EXITS, because for this unit type activation is the whole run. So
		// waiting on it here would mean the converge of one job blocked until that job finished:
		// a nightly batch would hold every other workload on the node behind it, and a job with
		// no deadline would hold them forever. The run is counted here instead, and its outcome
		// is read off the unit by States, which is where a job's outcome was always going to be
		// read from.
		n := r.runs.start(id)
		log.Info().Str("unit", unit).Int32("attempt", n).Msg("userns: starting a job")
		return startNoWait("start "+unit, start)
	})
}

// wiring is one workload's in-flight network handshake: the goroutine reading the trampoline's
// announcement, wiring it, and answering. stop waits for it, so a converge never returns with a
// half-wired workload behind it.
type wiring struct{ done <-chan struct{} }

func (w wiring) stop() {
	if w.done != nil {
		<-w.done
	}
}

// prepareNetwork sets up the two FIFOs an isolated workload's start needs and answers them in the
// background.
//
// It happens around the START rather than before it because the pid it needs does not exist yet:
// the namespace belongs to a process the trampoline is about to fork. Nothing here can create that
// namespace on the workload's behalf — entering one needs CAP_SYS_ADMIN in both the owning user
// namespace and the caller's own, which no unprivileged process has — so the workload makes it and
// this gives it an address.
//
// A workload on the host network gets none of this and the path is identical to what it was.
func (r *Runtime) prepareNetwork(ctx context.Context, id string, app workload.App) (wiring, error) {
	if app.HostNetwork {
		return wiring{}, nil
	}
	if r.net == nil {
		// Refused, never started flat. A workload that asked for its own network and silently got
		// the host's is a security posture nobody chose, discovered — if ever — by noticing it
		// can reach something it should not.
		return wiring{}, fmt.Errorf("workload %s asks for its own network and this node has no network helper", id)
	}
	if app.Address == "" {
		return wiring{}, fmt.Errorf("workload %s has no address: an isolated workload with no lease "+
			"would start into a namespace holding nothing but loopback", id)
	}
	pidPath, readyPath := r.netnsPidPath(id), r.networkReadyPath(id)
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o700); err != nil {
		return wiring{}, err
	}
	for _, p := range []string{pidPath, readyPath} {
		// Recreated every start: a FIFO left from a previous one may still hold a byte nobody
		// read, and a stale "go" would release the next workload before it was wired.
		_ = os.Remove(p)
		if err := unix.Mkfifo(p, 0o600); err != nil {
			return wiring{}, fmt.Errorf("mkfifo %s: %w", p, err)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := r.wireWorkload(ctx, id, app, pidPath, readyPath); err != nil {
			log.Error().Err(err).Str("workload", id).Msg("userns: wiring the workload's network")
			// Answering with anything but the ready byte ends the trampoline's wait, so a
			// workload whose network could not be built fails its start instead of hanging or —
			// worse — running unreachable.
			_ = answerFIFO(readyPath, 'x')
		}
	}()
	return wiring{done: done}, nil
}

// wireWorkload reads the trampoline's announcement, asks the helper for a veth, an address and
// routes, and releases the workload.
func (r *Runtime) wireWorkload(ctx context.Context, id string, app workload.App, pidPath, readyPath string) error {
	pid, err := readPID(pidPath)
	if err != nil {
		return err
	}
	if _, err := r.net.Setup(ctx, &netdapi.Workload{
		Id: id, Namespace: app.Namespace, Name: app.Name,
		Address: app.Address, Gateway: app.Gateway, Mtu: int32(app.MTU),
	}, pid); err != nil {
		return err
	}
	return answerFIFO(readyPath, 'w')
}

// networkHandshakeTimeout bounds both halves. A start that hangs on a FIFO is a unit systemd
// reports as "activating", indistinguishable from a slow image pull.
const networkHandshakeTimeout = 30 * time.Second

// readPID reads the trampoline's announcement.
//
// O_RDWR, which looks wrong on a read and is the whole point: a FIFO opened read-only with no
// writer yet attached returns EOF on the first read instead of waiting, so the agent read "the
// trampoline is finished" from a trampoline that had not started. Holding a write end open means
// there is always a writer, so a read waits for real bytes. O_NONBLOCK keeps the OPEN from
// blocking, and the deadline below bounds the wait — a trampoline that never starts must not park
// a goroutine for the life of the agent.
func readPID(path string) (int, error) {
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	if err := f.SetReadDeadline(time.Now().Add(networkHandshakeTimeout)); err != nil {
		return 0, err
	}
	buf := make([]byte, 32)
	n, err := f.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("read netns pid: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil {
		return 0, fmt.Errorf("netns pid %q: %w", strings.TrimSpace(string(buf[:n])), err)
	}
	return pid, nil
}

func answerFIFO(path string, b byte) error {
	// O_WRONLY and BLOCKING, which is the contract both ends were written to: the open waits until
	// the trampoline has its read end open, so the answer is delivered rather than raced.
	//
	// Neither alternative works, and both were tried on a stand. O_WRONLY|O_NONBLOCK fails with
	// ENXIO when the reader is not there yet. O_RDWR succeeds immediately — and then the byte is
	// written into a FIFO whose only read end is this function's own, so closing it DISCARDS the
	// answer and the workload waits for one that was already sent and thrown away.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.SetWriteDeadline(time.Now().Add(networkHandshakeTimeout)); err != nil {
		return err
	}
	_, err = f.Write([]byte{b})
	return err
}

// removeGrace is how long a teardown waits for a workload to go quietly. Remove has no spec to
// read a grace period from — the workload is gone from desired state — so it uses the default.
const removeGrace = time.Duration(corev1.DefaultTerminationGracePeriodSeconds) * time.Second

// stopUnit stops a unit and does not come back until it is stopped or killed.
//
// The wait is bounded at the grace period plus a margin, and the margin is not padding: it is
// how long systemd is given to act on its OWN expiry before this decides systemd is not going
// to. When it runs out the unit is killed outright — SIGKILL to every process in it, which is
// the one thing that always works on the init of a PID namespace, and which an operator can
// otherwise only do by hand.
//
// Bounding it is the point. A stop that never returns is a converge that never returns, and
// everything downstream of the converge — the workload it was replacing, every other workload
// on the node, and until the heartbeat was moved off this path the node's own liveness — waits
// behind one process that would not take a hint.
func stopUnit(ctx context.Context, c *sddbus.Conn, unit string, grace time.Duration) error {
	began := time.Now()
	err := runJobWithin(ctx, "stop "+unit, grace+stopMargin, func(ch chan<- string) (int, error) {
		return c.StopUnitContext(ctx, unit, "replace", ch)
	})
	if err == nil || ctx.Err() != nil {
		return err
	}
	// A stop fails for two quite different reasons and only one of them is a workload that would
	// not go: asking to stop a unit the manager does not hold — the ordinary case before a FIRST
	// start — fails instantly. Reporting both as "did not stop within its grace period", with the
	// budget printed as if it had been spent, describes a 40-second stall that never happened; it
	// cost one live round to read past.
	waited := time.Since(began)
	if waited < grace {
		log.Debug().Str("unit", unit).Dur("after", waited.Round(time.Millisecond)).Err(err).
			Msg("userns: stop failed without waiting; killing the unit anyway")
	} else {
		log.Warn().Str("unit", unit).Dur("waited", waited.Round(time.Second)).
			Msg("userns: the workload did not stop within its grace period; killing it")
	}
	c.KillUnitContext(ctx, unit, int32(syscall.SIGKILL))
	return runJobWithin(ctx, "stop "+unit, stopMargin, func(ch chan<- string) (int, error) {
		return c.StopUnitContext(ctx, unit, "replace", ch)
	})
}

// stopMargin is the grace systemd itself gets, on top of the workload's, to turn an expired
// grace period into a dead process.
const stopMargin = 10 * time.Second

// unitState is what one look at the manager says about a workload's unit: whether it is running
// as specified, whether it is running at all, and for how long. The last two are what let the
// caller tell a correction it asked for from a workload that will not stay up.
type unitState struct {
	converged bool
	running   bool
	activeFor time.Duration
}

// inspect reports whether systemd is already running this unit AS SPECIFIED. It compares what
// the manager actually applied, not a label the manager was told to carry.
//
// The description alone is not enough, and relying on it was a hole: it is plain text that
// anything able to start a transient unit under the same user can reproduce verbatim while
// running a different ExecStart. The agent would then read back its own expected string, call the
// workload converged, and never look again — the substitution surviving every later tick. Reading
// the applied properties closes that without a key or a signature: a forged description does not
// change the fact that the ExecStart underneath it is the wrong one.
//
// It is also how out-of-band property drift is caught — a relaxed MemoryMax or CPUQuota set
// through SetUnitProperties leaves the description untouched but shows up here, and the caller
// restarts the unit from the properties it wants.
//
// The argv carries the config's digest, which is what makes a SPEC change land: the config path
// is the same string for the life of a workload, so an argv comparison alone would call a
// workload running last week's environment converged. The digest changes with any byte of the
// rendered config, and the difference forces the restart.
func (r *Runtime) inspect(ctx context.Context, unit, id, configSum string, app workload.App, want []sddbus.Property) unitState {
	var out unitState
	_ = withUserConn(ctx, func(c *sddbus.Conn) error {
		state, err := c.GetUnitPropertyContext(ctx, unit, "ActiveState")
		if err != nil || state == nil {
			return nil
		}
		s, _ := state.Value.Value().(string)
		if s != "active" && s != "activating" && s != "reloading" {
			// A job that has finished is converged, however it finished: its unit will never be
			// active again, and starting it for that reason is precisely what Never forbids —
			// the converge loop would otherwise re-run a completed job on every tick and a failed
			// one forever. A service in a terminal state is drift instead, and falls through to
			// the restart below.
			//
			// "Finished" has to be read off LoadState, not ActiveState. Asking a manager about a
			// unit it has never heard of does not fail — it answers inactive, the same word a
			// job that ran and exited gets — so trusting ActiveState alone made a job that had
			// never started look like one that was already done, and it was never run at all.
			if !runToCompletion(app) || !unitLoaded(ctx, c, unit) {
				return nil
			}
			// For a job the ONLY state worth starting from is a failure with retries still
			// budgeted. Everything else here is a job that is over or on its way out, and
			// "deactivating" is emphatically the latter: a deadline kill spends its whole stop
			// timeout in that state, and treating it as drift ran the job a second time while
			// the first was still being killed — measured on the stand, attempts 2 for a job
			// with no retry budgeted at all.
			out.converged = s != "failed" || r.runs.spent(id)
			return nil
		}
		out.running = true
		out.activeFor = activeFor(ctx, c, unit, time.Now())
		props, err := c.GetUnitTypePropertiesContext(ctx, unit, "Service")
		if err != nil {
			return nil
		}
		out.converged = appliedMatches(props, want, r.sandboxArgv(id, configSum))
		return nil
	})
	return out
}

// activeFor is how long the unit has been up, from the manager's own ActiveEnterTimestamp
// (microseconds since the epoch). An unreadable or zero timestamp reports 0 — a start that
// cannot be shown to have held is not counted as having held.
func activeFor(ctx context.Context, c *sddbus.Conn, unit string, now time.Time) time.Duration {
	p, err := c.GetUnitPropertyContext(ctx, unit, "ActiveEnterTimestamp")
	if err != nil || p == nil {
		return 0
	}
	us, _ := p.Value.Value().(uint64)
	if us == 0 {
		return 0
	}
	if d := now.Sub(time.UnixMicro(int64(us))); d > 0 {
		return d
	}
	return 0
}

// appliedMatches compares the properties the manager reports against the ones we asked for.
//
// Only the properties this runtime sets are checked, and only those it can compare honestly:
// systemd normalizes some values on the way in (a quota becomes microseconds-per-second, a memory
// limit is rounded to a page), so comparing a field we never set, or one whose reported form does
// not round-trip, would report drift on every tick and restart healthy workloads forever. A
// mismatch here has to mean tampering, or it is worse than no check at all.
func appliedMatches(applied map[string]any, want []sddbus.Property, argv []string) bool {
	// A property we never set must still be at its default. Otherwise the check is one-sided:
	// relaxing a limit we manage is caught, but IMPOSING one on a workload that had none is not —
	// and MemoryMax=1M on someone else's database is a denial of service we would never revert.
	for _, name := range []string{"MemoryMax", "CPUQuotaPerSecUSec"} {
		if slices.ContainsFunc(want, func(p sddbus.Property) bool { return p.Name == name }) {
			continue // managed below, against the value we asked for
		}
		if v, ok := applied[name].(uint64); ok && v != math.MaxUint64 {
			return false // unmanaged, yet something set it
		}
	}
	for _, w := range want {
		got, ok := applied[w.Name]
		if !ok {
			continue // not reported in this form (ExecStart is handled below)
		}
		switch w.Name {
		case "ExecStart":
			if !execStartMatches(got, argv) {
				return false
			}
		case "MemoryMax", "CPUQuotaPerSecUSec", "RestartUSec", "TimeoutStopUSec", "TimeoutStartUSec":
			if u, isU := got.(uint64); !isU || u != w.Value.Value().(uint64) {
				return false
			}
		case "Restart", "CollectMode", "Description", "Type":
			if s, isS := got.(string); !isS || s != w.Value.Value().(string) {
				return false
			}
		case "RemainAfterExit":
			if b, isB := got.(bool); !isB || b != w.Value.Value().(bool) {
				return false
			}
		}
	}
	return true
}

// execStartMatches compares the argv systemd reports with the one we asked for. This is the
// comparison that matters: everything else is a limit, this is what actually runs.
func execStartMatches(applied any, want []string) bool {
	// The reported signature is a(sasbttttuii): path, argv, ignore_errors, then FOUR timestamps
	// (start and exit, each realtime + monotonic), pid, code, status. Getting the field count
	// wrong makes the decode fail rather than mismatch, which reads as drift on every tick and
	// restarts a healthy workload forever — the failure this cost one live round to find.
	type execStatus struct {
		Path         string
		Args         []string
		IgnoreErrors bool
		StartTS      uint64
		StartTSMono  uint64
		ExitTS       uint64
		ExitTSMono   uint64
		PID          uint32
		Code         int32
		Status       int32
	}
	var got []execStatus
	if err := godbus.Store([]any{applied}, &got); err != nil || len(got) == 0 {
		return false
	}
	return slices.Equal(got[0].Args, want)
}

// unitProperties is the transient unit's definition. There is no [Install] section to omit and
// no Requires= on the agent to add: a transient unit cannot be enabled into a boot target at
// all, so the property that block existed to emulate — never start without the agent — now holds
// by construction, for every workload rather than only the secret-bearing ones.
func (r *Runtime) unitProperties(id, configSum string, app workload.App) []sddbus.Property {
	props := []sddbus.Property{
		sddbus.PropDescription(unitDescription(app)),
		sddbus.PropExecStart(r.sandboxArgv(id, configSum), false),
		{Name: "Restart", Value: godbus.MakeVariant(restartMode(app))},
		{Name: "RestartUSec", Value: godbus.MakeVariant(uint64(2 * time.Second / time.Microsecond))},
		// How long a stop waits before SIGKILL. Always set, never left to the manager's default
		// (90s here), because that is the wrong bound for this shape of workload: the process is
		// PID 1 of its own namespace, and the kernel drops a signal PID 1 has no handler for —
		// SIGTERM included, and from an ancestor namespace too, since only SIGKILL and SIGSTOP are
		// forced. An image that installs no handler therefore always runs the period out, so the
		// period IS the latency of every restart: a changed spec reached the workload a minute and
		// a half after the agent decided to apply it. Fedora makes it worse than slow — a
		// service.d drop-in sets TimeoutStopFailureMode=abort, so the expiry crashes the unit
		// rather than killing it quietly.
		{Name: "TimeoutStopUSec", Value: godbus.MakeVariant(uint64(terminationGracePeriod(app) / time.Microsecond))},
		// What the expiry MEANS, which is the other half of that story. `abort` — Fedora's
		// default, via a drop-in — sends the watchdog signal to collect a core dump instead of
		// killing, and SIGABRT has a default action, so PID 1 of a namespace drops it exactly
		// like SIGTERM: the grace period expires into a signal the workload cannot receive
		// either, and the unit sits in final-watchdog with the workload still running. `kill`
		// is the failure mode that ends, since SIGKILL is one of the two signals the kernel
		// forces on a namespace's init.
		//
		// Asking for it is worth doing and is NOT worth relying on. A drop-in is applied after
		// transient properties, so one that matches every service wins over anything asked for
		// here: Fedora ships exactly that in /usr/lib/systemd/user/service.d/10-timeout-abort.conf
		// (from the "Shorter Shutdown Timer" change, which also cut DefaultTimeoutStopSec to 45s),
		// and a unit started with the property below still reports `abort`. Measured, not
		// assumed. What actually makes a stop terminate is stopUnit, which stops waiting and
		// kills the unit itself.
		{Name: "TimeoutStopFailureMode", Value: godbus.MakeVariant("kill")},
		{Name: "CollectMode", Value: godbus.MakeVariant(collectMode(app))},
		// The flapping backstop, and it has to be set HERE. A transient unit gets systemd's
		// defaults otherwise, and the agent cannot see a workload that is failing at all while
		// systemd keeps restarting it: every converge finds the unit active-ish and as
		// specified, so the loop is invisible from above and runs forever. With a limit the
		// unit reaches `failed`, which is the state the agent's own restart backoff reacts to.
		// The two are one mechanism: this stops the fast loop, the backoff stops the slow one.
		{Name: "StartLimitIntervalUSec", Value: godbus.MakeVariant(uint64(startLimitInterval / time.Microsecond))},
		{Name: "StartLimitBurst", Value: godbus.MakeVariant(uint32(startLimitBurst))},
	}
	if runToCompletion(app) {
		props = append(props,
			// A job is oneshot, and the difference from a service is not cosmetic: a simple unit
			// is "started" the moment the process is forked, so a workload that exits instantly
			// looks up and then dies, while a oneshot unit's activation IS the run — it completes
			// when the process leaves, and its outcome is the unit's Result. That is what makes
			// the deadline below expressible at all, and it is why the start job must not be
			// waited on (see Apply).
			sddbus.Property{Name: "Type", Value: godbus.MakeVariant("oneshot")},
			// Keep the unit loaded and "active (exited)" after the process leaves, which is what
			// makes Never mean Never. Without it a finished job is reaped, States stops reporting
			// it, the converge pass sees a wanted workload with no unit, and starts it again — a
			// run-to-completion job re-run forever on the heartbeat.
			sddbus.Property{Name: "RemainAfterExit", Value: godbus.MakeVariant(true)},
			// The job's deadline. For a oneshot unit the start timeout bounds the WHOLE run, so
			// this is spec.lifecycle.activeDeadlineSeconds exactly — not an approximation of it.
			// RuntimeMaxSec, which is what a service would use, does nothing here: systemd never
			// considers a oneshot unit to be running rather than starting.
			sddbus.Property{Name: "TimeoutStartUSec", Value: godbus.MakeVariant(activeDeadline(app))},
		)
	}
	if b := app.Limits.Memory.Value(); b > 0 {
		props = append(props, sddbus.Property{Name: "MemoryMax", Value: godbus.MakeVariant(uint64(b))})
	}
	if m := app.Limits.CPU.MilliValue(); m > 0 {
		// CPUQuota is a percentage on the command line but microseconds-per-second on the bus.
		usec := uint64(m) * uint64(time.Second/time.Microsecond) / 1000
		props = append(props, sddbus.Property{Name: "CPUQuotaPerSecUSec", Value: godbus.MakeVariant(usec)})
	}
	return props
}

// unitLoaded reports whether the manager actually holds this unit, which is how a workload that
// has run is told from one that never has: both answer ActiveState=inactive, and only LoadState
// distinguishes them ("loaded" against "not-found").
func unitLoaded(ctx context.Context, c *sddbus.Conn, unit string) bool {
	p, err := c.GetUnitPropertyContext(ctx, unit, "LoadState")
	if err != nil || p == nil {
		return false
	}
	s, _ := p.Value.Value().(string)
	return s == "loaded"
}

// runToCompletion reports whether this workload is a job rather than a service — spec.restartPolicy
// Never. Every other policy (including the unset one, which means Always) is a long-running
// service the node keeps up.
func runToCompletion(app workload.App) bool { return app.Lifecycle.RunToCompletion() }

// restartMode maps spec.restartPolicy onto systemd's Restart=. An unset policy is Always, the
// default the field documents: applied here, where the value is consumed, so an unset field keeps
// following the default rather than being stamped onto the object. An unknown value cannot reach
// this — admission rejects it — and is treated as the default rather than silently disabling
// restarts, since "no" is the one answer a typo must never produce.
func restartMode(app workload.App) string {
	switch app.Lifecycle.RestartPolicy {
	case corev1.RestartOnFailure:
		return "on-failure"
	case corev1.RestartNever:
		return "no"
	default:
		return "always"
	}
}

// collectMode decides when systemd may unload the unit, and the two answers are opposites for the
// two shapes of workload.
//
// A service is collected as soon as it is inactive or failed, so a stopped workload leaves no name
// behind for the next start to trip over. A job must NOT be: its terminal state is the only record
// that it ran, and reaping it would have the next converge pass see a wanted workload with no unit
// and start it over. "inactive" is the narrower mode — it leaves a failed unit loaded — and paired
// with RemainAfterExit a successful job never reaches inactive either.
//
// This holds a job down for the life of the manager, and no longer: the unit is transient, so a
// reboot forgets it and the agent runs the job again. Nothing on the node is durable by design,
// and a job that must run exactly once needs a record above the node to say it already did.
func collectMode(app workload.App) string {
	if runToCompletion(app) {
		return "inactive"
	}
	return "inactive-or-failed"
}

// activeDeadline is the job's whole-run bound as systemd's TimeoutStartUSec. An unset deadline is
// USEC_INFINITY rather than the manager's default: the default (90s here, 45s on a Fedora that
// shortened it) would silently kill any job that took longer, which is not something a field the
// author left blank is allowed to mean.
func activeDeadline(app workload.App) uint64 {
	s := app.Lifecycle.ActiveDeadlineSeconds
	if s == nil || *s <= 0 {
		return math.MaxUint64 // USEC_INFINITY
	}
	return uint64(*s) * uint64(time.Second/time.Microsecond)
}

// terminationGracePeriod is how long this workload's stop waits before the kill — the app's own
// lifecycle accessor, so the default lives in one place and the node cannot drift from what the
// API documents.
func terminationGracePeriod(app workload.App) time.Duration { return app.Lifecycle.GracePeriod() }

// sandboxArgv is what the unit execs: the trampoline, the config it reads and that config's
// sha256. One definition, used both to build the property and to check what came back, so the two
// cannot drift apart.
//
// The digest is an ARGUMENT rather than something the trampoline is trusted to look up, and it
// does two jobs with one value. It is the sandbox's integrity check — the config is a file under
// a directory the agent's user can write, and it names the layers to mount, the argv to exec and
// the id to drop to, so substituting it substitutes the workload; the sandbox hashes the bytes it
// read and refuses anything else. And because it rides in the argv, it is also what systemd
// reports back, which is how a content change becomes visible drift.
func (r *Runtime) sandboxArgv(id, configSum string) []string {
	return append(append([]string{}, r.sandboxCmd...), "--config", r.configPath(id), "--config-sha256", configSum)
}

// unitDescription is the operator-facing label systemd shows for the unit: the workload in the
// namespace/name form the API and kubectl use.
//
// It is a LABEL and nothing else — it carries no data anything reads back. The unit is named by
// the workload's uid, which is precise but says nothing to a human running `systemctl --user
// list-units`; this is the line that maps it to an application.
func unitDescription(app workload.App) string {
	return fmt.Sprintf("horchestra-app %s/%s", app.Namespace, app.Name)
}

// Remove stops the workload's unit and drops its per-workload overlay, secret-env and config
// state. Everything it deletes is named by the workload's id, which is the uid Runtime.List hands
// back — so teardown needs nothing the unit name does not already carry.
func (r *Runtime) Remove(ctx context.Context, name string, grace time.Duration) error {
	unit := r.UnitName(name)
	if grace <= 0 {
		grace = removeGrace // no spec to read one from; the documented default stands in
	}
	// Stopping is the whole teardown: CollectMode=inactive-or-failed makes systemd drop the unit
	// with it, and a transient unit has no file to delete, nothing to disable and no reload to
	// trigger.
	_ = withUserConn(ctx, func(c *sddbus.Conn) error {
		_ = stopUnit(ctx, c, unit, grace)
		_ = c.ResetFailedUnitContext(ctx, unit)
		return nil
	})
	// The workload's namespace dies with its unit — it is the process that held it. What outlives
	// it is the helper's half, the veth on this node, so that is what is taken back. Best effort
	// and never fatal: GC sweeps whatever a failed call here leaves, keyed on the same list.
	if r.net != nil {
		if err := r.net.Teardown(ctx, name); err != nil {
			log.Debug().Err(err).Str("workload", name).Msg("userns: unwiring on remove")
		}
	}
	for _, p := range []string{r.netnsPidPath(name), r.networkReadyPath(name)} {
		_ = os.Remove(p)
	}
	// The values go with the workload: both carriers live in tmpfs, and neither outlives it.
	_ = os.RemoveAll(runtime.SecretEnvFile(r.runtimeDir, name))
	_ = os.RemoveAll(runtime.SecretVolumeRoot(r.runtimeDir, name))
	for _, sub := range []string{"merged", "init"} {
		_ = os.RemoveAll(filepath.Join(r.stateDir, sub, name))
	}
	_ = os.Remove(r.configPath(name))
	// The retry budget goes with the workload too. A job removed and pushed again is a new run
	// of it, not the continuation of the one that failed.
	r.runs.forget(name)
	r.flap.forget(name)
	return nil
}

// States returns the workloads systemd currently holds units for, each with the state it is in.
// With transient units the manager is the only record — there are no files to glob — so this asks
// the bus, matching every state rather than only the active ones: a failed unit that CollectMode
// has not yet reaped is still a workload this node manages and must be able to tear down.
//
// The listing ALREADY carries ActiveState and SubState per unit, so the phase costs no extra round
// trip; it used to be received and thrown away, and the caller was left inferring "running" from
// the fact that a unit existed at all. Only the exit status needs a second question, and only for
// units that are no longer running.
func (r *Runtime) States(ctx context.Context) ([]workload.State, error) {
	var out []workload.State
	err := withUserConn(ctx, func(c *sddbus.Conn) error {
		units, err := c.ListUnitsByPatternsContext(ctx, nil, []string{unitGlob})
		if err != nil {
			return err
		}
		for _, u := range units {
			id, ok := unitID(u.Name)
			if !ok {
				continue
			}
			st := workload.State{ID: id, Phase: unitPhase(u.ActiveState, u.SubState)}
			st.Attempts, _ = r.runs.count(id)
			if st.Phase != corev1.AppPhaseRunning {
				var result string
				st.ExitCode, st.FinishedAt, result = exitStatus(ctx, c, u.Name)
				st.Reason = failureReason(id, result, r.runs)
			}
			out = append(out, st)
		}
		return nil
	})
	return out, err
}

// unitPhase maps systemd's two-level state onto the phase an Application reports.
//
// SubState is what carries the distinction, and it is why ActiveState alone was never enough:
// a job held by RemainAfterExit sits at active/exited — active, with nothing running. Only a job
// carries RemainAfterExit, so active/exited unambiguously means one that ran and returned zero;
// a job that returned anything else is parked at failed by CollectMode=inactive, which is what
// keeps its exit status readable at all.
func unitPhase(activeState, subState string) string {
	switch activeState {
	case "active":
		if subState == "exited" {
			return corev1.AppPhaseSucceeded
		}
		return corev1.AppPhaseRunning
	case "activating", "reloading", "deactivating":
		// Still coming up, or still going down with a process alive. Reporting anything
		// terminal here would make a restart look like an outcome.
		return corev1.AppPhaseRunning
	default: // failed, inactive
		return corev1.AppPhaseFailed
	}
}

// exitStatus is how a finished workload finished. Both values are systemd's own record of the
// main process, so they survive the process itself — which is the point: by the time anyone
// asks, there is nothing left to ask.
func exitStatus(ctx context.Context, c *sddbus.Conn, unit string) (int32, time.Time, string) {
	props, err := c.GetUnitTypePropertiesContext(ctx, unit, "Service")
	if err != nil {
		return 0, time.Time{}, ""
	}
	code, _ := props["ExecMainStatus"].(int32)
	result, _ := props["Result"].(string)
	usec, _ := props["ExecMainExitTimestamp"].(uint64)
	if usec == 0 {
		return code, time.Time{}, result
	}
	return code, time.UnixMicro(int64(usec)), result
}

// Reasons a job's failure is reported under. They are the two an operator cannot work out from an
// exit code, which is why they are the two worth naming: a workload killed at its deadline and one
// that simply crashed both leave a non-zero status behind.
const (
	reasonDeadlineExceeded     = "DeadlineExceeded: the job outran spec.lifecycle.activeDeadlineSeconds and was killed"
	reasonBackoffLimitExceeded = "BackoffLimitExceeded: the job failed and its spec.lifecycle.backoffLimit is spent"
)

// failureReason names why a job is over, from systemd's own Result plus the retry ledger. An empty
// reason is the ordinary case — a plain non-zero exit, which the exit code already describes, and a
// job that has runs left, which is not over at all.
func failureReason(id, result string, runs *runLedger) string {
	switch {
	case result == "timeout":
		return reasonDeadlineExceeded
	case result == "success" || result == "":
		return ""
	case runs.spent(id):
		if n, budget := runs.count(id); budget > 0 && n > 0 {
			return reasonBackoffLimitExceeded
		}
	}
	return ""
}

// GC reclaims the image store down to the keep-set.
func (r *Runtime) GC(ctx context.Context, keep []string) ([]string, error) {
	return runtime.GCImages(ctx, r.images, keep)
}

// Logs streams the workload's journal (its unit's stdout/stderr under systemd --user); follow tails
// it, tail bounds the backlog. The reader kills journalctl and releases the pipe on Close.
//
// The selector is a field match on _SYSTEMD_USER_UNIT, not `--user -u <unit>`, and the difference
// is load-bearing. A rootless workload runs as a SUBORDINATE uid out of the user-namespace map,
// and journald files every entry under the sender's _UID: a subuid has no journal of its own, so
// the workload's output lands in the system journal. It is tagged with the right user unit and
// cgroup — attribution is fine — but `--user` reads only THIS user's journal and `--user-unit`
// adds an implicit _UID match for the caller, so both come back empty while the output sits
// there. --merge spans whichever journal files hold it. Reading the system journal needs
// systemd-journal membership, which `node-tool install agent --user` checks and reports.
func (r *Runtime) Logs(ctx context.Context, name string, follow bool, tail int64) (io.ReadCloser, error) {
	args := []string{"--merge", "_SYSTEMD_USER_UNIT=" + r.UnitName(name), "-o", "cat", "--no-pager"}
	if tail > 0 {
		args = append(args, "-n", strconv.FormatInt(tail, 10))
	}
	if follow {
		args = append(args, "-f")
	}
	return utils.StartReader(exec.CommandContext(ctx, "journalctl", args...))
}

// configPath is where the sandbox config for a workload is written for its trampoline to read.
func (r *Runtime) configPath(id string) string {
	return filepath.Join(r.stateDir, "config", id+".json")
}

// unitID recovers a workload id from its unit name (<uid>.service); ok is false for a name that is
// not one of ours. The name is the id and nothing else, so there is nothing to unescape.
func unitID(unit string) (string, bool) {
	return strings.CutSuffix(unit, ".service")
}

// cpuQuota maps a CPU limit to systemd CPUQuota — a hard cap as a percentage of one CPU (500m ->
// "50%", 2 -> "200%"). Empty when unset. Mirrors pkg/systemd/units so this --user runtime and the
// default system runtime enforce a limit identically.
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

// memBytes renders a memory quantity as a byte count for systemd's Memory* knobs, which take bytes
// (not the Ki/Mi suffixes resource.Quantity prints). Empty when unset.
func memBytes(q resource.Quantity) string {
	if b := q.Value(); b > 0 {
		return strconv.FormatInt(b, 10)
	}
	return ""
}

// supportedVolumes fails closed on a volume kind this runtime cannot honour. A kind the sandbox
// does not project would otherwise be dropped SILENTLY and the workload started anyway: an app
// whose credentials are mandatory would come up serving the image's baked-in default at that
// path, and PV-destined writes would land on the ephemeral overlay that Remove deletes — with
// nothing surfaced in status. Returning the error puts it in the application's status instead of
// degrading the workload without telling anyone.
//
// What is left out is the two kinds that need a device: a block device and a filesystem image are
// attached, not bound, and this runtime shares the node's kernel and mount tree.
func supportedVolumes(volumes []workload.Volume) error {
	for _, v := range volumes {
		switch v.Kind {
		case workload.VolumeTmpfs, workload.VolumeSecret, workload.VolumeHostPath:
		default:
			return fmt.Errorf("runtime %q does not support the volume at %q: block-device and image volumes need a runtime that attaches them",
				RuntimeName, v.MountPath)
		}
	}
	return nil
}

// restrictedFloorUID is the non-root uid/gid a workload runs as when the securityContext leaves
// it unset — the same floor admission's policyEnforcement stamps.
const restrictedFloorUID = corev1.DefaultRunAsID

// buildConfig turns the image spec + app + resolved volumes into a sandbox config. Kubernetes
// command/args semantics apply. The rootfs itself carries no upperdir, so it is read-only from
// the moment it is mounted and every writable path is a mount on top of it: a tmpfs volume is
// ephemeral, a host-path volume is the node directory the Volumes driver resolved and is the only
// one whose writes outlive the workload. The workload is dropped to the non-root uid/gid from
// securityContext.runAsUser/
// runAsGroup (defaulting to the restricted floor) before exec — see dropPrivileges — so it never
// runs as the userns root (which maps to the agent's own host uid).
func (r *Runtime) buildConfig(id string, ls *runtime.LaunchSpec, app workload.App, volumes []workload.Volume, secretEnvFile string, secretMounts []runtime.SecretMount) apisandbox.Config {
	entry, cmd := ls.Entrypoint, ls.Cmd
	if len(app.Command) > 0 {
		entry, cmd = app.Command, nil
	}
	if len(app.Args) > 0 {
		cmd = app.Args
	}
	command := slices.Concat(entry, cmd)

	env := slices.Concat(ls.Env, app.Env) // image env + declared app env, in order

	uid, gid := workloadRunAs(app)

	var tmpfs []apisandbox.TmpfsMount
	var binds []apisandbox.BindMount
	for _, v := range volumes {
		if v.MountPath == "" {
			continue
		}
		switch v.Kind {
		case workload.VolumeTmpfs:
			tmpfs = append(tmpfs, apisandbox.TmpfsMount{Path: v.MountPath})
		case workload.VolumeHostPath:
			binds = append(binds, apisandbox.BindMount{Source: v.Ref, Target: v.MountPath, ReadOnly: v.ReadOnly})
		}
	}
	secrets := make([]apisandbox.SecretMount, 0, len(secretMounts))
	for _, m := range secretMounts {
		secrets = append(secrets, apisandbox.SecretMount{Source: m.Source, Target: m.Target})
	}
	return apisandbox.Config{
		LowerDirs:    ls.LayerDirs,
		Merged:       filepath.Join(r.stateDir, "merged", id),
		InitDir:      filepath.Join(r.stateDir, "init", id),
		Command:      command,
		Env:          env,
		WorkingDir:   ls.WorkingDir,
		Hostname:     app.Name,
		TmpfsMounts:  tmpfs,
		SecretMounts: secrets,
		BindMounts:   binds,
		UID:          int(uid),
		GID:          int(gid),
		// A path, not the values: this struct is written to persistent disk, and the file it
		// names lives in tmpfs.
		SecretEnvFile: secretEnvFile,
		// The routed-network fields are paths too, and they are in the config for the same reason
		// everything else is: the trampoline reads this file and nothing else. Their presence is
		// what turns on the handshake, so a workload on the host network carries none of them and
		// the trampoline's start path is byte-identical to what it was.
		Network:          networkMode(app),
		NetnsPidPath:     r.netnsPidPath(id),
		NetworkReadyPath: r.networkReadyPath(id),
	}
}

// networkMode is what this workload's sandbox does about the network: nothing (the host's, which
// is every workload today) or a namespace of its own to be wired.
func networkMode(app workload.App) string {
	if app.HostNetwork {
		return apisandbox.NetworkHost
	}
	return apisandbox.NetworkRouted
}

// The two FIFOs of the wiring handshake. Under the RAM-backed runtime dir: they are rendezvous
// points for one start, and a reboot must not leave a stale one behind for the next.
func (r *Runtime) netnsPidPath(id string) string {
	return filepath.Join(r.runtimeDir, "net", id+".pid")
}

func (r *Runtime) networkReadyPath(id string) string {
	return filepath.Join(r.runtimeDir, "net", id+".ready")
}

// The spec hash this file used to carry is gone: the rendered sandbox config is a strictly better
// version of the same signal. It is derived from the same desired state but digests the bytes
// that actually run — resolved layer directories rather than an image ref, so re-pointing a tag
// relaunches only when it resolves to different layers — and it needs no separate list of which
// fields matter, which could fall out of step with what buildConfig reads. The one input it does
// not cover is the Secret-sourced environment, which is a path here and never a value; a rotated
// value is caught by runtime.SecretEnvChanged.
