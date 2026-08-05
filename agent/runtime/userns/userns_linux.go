//go:build linux

package userns

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"golang.org/x/sys/unix"
)

const (
	// usernsMarker marks that the process is already running inside the agent's user namespace, so
	// EnterUserns proceeds instead of re-entering.
	usernsMarker = "HORCHESTRA_IN_USERNS"
	// sandboxSyncEnv names the fd a userns stage-1 child blocks on until the parent installs its id
	// maps; the parent releases it, and the child then re-execs — now uid 0 in the userns — so
	// execve regrants a full set of namespaced capabilities.
	sandboxSyncEnv = "HORCHESTRA_USERNS_SYNC"
)

const (
	// AgentUsernsFlags is the namespace set the AGENT enters for its persistent user namespace:
	// a user namespace (mapped-root + the /etc/subuid range, so image unpack can chown files to
	// subordinate ids) plus mount/uts/ipc isolation. It deliberately OMITS a PID namespace: a
	// process in its own PID namespace cannot connect to the per-user systemd bus (systemd-run
	// --user then fails with "connect to user scope bus: No data available"), and the rootless
	// runtime drives that bus to supervise workloads.
	AgentUsernsFlags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC
	// SandboxUsernsFlags is the workload trampoline's set: the agent's namespaces plus a PID
	// namespace, so the workload is PID 1 of its own process tree. The trampoline never touches the
	// user bus, so the PID namespace is safe there.
	SandboxUsernsFlags = AgentUsernsFlags | syscall.CLONE_NEWPID
)

// MapAndReexec is called first by any command that may be a user-namespace stage-1 child (born in
// a fresh userns, unmapped, no caps). It tells the parent it is ready (fd 3), waits for the parent
// to install its id maps (fd 4), then RE-EXECs the same command — now uid 0 in the userns, so
// execve regrants a full set of namespaced capabilities. A no-op when not a stage-1 child.
func MapAndReexec() error {
	if os.Getenv(sandboxSyncEnv) == "" {
		return nil
	}
	ready := os.NewFile(3, "ready")
	_, _ = ready.Write([]byte{1})
	_ = ready.Close()
	goF := os.NewFile(4, "go")
	_, _ = goF.Read(make([]byte, 1)) // released once the parent has installed the maps
	_ = goF.Close()
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, sandboxSyncEnv+"=") {
			env = append(env, e)
		}
	}
	return syscall.Exec("/proc/self/exe", os.Args, env)
}

// EnterUserns puts the caller inside a persistent user namespace (mapped-root + its /etc/subuid
// range, plus the extra namespaces in cloneFlags) — the podman/rootlesskit model. Once inside,
// image pull (chown of unpacked layers) and image reads see consistent subordinate-id ownership,
// with NO host caps. cloneFlags selects the namespace set: the agent passes AgentUsernsFlags (no PID
// namespace, so it can still reach the user systemd bus to supervise workloads); the workload
// trampoline passes SandboxUsernsFlags (with a PID namespace). On the first call (marker unset) it
// re-execs the caller into the userns and waits, mirroring its exit (never returns); inside the
// userns (marker set) it returns nil so the caller proceeds.
// UsernsOptions is what the entry needs: which namespaces, whose ids, and — for a routed network —
// the two ends of the handshake that lets somebody else wire the namespace before the workload
// runs in it.
type UsernsOptions struct {
	Flags                    uintptr
	WorkloadUID, WorkloadGID int64
	// AnnouncePath and ReadyPath turn on the routed-network handshake. Stage one writes the
	// namespaced child's HOST pid to AnnouncePath — inside its own PID namespace the child sees
	// itself as 1, so this is the only place the number anyone outside can use exists — and then
	// waits on ReadyPath until the agent reports the veth, address and routes in place.
	//
	// Waiting is the point. The namespace exists from birth holding nothing but loopback, and a
	// workload started into that cannot tell "not built yet" from "broken": it fails to resolve,
	// fails to connect, and looks like a bug in itself. Empty paths mean no handshake, which is
	// every workload on the host network.
	AnnouncePath, ReadyPath string
}

func EnterUserns(logw *os.File, opts UsernsOptions) error {
	if os.Getenv(usernsMarker) != "" {
		return nil
	}
	// Refuse root before anything else. A user namespace created BY root maps container 0 onto
	// host 0, so the process keeps genuine host capabilities while looking exactly like the
	// unprivileged case — same namespaces, same logs, same running workloads, none of the
	// isolation. That is worse than not entering a namespace at all, because nothing reveals it.
	//
	// The failure this replaces was accidental rather than designed: root usually has no
	// /etc/subuid range, so the id map failed and the error advised adding one — advice that, if
	// followed, produced exactly the silently-privileged agent described above.
	if os.Geteuid() == 0 {
		return errors.New("refusing to run as root: this process holds no host capability by design, " +
			"and a user namespace created by root confers none of the isolation it appears to — " +
			"run it as an unprivileged user with a subordinate id range")
	}
	cmd, err := spawnMappedUserns(os.Args[1:], []string{usernsMarker + "=1"}, logw, opts)
	if err != nil {
		return err
	}
	stopForwarding := forwardSignals(cmd)
	err = cmd.Wait()
	stopForwarding()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	}
	os.Exit(code)
	return nil // unreachable
}

// forwardSignals relays every signal this process receives to the namespaced child, until the
// returned function is called.
//
// Without it the child hears only what the init system sends the whole cgroup. That covers a stop
// (systemd's default KillMode is control-group) and nothing else: `systemctl kill -s HUP` reaches
// the unit's main PID, which is THIS process — a trampoline with no configuration to reload and
// no logs to rotate — and the workload never learns it was asked. Two signals are never relayed:
// SIGCHLD is this process's own bookkeeping, which cmd.Wait observes, and SIGURG is the Go
// runtime's async-preemption traffic.
//
// Relaying does NOT make a stop reliable, and nothing at this level could. The child ends up PID 1
// of its own PID namespace, where the kernel discards any signal it has installed no handler for —
// SIGTERM included, and from an ancestor namespace too, since only SIGKILL and SIGSTOP are forced.
// What ends such a workload is SIGKILL, which the agent escalates to on its own clock (stopUnit
// during a converge, Reap for a stop nobody is waiting on any more).
func forwardSignals(cmd *exec.Cmd) func() {
	// os/signal drops a signal the channel has no room for, so keep slack for bursts.
	ch := make(chan os.Signal, 64)
	signal.Notify(ch)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case s := <-ch:
				if s == syscall.SIGCHLD || s == syscall.SIGURG {
					continue
				}
				if p := cmd.Process; p != nil {
					_ = p.Signal(s)
				}
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// spawnMappedUserns re-execs /proc/self/exe with argv into a fresh user+mount+pid+uts+ipc
// namespace, then maps container id 0 → the agent's own id and 1..N → its subordinate range via
// newuidmap/newgidmap (a multi-segment map needs those setcap helpers), and releases the child.
func spawnMappedUserns(argv, extraEnv []string, logw *os.File, opts UsernsOptions) (*exec.Cmd, error) {
	subUID, err := subIDRange("/etc/subuid")
	if err != nil {
		return nil, fmt.Errorf("subuid: %w", err)
	}
	subGID, err := subIDRange("/etc/subgid")
	if err != nil {
		return nil, fmt.Errorf("subgid: %w", err)
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	goR, goW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/proc/self/exe", argv...)
	// argv[0] is carried over deliberately. exec.Command would put "/proc/self/exe" there, and the
	// node binary dispatches on argv[0]: started through its `horchestra-sandbox` alias, the child
	// would lose the alias, fall through to the root command, and die on an unknown --config —
	// inside stage one of every workload start, where the only trace is that workload's journal.
	cmd.Args = append([]string{os.Args[0]}, argv...)
	cmd.Env = append(append(os.Environ(), extraEnv...), sandboxSyncEnv+"=1")
	cmd.ExtraFiles = []*os.File{readyW, goR} // fd 3 (ready, child writes), fd 4 (go, child reads)
	cmd.Stdout, cmd.Stderr = logw, logw
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: opts.Flags,
		Setsid:     true,
	}
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{readyR, readyW, goR, goW} {
			_ = f.Close()
		}
		return nil, err
	}
	_ = readyW.Close()
	_ = goR.Close()
	fail := func(err error) (*exec.Cmd, error) {
		_ = goW.Close()
		_ = readyR.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, err
	}
	if _, err := readyR.Read(make([]byte, 1)); err != nil {
		return fail(fmt.Errorf("child ready: %w", err))
	}
	pid := cmd.Process.Pid
	if err := writeMap("newuidmap", pid, os.Getuid(), subUID, opts.WorkloadUID); err != nil {
		return fail(err)
	}
	if err := writeMap("newgidmap", pid, os.Getgid(), subGID, opts.WorkloadGID); err != nil {
		return fail(err)
	}
	// The child is already held here, waiting for its id maps; the network goes into the same
	// hold rather than a second one. Nothing downstream changes: stage two is released once, and
	// by then it has an address or the start has failed.
	if err := wireNetwork(opts, pid); err != nil {
		return fail(err)
	}
	_ = goW.Close()
	_ = readyR.Close()
	return cmd, nil
}

// networkWireTimeout bounds the handshake. It is generous — the agent has to reach a helper, which
// has to talk to the kernel — and bounded all the same: a start that hangs forever on a FIFO is a
// unit systemd reports as "activating" and an operator cannot tell from a slow image pull.
const networkWireTimeout = 30 * time.Second

// networkReadyOK is what the agent writes when the namespace is wired. A byte with a value rather
// than a closed pipe, so "wired" and "the writer gave up" are different events on the wire.
const networkReadyOK = 'w'

// wireNetwork announces the namespaced child and waits for it to be given an address.
//
// The child creates its own network namespace because nothing else can give it one: entering a
// network namespace needs CAP_SYS_ADMIN in BOTH the namespace's owning user namespace and the
// caller's current one, so a namespace made anywhere else is one this unprivileged process could
// never join (measured, EPERM, on both arrangements that looked plausible). What it cannot do is
// give itself a veth — hence this handshake.
func wireNetwork(opts UsernsOptions, pid int) error {
	if opts.AnnouncePath == "" || opts.ReadyPath == "" {
		return nil
	}
	if err := writeDeadlined(opts.AnnouncePath, []byte(strconv.Itoa(pid)+"\n")); err != nil {
		return fmt.Errorf("announce netns: %w", err)
	}
	b, err := readDeadlined(opts.ReadyPath, 1)
	if err != nil {
		return fmt.Errorf("await network: %w", err)
	}
	if b[0] != networkReadyOK {
		return errors.New("await network: the agent could not wire this namespace")
	}
	return nil
}

// writeDeadlined and readDeadlined talk to a FIFO the agent created, opened NON-BLOCKING so a
// missing peer is a deadline rather than a hang. A blocking open on a FIFO waits for its
// counterpart with no way to give up, and this runs inside a unit start.
func writeDeadlined(path string, data []byte) error {
	// O_RDWR on the WRITE side too, and for the mirror of the reason below: a write-only
	// non-blocking open of a FIFO nobody is reading yet fails outright with ENXIO. The agent opens
	// its end only after asking systemd to start the unit, so the trampoline regularly gets there
	// first — measured on a stand as `announce netns: ... no such device or address` on restart
	// after restart, each one a start systemd had to retry.
	//
	// It does not weaken the handshake: holding a read end of one's own makes the announce always
	// land in the buffer, and what the trampoline actually waits on is the ANSWER on the other
	// FIFO, which has its own deadline.
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.SetWriteDeadline(time.Now().Add(networkWireTimeout)); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

func readDeadlined(path string, n int) ([]byte, error) {
	// O_RDWR for the reason readPID uses it on the other side: a read-only FIFO with no writer
	// attached reads EOF rather than waiting, which would let the trampoline decide it had been
	// answered before anyone answered.
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if err := f.SetReadDeadline(time.Now().Add(networkWireTimeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// subIDRange returns the current user's range from path, matched by username or numeric id.
// SubordinateIDs is the range of ids this agent may hand to a workload — and, once it is inside
// its own user namespace, the range that namespace maps.
//
// It reads the KERNEL's answer (/proc/self/uid_map) rather than /etc/subuid, because by the time
// anything needs it the agent has re-exec'd into its namespace, where it is root and /etc/subuid
// has no line for root. The map is also the better source: it is what the ids actually are, not
// what a file says they should be, and the agent wrote it from that file one step earlier.
//
// Outside a namespace (the identity map every process starts with) it falls back to /etc/subuid,
// which is what the entry path itself uses to build the map in the first place.
func SubordinateIDs() (uid, gid corev1.IDRange, err error) {
	if uid, err = mappedRange("/proc/self/uid_map", "/etc/subuid"); err != nil {
		return corev1.IDRange{}, corev1.IDRange{}, err
	}
	gid, err = mappedRange("/proc/self/gid_map", "/etc/subgid")
	return uid, gid, err
}

// mappedRange is the subordinate segment of this process's id map: the one that maps in-namespace
// id 1 onto the host. An identity map means no namespace has been entered yet, and the file is
// consulted instead.
func mappedRange(mapPath, subPath string) (corev1.IDRange, error) {
	b, err := os.ReadFile(mapPath)
	if err != nil {
		return subIDRange(subPath)
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "1" {
			continue // 0 → the agent's own id; anything else is a workload's own segment
		}
		host, err1 := strconv.ParseInt(f[1], 10, 64)
		size, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil || size <= 0 {
			break
		}
		return corev1.IDRange{Min: host, Size: size}, nil
	}
	return subIDRange(subPath)
}

func subIDRange(path string) (corev1.IDRange, error) {
	me, err := user.Current()
	if err != nil {
		return corev1.IDRange{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return corev1.IDRange{}, err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) != 3 || (f[0] != me.Username && f[0] != me.Uid) {
			continue
		}
		start, e1 := strconv.ParseInt(f[1], 10, 64)
		count, e2 := strconv.ParseInt(f[2], 10, 64)
		if e1 == nil && e2 == nil && count > 0 {
			return corev1.IDRange{Min: start, Size: count}, nil
		}
	}
	return corev1.IDRange{}, fmt.Errorf("no subordinate range for %s in %s (run: sudo usermod --add-subuids/--add-subgids)", me.Username, path)
}

// writeMap installs the id map on pid via newuidmap/newgidmap: container id 0 → hostID (the agent
// itself), container 1.. → the subordinate range, and — for a workload sandbox — one further
// segment carrying the id the control plane allocated to it.
//
// That last segment has to land on a DIFFERENT host id per workload, which is the whole point.
// The container-side id is private to each sandbox, but /proc/<pid>/root on the node is checked
// against the HOST id, so mapping every workload onto one subordinate id would hand back exactly
// the cross-tenant reach the per-namespace allocation just removed. The host id is therefore
// derived from the allocated one, inside a slot region carved off the top of the range.
//
// The range is 65536 ids wide, so this is a hash, not a bijection: two workloads on one node
// collide when their allocated ids are congruent modulo workloadSlots. Widening /etc/subuid and
// workloadSlots together is what raises that ceiling.
func writeMap(tool string, pid, hostID int, sub corev1.IDRange, workloadID int64) error {
	args := []string{
		strconv.Itoa(pid),
		"0", strconv.Itoa(hostID), "1", // container id 0 → the agent's own id
	}
	shared := sub.Size
	if workloadID > 0 {
		shared = sub.Size - min(int64(workload.Slots), sub.Size/2)
		// One function decides this for both sides: here, where the workload is TOLD its id, and
		// in the agent, where files are chowned so the workload owns them. Two derivations would
		// disagree exactly once and hand a workload files it cannot read.
		args = append(args, strconv.FormatInt(workloadID, 10),
			strconv.FormatInt(workload.HostID(sub, workloadID), 10), "1")
	}
	// container 1.. → the subordinate range the image's file ownership lives in
	args = append(args, "1", strconv.FormatInt(sub.Min, 10), strconv.FormatInt(shared, 10))
	if out, err := exec.Command(tool, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", tool, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
