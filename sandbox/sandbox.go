//go:build linux

package sandbox

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const defaultPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// enter is stage two, PID 1 of the new namespaces: it assembles the read-only root, pivots into
// it, drops every privilege it needed to get there and becomes the workload via execve.
func enter(cfg *Config) error {
	// NO_NEW_PRIVS, the capability bounding set and the seccomp filter are per-THREAD attributes
	// preserved across execve, so they have to be set on the very thread that calls
	// unix.Exec. Without this pin the Go scheduler is free to move the goroutine in between,
	// and the workload would start with none of them — silently, with nothing to observe.
	runtime.LockOSThread()

	resetInheritedSignals()

	// Wait to be wired, before anything else and long before execve. The namespace exists from
	// birth but has nothing in it except loopback, and a workload started into that has no way to
	// tell "the network is not built yet" from "the network is broken".
	if err := awaitNetwork(cfg); err != nil {
		return err
	}

	// Resolve the secret environment FIRST: the file lives on a host tmpfs that pivot_root puts
	// out of reach, and the values must never land anywhere the workload can read them back.
	// Fail-closed — a workload whose spec sources credentials must not start without them and
	// discover it as an application error somewhere else.
	secretEnv, err := readSecretEnv(cfg.SecretEnvFile)
	if err != nil {
		return err
	}

	lowers := append([]string(nil), cfg.LowerDirs...)
	for _, d := range lowers {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			return fmt.Errorf("lower dir %q: %w", d, err)
		}
	}

	if len(cfg.SecretEnvDir) > 0 {
		if err := requireTmpfs(cfg.SecretEnvDir); err != nil {
			return fmt.Errorf("SecretEnvDir: %w", err)
		}
		// Topmost layer: secret files shadow same-named image files.
		lowers = append(lowers, cfg.SecretEnvDir)
	}

	// The clone copied the host mount table with its propagation intact; on a systemd host that
	// is shared, and pivot_root refuses a shared root. Recursively private also stops mount
	// events traveling either way.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}

	if err := prepareSkeleton(cfg); err != nil {
		return err
	}
	// Bottommost layer: the skeleton fills mount-point gaps and can never shadow image content.
	// It also supplies the two lowerdirs overlayfs requires when mounting without an upperdir.
	lowers = append([]string{cfg.InitDir}, lowers...)

	if err := mountOverlay(lowers, cfg.Merged); err != nil {
		return fmt.Errorf("mount root: %w", err)
	}
	// From here the root is strictly read-only; everything below adds mounts on top of it.
	if err := mountVolumes(cfg.Merged, cfg.TmpfsMounts); err != nil {
		return err
	}
	// Persistent volumes before secrets: a secret projected at a path INSIDE a volume must win,
	// and the reverse order would mask it with the volume's own content.
	if err := mountBinds(cfg.Merged, cfg.BindMounts); err != nil {
		return err
	}
	if err := mountSecrets(cfg.Merged, cfg.SecretMounts); err != nil {
		return err
	}
	if err := setupDev(cfg.Merged); err != nil {
		return fmt.Errorf("/dev: %w", err)
	}
	if err := mountProc(cfg.Merged); err != nil {
		return fmt.Errorf("/proc: %w", err)
	}
	if err := mountSys(cfg.Merged); err != nil {
		return fmt.Errorf("/sys: %w", err)
	}

	if err := unix.Sethostname([]byte(cfg.Hostname)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}

	if cfg.Network == NetworkNone {
		if err := bringLoopbackUp(); err != nil {
			return err
		}
	}

	if err := pivotRoot(cfg.Merged); err != nil {
		return err
	}

	if err := os.Chdir(cfg.WorkingDir); err != nil {
		return fmt.Errorf("working directory: %w", err)
	}

	env := append([]string(nil), cfg.Env...)
	env = append(env, secretEnv...)
	if !envHas(env, "PATH") {
		env = append(env, defaultPath)
	}
	// Resolve the binary while the capabilities that read the image are still held, so a missing
	// entrypoint is a clear error rather than a permission failure after the drop.
	path, err := lookPath(cfg.Command[0], env)
	if err != nil {
		return err
	}

	// Before the drop, while a failure can still be reported: the limits themselves need no
	// privilege to lower, but a workload started without the ones it was given would be running
	// under a config nobody applied.
	if err := applyRlimits(cfg.Rlimits); err != nil {
		return err
	}
	if err := dropPrivileges(cfg.UID, cfg.GID, cfg.Seccomp); err != nil {
		return err
	}
	return unix.Exec(path, cfg.Command, env)
}

// pivotRoot makes root the new root filesystem and detaches the old one, leaving no path or file
// descriptor back to the host. pivot_root(".", ".") is valid, not chroot's poor cousin: the new
// root is stacked over the old one at the same directory, so no writable put_old is needed —
// which the read-only root could not provide. The old root is then re-entered by fd, not cwd —
// the kernel does not promise where the cwd points after a pivot — and detached lazily; every
// mount here is already recursively private, so the detach cannot propagate to the host.
// (After runc's pivotRoot, Apache-2.0; the pivot-into-itself trick is the LXC developers'.)
func pivotRoot(root string) error {
	oldroot, err := unix.Open("/", unix.O_DIRECTORY|unix.O_PATH, 0)
	if err != nil {
		return fmt.Errorf("open old root: %w", err)
	}
	defer func() { _ = unix.Close(oldroot) }()

	if err := unix.Chdir(root); err != nil {
		return fmt.Errorf("chdir %s: %w", root, err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Fchdir(oldroot); err != nil {
		return fmt.Errorf("fchdir old root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}
	return nil
}

// bringLoopbackUp raises lo in the sandbox's own network namespace, which the kernel creates
// with the interface DOWN. Nothing the workload could do would raise it afterwards: that takes
// CAP_NET_ADMIN, which dropPrivileges takes away — so a namespace left as the kernel made it
// would mean no 127.0.0.1 at all, and a great many programs talk to themselves that way.
//
// It is done with SIOCSIFFLAGS rather than netlink: setting one flag on one interface is the
// whole requirement, and an ioctl keeps this to a socket and two calls instead of a netlink
// message encoder.
func bringLoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("loopback: socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return fmt.Errorf("loopback: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("loopback: read flags: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("loopback: set UP: %w", err)
	}
	return nil
}

// awaitNetwork blocks until the caller reports this sandbox's namespace wired.
//
// Reading a FIFO the caller created: the open itself blocks until a writer arrives, so there is no
// polling, no timeout to tune here, and no state to inspect. If the caller dies without writing,
// the read ends and the workload never starts — which is the correct outcome, because a workload
// that cannot be given its address should not run instead of running unreachable.
func awaitNetwork(cfg *Config) error {
	if cfg.Network != NetworkRouted {
		return nil
	}
	// Blocking open, matching the announcement: the read end must be OPEN before the caller writes,
	// or its single byte goes into a FIFO nobody is holding and is discarded on close. Opening
	// here — early in stage two, before any mounting — is what makes that ordering hold.
	f, err := os.Open(cfg.NetworkReadyPath)
	if err != nil {
		return fmt.Errorf("await network: %w", err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(f, buf); err != nil {
		return fmt.Errorf("await network: %w", err)
	}
	if buf[0] != networkReadyOK {
		return fmt.Errorf("await network: the caller could not wire this namespace")
	}
	return nil
}

// networkReadyOK is what a caller writes when the namespace is wired. A byte with a value rather
// than a closed pipe, so "wired" and "the writer gave up" are different events on the wire.
const networkReadyOK = 'w'

// networkHandshakeTimeout bounds both halves. A start that hangs on a FIFO is a unit systemd
// reports as still starting, forever — the worst shape a failure can take.
const networkHandshakeTimeout = 30 * time.Second

// resetInheritedSignals guarantees the workload a pristine signal table. An ignored disposition
// survives both fork and execve, so whatever the invoking shell left ignored — bash runs
// background children with INT and QUIT at SIG_IGN — would reach the workload untrappable: a
// POSIX shell refuses to trap a signal ignored on entry, and delivering a signal to a
// pid-namespace init from outside requires exactly the handler that refusal prevents, leaving
// the StopSignal undeliverable. Taking every catchable signal over with the Go runtime's handler
// makes the workload's execve reset each of them to its default — execve only preserves SIG_IGN.
func resetInheritedSignals() {
	sigs := make([]os.Signal, 0, 64)
	for n := 1; n <= 64; n++ {
		if s := syscall.Signal(n); s != unix.SIGKILL && s != unix.SIGSTOP {
			sigs = append(sigs, s)
		}
	}
	signal.Notify(make(chan os.Signal, 1), sigs...)
}

func envHas(env []string, key string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			return true
		}
	}
	return false
}

// lookPath resolves argv[0] against the workload environment's PATH — the process' own PATH
// still points at the host's.
func lookPath(argv0 string, env []string) (string, error) {
	if strings.Contains(argv0, "/") {
		return argv0, nil
	}

	var path string
	for _, e := range env {
		if p, ok := strings.CutPrefix(e, "PATH="); ok {
			path = p
			break
		}
	}

	if len(path) == 0 {
		path, _ = strings.CutPrefix(defaultPath, "PATH=")
	}

	for _, dir := range strings.Split(path, ":") {
		cand := filepath.Join(dir, argv0)
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand, nil
		}
	}

	return "", fmt.Errorf("%q not found on PATH", argv0)
}

// readSecretEnv reads a caller-written environment file into NAME=value assignments. The shape is
// re-checked here rather than trusted: the path came out of a config file, and a line that is not
// an assignment would otherwise reach execve as one.
func readSecretEnv(path string) ([]string, error) {
	if len(path) == 0 {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secret env: %w", err)
	}
	var env []string
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if len(line) == 0 {
			continue
		}
		name, _, ok := strings.Cut(line, "=")
		if !ok || len(name) == 0 {
			return nil, fmt.Errorf("secret env: %q is not an assignment", line)
		}
		env = append(env, line)
	}
	return env, nil
}
