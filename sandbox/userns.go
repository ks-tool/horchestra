//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	api "github.com/ks-tool/horchestra/api/sandbox"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// envReexec marks the second stage. Namespaces can only be entered at clone
// time, never from a running multithreaded Go process, so stage one re-execs
// itself into them and stage two does everything else.
const envReexec = "SANDBOX_REEXEC"

// inSandbox reports whether this process is the second stage.
func inSandbox() bool { return len(os.Getenv(envReexec)) > 0 }

// reexec is stage one: it restarts this binary inside fresh namespaces and
// shepherds its lifetime, forwarding the caller's signals and reporting the
// workload's exit code.
func reexec(cfg *Config) error {
	child := exec.Command("/proc/self/exe", os.Args[1:]...)
	// argv[0] is carried over deliberately. exec.Command would put "/proc/self/exe" there, and a
	// host binary that dispatches on argv[0] — as the node binary does for its `horchestra-sandbox`
	// alias — would lose the alias in the child and fall through to its root command, dying on an
	// unknown flag inside stage one of every workload start.
	child.Args = append([]string{os.Args[0]}, os.Args[1:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = append(os.Environ(), envReexec+"=1")
	// SysProcAttr and SysProcIDMap are the types os/exec accepts — the two names that keep the
	// syscall import; every constant and call comes from x/sys/unix.
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: cloneFlags(cfg),
		// Single-identity map: the workload's non-root UID/GID inside the sandbox are the
		// invoking user outside, and no other host identity exists inside it.
		UidMappings: []syscall.SysProcIDMap{{ContainerID: cfg.UID, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: cfg.GID, HostID: os.Getgid(), Size: 1}},
		// The clone hands the child a full namespaced capability set, but that set does not
		// survive stage two's execve: with a non-zero uid (root is never mapped here) the kernel
		// recalculates every set to exactly the AMBIENT set, which is empty by default — stage
		// two would arrive capless and fail its very first mount. These two are therefore
		// carried across in the ambient set: SYS_ADMIN mounts and pivots, SETPCAP empties the
		// bounding set. Ambient capabilities survive the workload's execve the same way, so
		// dropPrivileges clears the set before the exec.
		AmbientCaps: ambientCaps(cfg),
		// Writing an unprivileged gid map requires setgroups to be denied first; the kernel
		// then refuses it for the life of the namespace, so the workload's supplementary
		// group set can never be widened.
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  unix.SIGKILL,
	}
	if err := child.Start(); err != nil {
		return explainUsernsRefusal(err)
	}
	// The child's HOST pid is the only handle to its network namespace, and stage one is the only
	// place that knows it — inside its own PID namespace the child sees itself as 1. Written
	// before anything else so whoever is wiring can start the moment the namespace exists.
	if err := announceNetns(cfg, child.Process.Pid); err != nil {
		_ = child.Process.Kill()
		return err
	}

	// Every caller signal is forwarded verbatim — HUP reloads nginx, USR1 rotates logs, QUIT
	// quits it gracefully — except the two generic stop signals. systemd knows units, not
	// images: it stops one with its generic KillSignal, while the workload's shutdown contract
	// lives in the image's StopSignal (postgres: SIGINT is the fast shutdown, SIGTERM waits out
	// every open session). This loop is where the two meet — a received TERM or INT leaves as
	// the signal the workload actually understands.
	var stop os.Signal
	if len(cfg.StopSignal) > 0 {
		stop, _ = api.ParseSignal(cfg.StopSignal) // already validated with the config
	}
	// os/signal drops a signal the channel has no room for, so keep slack for bursts.
	sigs := make(chan os.Signal, 64)
	signal.Notify(sigs)
	go func() {
		for s := range sigs {
			switch s {
			case unix.SIGCHLD, unix.SIGURG:
				// The child's exit is child.Wait's to observe, and URG is the Go runtime's
				// async-preemption noise — neither is the caller talking to the workload.
				continue
			case unix.SIGTERM, unix.SIGINT:
				if stop != nil {
					s = stop
				}
			}
			_ = child.Process.Signal(s)
		}
	}()

	return child.Wait()
}

// announceNetns tells whoever is wiring this sandbox which process to wire, by writing the
// namespaced child's host pid.
//
// O_WRONLY and BLOCKING on purpose: the open waits until the caller has its read end open, so an
// announcement is delivered rather than raced. O_RDWR would make the open succeed immediately and
// then throw the pid away when this function returns, because the only reader would have been
// itself.
func announceNetns(cfg *Config, pid int) error {
	if cfg.Network != NetworkRouted {
		return nil
	}
	f, err := os.OpenFile(cfg.NetnsPidPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("announce netns: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintf(f, "%d\n", pid); err != nil {
		return fmt.Errorf("announce netns: %w", err)
	}
	return nil
}

// cloneFlags is the namespace set stage two is born into. user+mnt give an unprivileged process
// the right to assemble the read-only overlay; pid isolates the process tree and backs a fresh
// /proc; uts+ipc cut the remaining shared-kernel surfaces. A network namespace is added only
// when the config asks for one — the default shares the host's, deliberately.
func cloneFlags(cfg *Config) uintptr {
	flags := uintptr(unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID |
		unix.CLONE_NEWUTS | unix.CLONE_NEWIPC)
	if cfg.Network == NetworkNone || cfg.Network == NetworkRouted {
		flags |= unix.CLONE_NEWNET
	}
	return flags
}

// ambientCaps is what stage two carries across its own execve. NET_ADMIN joins the set only for
// a private network namespace, where it is spent bringing loopback up and then dropped with
// everything else: a fresh namespace's lo starts DOWN, and nothing the workload can do afterwards
// would raise it.
func ambientCaps(cfg *Config) []uintptr {
	caps := []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP}
	if cfg.Network == NetworkNone {
		caps = append(caps, unix.CAP_NET_ADMIN)
	}
	return caps
}

// usernsGates are the host settings that refuse an unprivileged user namespace, each with the
// value that means "blocked". Whether a user may create one is a host policy decision, but the
// kernel reports the refusal as a bare EPERM on fork/exec — indistinguishable from a missing
// binary or a bad mode, and saying nothing about which gate said no.
var usernsGates = []struct{ path, blocked, hint string }{
	{
		// Ubuntu 24.04+ ships this on. It is why sandbox cannot start there out of the box.
		"/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "1",
		"AppArmor restricts unprivileged user namespaces (Ubuntu 24.04 and later): install the " +
			"profile from apparmor/sandbox, or set kernel.apparmor_restrict_unprivileged_userns=0",
	},
	{
		// Older Debian and Arch.
		"/proc/sys/kernel/unprivileged_userns_clone", "0",
		"unprivileged user namespaces are disabled: set kernel.unprivileged_userns_clone=1",
	},
	{
		// RHEL/CentOS 7 shipped this at zero.
		"/proc/sys/user/max_user_namespaces", "0",
		"this user's namespace budget is zero: raise user.max_user_namespaces",
	},
}

// explainUsernsRefusal turns a refused clone into an error that names the reason. The gates are
// read only on this path, so the successful start costs nothing, and only those actually set are
// reported — a list of everything that could theoretically be wrong is what the bare errno
// already amounts to.
func explainUsernsRefusal(err error) error {
	if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.ENOSPC) {
		return err
	}

	var hints []string
	for _, g := range usernsGates {
		b, readErr := os.ReadFile(g.path)
		if readErr == nil && strings.TrimSpace(string(b)) == g.blocked {
			hints = append(hints, g.hint)
		}
	}
	if len(hints) == 0 {
		// Nothing readable explains it: a container runtime, an LSM or a seccomp filter above
		// this process can refuse the clone without leaving a knob behind.
		return fmt.Errorf("%w (the kernel refused a new user namespace; no host setting explains it, "+
			"so look for an LSM, a seccomp filter or a container runtime above this process)", err)
	}
	return fmt.Errorf("%w: %s", err, strings.Join(hints, "; "))
}
