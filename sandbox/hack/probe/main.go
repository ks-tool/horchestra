//go:build linux

// Command probe reports, from inside a sandbox, what the sandbox actually did — the confinement
// as the workload experiences it rather than as the config describes it.
//
// It is meant to be injected as an extra overlay layer rather than built into an image, so any
// real rootfs can be inspected without being modified:
//
//	make probe                                   # -> bin/probe (for the target platform)
//	install -Dm755 bin/probe /var/lib/probe/usr/local/bin/probe
//	# then, in the config: append "/var/lib/probe" to LowerDirs and set
//	# "Command": ["/usr/local/bin/probe", "caps"]
//	# or, to keep one config and vary the check:
//	# "Command": ["/usr/local/bin/probe", "exec", "sh", "-c", "cat /proc/self/mountinfo"]
//
// Subcommands:
//
//	caps                     capability sets, NO_NEW_PRIVS, seccomp mode and the ids
//	syscall <nr>...          issue each raw syscall and name the errno it answers with
//	net [tcp-addr] [@name]   reachability of a host loopback port and an abstract socket
//	mem <MiB>                allocate and touch memory, a MiB at a time
//	files <dir> [max]        create empty files until one fails
//	write <path>...          try to create each path, and say what stopped it
//	rlimits                  the per-process limits as the workload has them
//	exec <cmd> [args...]     run a command under this confinement and name what stopped it
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: probe <caps|syscall|net|mem|files|write|rlimits|exec> [args]")
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "caps":
		caps()
	case "syscall":
		syscalls(args)
	case "net":
		network(args)
	case "mem":
		mem(args)
	case "files":
		files(args)
	case "write":
		write(args)
	case "rlimits":
		rlimits()
	case "exec":
		execute(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// caps prints the fields of /proc/self/status that say what the privilege drop achieved. All
// four capability sets should be zero and NoNewPrivs 1; Seccomp 2 means a filter is installed.
func caps() {
	want := map[string]string{
		"CapInh": "0000000000000000", "CapPrm": "0000000000000000",
		"CapEff": "0000000000000000", "CapBnd": "0000000000000000",
		"CapAmb": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2",
	}
	blob, err := os.ReadFile("/proc/self/status")
	if err != nil {
		fatal(err)
	}
	for line := range strings.SplitSeq(string(blob), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch name {
		case "Uid", "Gid", "Groups":
			fmt.Printf("%-12s %s\n", name, value)
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp":
			verdict := "ok"
			if value != want[name] {
				verdict = "UNEXPECTED, want " + want[name]
			}
			fmt.Printf("%-12s %-20s %s\n", name, value, verdict)
		}
	}
}

// syscalls issues each numbered syscall with zero arguments and names the answer. The
// distinction that matters: EPERM is the sandbox's filter refusing the call, while ENOSYS is the
// kernel not having it — so a number above the filter's ceiling answering ENOSYS means the
// ceiling is not doing its job.
func syscalls(args []string) {
	if len(args) == 0 {
		fatal(fmt.Errorf("usage: probe syscall <nr>..."))
	}
	for _, a := range args {
		nr, err := strconv.ParseUint(a, 10, 32)
		if err != nil {
			fatal(err)
		}
		_, _, errno := syscall.Syscall(uintptr(nr), 0, 0, 0)
		switch errno {
		case 0:
			fmt.Printf("syscall %-4d allowed\n", nr)
		case syscall.EPERM:
			fmt.Printf("syscall %-4d EPERM (refused by the filter)\n", nr)
		case syscall.ENOSYS:
			fmt.Printf("syscall %-4d ENOSYS (the kernel does not have it; NOT filtered)\n", nr)
		default:
			fmt.Printf("syscall %-4d %v (reached the kernel)\n", nr, errno)
		}
	}
}

// network reports whether the host's loopback services and abstract unix sockets are reachable.
// Both are what a shared network namespace grants and "Network": "none" takes away — abstract
// sockets especially, since they are scoped to the network namespace and no amount of mount
// isolation hides them.
func network(args []string) {
	addr, abstract := "127.0.0.1:18080", "@sandbox-probe"
	for _, a := range args {
		if strings.HasPrefix(a, "@") {
			abstract = a
		} else {
			addr = a
		}
	}
	dial := func(network, address string) {
		c, err := net.DialTimeout(network, address, 2*time.Second)
		if err != nil {
			fmt.Printf("%-24s UNREACHABLE (%v)\n", address, err)
			return
		}
		_ = c.Close()
		fmt.Printf("%-24s REACHED\n", address)
	}
	dial("unix", abstract)
	dial("tcp", addr)
}

// mem allocates and touches memory a MiB at a time, so the pages are really faulted in and the
// cgroup really accounts for them. Under MemoryMax alone on a host with swap this finishes
// anyway, having swapped; with MemorySwapMax=0 it is killed.
func mem(args []string) {
	if len(args) != 1 {
		fatal(fmt.Errorf("usage: probe mem <MiB>"))
	}
	total, err := strconv.Atoi(args[0])
	if err != nil || total <= 0 {
		fatal(fmt.Errorf("mem: %q is not a positive number of MiB", args[0]))
	}
	held := make([][]byte, 0, total)
	for mb := 1; mb <= total; mb++ {
		chunk := make([]byte, 1<<20)
		for i := range chunk {
			chunk[i] = byte(i)
		}
		held = append(held, chunk)
		if mb%25 == 0 || mb == total {
			fmt.Printf("allocated %d MiB\n", mb)
			_ = os.Stdout.Sync()
		}
	}
	fmt.Printf("allocated %d MiB without being stopped\n", total)
}

// files creates empty files until one fails, which is how an inode cap shows itself: empty files
// occupy no blocks, so a size= limit never stops them and only nr_inodes does.
func files(args []string) {
	if len(args) == 0 || len(args) > 2 {
		fatal(fmt.Errorf("usage: probe files <dir> [max]"))
	}
	max := 100000
	if len(args) == 2 {
		n, err := strconv.Atoi(args[1])
		if err != nil {
			fatal(err)
		}
		max = n
	}
	for i := range max {
		f, err := os.Create(filepath.Join(args[0], "probe-"+strconv.Itoa(i)))
		if err != nil {
			fmt.Printf("stopped after %d files: %v\n", i, err)
			return
		}
		_ = f.Close()
	}
	fmt.Printf("created %d files without being stopped\n", max)
}

// write tries to create each path and reports what stopped it. EROFS on a path in the image is
// the read-only root working; success on a tmpfs path is the volume working.
func write(args []string) {
	if len(args) == 0 {
		fatal(fmt.Errorf("usage: probe write <path>..."))
	}
	for _, p := range args {
		f, err := os.Create(p)
		if err != nil {
			fmt.Printf("%-32s REFUSED (%v)\n", p, err)
			continue
		}
		_ = f.Close()
		_ = os.Remove(p)
		fmt.Printf("%-32s WRITABLE\n", p)
	}
}

// rlimits prints the limits as the workload has them, which is the only place the config's
// Rlimits can be confirmed: they are set before execve and leave no other trace.
func rlimits() {
	// The order is the kernel's own RLIMIT_ numbering, so the names line up with getrlimit(2).
	names := []string{
		"CPU", "FSIZE", "DATA", "STACK", "CORE", "RSS", "NPROC", "NOFILE",
		"MEMLOCK", "AS", "LOCKS", "SIGPENDING", "MSGQUEUE", "NICE", "RTPRIO", "RTTIME",
	}
	for res, name := range names {
		var rl syscall.Rlimit
		if err := syscall.Getrlimit(res, &rl); err != nil {
			fmt.Printf("%-11s error: %v\n", name, err)
			continue
		}
		fmt.Printf("%-11s soft=%-22s hard=%s\n", name, limitString(rl.Cur), limitString(rl.Max))
	}
}

// execute runs a command under exactly the confinement probe itself has. The empty capability
// sets, NO_NEW_PRIVS, the seccomp filter and the read-only root all survive execve, so the child
// stands behind every wall the workload does — and naming which wall it hit is the point: a unit
// reports "exit 1" or "killed" and never which of an EPERM, an rlimit and the cgroup did it.
//
// It forks rather than replacing itself, because a replaced process cannot report anything. probe
// therefore stays pid 1 of the sandbox's pid namespace and forwards the caller's signals down, the
// way sandbox itself does for the workload — without that, a systemctl stop would reach probe and
// never the command. To simply *be* the command, put it in the config's Command: same execve,
// same confinement, no verdict.
func execute(args []string) {
	if len(args) == 0 {
		fatal(errors.New("usage: probe exec <command> [args...]"))
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Printf("%-32s DID NOT START (%v)%s\n", args[0], err, startHint(err))
		os.Exit(127) // the shell's status for a command that could not be run at all
	}
	// The resolved path and the pid together say which file was found on the image's PATH and that
	// the pid namespace is the sandbox's own — a first child numbered 2, not a host pid.
	fmt.Fprintf(os.Stderr, "probe: %s running as pid %d\n", cmd.Path, cmd.Process.Pid)

	// os/signal drops a signal the channel has no room for, so keep slack for bursts.
	sigs := make(chan os.Signal, 64)
	signal.Notify(sigs)
	go func() {
		for s := range sigs {
			// The child's exit is Wait's to observe, and URG is the Go runtime's async-preemption
			// noise — neither is the caller talking to the command.
			if s == syscall.SIGCHLD || s == syscall.SIGURG {
				continue
			}
			_ = cmd.Process.Signal(s)
		}
	}()

	_ = cmd.Wait()
	st, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		fatal(fmt.Errorf("%s: unexpected wait status", cmd.Path))
	}
	if st.Signaled() {
		sig := st.Signal()
		fmt.Printf("%-32s KILLED by %s (%v)%s\n", args[0], signalName(sig), sig, signalHint(sig))
		// The shell's convention, and the one systemd's $EXIT_STATUS reports for a killed unit.
		os.Exit(128 + int(sig))
	}
	fmt.Printf("%-32s exited %d\n", args[0], st.ExitStatus())
	os.Exit(st.ExitStatus())
}

// startHint explains the failures that look alike from the outside but mean different walls: a
// missing file and a refused one both surface as "cannot start".
func startHint(err error) string {
	if errors.Is(err, exec.ErrNotFound) {
		return " — not on the PATH the workload was given"
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return ""
	}
	switch errno {
	case syscall.ENOENT:
		// The classic one: the binary is there, its interpreter is not.
		return " — the binary, or the dynamic loader it names, is not in the image"
	case syscall.EACCES:
		return " — not executable, or on a mount carrying noexec"
	case syscall.ENOEXEC:
		return " — not a binary this kernel runs (an image for another architecture?)"
	case syscall.EPERM:
		return " — refused before it ran"
	}
	return ""
}

// signalHint names the sandbox wall a fatal signal came from, for the ones a sandbox actually
// produces. Anything else is the command's own business and gets no guess.
func signalHint(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGSYS:
		return " — the seccomp filter, under a kill action rather than the default EPERM"
	case syscall.SIGKILL:
		return " — from outside: a cgroup limit (MemoryMax) or systemd stopping the unit"
	case syscall.SIGXCPU:
		return " — RLIMIT_CPU"
	case syscall.SIGXFSZ:
		return " — RLIMIT_FSIZE"
	}
	return ""
}

// signalName prefers the name people grep for over the number.
func signalName(sig syscall.Signal) string {
	if name := unix.SignalName(sig); len(name) > 0 {
		return name
	}
	return strconv.Itoa(int(sig))
}

func limitString(v uint64) string {
	if v == ^uint64(0) {
		return "infinity"
	}
	return strconv.FormatUint(v, 10)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "probe:", err)
	os.Exit(1)
}
