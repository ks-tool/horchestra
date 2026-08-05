//go:build linux

package sandbox

import (
	"strconv"
	"testing"
)

// simulate walks the classic-BPF program the way the kernel does, for one (arch, nr, arg0)
// triple, and returns the seccomp return value. Only the opcodes this filter uses are
// implemented — enough to prove what the program decides, which is the thing worth asserting.
func simulate(t *testing.T, prog []sockFilter, arch, nr, arg0 uint32) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog); {
		ins := prog[pc]
		switch ins.code {
		case bpfLdWAbs:
			switch ins.k {
			case offArch:
				a = arch
			case offNr:
				a = nr
			case offArgs0:
				a = arg0
			default:
				t.Fatalf("unexpected load offset %d", ins.k)
			}
			pc++
		case bpfJeqK:
			if a == ins.k {
				pc += 1 + int(ins.jt)
			} else {
				pc += 1 + int(ins.jf)
			}
		case bpfJgeK:
			if a >= ins.k {
				pc += 1 + int(ins.jt)
			} else {
				pc += 1 + int(ins.jf)
			}
		case bpfJsetK:
			if a&ins.k != 0 {
				pc += 1 + int(ins.jt)
			} else {
				pc += 1 + int(ins.jf)
			}
		case bpfRetK:
			return ins.k
		default:
			t.Fatalf("unexpected opcode %#x at %d", ins.code, pc)
		}
	}
	t.Fatal("program ran off the end without returning")
	return 0
}

const (
	auditArchX8664    = 0xC000003E
	auditArchAArch64  = 0xC00000B7
	auditArchI386     = 0x40000003
	retEPERM          = seccompRetErrno | errnoEPERM
	retENOSYS         = seccompRetErrno | errnoENOSYS
	amd64Unshare      = 272
	amd64Clone        = 56
	amd64Clone3       = 435
	amd64Read         = 0
	amd64Keyctl       = 250
	amd64Mount        = 165
	arm64Unshare      = 97
	arm64Clone        = 220
	cloneNewUserFlag  = 0x10000000
	cloneThreadedFlag = 0x00010f00 // CLONE_VM|FS|FILES|SIGHAND|THREAD, what a threading libc uses
)

// TestSeccompUnsupportedArchFailsClosed: the filter numbers are per-architecture, so an
// architecture with no table cannot be filtered — and must therefore not run. Degrading to
// allow-all while still reporting success would leave every workload on such a node unfiltered.
func TestSeccompUnsupportedArchFailsClosed(t *testing.T) {
	for _, goarch := range []string{"riscv64", "ppc64le", "s390x", "386", ""} {
		if _, err := seccompProgram(goarch, nil); err == nil {
			t.Fatalf("GOARCH %q has no filter table, so building a program must fail rather than return an empty filter", goarch)
		}
	}
}

// TestSeccompDeniesAcrossArches: every supported architecture must actually deny its own
// denylist. A table whose numbers were never exercised is the same defect as no table.
func TestSeccompDeniesAcrossArches(t *testing.T) {
	cases := []struct {
		goarch  string
		arch    uint32
		unshare uint32
	}{
		{"amd64", auditArchX8664, amd64Unshare},
		{"arm64", auditArchAArch64, arm64Unshare},
	}
	for _, tc := range cases {
		t.Run(tc.goarch, func(t *testing.T) {
			prog, err := seccompProgram(tc.goarch, nil)
			if err != nil {
				t.Fatalf("seccompProgram(%q): %v", tc.goarch, err)
			}
			if got := simulate(t, prog, tc.arch, tc.unshare, 0); got != retEPERM {
				t.Fatalf("unshare = %#x, want EPERM", got)
			}
			a := archFilters[tc.goarch]
			for _, nr := range a.denied {
				if got := simulate(t, prog, tc.arch, nr, 0); got != retEPERM {
					t.Fatalf("denied syscall %d = %#x, want EPERM", nr, got)
				}
			}
		})
	}
}

// TestSeccompDeniesMountFamily is the read-only guarantee stated as a test: the workload must not
// be able to mount anything over its own root, by any of the syscalls that can.
func TestSeccompDeniesMountFamily(t *testing.T) {
	prog, err := seccompProgram("amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, nr := range map[string]uint32{
		"mount": amd64Mount, "umount2": 166, "pivot_root": 155,
		"move_mount": 429, "fsopen": 430, "fsmount": 432, "open_tree": 428,
		"mount_setattr": 442, "unshare": amd64Unshare, "setns": 308,
	} {
		if got := simulate(t, prog, auditArchX8664, nr, 0); got != retEPERM {
			t.Fatalf("%s = %#x, want EPERM", name, got)
		}
	}
}

// TestSeccompDeniesForeignArch: a syscall arriving under a different ABI carries different
// numbers, so the comparisons are meaningless there and the call must be refused rather than
// waved through.
func TestSeccompDeniesForeignArch(t *testing.T) {
	prog, err := seccompProgram("amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []uint32{auditArchI386, auditArchAArch64, 0} {
		if got := simulate(t, prog, arch, amd64Read, 0); got != retEPERM {
			t.Fatalf("arch %#x = %#x, want EPERM", arch, got)
		}
	}
}

// TestSeccompDeniesX32: an x32 process reports AUDIT_ARCH_X86_64 but ORs 0x40000000 into the
// syscall number, so every bare comparison misses. unshare and keyctl must still be denied when
// issued that way.
func TestSeccompDeniesX32(t *testing.T) {
	prog, err := seccompProgram("amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, nr := range []uint32{amd64Unshare, amd64Keyctl, amd64Read} {
		x32 := nr | x32SyscallBit
		if got := simulate(t, prog, auditArchX8664, x32, 0); got != retEPERM {
			t.Fatalf("x32 syscall %#x = %#x, want EPERM", x32, got)
		}
	}
}

// TestSeccompCloneNamespaceFlags: clone cannot be denied outright — every threading runtime uses
// it — so it is filtered on its flags. A new namespace is the nested-user-namespace primitive
// unshare is denied for, and it must not be reachable through clone instead.
func TestSeccompCloneNamespaceFlags(t *testing.T) {
	for _, tc := range []struct {
		goarch string
		arch   uint32
		clone  uint32
	}{
		{"amd64", auditArchX8664, amd64Clone},
		{"arm64", auditArchAArch64, arm64Clone},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			prog, err := seccompProgram(tc.goarch, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := simulate(t, prog, tc.arch, tc.clone, cloneNewUserFlag); got != retEPERM {
				t.Fatalf("clone(CLONE_NEWUSER) = %#x, want EPERM", got)
			}
			if got := simulate(t, prog, tc.arch, tc.clone, cloneThreadedFlag); got != seccompRetAllow {
				t.Fatalf("clone() for an ordinary thread = %#x, want ALLOW", got)
			}
		})
	}
}

// TestSeccompClone3ReturnsENOSYS: clone3's flags sit behind a pointer seccomp cannot dereference,
// so it cannot be filtered on them. ENOSYS (not EPERM) is deliberate: glibc treats it as "kernel
// too old" and falls back to clone, which IS filtered. EPERM would instead break the workload.
func TestSeccompClone3ReturnsENOSYS(t *testing.T) {
	prog, err := seccompProgram("amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := simulate(t, prog, auditArchX8664, amd64Clone3, 0); got != retENOSYS {
		t.Fatalf("clone3 = %#x, want ENOSYS", got)
	}
}

// TestSeccompAllowsOrdinarySyscalls: it is a denylist, so anything not named must pass — a filter
// that denied read(2) would be caught by nothing else here.
func TestSeccompAllowsOrdinarySyscalls(t *testing.T) {
	prog, err := seccompProgram("amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, nr := range []uint32{0 /*read*/, 1 /*write*/, 9 /*mmap*/, 257 /*openat*/, 202 /*futex*/} {
		if got := simulate(t, prog, auditArchX8664, nr, 0); got != seccompRetAllow {
			t.Fatalf("syscall %d = %#x, want ALLOW", nr, got)
		}
	}
}

// TestSeccompCloneMaskDoesNotCatchThreadFlags guards the mistake that is easy to make in the
// mask itself: CLONE_NEWNS is 0x00020000, while 0x00000100 is CLONE_VM. Masking on the wrong bit
// denies every thread creation, so the filter would break every workload rather than confine it —
// a failure the namespace cases above cannot distinguish from success.
func TestSeccompCloneMaskDoesNotCatchThreadFlags(t *testing.T) {
	const (
		cloneVM       = 0x00000100
		cloneFS       = 0x00000200
		cloneFILES    = 0x00000400
		cloneSIGHAND  = 0x00000800
		cloneTHREAD   = 0x00010000
		cloneSETTLS   = 0x00080000
		cloneSYSVSEM  = 0x00040000
		clonePARENTID = 0x00100000
	)
	ordinary := uint32(cloneVM | cloneFS | cloneFILES | cloneSIGHAND | cloneTHREAD |
		cloneSETTLS | cloneSYSVSEM | clonePARENTID)
	if cloneNewNamespaces&ordinary != 0 {
		t.Fatalf("the CLONE_NEW* mask %#x overlaps ordinary thread flags %#x", cloneNewNamespaces, ordinary)
	}
	prog, err := seccompProgram("amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := simulate(t, prog, auditArchX8664, amd64Clone, ordinary); got != seccompRetAllow {
		t.Fatalf("a normal pthread_create-style clone = %#x, want ALLOW", got)
	}
}

// TestSeccompDeniesKernelSurfaceExpanders covers the entries that exist for attack surface
// rather than for the read-only root: io_uring runs submitted operations on kernel worker
// threads, syslog reads the kernel ring buffer, and open_by_handle_at reaches a file by handle
// rather than by path.
func TestSeccompDeniesKernelSurfaceExpanders(t *testing.T) {
	for _, tc := range []struct {
		goarch string
		arch   uint32
		nrs    map[string]uint32
	}{
		{"amd64", auditArchX8664, map[string]uint32{
			"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
			"syslog": 103, "open_by_handle_at": 304, "kcmp": 312, "pidfd_getfd": 438,
		}},
		{"arm64", auditArchAArch64, map[string]uint32{
			"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
			"syslog": 116, "open_by_handle_at": 265, "kcmp": 272, "pidfd_getfd": 438,
		}},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			prog, err := seccompProgram(tc.goarch, nil)
			if err != nil {
				t.Fatal(err)
			}
			for name, nr := range tc.nrs {
				if got := simulate(t, prog, tc.arch, nr, 0); got != retEPERM {
					t.Errorf("%s = %#x, want EPERM", name, got)
				}
			}
		})
	}
}

// A policy's Deny must reach the program, whether the caller spelled the syscall or numbered it.
func TestSeccompPolicyDeny(t *testing.T) {
	const amd64Getpid = 39
	for _, entry := range []string{"getpid", "39"} {
		prog, err := seccompProgram("amd64", &SeccompPolicy{Deny: []string{entry}})
		if err != nil {
			t.Fatalf("policy Deny %q: %v", entry, err)
		}
		if got := simulate(t, prog, auditArchX8664, amd64Getpid, 0); got != retEPERM {
			t.Errorf("Deny %q: getpid = %#x, want EPERM", entry, got)
		}
		// The built-in entries stay in force alongside it.
		if got := simulate(t, prog, auditArchX8664, amd64Mount, 0); got != retEPERM {
			t.Errorf("Deny %q: mount = %#x, want EPERM", entry, got)
		}
	}
}

// Allow is the escape hatch: it takes a syscall OUT of the built-in denylist, and wins over Deny
// so an operator overriding a default cannot be defeated by their own broader rule.
func TestSeccompPolicyAllow(t *testing.T) {
	const amd64Ptrace = 101
	prog, err := seccompProgram("amd64", &SeccompPolicy{Allow: []string{"ptrace"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := simulate(t, prog, auditArchX8664, amd64Ptrace, 0); got != seccompRetAllow {
		t.Errorf("Allow ptrace: ptrace = %#x, want ALLOW", got)
	}
	if got := simulate(t, prog, auditArchX8664, amd64Mount, 0); got != retEPERM {
		t.Errorf("Allow ptrace: mount = %#x, want EPERM", got)
	}

	prog, err = seccompProgram("amd64", &SeccompPolicy{Deny: []string{"ptrace"}, Allow: []string{"ptrace"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := simulate(t, prog, auditArchX8664, amd64Ptrace, 0); got != seccompRetAllow {
		t.Errorf("Deny+Allow ptrace: ptrace = %#x, want ALLOW", got)
	}
}

// A policy the sandbox cannot honour verbatim must be refused, never applied approximately: a
// filter missing the rule its author wrote is a sandbox weaker than they believe they configured.
func TestSeccompPolicyRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy SeccompPolicy
	}{
		{"unknown name", SeccompPolicy{Deny: []string{"definitely_not_a_syscall"}}},
		{"unknown name in Allow", SeccompPolicy{Allow: []string{"definitely_not_a_syscall"}}},
		{"empty entry", SeccompPolicy{Deny: []string{""}}},
		// clone and clone3 are branches of the program, not denylist entries.
		{"clone", SeccompPolicy{Deny: []string{"clone"}}},
		{"clone3", SeccompPolicy{Allow: []string{"clone3"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := seccompProgram("amd64", &tc.policy); err == nil {
				t.Fatal("expected the policy to be refused")
			}
		})
	}
}

// Classic-BPF jumps are 8-bit, so a denylist past maxDenied would truncate a jump into the middle
// of the program — a filter that allows what it claims to deny. It must be refused instead.
func TestSeccompPolicyRefusesOversizedDenylist(t *testing.T) {
	var deny []string
	for nr := range maxDenied + 1 {
		deny = append(deny, strconv.Itoa(nr))
	}
	if _, err := seccompProgram("amd64", &SeccompPolicy{Deny: deny}); err == nil {
		t.Fatal("expected an oversized denylist to be refused")
	}
}

// The embedded name tables are what makes a policy portable across architectures: the same name
// must resolve to each ABI's own number.
func TestSyscallNameTables(t *testing.T) {
	for _, tc := range []struct {
		goarch string
		name   string
		want   uint32
	}{
		{"amd64", "mount", 165},
		{"amd64", "io_uring_setup", 425},
		{"arm64", "mount", 40},
		{"arm64", "io_uring_setup", 425},
		{"arm64", "syslog", 116},
	} {
		got, err := archFilters[tc.goarch].syscallNumber(tc.name)
		if err != nil || got != tc.want {
			t.Errorf("%s/%s = %d, %v; want %d", tc.goarch, tc.name, got, err, tc.want)
		}
	}
}

// TestSeccompDeniesAboveTheTable closes the hole a denylist has by nature: a syscall number the
// build has never heard of — one a later kernel added — must be refused rather than waved
// through, and the ceiling must not eat any number the table does know.
func TestSeccompDeniesAboveTheTable(t *testing.T) {
	for _, tc := range []struct {
		goarch string
		arch   uint32
	}{
		{"amd64", auditArchX8664},
		{"arm64", auditArchAArch64},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			a := archFilters[tc.goarch]
			prog, err := seccompProgram(tc.goarch, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, nr := range []uint32{a.maxNr + 1, a.maxNr + 100, 1 << 20} {
				if got := simulate(t, prog, tc.arch, nr, 0); got != retEPERM {
					t.Errorf("syscall %d above the table = %#x, want EPERM", nr, got)
				}
			}
			// The last number the table knows is still ordinary.
			if got := simulate(t, prog, tc.arch, a.maxNr, 0); got != seccompRetAllow {
				t.Errorf("syscall %d (the table's own maximum) = %#x, want ALLOW", a.maxNr, got)
			}
		})
	}
}

// The ceiling is only useful if it tracks the table it is generated from.
func TestSyscallCeilingMatchesTable(t *testing.T) {
	for goarch, a := range archFilters {
		var max uint32
		for _, nr := range a.names {
			if nr > max {
				max = nr
			}
		}
		if a.maxNr != max {
			t.Errorf("%s: maxNr = %d, but the name table's highest is %d (regenerate syscalls.go)",
				goarch, a.maxNr, max)
		}
	}
}
