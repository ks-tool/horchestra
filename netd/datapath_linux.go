//go:build linux

package netd

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// btfPath is where the kernel exposes its own type information. Its ABSENCE is the whole reason
// this check exists: a CO-RE program is relocated against these types at load time, so a kernel
// built without them cannot run one no matter how new it is.
const btfPath = "/sys/kernel/btf/vmlinux"

// datapathSupport reports whether this kernel can run the datapath, and says why not in the words
// an operator needs.
//
// It is a real load, not a version comparison. A kernel version tells you what was merged, not what
// this build enabled, what this distro's lockdown allows or whether the helper holds the right
// capability — and every one of those turns into the same symptom later: a workload whose
// ClusterIP silently answers nothing. Loading a four-instruction program answers all of them at
// once, costs microseconds, and is thrown away immediately.
//
// The program is deliberately the simplest one the verifier will accept for the type the socket-LB
// uses (BPF_PROG_TYPE_CGROUP_SOCK_ADDR): set r0 = 1 (allow) and return. If THAT will not load, the
// real one certainly will not.
func datapathSupport() (ok bool, reason string) {
	if _, err := os.Stat(btfPath); err != nil {
		return false, fmt.Sprintf("this kernel exposes no BTF at %s: a CO-RE program cannot be relocated against it", btfPath)
	}
	if err := probeProgLoad(); err != nil {
		if errors.Is(err, unix.EPERM) {
			return false, "loading a BPF program was refused (EPERM): this helper is missing CAP_BPF, " +
				"or kernel.unprivileged_bpf_disabled and the lockdown policy forbid it"
		}
		return false, "this kernel refused a minimal BPF program: " + err.Error()
	}
	return true, ""
}

// probeProgLoad loads and immediately closes a trivial program of the type the socket-LB needs.
func probeProgLoad() error {
	// r0 = 1; exit. In BPF: MOV64_IMM(BPF_REG_0, 1), EXIT.
	insns := []bpfInsn{
		{Code: unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_K, Dst: 0, Imm: 1},
		{Code: unix.BPF_JMP | unix.BPF_EXIT},
	}
	license := append([]byte("GPL"), 0)

	attr := struct {
		progType    uint32
		insnCnt     uint32
		insns       uint64
		license     uint64
		logLevel    uint32
		logSize     uint32
		logBuf      uint64
		kernVersion uint32
		progFlags   uint32
		progName    [16]byte
		progIfindex uint32
		// expectedAttachType is NOT optional for this program type, which is the sort of thing a
		// probe finds and a version check never would: the kernel answers EINVAL without it,
		// which reads exactly like "your kernel cannot do this".
		expectedAttachType uint32
		_                  [32]byte // the rest of bpf_attr's union, read as zeroes
	}{
		progType: unix.BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
		insnCnt:  uint32(len(insns)),
		insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
		// The hook the socket-LB will use: a connect() on an AF_INET socket, which is where a
		// ClusterIP is rewritten to a backend.
		expectedAttachType: unix.BPF_CGROUP_INET4_CONNECT,
	}
	copy(attr.progName[:], "horc_probe")

	fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(unix.BPF_PROG_LOAD),
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return errno
	}
	_ = unix.Close(int(fd))
	return nil
}

// bpfInsn is one eBPF instruction as the kernel's loader reads it.
type bpfInsn struct {
	Code uint8
	Dst  uint8 // low nibble; Src is the high one, and this probe needs neither set
	Off  int16
	Imm  int32
}
