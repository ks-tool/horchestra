//go:build linux

package sandbox

import (
	"fmt"
	api "github.com/ks-tool/horchestra/api/sandbox"

	"golang.org/x/sys/unix"
)

// capLastCap is the upper bound for the bounding-set drop loop. It is the width of the
// capability ABI, not the last capability any particular kernel defines (40,
// CAP_CHECKPOINT_RESTORE, at the time of writing): capabilities live in two 32-bit words, so 63
// is the highest number the interface can ever express, and looping to it drops the ones a
// future kernel adds without this constant having to learn about them. Ids the running kernel
// does not know answer EINVAL, which the loop ignores.
//
// Reading /proc/sys/kernel/cap_last_cap would be exact but adds a file read, and a failure
// path, immediately before execve; unix.CAP_LAST_CAP would go stale the same way a literal
// does, only less visibly — it is fixed when the binary is compiled, not when it runs.
const capLastCap = 63

// clearInheritable empties the inheritable capability set, the one set nothing else here
// touches. Raising a capability into the ambient set requires it in the inheritable set first,
// so the mechanism that carries stage two's privileges across its own execve leaves them there —
// and inheritable, alone among the sets, is simply preserved by execve rather than recomputed.
//
// What it could do is bounded already: inheritable capabilities only become permitted when the
// executed FILE carries matching inheritable file capabilities, which the rootfs cannot supply
// (mounted nosuid, where the kernel ignores file capabilities) and NO_NEW_PRIVS would refuse
// anyway. Emptying it is still worth one syscall — it makes the invariant "every capability set
// of the workload is zero", which is a thing that can be checked rather than argued.
func clearInheritable() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	data[0].Inheritable, data[1].Inheritable = 0, 0
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset (clear inheritable): %w", err)
	}
	return nil
}

// dropPrivileges locks the workload down in the last moments before execve: set NO_NEW_PRIVS,
// empty the capability bounding set, install the seccomp filter, then re-assert the workload's
// non-root uid/gid. Run it only after the rootfs is fully assembled — every mount above needs the
// namespaced capabilities this takes away — and immediately before exec.
//
// Why each step is load-bearing here:
//
//   - Stage two's capabilities live in the AMBIENT set (see reexec) — the only set an execve
//     with a non-root uid preserves, which is what let a capless re-exec mount the overlay at
//     all. They would survive the workload's execve the same way, so the set is emptied here
//     explicitly; validRunAsID guarantees the non-root uid that makes the empty ambient set
//     final, and it is re-checked here rather than trusted from the config.
//   - The bounding set outlives execve and caps what any descendant may ever hold, so it is
//     emptied while CAP_SETPCAP is still held.
//   - The seccomp filter denies unshare/setns/clone(CLONE_NEW*) and the mount family, which is
//     what stops the workload from building a namespace of its own where it would again hold
//     CAP_SYS_ADMIN — and with it the ability to mount over the read-only root.
//
// Every one of these is a per-THREAD attribute preserved across execve, so the caller must hold
// runtime.LockOSThread() from before this point through unix.Exec.
func dropPrivileges(uid, gid int, policy *SeccompPolicy) error {
	// The last gate before execve re-validates rather than trusting the config that reached it.
	if err := api.ValidRunAsID("UID", uid); err != nil {
		return err
	}
	if err := api.ValidRunAsID("GID", gid); err != nil {
		return err
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(NO_NEW_PRIVS): %w", err)
	}
	for c := 0; c <= capLastCap; c++ {
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
	}
	// The ambient set is how this process' capabilities survived its own execve, and it would
	// ride into the workload's execve exactly the same way.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(CAP_AMBIENT_CLEAR_ALL): %w", err)
	}
	if err := clearInheritable(); err != nil {
		return err
	}
	// After NO_NEW_PRIVS (which a non-root caller needs to install a filter) and before the id
	// calls, so the whole workload subtree runs under it.
	if err := installSeccomp(policy); err != nil {
		return err
	}

	// No setgroups(2) call: writing an unprivileged gid map requires "deny" in
	// /proc/self/setgroups, which the parent already wrote, so the kernel refuses setgroups for
	// the life of this namespace. The supplementary set can never be widened — a stronger
	// guarantee than the call would give, and calling it here would only fail with EPERM.
	if err := unix.Setresgid(gid, gid, gid); err != nil {
		return fmt.Errorf("setresgid(%d): %w", gid, err)
	}
	if err := unix.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("setresuid(%d): %w", uid, err)
	}
	return nil
}
