//go:build linux

package netd

import (
	"strings"

	"golang.org/x/sys/unix"
)

// missingCaps names the capabilities this helper needs and does not hold, or "" when it holds them
// all. It is the difference between "I am the privileged half" and "I was configured to be".
//
// CAP_SYS_ADMIN creates and enters a network namespace; CAP_NET_ADMIN makes a veth, addresses it
// and routes it. Both are checked against the EFFECTIVE set, which is what a syscall is judged by —
// a capability that is merely permitted is one this process has not raised and would still be
// refused for.
func missingCaps() string {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		// Unknowable is not the same as absent, and guessing either way would be worse than
		// saying which check failed.
		return "readable capabilities (" + err.Error() + ")"
	}
	var missing []string
	for _, c := range []struct {
		name string
		bit  uint
	}{
		{"CAP_SYS_ADMIN", unix.CAP_SYS_ADMIN},
		{"CAP_NET_ADMIN", unix.CAP_NET_ADMIN},
	} {
		if data[c.bit>>5].Effective&(1<<(c.bit&31)) == 0 {
			missing = append(missing, c.name)
		}
	}
	return strings.Join(missing, ", ")
}
