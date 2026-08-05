//go:build linux

package netd

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// activationListener returns the socket systemd passed, if this helper was socket-activated.
//
// LISTEN_PID is checked strictly: a stale LISTEN_FDS inherited by some other process would
// otherwise make it adopt a descriptor that is not its own.
func activationListener() (net.Listener, bool, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, false, nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		return nil, false, nil
	}
	if n > 1 {
		return nil, false, fmt.Errorf("netd: systemd passed %d sockets; this helper serves exactly one", n)
	}
	const firstFD = 3 // SD_LISTEN_FDS_START
	unix.CloseOnExec(firstFD)
	f := os.NewFile(firstFD, "netd.sock")
	l, err := net.FileListener(f)
	// FileListener dups the descriptor, so the original is ours to close either way.
	_ = f.Close()
	if err != nil {
		return nil, false, err
	}
	return l, true, nil
}
