//go:build !linux

package netd

import "net"

// Socket activation is systemd's, and systemd is Linux's.
func activationListener() (net.Listener, bool, error) { return nil, false, nil }
