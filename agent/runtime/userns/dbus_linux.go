//go:build linux

package userns

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
)

// newUserConn opens a connection to the per-user systemd manager, mirroring podman's rootless
// approach (pkg/systemd/dbus.go newRootlessConnection): it dials the manager's PRIVATE socket at
// $XDG_RUNTIME_DIR/systemd/private and authenticates EXTERNAL with the caller's uid — bypassing the
// D-Bus session broker. This is deliberate: the private socket needs no polkit, and the broker path
// is exactly what a process in a separate PID namespace cannot reach (the reason the agent's userns
// omits CLONE_NEWPID). Connecting straight to systemd is both more robust and independent of a
// running dbus-daemon/session bus.
func newUserConn(_ context.Context) (*sddbus.Conn, error) {
	return sddbus.NewConnection(func() (*godbus.Conn, error) {
		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			return nil, fmt.Errorf("XDG_RUNTIME_DIR unset: no user systemd bus (need a systemd --user session with linger)")
		}
		path, err := filepath.EvalSymlinks(filepath.Join(xdg, "systemd", "private"))
		if err != nil {
			return nil, fmt.Errorf("user systemd private socket: %w", err)
		}
		conn, err := godbus.Dial(fmt.Sprintf("unix:path=%s", path))
		if err != nil {
			return nil, err
		}
		// EXTERNAL auth with our uid; the private socket then trusts us as the manager's owner. No
		// Hello() here — go-systemd's connection setup issues it.
		if err := conn.Auth([]godbus.Auth{godbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	})
}

// withUserConn opens a user systemd connection, runs fn, and closes it. Each operation gets a fresh
// connection (as pkg/systemd/units does): connects are cheap against the local private socket and a
// short-lived connection cannot go stale between reconciles.
func withUserConn(ctx context.Context, fn func(*sddbus.Conn) error) error {
	conn, err := newUserConn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return fn(conn)
}

// runJob issues a systemd job (start/stop/restart) and waits for its terminal result, so a failure
// surfaces as an error rather than being fire-and-forget. mode is the systemd job mode ("replace").
// runJobWithin is runJob with a deadline of its own, for the jobs that can legitimately never
// finish. A systemd job has no inherent bound: the agent used to wait on the session context
// alone, so ONE unit whose stop never completed blocked the converge loop for the life of the
// session — and the node's heartbeat, which shared that goroutine, went with it. Waiting forever
// is a decision, and this is the one place it can be taken back.
func runJobWithin(ctx context.Context, verb string, timeout time.Duration, op func(ch chan<- string) (int, error)) error {
	within, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return runJob(within, verb, op)
}

// startNoWait issues a job and returns as soon as the manager has accepted it, without waiting
// for the job to complete. It exists for one unit type: a oneshot unit's start job completes when
// the workload EXITS, so waiting on it is waiting for the job to run to the end.
//
// The channel is still passed and still buffered. systemd's client delivers the result on it, and
// a nil or unbuffered channel would either lose the callback or block the delivering goroutine
// forever; nobody reads this one, and it is collected with the closure.
func startNoWait(verb string, op func(ch chan<- string) (int, error)) error {
	if _, err := op(make(chan string, 1)); err != nil {
		return fmt.Errorf("%s: %w", verb, err)
	}
	return nil
}

func runJob(ctx context.Context, verb string, op func(ch chan<- string) (int, error)) error {
	ch := make(chan string, 1)
	if _, err := op(ch); err != nil {
		return fmt.Errorf("%s: %w", verb, err)
	}
	select {
	case res := <-ch:
		if res != "done" {
			return fmt.Errorf("%s: job result %q", verb, res)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
