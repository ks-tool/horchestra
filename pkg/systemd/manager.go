//go:build linux

package systemd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/coreos/go-systemd/v22/dbus"
)

// EnableAndRestart daemon-reloads systemd, enables the unit file at path, and
// (re)starts it over D-Bus. It restarts rather than starts so a re-install picks
// up a changed ExecStart instead of leaving the running service on the old
// command (StartUnit is a no-op for an already-active unit). user selects the
// caller's per-user manager (a --user unit that runs unprivileged) over the
// system manager.
func EnableAndRestart(unitPath string, user bool) error {
	ctx := context.Background()
	connect := dbus.NewSystemdConnectionContext
	if user {
		connect = dbus.NewUserConnectionContext
		// The user bus lives at $XDG_RUNTIME_DIR/systemd/private; a non-login shell (some
		// `ssh host cmd`, cron) may not have it exported. Default it to the well-known path so
		// the connection resolves instead of failing with a bare "no such file".
		if os.Getenv("XDG_RUNTIME_DIR") == "" {
			_ = os.Setenv("XDG_RUNTIME_DIR", fmt.Sprintf("/run/user/%d", os.Getuid()))
		}
	}
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.ReloadContext(ctx); err != nil {
		return err
	}
	if _, _, err := conn.EnableUnitFilesContext(ctx, []string{unitPath}, false, true); err != nil {
		return err
	}
	name := filepath.Base(unitPath)
	return RunUnitJob("restart", name, func(ch chan<- string) (int, error) {
		return conn.RestartUnitContext(ctx, name, "replace", ch)
	})
}

// RunUnitJob issues a D-Bus unit job (Start/Stop/Restart via start) and blocks on its result:
// it buffers the result channel, invokes start, and turns a non-"done" job result into an error.
// verb labels the operation in that error. It is the single home for the go-systemd "done"
// job-result contract, shared by the unit adapter and the installer.
func RunUnitJob(verb, name string, start func(ch chan<- string) (int, error)) error {
	ch := make(chan string, 1)
	if _, err := start(ch); err != nil {
		return err
	}
	if res := <-ch; res != "done" {
		return fmt.Errorf("%s %s: %s", verb, name, res)
	}
	return nil
}

// EnableLinger turns on lingering for the calling user, so their systemd user manager — and
// every user unit it has enabled — starts at boot and keeps running with no active login
// session. It is the piece that makes a --user install survive a reboot. Shells out to
// loginctl (logind has no go-systemd binding); "enable-linger" with no argument targets the
// caller, which logind's default policy permits from an active session without root.
func EnableLinger() error {
	if out, err := exec.CommandContext(context.Background(), "loginctl", "enable-linger").CombinedOutput(); err != nil {
		return fmt.Errorf("loginctl enable-linger: %w: %s", err, out)
	}
	return nil
}
