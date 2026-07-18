//go:build linux

package systemd

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/coreos/go-systemd/v22/dbus"
)

// EnableAndRestart daemon-reloads systemd, enables the unit file at path, and
// (re)starts it over D-Bus. It restarts rather than starts so a re-install picks
// up a changed ExecStart instead of leaving the running service on the old
// command (StartUnit is a no-op for an already-active unit).
func EnableAndRestart(unitPath string) error {
	ctx := context.Background()
	conn, err := dbus.NewSystemdConnectionContext(ctx)
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
	ch := make(chan string, 1)
	if _, err := conn.RestartUnitContext(ctx, name, "replace", ch); err != nil {
		return err
	}
	if res := <-ch; res != "done" {
		return fmt.Errorf("restart %s: %s", name, res)
	}
	return nil
}
