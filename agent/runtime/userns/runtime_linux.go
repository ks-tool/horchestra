//go:build linux

package userns

import (
	"bytes"
	"errors"
	apisandbox "github.com/ks-tool/horchestra/api/sandbox"
	"os"
	"path/filepath"
)

// marshalSandboxConfig renders a workload's SandboxConfig and returns the bytes together with
// their sha256. The digest is the workload's converge signal and the sandbox's integrity check,
// so it must be a function of the config alone: SandboxConfig holds only slices and scalars —
// never a map, whose serialization order would flap the digest and restart a healthy workload
// every tick.
func marshalSandboxConfig(cfg apisandbox.Config) ([]byte, string, error) {
	return apisandbox.Marshal(cfg)
}

// ensureSandboxConfig makes path hold exactly blob, for the horchestra-sandbox trampoline to read.
// The config is handed to the systemd --user unit's ExecStart via --config, not an environment
// variable, so it survives the unit outliving the agent (an agent restart re-reads nothing —
// systemd already holds the running unit, whose ExecStart still points at this file).
//
// Unchanged content is left alone, so the converge path does not rewrite every workload's config
// on every tick. When it does write, it writes a temporary file and renames it over the target: a
// workload may be starting concurrently, and rename is the only way it reads either the whole old
// config or the whole new one rather than a truncated file.
func ensureSandboxConfig(path string, blob []byte) error {
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, blob) {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once the rename succeeds
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
