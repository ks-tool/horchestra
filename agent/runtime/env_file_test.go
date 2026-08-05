//go:build linux

package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSecretEnvFileIsRamOnly is the regression test for the leak this feature shipped with once:
// the resolved values were written under the state dir, on persistent disk, where a secret
// outlives the agent that fetched it, survives a reboot with nothing to re-authorize it, and is
// copied into every backup of the node. They belong in the RAM-backed runtime dir and nowhere
// else — as a plain 0600 carrier file the runtimes deliver as process environment at spawn.
func TestSecretEnvFileIsRamOnly(t *testing.T) {
	runtimeDir := t.TempDir()
	path, err := WriteSecretEnvFile(runtimeDir, "team-a_web", []string{"PGPASSWORD=s3cr3t", "PG_host=db.internal"})
	if err != nil {
		t.Fatalf("WriteSecretEnvFile: %v", err)
	}
	if want := filepath.Join(runtimeDir, "secretenv", "team-a_web"); path != want {
		t.Fatalf("path = %s, want %s", path, want)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the env file: %v", err)
	}
	if content := "PGPASSWORD=s3cr3t\nPG_host=db.internal\n"; string(got) != content {
		t.Fatalf("env file = %q, want %q", got, content)
	}
	if perm := permOf(t, path); perm != 0o600 {
		t.Fatalf("mode = %o, want 0600 — only its owner (the agent) and PID1 read the carrier", perm)
	}
	if perm := permOf(t, filepath.Dir(path)); perm != 0o700 {
		t.Fatalf("parent mode = %o, want 0700", perm)
	}
}

// TestSecretEnvFileIsIdempotent: an unchanged environment must not rewrite the file — the write
// and the change detector key off the same bytes, so a rewrite here would be pure churn (and
// under the retired overlay-layer delivery it was an actual bug: recreating the carrier under a
// live mount made the values vanish from the running workload).
func TestSecretEnvFileIsIdempotent(t *testing.T) {
	runtimeDir := t.TempDir()
	env := []string{"PGPASSWORD=s3cr3t"}
	path, err := WriteSecretEnvFile(runtimeDir, "team-a_web", env)
	if err != nil {
		t.Fatal(err)
	}
	// A read-only file makes any second write fail loudly — so success proves no write happened.
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteSecretEnvFile(runtimeDir, "team-a_web", env); err != nil {
		t.Fatalf("an unchanged env must not rewrite the file, got %v", err)
	}
	_ = os.Chmod(path, 0o600)
}

// TestSecretEnvFileReplacesTheRetiredLayerLayout: the carrier used to be a per-workload overlay
// layer DIRECTORY at the same path; an upgrade must replace it with the plain file, not fail on
// EISDIR forever.
func TestSecretEnvFileReplacesTheRetiredLayerLayout(t *testing.T) {
	runtimeDir := t.TempDir()
	old := filepath.Join(runtimeDir, "secretenv", "team-a_web", "etc")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	path, err := WriteSecretEnvFile(runtimeDir, "team-a_web", []string{"PGPASSWORD=s3cr3t"})
	if err != nil {
		t.Fatalf("WriteSecretEnvFile over the old layout: %v", err)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("want a plain file at %s, got fi=%v err=%v", path, fi, err)
	}
}

// TestNoSecretEnvLeavesNoFile: an app that sources no environment gets no carrier at all, and a
// file left by a previous spec is reclaimed.
func TestNoSecretEnvLeavesNoFile(t *testing.T) {
	runtimeDir := t.TempDir()
	if _, err := WriteSecretEnvFile(runtimeDir, "team-a_web", []string{"PGPASSWORD=s3cr3t"}); err != nil {
		t.Fatal(err)
	}
	path, err := WriteSecretEnvFile(runtimeDir, "team-a_web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Fatalf("no env must yield no path, got %q", path)
	}
	if _, err := os.Lstat(SecretEnvFile(runtimeDir, "team-a_web")); !os.IsNotExist(err) {
		t.Fatalf("the stale carrier must be reclaimed, got err = %v", err)
	}
}

// TestSecretEnvIsRevalidatedOnTheNode: the runtime trusts nothing that arrived over the wire, the
// same rule ValidateVolumes applies to mount destinations. A name or value that could forge a
// second assignment fails the converge instead of being written.
func TestSecretEnvIsRevalidatedOnTheNode(t *testing.T) {
	cases := map[string]string{
		"name a shell cannot express": "pg.password=x",
		"forged second assignment":    "A=x\nB=forged",
		"not an assignment at all":    "JUST_A_NAME",
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := WriteSecretEnvFile(t.TempDir(), "team-a_web", []string{entry}); err == nil {
				t.Fatal("must be refused node-side")
			}
		})
	}
}

// TestSecretEnvShapeChange draws the line the environment path lives on: a workload restarts when
// the SET of variables changes, and not when a value rotates.
//
// It cannot be otherwise. Environment is spawn-time state — nothing can replace it under a
// running process — so "rotating" an env secret means restarting the workload, and restarting a
// workload because a credential rotated is a worse answer than not rotating it. The new value is
// still written, so the next start for any other reason uses it; a credential that must rotate
// under a running process is mounted as a file instead.
func TestSecretEnvShapeChange(t *testing.T) {
	runtimeDir := t.TempDir()
	const id = "team-a_web"
	env := []string{"PGPASSWORD=old"}

	if !SecretEnvShapeChanged(runtimeDir, id, env) {
		t.Fatal("no file written yet, so the desired env must count as a shape change")
	}
	if _, err := WriteSecretEnvFile(runtimeDir, id, env); err != nil {
		t.Fatal(err)
	}
	if SecretEnvShapeChanged(runtimeDir, id, env) {
		t.Fatal("the written file matches the desired env; nothing changed")
	}

	// A rotated VALUE is not a restart.
	if SecretEnvShapeChanged(runtimeDir, id, []string{"PGPASSWORD=new"}) {
		t.Error("a rotated value forced a restart; env rotation must not disturb a running workload")
	}
	// A new VARIABLE is: the workload's environment has a different shape, and only a new
	// process can have it.
	if !SecretEnvShapeChanged(runtimeDir, id, []string{"PGPASSWORD=old", "API_TOKEN=t"}) {
		t.Error("an added variable must restart the workload")
	}
	if !SecretEnvShapeChanged(runtimeDir, id, nil) {
		t.Error("a removed variable must restart the workload")
	}
}

func permOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}
