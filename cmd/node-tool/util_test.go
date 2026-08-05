package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteNoFollowRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "ca.key")
	if err := os.Symlink(victim, target); err != nil {
		t.Fatal(err)
	}

	if err := writeNoFollow(target, []byte("SECRET"), 0o600); err == nil {
		t.Fatal("a symlink target must be refused")
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Fatalf("the symlink destination was written through: %q", got)
	}
	if fi, err := os.Lstat(target); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink itself must be left in place as evidence, got %v/%v", fi, err)
	}
}

func TestWriteNoFollowDoesNotInheritMode(t *testing.T) {
	target := filepath.Join(t.TempDir(), "admin.conf")
	// os.WriteFile would keep an existing 0666; the helper must chmod explicitly.
	if err := os.WriteFile(target, []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}

	if err := writeNoFollow(target, []byte("new"), 0o600); err != nil {
		t.Fatalf("rewrite of an existing regular file must work: %v", err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o, want 0600 (permissive existing mode must not be inherited)", fi.Mode().Perm())
	}
	if got, _ := os.ReadFile(target); string(got) != "new" {
		t.Fatalf("content = %q, want %q", got, "new")
	}
}

func TestWriteNoFollowCreatesWithExactMode(t *testing.T) {
	target := filepath.Join(t.TempDir(), "ca.crt")
	if err := writeNoFollow(target, []byte("pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	// Chmod is explicit, so the mode holds regardless of the process umask.
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %#o, want 0644", fi.Mode().Perm())
	}
}

func TestEnsurePrivateDirCreates0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %#o, want 0700", fi.Mode().Perm())
	}
	// A second run over its own directory must pass.
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatalf("re-run over an owned 0700 dir must pass: %v", err)
	}
}

func TestEnsurePrivateDirRefusesWritable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	// t.TempDir parents may mask the mode; force it.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	err := ensurePrivateDir(dir)
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("a group/world-writable dir must be refused, got %v", err)
	}
}

// TestSignerModeHasThreeAnswersAndNoDefault: how a node's certificate gets renewed is a security
// decision with three genuinely different answers, so the tool refuses to pick one — and refuses
// two, since `vaultPKI` beside `clusterCAKey` would mean a signing key on the host after all, which
// is the one thing Vault mode exists to avoid.
func TestSignerModeHasThreeAnswersAndNoDefault(t *testing.T) {
	vault := func() *VaultPKISpec {
		return &VaultPKISpec{Server: "https://vault:8200", Role: "nodes", Cert: "c.crt", Key: "c.key"}
	}

	_, err := ControllerSpec{}.signerMode()
	if err == nil {
		t.Fatal("a controller with no signer choice must be refused")
	}
	for _, want := range []string{signerLocal, signerVault, signerOffline} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q, got: %v", want, err)
		}
	}

	for _, tc := range []struct {
		name string
		spec ControllerSpec
		want string
	}{
		{"the CA key on the host", ControllerSpec{ClusterCAKey: "pki/ca.key"}, signerLocal},
		{"no signer at all", ControllerSpec{OfflineCA: true}, signerOffline},
		{"signed through Vault", ControllerSpec{VaultPKI: vault()}, signerVault},
	} {
		got, err := tc.spec.signerMode()
		if err != nil || got != tc.want {
			t.Errorf("%s: signerMode = %q (%v), want %q", tc.name, got, err, tc.want)
		}
	}

	for _, tc := range []struct {
		name string
		spec ControllerSpec
	}{
		{"a key and no rotation", ControllerSpec{ClusterCAKey: "pki/ca.key", OfflineCA: true}},
		{"a key and Vault", ControllerSpec{ClusterCAKey: "pki/ca.key", VaultPKI: vault()}},
		{"Vault and no rotation", ControllerSpec{OfflineCA: true, VaultPKI: vault()}},
	} {
		if _, err := tc.spec.signerMode(); err == nil {
			t.Errorf("%s: two signers must be refused", tc.name)
		}
	}

	// Vault needs more than an address, and each missing piece is named rather than left for the
	// controller to discover at startup on a host nobody is watching.
	for _, tc := range []struct {
		name string
		v    *VaultPKISpec
		want string
	}{
		{"no role", &VaultPKISpec{Server: "https://vault:8200", Cert: "c.crt", Key: "c.key"}, "role"},
		{"no client credential", &VaultPKISpec{Server: "https://vault:8200", Role: "nodes"}, "cert"},
	} {
		_, err := ControllerSpec{VaultPKI: tc.v}.signerMode()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want an error naming %q, got %v", tc.name, tc.want, err)
		}
	}
}

func TestEnsurePrivateDirRefusesSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "pki")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked pki dir must be refused, got %v", err)
	}
}
