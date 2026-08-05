//go:build linux

package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The mode a path is expected to come up with and the size cap have to survive together in one
// option string — dropping either silently is how /tmp ends up not sticky or not bounded.
func TestTmpfsDataCombinesModeAndSize(t *testing.T) {
	for _, tc := range []struct {
		mount TmpfsMount
		want  string
	}{
		{TmpfsMount{Path: "/tmp", Size: "512m"}, "mode=1777,size=512m"},
		{TmpfsMount{Path: "/tmp", Size: "512m", Inodes: "4k"}, "mode=1777,size=512m,nr_inodes=4k"},
		{TmpfsMount{Path: "/data", Inodes: "4k"}, "nr_inodes=4k"},
		{TmpfsMount{Path: "/run", Size: "64m"}, "mode=0755,size=64m"},
		{TmpfsMount{Path: "/tmp"}, "mode=1777"},
		{TmpfsMount{Path: "/data", Size: "1g"}, "size=1g"},
		{TmpfsMount{Path: "/data"}, ""},
	} {
		if got := tmpfsData(tc.mount); got != tc.want {
			t.Errorf("tmpfsData(%+v) = %q, want %q", tc.mount, got, tc.want)
		}
	}
}

// TestLoadConfigSeccompPolicy lives HERE and not with the contract: validating a syscall NAME means
// compiling the filter for this build's architecture, which only the program that installs it can
// do. api/sandbox checks the shape; this checks what will actually run.
// The filter is built when the config is loaded, so a policy the sandbox cannot honour is a
// refusal to start rather than a workload running under a filter missing one of its rules.
func TestLoadConfigSeccompPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy SeccompPolicy
		ok     bool
	}{
		{"deny by name", SeccompPolicy{Deny: []string{"io_uring_setup"}}, true},
		{"allow by name", SeccompPolicy{Allow: []string{"ptrace"}}, true},
		{"deny by number", SeccompPolicy{Deny: []string{"425"}}, true},
		{"unknown syscall", SeccompPolicy{Deny: []string{"not_a_syscall"}}, false},
		{"clone is structural", SeccompPolicy{Deny: []string{"clone"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Seccomp = &tc.policy
			_, err := LoadConfig(writeConfig(t, cfg))
			if tc.ok && err != nil {
				t.Fatalf("valid policy refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected the config to be refused")
			}
		})
	}
}

// validConfig and writeConfig mirror the contract's own test helpers: this package tests what it
// adds on top of api/sandbox's validation, so it needs the same well-formed starting point.
func validConfig() Config {
	return Config{
		LowerDirs:   []string{"/var/lib/layers/a", "/var/lib/layers/b"},
		Merged:      "/run/app/rootfs",
		InitDir:     "/var/lib/app/init",
		Command:     []string{"/usr/bin/app"},
		TmpfsMounts: []TmpfsMount{{Path: "/tmp"}},
		UID:         1000,
		GID:         1000,
	}
}

func writeConfig(t *testing.T, cfg any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandbox.json")
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
