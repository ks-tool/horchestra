//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveUnitPath_System(t *testing.T) {
	// A system unit goes to the system unit dir, with nothing to configure: the path used to be
	// overridable and is not any more, because a fleet description that could relocate one host's
	// unit would describe a fleet nobody can reason about.
	got, err := resolveUnitPath("horchestra-controller.service", false)
	if err != nil {
		t.Fatalf("resolveUnitPath(system) unexpected error: %v", err)
	}
	if want := "/etc/systemd/system/horchestra-controller.service"; got != want {
		t.Fatalf("resolveUnitPath(system) = %q, want %q", got, want)
	}
}

func TestResolveUnitPath_User(t *testing.T) {
	// user=true resolves under the caller's XDG config dir and creates the per-user unit dir.
	// Pin XDG_CONFIG_HOME to a temp dir so os.UserConfigDir is deterministic and no real home is
	// touched.
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)

	got, err := resolveUnitPath("horchestra-agent.service", true)
	if err != nil {
		t.Fatalf("resolveUnitPath(user) unexpected error: %v", err)
	}

	wantDir := filepath.Join(cfg, "systemd", "user")
	want := filepath.Join(wantDir, "horchestra-agent.service")
	if got != want {
		t.Fatalf("resolveUnitPath(user) = %q, want %q", got, want)
	}

	// The per-user unit dir must be created as a side effect.
	info, err := os.Stat(wantDir)
	if err != nil {
		t.Fatalf("resolveUnitPath(user) did not create %q: %v", wantDir, err)
	}
	if !info.IsDir() {
		t.Fatalf("resolveUnitPath(user) created %q but it is not a directory", wantDir)
	}
}

func TestResolveUnitPath_UserFallsBackToHome(t *testing.T) {
	// With XDG_CONFIG_HOME unset, os.UserConfigDir falls back to $HOME/.config, so the resolved
	// path ends with .config/systemd/user/<name> and that dir is created.
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	got, err := resolveUnitPath("horchestra-agent.service", true)
	if err != nil {
		t.Fatalf("resolveUnitPath(user, HOME fallback) unexpected error: %v", err)
	}

	wantSuffix := filepath.Join(".config", "systemd", "user", "horchestra-agent.service")
	if !strings.HasSuffix(got, wantSuffix) {
		t.Fatalf("resolveUnitPath(user, HOME fallback) = %q, want suffix %q", got, wantSuffix)
	}

	wantDir := filepath.Join(home, ".config", "systemd", "user")
	if info, err := os.Stat(wantDir); err != nil {
		t.Fatalf("resolveUnitPath(user, HOME fallback) did not create %q: %v", wantDir, err)
	} else if !info.IsDir() {
		t.Fatalf("resolveUnitPath(user, HOME fallback) created %q but it is not a directory", wantDir)
	}
}

func TestRefusePrivilegedPort(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"", false},
		{":8443", false},
		{"0.0.0.0:8443", false},
		{":443", true},
		{"10.0.0.1:80", true},
		{"no-port", true},
	}
	for _, tt := range tests {
		if err := refusePrivilegedPort(tt.addr); (err != nil) != tt.wantErr {
			t.Errorf("refusePrivilegedPort(%q) = %v, wantErr %v", tt.addr, err, tt.wantErr)
		}
	}
}

func TestInstallTarget(t *testing.T) {
	tests := []struct {
		name string
		user bool
		want string
	}{
		{"user unit enables into default.target", true, "default.target"},
		{"system unit defers to the renderer default", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := installTarget(tt.user); got != tt.want {
				t.Fatalf("installTarget(%v) = %q, want %q", tt.user, got, tt.want)
			}
		})
	}
}

// TestTheNetdUnitCarriesTheFleetsOverlay: the encapsulation is a fleet decision, so it has to reach
// the unit's ExecStart — a node that fell back to netd's own default would be a node the others
// cannot reach, and nothing would say so.
func TestTheNetdUnitCarriesTheFleetsOverlay(t *testing.T) {
	unit := netdServiceUnit("/usr/local/bin/horchestra-netd", "ks-tool", "/run/horchestra/netd.sock",
		NetdSpec{Uplink: "eth0", Overlay: "ipip"})
	for _, want := range []string{"--agent-user=ks-tool", "--uplink=eth0", "--overlay=ipip"} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit does not carry %q:\n%s", want, unit)
		}
	}
	// An unset field must not appear at all: an empty --overlay= would be a value, and netd
	// would have to have an opinion about what an empty one means.
	bare := netdServiceUnit("/usr/local/bin/horchestra-netd", "ks-tool", "/run/horchestra/netd.sock", NetdSpec{})
	if strings.Contains(bare, "--uplink") || strings.Contains(bare, "--overlay") {
		t.Errorf("unset fields leaked into the unit:\n%s", bare)
	}
}

// TestOnlyTheMonolithTakesARoleSubcommand is a regression test for a live failure: every binary
// shipped, both units written, and both roles dead in a restart loop on `unknown command
// "controller"`. The split binaries make the role the process ROOT — horchestra-agent IS the agent
// — and the ExecStart builder had been carried over from a tree where only the monolith existed.
func TestOnlyTheMonolithTakesARoleSubcommand(t *testing.T) {
	for _, tc := range []struct {
		runtime string
		role    string
		want    []string
	}{
		{"./bin/horchestra-controller", "controller", []string{"/usr/local/bin/horchestra-controller"}},
		{"./bin/horchestra", "agent", []string{"/usr/local/bin/horchestra", "agent"}},
		{"./bin/horchestra", "netd", []string{"/usr/local/bin/horchestra", "netd"}},
	} {
		got := roleArgs(tc.runtime, tc.role)
		if len(got) != len(tc.want) {
			t.Errorf("roleArgs(%q, %q) = %v, want %v", tc.runtime, tc.role, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("roleArgs(%q, %q) = %v, want %v", tc.runtime, tc.role, got, tc.want)
				break
			}
		}
	}
}

// TestLocalApplyIsOneAddress pins what replaced the `install` command lines: the on-host half is
// told which host it is and NOTHING else — not which half to do, since each half is gated on
// something that process can check about itself.
func TestLocalApplyIsOneAddress(t *testing.T) {
	got := localApply("10.92.16.17")
	want := "/usr/local/bin/node-tool apply -f /etc/horchestra/node-tool.yaml --local 10.92.16.17"
	if got != want {
		t.Fatalf("localApply = %q, want %q", got, want)
	}
}
