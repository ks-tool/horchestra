//go:build linux

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Whether a user may create a user namespace is a host policy decision, and the kernel reports a
// refusal as a bare EPERM. The gate that explains it must reach the operator, or the message is
// indistinguishable from a missing binary.
func TestExplainUsernsRefusal(t *testing.T) {
	// An error that is not a refusal passes through untouched.
	other := errors.New("exec format error")
	if got := explainUsernsRefusal(other); got != other {
		t.Errorf("unrelated error was rewritten: %v", got)
	}

	// A refusal with no readable gate still says what kind of thing to look for.
	err := explainUsernsRefusal(unix.EPERM)
	if !errors.Is(err, unix.EPERM) {
		t.Error("the original errno must survive wrapping, so callers can still match on it")
	}
	if !strings.Contains(err.Error(), "user namespace") {
		t.Errorf("message says nothing about the namespace: %v", err)
	}
}

// The gate table is only useful if each entry names a real knob and the value that blocks it.
func TestUsernsGatesAreWellFormed(t *testing.T) {
	for _, g := range usernsGates {
		if !filepath.IsAbs(g.path) || !strings.HasPrefix(g.path, "/proc/sys/") {
			t.Errorf("gate %q is not a /proc/sys path", g.path)
		}
		if len(g.blocked) == 0 || len(g.hint) == 0 {
			t.Errorf("gate %q has an empty blocking value or hint", g.path)
		}
		// The hint has to name the setting, not just describe the symptom.
		knob := strings.TrimPrefix(g.path, "/proc/sys/")
		knob = strings.ReplaceAll(knob, "/", ".")
		if !strings.Contains(g.hint, knob[strings.LastIndex(knob, ".")+1:]) {
			t.Errorf("hint for %q does not name the setting: %q", g.path, g.hint)
		}
	}
}

// A gate that IS set must be reported, which is the whole point of reading them back.
func TestExplainUsernsRefusalReportsASetGate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gate")
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := usernsGates
	t.Cleanup(func() { usernsGates = saved })
	usernsGates = []struct{ path, blocked, hint string }{{path, "1", "the test gate is closed"}}

	err := explainUsernsRefusal(unix.EPERM)
	if !strings.Contains(err.Error(), "the test gate is closed") {
		t.Errorf("a set gate was not reported: %v", err)
	}
}

// The network namespace is the one isolation this sandbox leaves off by default, so both halves
// of the switch have to be exact: the flag that creates the namespace, and the capability that
// makes it usable.
func TestCloneFlagsAndCapsFollowNetwork(t *testing.T) {
	for _, tc := range []struct {
		network string
		netns   bool
	}{
		{"", false},
		{NetworkHost, false},
		{NetworkNone, true},
	} {
		t.Run("network="+tc.network, func(t *testing.T) {
			cfg := &Config{Network: tc.network}
			flags := cloneFlags(cfg)

			if got := flags&unix.CLONE_NEWNET != 0; got != tc.netns {
				t.Errorf("CLONE_NEWNET = %v, want %v", got, tc.netns)
			}
			// The namespaces that are never optional.
			for name, flag := range map[string]uintptr{
				"CLONE_NEWUSER": unix.CLONE_NEWUSER, "CLONE_NEWNS": unix.CLONE_NEWNS,
				"CLONE_NEWPID": unix.CLONE_NEWPID, "CLONE_NEWUTS": unix.CLONE_NEWUTS,
				"CLONE_NEWIPC": unix.CLONE_NEWIPC,
			} {
				if flags&flag == 0 {
					t.Errorf("%s missing from the clone flags", name)
				}
			}

			caps := ambientCaps(cfg)
			hasNetAdmin := slices.Contains(caps, uintptr(unix.CAP_NET_ADMIN))
			if hasNetAdmin != tc.netns {
				t.Errorf("CAP_NET_ADMIN in the ambient set = %v, want %v (it exists only to raise lo)",
					hasNetAdmin, tc.netns)
			}
			// Without these two the rootfs cannot be assembled at all.
			for _, c := range []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP} {
				if !slices.Contains(caps, c) {
					t.Errorf("capability %d missing from the ambient set", c)
				}
			}
		})
	}
}
