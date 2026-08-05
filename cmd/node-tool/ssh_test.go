package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func genHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer.PublicKey()
}

// isolateHome pins HOME and XDG_CONFIG_HOME to a temp dir so os.UserHomeDir and
// os.UserConfigDir never touch the operator's real files.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return home
}

func TestPinnedKeyMatcher(t *testing.T) {
	key, other := genHostKey(t), genHostKey(t)

	tests := []struct {
		name string
		pin  string
		want bool
	}{
		{"SHA256 fingerprint match", ssh.FingerprintSHA256(key), true},
		{"SHA256 fingerprint mismatch", ssh.FingerprintSHA256(other), false},
		{"known_hosts line match", knownhosts.Line([]string{"node1"}, key), true},
		{"known_hosts line mismatch", knownhosts.Line([]string{"node1"}, other), false},
		{"bare public-key line match", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := pinnedKeyMatcher(tt.pin)
			if err != nil {
				t.Fatalf("pinnedKeyMatcher(%q): %v", tt.pin, err)
			}
			if got := match(key); got != tt.want {
				t.Fatalf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPinnedKeyMatcherRejectsGarbage(t *testing.T) {
	if _, err := pinnedKeyMatcher("not a key at all"); err == nil {
		t.Fatal("garbage --host-key must be rejected")
	}
}

func TestHostKeyCallbackUnknownFailsClosed(t *testing.T) {
	home := isolateHome(t)
	key := genHostKey(t)

	cb, err := hostKeyCallback("", false)
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}
	// Tests run without a terminal, so the interactive confirmation cannot fire:
	// the unknown host must be refused, naming the fingerprint and the flags.
	err = cb("10.0.0.9:22", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 22}, key)
	if err == nil {
		t.Fatal("an unknown host key must fail closed without a terminal")
	}
	for _, want := range []string{ssh.FingerprintSHA256(key), "--host-key", "--accept-new"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must mention %q", err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "known_hosts")); !os.IsNotExist(err) {
		t.Error("~/.ssh/known_hosts must never be created")
	}
}

func TestHostKeyCallbackAcceptNewPinsToolFile(t *testing.T) {
	home := isolateHome(t)
	key, other := genHostKey(t), genHostKey(t)
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 22}

	cb, err := hostKeyCallback("", true)
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}
	if err := cb("10.0.0.9:22", addr, key); err != nil {
		t.Fatalf("--accept-new must pin an unknown host key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "known_hosts")); !os.IsNotExist(err) {
		t.Fatal("the pin must land in the tool-owned file, not ~/.ssh/known_hosts")
	}

	// A fresh strict callback now verifies against the pin — and refuses a changed key.
	strict, err := hostKeyCallback("", false)
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}
	if err := strict("10.0.0.9:22", addr, key); err != nil {
		t.Fatalf("the pinned key must verify on the next connect: %v", err)
	}
	if err := strict("10.0.0.9:22", addr, other); err == nil || !strings.Contains(err.Error(), "MITM") {
		t.Fatalf("a changed key must be refused as a possible MITM, got %v", err)
	}
}

func TestHostKeyCallbackPinnedFlag(t *testing.T) {
	isolateHome(t)
	key, other := genHostKey(t), genHostKey(t)
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 22}

	cb, err := hostKeyCallback(ssh.FingerprintSHA256(key), false)
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}
	if err := cb("10.0.0.9:22", addr, key); err != nil {
		t.Fatalf("--host-key match must be accepted before any TOFU branch: %v", err)
	}
	if err := cb("10.0.0.9:22", addr, other); err == nil {
		t.Fatal("a key that does not match --host-key must be refused")
	}
}
