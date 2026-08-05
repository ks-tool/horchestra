//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fifoPair makes the two FIFOs a routed sandbox is wired through, and a config naming them.
func fifoPair(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{
		Network:          NetworkRouted,
		NetnsPidPath:     filepath.Join(dir, "pid"),
		NetworkReadyPath: filepath.Join(dir, "ready"),
	}
	for _, p := range []string{cfg.NetnsPidPath, cfg.NetworkReadyPath} {
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

// TestTheAnnouncementWaitsForItsReader pins what the announcement's open mode has to do when the
// caller has not arrived yet: WAIT.
//
// The two wrong answers both look reasonable and both fail only on a live node. O_WRONLY|O_NONBLOCK
// fails with ENXIO the moment nothing is reading. O_RDWR succeeds instantly and then throws the pid
// away on Close, because the only read end was the writer's own — and the caller, arriving a
// moment later, finds an empty FIFO and waits for a pid that was already sent and discarded.
func TestTheAnnouncementWaitsForItsReader(t *testing.T) {
	cfg := fifoPair(t)

	done := make(chan error, 1)
	go func() { done <- announceNetns(cfg, 4242) }()

	select {
	case err := <-done:
		t.Fatalf("announceNetns returned before any reader opened (err=%v): the pid is going nowhere, "+
			"and whoever must wire this namespace will never learn which one it is", err)
	case <-time.After(200 * time.Millisecond):
	}

	f, err := os.OpenFile(cfg.NetnsPidPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 32)
	n, err := f.Read(buf)
	if err != nil {
		t.Fatalf("reading the announcement: %v", err)
	}
	if got := strings.TrimSpace(string(buf[:n])); got != strconv.Itoa(4242) {
		t.Errorf("announced %q, want 4242", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("announceNetns: %v", err)
	}
}

// TestTheWaitEndsOnlyWhenWired covers the other half: stage two must block until the answer comes,
// and must distinguish "wired" from "could not be wired" rather than starting either way.
//
// A workload released into an unwired namespace has loopback and nothing else, and it cannot tell
// that from a network that is merely broken — it fails to resolve, fails to connect, and looks like
// a bug in itself, somewhere far from here.
func TestTheWaitEndsOnlyWhenWired(t *testing.T) {
	cfg := fifoPair(t)

	done := make(chan error, 1)
	go func() { done <- awaitNetwork(cfg) }()

	select {
	case err := <-done:
		t.Fatalf("awaitNetwork returned before anything answered (err=%v): the workload would start "+
			"into a namespace holding nothing but loopback", err)
	case <-time.After(200 * time.Millisecond):
	}

	answer(t, cfg.NetworkReadyPath, networkReadyOK)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("awaitNetwork: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("awaitNetwork did not return after the namespace was reported wired")
	}
}

// TestARefusedWiringFailsTheStart: any byte that is not the ready one means the caller could not
// build this network, and the sandbox has to fail rather than run unreachable.
func TestARefusedWiringFailsTheStart(t *testing.T) {
	cfg := fifoPair(t)

	done := make(chan error, 1)
	go func() { done <- awaitNetwork(cfg) }()

	answer(t, cfg.NetworkReadyPath, 'x')
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a refused wiring was accepted as success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("awaitNetwork did not return after the refusal")
	}
}

// TestTheHandshakeCompletesInOrder is the round trip the two halves actually perform: stage one
// announces, the caller reads that pid and answers, stage two proceeds. It is written with the
// caller arriving LAST — the order that broke on a stand, because stage two only reaches its wait
// after a clone and an execve.
func TestTheHandshakeCompletesInOrder(t *testing.T) {
	cfg := fifoPair(t)

	announced := make(chan error, 1)
	go func() { announced <- announceNetns(cfg, 7) }()
	waited := make(chan error, 1)
	go func() { waited <- awaitNetwork(cfg) }()

	// The caller shows up after both ends are already waiting, which is the real sequence.
	time.Sleep(150 * time.Millisecond)

	f, err := os.OpenFile(cfg.NetnsPidPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := f.Read(buf)
	_ = f.Close()
	if err != nil {
		t.Fatalf("reading the announcement: %v", err)
	}
	if got := strings.TrimSpace(string(buf[:n])); got != "7" {
		t.Fatalf("announced %q, want 7", got)
	}
	answer(t, cfg.NetworkReadyPath, networkReadyOK)

	for _, c := range []struct {
		name string
		ch   chan error
	}{{"announce", announced}, {"await", waited}} {
		select {
		case err := <-c.ch:
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not complete", c.name)
		}
	}
}

// answer writes one byte the way the caller does: a blocking open, so it waits for the reader
// rather than racing it.
func answer(t *testing.T, path string, b byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write([]byte{b}); err != nil {
		t.Fatal(err)
	}
}
