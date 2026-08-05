//go:build linux

package userns

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestTheAnswerWaitsForItsReader pins the one property of this FIFO that both plausible
// "improvements" break, each in its own way and each only on a live node.
//
// The answer is a single byte written to a FIFO the trampoline reads. The trampoline opens its end
// LATE — stage two reaches it only after a clone and an execve — so the write routinely happens
// first, and what the open mode does in that window is the whole behaviour:
//
//	O_WRONLY|O_NONBLOCK  fails outright with ENXIO, and the workload waits for an answer that
//	                     errored out somewhere it cannot see
//	O_RDWR               succeeds instantly — and the byte lands in a FIFO whose only read end is
//	                     the writer's own, so Close DISCARDS it and the workload waits forever for
//	                     an answer that was already sent and thrown away
//	O_WRONLY (blocking)  waits for the reader, which is the contract both ends were written to
//
// Both wrong answers were shipped to a stand before this test existed. Each cost an afternoon,
// because a workload that hangs in stage two looks identical to a slow image pull.
func TestTheAnswerWaitsForItsReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- answerFIFO(path, networkReadyOK) }()

	// Nothing has this FIFO open for reading yet, so the write must still be waiting. A return
	// here — success OR failure — means the answer is not being delivered to anybody.
	select {
	case err := <-done:
		t.Fatalf("answerFIFO returned before any reader opened (err=%v): the byte is going nowhere, "+
			"and the workload it was meant for will wait for an answer it can never receive", err)
	case <-time.After(200 * time.Millisecond):
	}

	// The reader arrives, as stage two eventually does.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 1)
	if _, err := io.ReadFull(f, buf); err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	if buf[0] != networkReadyOK {
		t.Errorf("answer = %q, want %q", buf[0], networkReadyOK)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("answerFIFO: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("answerFIFO did not return once its byte was read")
	}
}

// TestTheFailedAnswerAlsoReaches: a wiring that could not be done answers with a byte that is not
// the ready one, and that answer has to arrive by the same route. If it did not, a workload whose
// network failed would hang instead of failing — the difference between a node an operator can
// diagnose and one that looks merely slow.
func TestTheFailedAnswerAlsoReaches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- answerFIFO(path, 'x') }()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 1)
	if _, err := io.ReadFull(f, buf); err != nil {
		t.Fatalf("reading the refusal: %v", err)
	}
	if buf[0] == networkReadyOK {
		t.Fatalf("a failed wiring answered %q, which the trampoline reads as success", buf[0])
	}
	if err := <-done; err != nil {
		t.Fatalf("answerFIFO: %v", err)
	}
}

// TestTheAnnouncementIsWaitedFor is the mirror property on the reading side: the agent opens the
// pid FIFO before the trampoline has written anything, and must WAIT rather than conclude there is
// no pid. It reads with a deadline, so this also pins that the deadline is long enough to be a
// timeout rather than a poll.
func TestTheAnnouncementIsWaitedFor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pid")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	type result struct {
		pid int
		err error
	}
	done := make(chan result, 1)
	go func() {
		pid, err := readPID(path)
		done <- result{pid, err}
	}()

	// The announcement comes late, as a trampoline's does.
	time.Sleep(150 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("4242\n")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("readPID: %v", r.err)
		}
		if r.pid != 4242 {
			t.Errorf("pid = %d, want 4242", r.pid)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readPID did not return after the pid was announced")
	}
}
