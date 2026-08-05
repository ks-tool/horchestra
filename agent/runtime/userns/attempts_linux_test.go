//go:build linux

package userns

import "testing"

// TestSeedIsAFloorNotAReset is the property the whole budget rests on. The count lives on the
// object, the ledger lives in this manager's memory, and the object is always the LAGGING copy:
// a job started here reaches status.attempts only on the next heartbeat. Seeding from a report
// that has not caught up must therefore never lower the count — do it and the run just started
// is refunded, and a job with backoffLimit 1 runs forever, one heartbeat at a time.
func TestSeedIsAFloorNotAReset(t *testing.T) {
	l := newRunLedger()
	l.seed("job", 0, 2)
	if got := l.start("job"); got != 1 {
		t.Fatalf("first run counted as %d, want 1", got)
	}
	l.seed("job", 0, 2) // the controller has not heard about that run yet
	if n, _ := l.count("job"); n != 1 {
		t.Errorf("a lagging report reset the count to %d — the run was refunded", n)
	}
	// A report that is AHEAD is what a restarted agent sees, and it is authoritative: the runs
	// it names happened, this process just did not make them.
	l.seed("job", 5, 2)
	if n, _ := l.count("job"); n != 5 {
		t.Errorf("count = %d, want the reported 5 — a reboot must not refund the budget", n)
	}
}

// TestSpentBoundsTheRetries: the budget is retries, so a limit of 2 buys three runs in total.
func TestSpentBoundsTheRetries(t *testing.T) {
	l := newRunLedger()
	l.seed("job", 0, 2)
	for run := 1; run <= 3; run++ {
		l.start("job")
		if spent := l.spent("job"); spent != (run > 2) {
			t.Errorf("after run %d spent = %v", run, spent)
		}
	}
}

// TestAnUnknownJobCountsAsOneRun: a job this manager never started but finds failed — what an
// agent restart or a takeover looks like — has no entry here. Reading that as zero runs would
// make a no-retry job eligible to start again, which is precisely what Never forbids.
func TestAnUnknownJobCountsAsOneRun(t *testing.T) {
	l := newRunLedger()
	if !l.spent("never-seen") {
		t.Error("a job with no ledger entry has budget left, so a failed one would be re-run")
	}
	l.seed("with-budget", 0, 1)
	if l.spent("with-budget") {
		t.Error("a job whose spec budgets a retry is already spent before it ran")
	}
}

// TestForgetEndsTheBudget: a workload torn down and pushed again is a new job, not the
// continuation of the one that failed, so it gets its allowance back.
func TestForgetEndsTheBudget(t *testing.T) {
	l := newRunLedger()
	l.seed("job", 0, 1)
	l.start("job")
	l.start("job")
	if !l.spent("job") {
		t.Fatal("two runs against a budget of one retry is not spent")
	}
	l.forget("job")
	l.seed("job", 0, 1)
	if l.spent("job") {
		t.Error("a re-created job inherited the dead one's spent budget")
	}
}

// TestFailureReasonNamesOnlyWhatTheExitCodeCannot. A plain crash is already described by its exit
// code; a deadline kill and a spent budget are not, and an operator reading "exit 143" has no way
// to tell either of them from the workload deciding to leave.
func TestFailureReasonNamesOnlyWhatTheExitCodeCannot(t *testing.T) {
	l := newRunLedger()
	l.seed("timed-out", 0, 3)
	l.start("timed-out")
	if got := failureReason("timed-out", "timeout", l); got != reasonDeadlineExceeded {
		t.Errorf("a job killed at its deadline reports %q", got)
	}
	// Success and a still-running unit say nothing.
	for _, result := range []string{"success", ""} {
		if got := failureReason("timed-out", result, l); got != "" {
			t.Errorf("result %q produced the reason %q", result, got)
		}
	}
	// A crash with budget left is not over, so it is not reported as over.
	l.seed("retrying", 0, 2)
	l.start("retrying")
	if got := failureReason("retrying", "exit-code", l); got != "" {
		t.Errorf("a job with a retry left reports %q", got)
	}
	// Only once the budget is gone.
	l.start("retrying")
	l.start("retrying")
	if got := failureReason("retrying", "exit-code", l); got != reasonBackoffLimitExceeded {
		t.Errorf("a job out of retries reports %q", got)
	}
	// A job that never budgeted any retry is over on its first failure, and its exit code says
	// everything there is to say — naming a limit nobody set would be noise.
	l.seed("no-budget", 0, 0)
	l.start("no-budget")
	if got := failureReason("no-budget", "exit-code", l); got != "" {
		t.Errorf("a job with no backoffLimit reports %q", got)
	}
}
