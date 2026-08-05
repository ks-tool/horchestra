package userns

import (
	"testing"
	"time"
)

// first drops the wait a caller would report, so the assertions read as the policy question they
// are asking: may it start now?
func first(allow bool, _ time.Duration) bool { return allow }

// clockedGuard is a guard whose clock the test drives, so a five-minute backoff takes no time to
// verify and the assertions are about the policy rather than about timing.
func clockedGuard() (*flapGuard, *time.Time) {
	now := time.Unix(1_800_000_000, 0)
	g := newFlapGuard()
	g.now = func() time.Time { return now }
	return g, &now
}

// TestFirstRestartIsImmediate: a workload that died once is usually a workload that should come
// straight back. Rate-limiting the first restart would make the common case slower to heal in
// order to punish the rare one.
func TestFirstRestartIsImmediate(t *testing.T) {
	g, _ := clockedGuard()
	if !first(g.mayStart("app", "sum1")) {
		t.Fatal("the first start was refused")
	}
	if !first(g.mayStart("app", "sum1")) {
		t.Fatal("the first RESTART was refused; one failure is not a flap")
	}
}

// TestRepeatedFailureBacksOff is the regression this exists for. A workload that will not stay up
// used to be restarted once per converge tick forever: systemd's own start limit cannot stop it,
// because the converge collects and resets the unit before recreating it.
func TestRepeatedFailureBacksOff(t *testing.T) {
	g, now := clockedGuard()
	g.mayStart("app", "sum1") // first start
	g.mayStart("app", "sum1") // first restart, immediate — arms the 15s window

	if first(g.mayStart("app", "sum1")) {
		t.Fatal("a third start was allowed immediately: the workload would be restarted every tick")
	}
	*now = now.Add(restartBackoffBase - time.Second)
	if first(g.mayStart("app", "sum1")) {
		t.Fatal("a start was allowed before the window closed")
	}
	*now = now.Add(2 * time.Second)
	if !first(g.mayStart("app", "sum1")) {
		t.Fatal("a start was refused after the window closed")
	}

	// And each further failure waits longer, up to the ceiling.
	for want := 2 * restartBackoffBase; want < restartBackoffMax; want *= 2 {
		if first(g.mayStart("app", "sum1")) {
			t.Fatalf("a start was allowed inside the %s window", want)
		}
		*now = now.Add(want)
		if !first(g.mayStart("app", "sum1")) {
			t.Fatalf("a start was refused after the %s window", want)
		}
	}
}

// TestReportedWaitIsTheRealOne pins what the agent logs when it restarts a failing workload: the
// delay before the NEXT attempt, not the one after it. An operator reads that number to decide
// whether to wait or intervene, and it was briefly double the truth.
func TestReportedWaitIsTheRealOne(t *testing.T) {
	g, now := clockedGuard()
	g.mayStart("app", "sum1") // first start
	_, wait := g.mayStart("app", "sum1")
	if wait != restartBackoffBase {
		t.Fatalf("reported wait = %s, want %s", wait, restartBackoffBase)
	}
	// And it is the truth: a start is refused right up to it, and allowed at it.
	*now = now.Add(wait - time.Second)
	if first(g.mayStart("app", "sum1")) {
		t.Fatal("a start was allowed before the reported wait elapsed")
	}
	*now = now.Add(time.Second)
	if _, wait = g.mayStart("app", "sum1"); wait != 2*restartBackoffBase {
		t.Fatalf("second reported wait = %s, want %s", wait, 2*restartBackoffBase)
	}
}

// TestBackoffIsCapped: the delay stops growing, because the cause of a failure is often elsewhere
// — a registry that was down, a volume not mounted yet — and a workload that gave up permanently
// would need an operator to notice before it could ever come back.
func TestBackoffIsCapped(t *testing.T) {
	for _, attempts := range []int{20, 60, 1000} {
		if d := restartDelay(attempts); d != restartBackoffMax {
			t.Errorf("restartDelay(%d) = %s, want the %s ceiling", attempts, d, restartBackoffMax)
		}
	}
}

// TestNewContentStartsOver: an operator pushing a fix should not wait out the backoff earned by
// the version they are fixing, so the count is keyed on the workload's content digest.
func TestNewContentStartsOver(t *testing.T) {
	g, _ := clockedGuard()
	g.mayStart("app", "sum1")
	g.mayStart("app", "sum1")
	if first(g.mayStart("app", "sum1")) {
		t.Fatal("precondition: the guard should be backing off by now")
	}
	if !first(g.mayStart("app", "sum2")) {
		t.Fatal("a new spec was made to wait out the previous spec's backoff")
	}
}

// TestForgetClearsTheCount: a start that HELD is the only evidence the last restart worked, and
// the caller clears the count on it. A workload up for a week must not carry a five-minute delay
// into its first crash.
func TestForgetClearsTheCount(t *testing.T) {
	g, _ := clockedGuard()
	g.mayStart("app", "sum1")
	g.mayStart("app", "sum1")
	if first(g.mayStart("app", "sum1")) {
		t.Fatal("precondition: the guard should be backing off by now")
	}
	g.forget("app")
	if !first(g.mayStart("app", "sum1")) {
		t.Fatal("a workload that came up and held is still being backed off")
	}
}

// TestGuardIsPerWorkload: one flapping app must not delay the restart of another.
func TestGuardIsPerWorkload(t *testing.T) {
	g, _ := clockedGuard()
	g.mayStart("noisy", "sum1")
	g.mayStart("noisy", "sum1")
	if first(g.mayStart("noisy", "sum1")) {
		t.Fatal("precondition: the noisy app should be backing off")
	}
	if !first(g.mayStart("quiet", "sum1")) {
		t.Fatal("a second workload was delayed by the first one's failures")
	}
}
