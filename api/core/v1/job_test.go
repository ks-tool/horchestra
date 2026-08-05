package v1

import "testing"

func lifecycle(policy string, retries *int32) Lifecycle {
	return Lifecycle{RestartPolicy: policy, BackoffLimit: retries}
}

// TestTerminalPhaseSpendsTheRetryBudget: a Failed job is over only once it has no run left, and
// that is the whole point of the budget — three readers act on "terminal" (the node transport
// withholds the workload, the scheduler and the capacity admission stop counting it), so a job
// called terminal at its first failure is a job whose backoffLimit does nothing at all.
func TestTerminalPhaseSpendsTheRetryBudget(t *testing.T) {
	for _, tc := range []struct {
		name     string
		phase    string
		lc       Lifecycle
		attempts int32
		want     bool
	}{
		{"a service that crashed is restarted", AppPhaseFailed, lifecycle(RestartAlways, nil), 3, false},
		{"a job with no budget is over at once", AppPhaseFailed, lifecycle(RestartNever, nil), 1, true},
		{"a job with a run left is not over", AppPhaseFailed, lifecycle(RestartNever, new(int32(2))), 2, false},
		{"a job that spent its budget is over", AppPhaseFailed, lifecycle(RestartNever, new(int32(2))), 3, true},
		{"success is terminal whatever the budget", AppPhaseSucceeded, lifecycle(RestartNever, new(int32(5))), 1, true},
		{"running is never terminal", AppPhaseRunning, lifecycle(RestartNever, nil), 1, false},
		// An unreported count is one run, not zero: a workload cannot have reached Failed
		// without running, and reading it as zero would retry a no-budget job forever.
		{"an unreported count is one run", AppPhaseFailed, lifecycle(RestartNever, nil), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TerminalPhase(tc.phase, tc.lc, tc.attempts); got != tc.want {
				t.Errorf("TerminalPhase(%q, retries=%d, attempts=%d) = %v, want %v",
					tc.phase, tc.lc.Retries(), tc.attempts, got, tc.want)
			}
		})
	}
}

// TestFinishedNeedsBothTerms: a job with retries left must keep reaching its node, or the retry
// never happens — the transport withholds a finished workload, so "finished" and "may still run"
// are the same question asked from two sides.
func TestFinishedNeedsBothTerms(t *testing.T) {
	job := Application{Spec: ApplicationSpec{Lifecycle: lifecycle(RestartNever, new(int32(1)))}}
	job.Generation = 4
	job.Status = ApplicationStatus{Phase: AppPhaseFailed, ObservedGeneration: 4, Attempts: 1}
	if job.Finished() {
		t.Error("a job with a retry left is finished, so its node will never be told to run it")
	}
	job.Status.Attempts = 2
	if !job.Finished() {
		t.Error("a job that spent its budget is not finished")
	}
	// The generation term is what lets an edited job run again: without it a job would be done
	// forever, and editing the spec — the one way anything else here is re-triggered — could
	// never restart it.
	job.Generation = 5
	if job.Finished() {
		t.Error("an edited job is still finished on the outcome of the spec before it")
	}
}
