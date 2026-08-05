package agent

import (
	"context"
	"testing"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"k8s.io/apimachinery/pkg/api/resource"
)

const jobUID = "9c1d4b2a-3e5f-4a7b-8c9d-0e1f2a3b4c5d"

// jobAndService is one run-to-completion workload and one long-running one, each asking for a
// whole CPU so the allocation arithmetic is readable.
func jobAndService() map[string]workload.App {
	req := corev1.ResourceAmounts{CPU: resource.MustParse("1"), Memory: resource.MustParse("512Mi")}
	return map[string]workload.App{
		jobUID:    {UID: jobUID, Namespace: "ns", Name: "job", Lifecycle: corev1.Lifecycle{RestartPolicy: corev1.RestartNever}, Requests: req},
		wantedUID: {UID: wantedUID, Namespace: "ns", Name: "svc", Requests: req},
	}
}

func statusFor(t *testing.T, a *Agent, name string) *nodeAppStatus {
	t.Helper()
	for _, m := range a.appStatusMessages(context.Background()) {
		if as := m.GetAppStatus(); as != nil && as.GetName() == name {
			return &nodeAppStatus{
				phase: as.GetPhase(), exitCode: as.GetExitCode(), finishedAt: as.GetFinishedAtUnixNano(),
			}
		}
	}
	t.Fatalf("no status reported for %q", name)
	return nil
}

type nodeAppStatus struct {
	phase      string
	exitCode   int32
	finishedAt int64
}

// TestFinishedJobReportsSucceeded: a job whose unit the runtime still holds used to report
// Running for the life of the node's manager, because presence in the runtime's listing WAS the
// phase. The finished job is now told from the running service, and how it finished travels with
// it — a phase says a job ended, the exit status says whether it ended the way it was meant to.
func TestFinishedJobReportsSucceeded(t *testing.T) {
	rt := &fakeRuntime{states: []workload.State{
		{ID: jobUID, Phase: corev1.AppPhaseSucceeded, ExitCode: 0},
		{ID: wantedUID, Phase: corev1.AppPhaseRunning},
	}}
	a := &Agent{runtime: rt, want: jobAndService()}

	if got := statusFor(t, a, "job"); got.phase != corev1.AppPhaseSucceeded {
		t.Errorf("finished job = %s, want Succeeded", got.phase)
	}
	if got := statusFor(t, a, "svc"); got.phase != corev1.AppPhaseRunning {
		t.Errorf("running service = %s, want Running", got.phase)
	}

	// A job that returned non-zero is Failed and carries the code, which is the only thing that
	// distinguishes one failure from another after the process is gone.
	rt.states = []workload.State{{ID: jobUID, Phase: corev1.AppPhaseFailed, ExitCode: 7}}
	got := statusFor(t, a, "job")
	if got.phase != corev1.AppPhaseFailed || got.exitCode != 7 {
		t.Errorf("failed job = %s exit %d, want Failed exit 7", got.phase, got.exitCode)
	}
}

// TestRunningWorkloadReportsNoExitStatus: the node sends zeroes for a workload that has not
// finished, and a stored exitCode of 0 reads as a success that never happened.
func TestRunningWorkloadReportsNoExitStatus(t *testing.T) {
	a := &Agent{
		runtime: &fakeRuntime{states: []workload.State{{ID: wantedUID, Phase: corev1.AppPhaseRunning}}},
		want:    jobAndService(),
	}
	if got := statusFor(t, a, "svc"); got.exitCode != 0 || got.finishedAt != 0 {
		t.Errorf("a running workload reported exit %d at %d", got.exitCode, got.finishedAt)
	}
}

// TestAllocationCountsOnlyTheLoadTheNodeCarries: a finished job holds a unit and nothing else, so
// counting it would retire a slice of the node with every job that ever ran there. A workload
// that is merely not running right now — starting, restarting, failed-and-restartable — is load
// the node has committed to and keeps its reservation, or capacity would breathe and the
// scheduler would place against room that is about to be taken back.
func TestAllocationCountsOnlyTheLoadTheNodeCarries(t *testing.T) {
	a := &Agent{want: jobAndService()}
	cpu := func() int64 {
		alloc := a.nodeStatus().Allocated
		return alloc.CPU.MilliValue()
	}

	a.runtime = &fakeRuntime{states: []workload.State{
		{ID: jobUID, Phase: corev1.AppPhaseRunning}, {ID: wantedUID, Phase: corev1.AppPhaseRunning},
	}}
	a.observe(context.Background())
	if got := cpu(); got != 2000 {
		t.Fatalf("two running workloads allocate %dm, want 2000m", got)
	}

	a.runtime = &fakeRuntime{states: []workload.State{
		{ID: jobUID, Phase: corev1.AppPhaseSucceeded}, {ID: wantedUID, Phase: corev1.AppPhaseRunning},
	}}
	a.observe(context.Background())
	if got := cpu(); got != 1000 {
		t.Errorf("a finished job still holds %dm of the node", got-1000)
	}

	// The service crashed and will be restarted: still this node's load.
	a.runtime = &fakeRuntime{states: []workload.State{
		{ID: jobUID, Phase: corev1.AppPhaseSucceeded}, {ID: wantedUID, Phase: corev1.AppPhaseFailed},
	}}
	a.observe(context.Background())
	if got := cpu(); got != 1000 {
		t.Errorf("a restartable service dropped its reservation: %dm", got)
	}
}

// TestTerminalPhaseNeedsTheRestartPolicy: Failed means opposite things for the two shapes of
// workload, and the phase alone cannot tell them apart.
func TestTerminalPhaseNeedsTheRestartPolicy(t *testing.T) {
	for _, tc := range []struct {
		phase, policy string
		want          bool
	}{
		{corev1.AppPhaseSucceeded, corev1.RestartNever, true},
		{corev1.AppPhaseFailed, corev1.RestartNever, true}, // a job that failed is over
		{corev1.AppPhaseFailed, "", false},                 // a service is restarted
		{corev1.AppPhaseFailed, corev1.RestartOnFailure, false},
		{corev1.AppPhaseRunning, corev1.RestartNever, false},
	} {
		lc := corev1.Lifecycle{RestartPolicy: tc.policy}
		if got := corev1.TerminalPhase(tc.phase, lc, 1); got != tc.want {
			t.Errorf("TerminalPhase(%q, %q) = %v, want %v", tc.phase, tc.policy, got, tc.want)
		}
	}
}
