//go:build linux

package userns

import (
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// TestUnitPhaseTellsAFinishedJobFromARunningOne is the whole point of asking systemd for SubState
// as well as ActiveState. A job held by RemainAfterExit sits at active/exited — active, with
// nothing running — and reading ActiveState alone reported it as Running for as long as the unit
// was held, which made a job that had done its work indistinguishable from one still doing it.
func TestUnitPhaseTellsAFinishedJobFromARunningOne(t *testing.T) {
	for _, tc := range []struct {
		active, sub string
		want        string
		why         string
	}{
		{"active", "running", corev1.AppPhaseRunning, "a service with its process up"},
		{"active", "exited", corev1.AppPhaseSucceeded, "a job that ran and returned zero (RemainAfterExit holds the unit active)"},
		{"activating", "start", corev1.AppPhaseRunning, "coming up is not an outcome"},
		{"deactivating", "stop", corev1.AppPhaseRunning, "going down with a process still alive"},
		{"failed", "failed", corev1.AppPhaseFailed, "a job that returned non-zero, parked by CollectMode=inactive"},
		{"inactive", "dead", corev1.AppPhaseFailed, "wanted, and the node is not running it"},
	} {
		if got := unitPhase(tc.active, tc.sub); got != tc.want {
			t.Errorf("%s/%s = %s, want %s — %s", tc.active, tc.sub, got, tc.want, tc.why)
		}
	}
}
