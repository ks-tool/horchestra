package workload

import (
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// State is what the node's runtime holds for one workload right now.
//
// It exists because presence is not a state. The runtime lists the workloads it holds units
// for in EVERY state on purpose — a unit that failed is still one this node must be able to
// tear down — so reading that list as "these are running" reported a job that had run and
// exited as Running for as long as its unit was held, which is the one thing nobody could
// afford to be told about a job. The init system already answers the finer question in the
// same call; this is where the answer lands instead of being dropped.
type State struct {
	// ID is the workload id (the Application's uid), the same key Apply and Remove take.
	ID string
	// Phase is one of the corev1.AppPhase* values, as the runtime observes it — never as the
	// desired state wishes it were.
	Phase string
	// ExitCode and FinishedAt describe how a finished workload finished. Both are zero while
	// it is still running; a caller reads them only when Phase is terminal.
	ExitCode   int32
	FinishedAt time.Time
	// Attempts is how many runs of this job the node has spent, including the one it is
	// reporting. Zero for a service and for a job the runtime has no count for.
	Attempts int32
	// Reason names WHY a job failed when the failure is one the runtime can distinguish from a
	// plain non-zero exit: DeadlineExceeded (it outran spec.lifecycle.activeDeadlineSeconds) or
	// BackoffLimitExceeded (its retry budget is spent). Empty otherwise.
	Reason string
}

// Running reports whether the workload is up.
func (s State) Running() bool { return s.Phase == corev1.AppPhaseRunning }
