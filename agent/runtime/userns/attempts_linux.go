//go:build linux

package userns

import "sync"

// runLedger counts how many times this manager has started each job, and what budget it was told
// to spend. It is the node-side half of spec.lifecycle.backoffLimit; the durable half is
// status.attempts on the object, which is what seeds this.
//
// It has to be seeded rather than merely counted, because a job's unit is transient: it dies with
// the manager, so a node that rebooted mid-budget would start counting from zero and the job would
// get its full allowance again on every boot — which is not a retry budget, it is a slow loop.
// The object outlives the node, so what the object reports is the floor.
//
// The budget is remembered beside the count for one reason: States reports a job's outcome and has
// no spec to read, so this is where "the budget is spent" is answerable at all.
type runLedger struct {
	mu   sync.Mutex
	runs map[string]runCount
}

type runCount struct {
	n      int32 // runs started, including the one currently going
	budget int32 // the retries this job was allowed, from spec.lifecycle.backoffLimit
}

func newRunLedger() *runLedger { return &runLedger{runs: map[string]runCount{}} }

// seed records what the object says about a job before anything is decided from it: the reported
// attempt count is a floor, never a reset, so a stale report from a controller that has not caught
// up with this node's last start cannot refund a run. The budget is taken as-is — it is spec, and
// an operator raising it is exactly how a job gets another chance.
func (l *runLedger) seed(id string, reported, budget int32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.runs[id]
	c.n = max(c.n, reported)
	c.budget = budget
	l.runs[id] = c
}

// start counts one run and returns the new total.
func (l *runLedger) start(id string) int32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.runs[id]
	c.n++
	l.runs[id] = c
	return c.n
}

// spent reports whether this job has no run left. An id with no ledger entry — a unit this
// manager did not start, which is what a job found already failed after an agent restart looks
// like — counts as one run, the same reading TerminalPhase takes: a workload cannot have failed
// without running.
func (l *runLedger) spent(id string) bool {
	n, budget := l.count(id)
	return max(n, 1) > budget
}

// count is the run total and the budget recorded for a job.
func (l *runLedger) count(id string) (int32, int32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.runs[id]
	return c.n, c.budget
}

// forget drops a torn-down workload's ledger entry.
func (l *runLedger) forget(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.runs, id)
}
