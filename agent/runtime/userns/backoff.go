package userns

import (
	"sync"
	"time"
)

// Restart backoff bounds. The floor is longer than any converge tick, so a workload that cannot
// stay up is not restarted once per tick forever; the ceiling keeps a node that has been failing
// for hours still trying, because the cause is often elsewhere — a registry that was down, a
// volume that was not mounted yet — and a workload that gives up permanently would need an
// operator to notice and intervene.
const (
	restartBackoffBase = 15 * time.Second
	restartBackoffMax  = 5 * time.Minute
	// flapWindow is how long a start must hold before it counts as having worked. Without it a
	// tick landing in the sliver where a crash-looping unit is briefly up would clear the count
	// and the backoff would never engage.
	flapWindow = restartBackoffBase
	// startLimitInterval/startLimitBurst are systemd's own backstop, set on every workload unit.
	// They stop the FAST loop — a workload that exits immediately, restarted by systemd as fast
	// as it can — and leave the unit `failed`, which is the only way the agent gets to see that
	// it is failing at all. The window is wider than systemd's 10s default so a workload that
	// takes a moment to fail is still caught.
	startLimitInterval = 30 * time.Second
	startLimitBurst    = 5
)

// flapGuard rate-limits restarts of a workload that will not stay up.
//
// It is the second half of the flapping backstop, and it exists because the first half cannot
// hold on its own. systemd's StartLimit* stops the fast loop and parks the unit in `failed` — but
// the converge then collects it (CollectMode) and resets it before recreating it (a failed unit
// holds its name), both of which the level-driven self-heal needs, and both of which hand the
// unit a fresh counter. So the limit below stops a workload failing many times a second, and this
// stops the agent handing it a clean slate every tick.
//
// The count is keyed on the workload's CONTENT digest, so a new spec starts over: an operator
// pushing a fix should not wait out the backoff earned by the version they are fixing.
type flapGuard struct {
	mu   sync.Mutex
	now  func() time.Time
	seen map[string]*flapState
}

type flapState struct {
	sum      string    // the config digest these attempts were for
	attempts int       // starts issued for this content, including the first
	next     time.Time // earliest the next one may be issued
}

func newFlapGuard() *flapGuard {
	return &flapGuard{now: time.Now, seen: map[string]*flapState{}}
}

// mayStart reports whether the workload may be (re)started now, recording the attempt when it
// says yes, and how long the NEXT one will have to wait. The first restart after a failure is
// always allowed: a workload that died once is usually a workload that should come straight
// back, and rate-limiting that would make the common case slower to heal in order to punish the
// rare one. The returned wait is what the caller reports — one line per attempt, rather than one
// per tick spent waiting.
func (g *flapGuard) mayStart(id, sum string) (bool, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	st, ok := g.seen[id]
	if !ok || st.sum != sum {
		g.seen[id] = &flapState{sum: sum, attempts: 1}
		return true, 0
	}
	if now.Before(st.next) {
		return false, st.next.Sub(now)
	}
	st.attempts++
	st.next = now.Add(restartDelay(st.attempts))
	// The wait just armed — when this workload may be started again if this attempt does not
	// stick either. Reporting the one after it would understate how long a failing workload is
	// about to sit there, which is the number someone reading the log is trying to learn.
	return true, st.next.Sub(now)
}

// forget clears a workload's flap state: it is up and has held, or its content changed, so the
// next start is a first start.
func (g *flapGuard) forget(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.seen, id)
}

// restartDelay is how long to wait before the nth start of the same content. The first is
// immediate and so is the second — one failure is not a flap — and each one after that doubles
// from the base to the ceiling.
func restartDelay(attempts int) time.Duration {
	if attempts < 2 {
		return 0
	}
	d := restartBackoffBase << (attempts - 2)
	if d <= 0 || d > restartBackoffMax { // <=0 catches the shift overflowing
		return restartBackoffMax
	}
	return d
}
