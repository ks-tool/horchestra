//go:build linux

package userns

import (
	"context"
	"syscall"
	"time"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/rs/zerolog/log"
)

// Reap finishes every stop that is still running past its own budget.
//
// A workload is PID 1 of its own PID namespace, and the kernel discards a signal sent to a
// namespace's init when that init has installed no handler — SIGTERM included, and from an
// ancestor namespace too, since only SIGKILL and SIGSTOP are forced. So an image that handles no
// signal ALWAYS runs its grace period out, and on a host whose service.d sets
// TimeoutStopFailureMode=abort the expiry is a SIGABRT the same init discards again: the unit
// then sits in final-watchdog with the workload still running, indefinitely.
//
// stopUnit already bounds this for a stop the converge itself issued. This is the other half:
// the same thing on a stop nobody is waiting on any more — the converge was cancelled, the agent
// restarted, or the controller went away mid-teardown. Nothing else would ever come back for it,
// and the unit holds its name, its cgroup and its rootfs mount for as long as it stands there.
//
// It reads the deadline off the UNIT rather than off any spec, which is what lets it run with no
// desired state at all: the agent wrote TimeoutStopUSec from the workload's own
// terminationGracePeriodSeconds when it started the unit, so the unit is the record of what this
// workload was promised. Same reason the converge asks systemd what is running instead of keeping
// a file — there is one source of truth and it is the running unit.
func (r *Runtime) Reap(ctx context.Context) error {
	return withUserConn(ctx, func(c *sddbus.Conn) error {
		units, err := c.ListUnitsByPatternsContext(ctx, []string{"deactivating"}, []string{unitGlob})
		if err != nil {
			return err
		}
		now := time.Now()
		for _, u := range units {
			if _, ok := unitID(u.Name); !ok {
				continue
			}
			since, budget := stoppingFor(ctx, c, u.Name, now)
			if since <= budget+stopMargin {
				continue // still within what this workload was promised
			}
			log.Warn().Str("unit", u.Name).Str("sub_state", u.SubState).
				Dur("stopping_for", since.Round(time.Second)).Dur("budget", budget).
				Msg("userns: a stop nobody is waiting on has outstayed its grace period; killing it")
			c.KillUnitContext(ctx, u.Name, int32(syscall.SIGKILL))
			// The kill ends the processes; the JOB still has to be told, or the unit stays in
			// deactivating with an empty cgroup and is reaped again on every pass.
			if err := runJobWithin(ctx, "stop "+u.Name, stopMargin, func(ch chan<- string) (int, error) {
				return c.StopUnitContext(ctx, u.Name, "replace", ch)
			}); err != nil {
				log.Debug().Err(err).Str("unit", u.Name).Msg("userns: stop after kill")
			}
		}
		return nil
	})
}

// stoppingFor is how long this unit has been going down, and how long it was given to. The stop
// began when the unit left active (ActiveExitTimestamp, microseconds since the epoch); the budget
// is the unit's own TimeoutStopUSec, which the agent set from the workload's spec.
//
// An unreadable or zero timestamp reports a zero duration, so a unit whose clock cannot be read is
// left alone rather than killed on a guess.
func stoppingFor(ctx context.Context, c *sddbus.Conn, unit string, now time.Time) (since, budget time.Duration) {
	if p, err := c.GetUnitPropertyContext(ctx, unit, "ActiveExitTimestamp"); err == nil && p != nil {
		if us, ok := p.Value.Value().(uint64); ok && us > 0 {
			if d := now.Sub(time.UnixMicro(int64(us))); d > 0 {
				since = d
			}
		}
	}
	budget = removeGrace
	if p, err := c.GetUnitPropertyContext(ctx, unit, "TimeoutStopUSec"); err == nil && p != nil {
		// USEC_INFINITY is a unit that may take as long as it likes, and it is not this
		// function's place to overrule that: report a budget nothing can exceed.
		if us, ok := p.Value.Value().(uint64); ok && us > 0 {
			if us == ^uint64(0) {
				return since, 1<<62 - 1
			}
			budget = time.Duration(us) * time.Microsecond
		}
	}
	return since, budget
}
