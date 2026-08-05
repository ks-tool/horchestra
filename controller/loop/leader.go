package loop

import "context"

// LeaderElector gates a Manager's mutating loops: only the replica that holds leadership
// runs them, so a multi-replica control plane never double-schedules. The single-node
// default is AlwaysLeader; an etcd/postgres-backed elector implements the same port for HA.
type LeaderElector interface {
	// Lead blocks until this replica acquires leadership or ctx is cancelled. It returns a
	// context that stays live while leadership is held and is cancelled when it is lost or
	// ctx ends, plus a resign func that releases leadership. On ctx cancellation before
	// acquisition it returns ctx.Err().
	Lead(ctx context.Context) (leading context.Context, resign func(), err error)
}

// AlwaysLeader is the single-node no-op elector: it leads immediately and never resigns.
// It is the default when no external elector is wired, so single-node behaviour is
// unchanged — the loops start at once.
type AlwaysLeader struct{}

// Lead returns ctx unchanged and a no-op resign; leadership is held for ctx's lifetime.
func (AlwaysLeader) Lead(ctx context.Context) (context.Context, func(), error) {
	return ctx, func() {}, nil
}
