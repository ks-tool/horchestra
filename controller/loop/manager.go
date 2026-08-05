// Package loop is the controller's level-driven control-loop substrate. A Reconciler
// is one loop: it re-lists and converges on every coalesced wake and on a resync timer.
// The Manager owns the shared machinery every loop needs — one coalesced Watch per Kind
// fanned to all loops that watch it, a per-loop resync ticker, leader gating, and the
// single-goroutine-per-loop invariant (so a ReconcileOnce needs no locking).
//
// It replaces the ad-hoc `go X.Run(ctx)` goroutines each loop used to own: the scheduler,
// and later appset/ipam/netconfig, all register onto one Manager and share
// its watches and leader election.
package loop

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ks-tool/horchestra/api/types"
)

// WatchFunc opens a coalesced change stream for one Kind. The Manager opens exactly one
// per distinct Kind across all registered loops and fans each signal to every loop that
// watches that Kind. It is only a nudge — loops re-list on every wake and a resync timer
// backs it up — so a lossy or dropped event self-corrects.
type WatchFunc func(ctx context.Context, kind types.ObjectMeta) (<-chan struct{}, error)

// Reconciler is one level-driven control loop.
type Reconciler interface {
	// Name identifies the loop in logs.
	Name() string
	// Watches lists the Kinds whose changes should wake this loop (ApiVersion+Kind; the
	// Namespace/Name are ignored). A loop that watches nothing runs on the resync timer only.
	Watches() []types.ObjectMeta
	// ReconcileOnce re-lists and converges once. It must be idempotent, and is only ever
	// called from the loop's own single goroutine, so it needs no locking. A loop that writes
	// the status of a Kind it Watches MUST equality-check against the stored object before
	// writing: the Manager wakes it on that Kind's own changes, so an unconditional status
	// write would wake itself and busy-loop.
	ReconcileOnce(ctx context.Context)
}

// Config tunes a Manager; the zero value is usable (30s resync, single-node AlwaysLeader,
// no logging).
type Config struct {
	Resync  time.Duration
	Elector LeaderElector
	Logger  *zerolog.Logger
}

// Manager runs a set of Reconcilers under one leader gate and one watch fan-out.
type Manager struct {
	watch   WatchFunc
	resync  time.Duration
	elector LeaderElector
	log     zerolog.Logger
	loops   []Reconciler
}

// NewManager builds a Manager whose per-Kind watches are opened through watch. watch may
// be nil, in which case every loop runs on the resync timer only.
func NewManager(watch WatchFunc, cfg Config) *Manager {
	m := &Manager{watch: watch, resync: cfg.Resync, elector: cfg.Elector}
	if m.resync <= 0 {
		m.resync = 30 * time.Second
	}
	if m.elector == nil {
		m.elector = AlwaysLeader{}
	}
	if cfg.Logger != nil {
		m.log = *cfg.Logger
	} else {
		m.log = zerolog.Nop()
	}
	return m
}

// Add registers a Reconciler. Call before Run.
func (m *Manager) Add(r Reconciler) { m.loops = append(m.loops, r) }

// Run acquires leadership, then drives every registered loop until ctx is cancelled or
// leadership is lost. Each loop reconciles once immediately, then on every coalesced wake
// for a Kind it watches and on the resync ticker. It blocks until all loops stop.
func (m *Manager) Run(ctx context.Context) error {
	leading, resign, err := m.elector.Lead(ctx)
	if err != nil {
		return err
	}
	defer resign()

	wakes := make([]chan struct{}, len(m.loops))
	for i := range m.loops {
		wakes[i] = make(chan struct{}, 1)
	}
	m.startWatches(leading, wakes)

	var wg sync.WaitGroup
	for i, r := range m.loops {
		wg.Add(1)
		go func(r Reconciler, wake <-chan struct{}) {
			defer wg.Done()
			m.runLoop(leading, r, wake)
		}(r, wakes[i])
	}
	wg.Wait()
	return leading.Err()
}

// startWatches dedups the Kinds every loop watches, opens one watch per distinct Kind, and
// fans each Kind's signal to the wake channels of the loops that watch it.
func (m *Manager) startWatches(ctx context.Context, wakes []chan struct{}) {
	if m.watch == nil {
		return
	}
	kinds := map[string]types.ObjectMeta{}
	subs := map[string][]int{}
	for i, r := range m.loops {
		for _, k := range r.Watches() {
			key := k.ApiVersion + "/" + k.Kind
			if _, seen := kinds[key]; !seen {
				kinds[key] = types.ObjectMeta{ApiVersion: k.ApiVersion, Kind: k.Kind}
			}
			subs[key] = append(subs[key], i)
		}
	}
	for key, meta := range kinds {
		ch, err := m.watch(ctx, meta)
		if err != nil {
			m.log.Warn().Err(err).Str("kind", meta.Kind).Msg("loop: watch unavailable; resync only")
			continue
		}
		targets := subs[key]
		go func(ch <-chan struct{}, targets []int) {
			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-ch:
					if !ok {
						return
					}
				}
				for _, i := range targets {
					poke(wakes[i])
				}
			}
		}(ch, targets)
	}
}

// runLoop reconciles once, then on every wake and resync tick until ctx is cancelled.
func (m *Manager) runLoop(ctx context.Context, r Reconciler, wake <-chan struct{}) {
	ticker := time.NewTicker(m.resync)
	defer ticker.Stop()
	for {
		r.ReconcileOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-wake:
		}
	}
}

// poke delivers a coalescing nudge: a wake already pending is left as-is.
func poke(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
