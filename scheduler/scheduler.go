// Package scheduler assigns a node to each Application that has no spec.nodeName,
// by fitting the app's resource requests onto a node that has room. An Application
// whose nodeName is already set is author-pinned and never touched.
//
// It is level-driven: it re-lists Applications and Nodes on every change and on a
// resync timer, so a lossy watch or a missed event self-corrects on the next pass.
// Placement is written back through the control plane (Cluster.Assign), so
// admission re-validates it — a node that filled up between the decision and the
// write is rejected and the Application stays pending for the next cycle.
package scheduler

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// Cluster is the control-plane access the scheduler needs.
type Cluster interface {
	// Applications and Nodes return the current objects.
	Applications(ctx context.Context) ([]corev1.Application, error)
	Nodes(ctx context.Context) ([]corev1.Node, error)
	// Assign pins app to node by setting spec.nodeName THROUGH the control plane,
	// so admission (capacity, node-exists) re-validates the placement. An error
	// (e.g. the node filled up) leaves the app pending for the next cycle.
	Assign(ctx context.Context, app, node string) error
}

// Watcher is an optional Cluster capability: a coalesced signal that Applications
// or Nodes may have changed, so the scheduler wakes without waiting for the resync
// timer. A Cluster that does not implement it is polled on the timer only.
type Watcher interface {
	Watch(ctx context.Context) (<-chan struct{}, error)
}

// Policy is how a node is chosen among those an Application fits.
type Policy string

const (
	// Spread (the default) balances load: the node left least utilized wins.
	Spread Policy = "spread"
	// Binpack packs tight: the node left most utilized that still fits wins, so
	// whole nodes are freed to scale down.
	Binpack Policy = "binpack"
)

// Config tunes a Scheduler; the zero value is usable (Spread, 30s resync, 45s
// node-ready timeout, no logging).
type Config struct {
	Policy       Policy
	Resync       time.Duration
	ReadyTimeout time.Duration
	Logger       *zerolog.Logger
}

// Scheduler places pending Applications onto nodes.
type Scheduler struct {
	cluster      Cluster
	policy       Policy
	resync       time.Duration
	readyTimeout time.Duration
	log          zerolog.Logger
	now          func() time.Time
}

// New builds a Scheduler over cluster, filling defaults for the zero Config.
func New(cluster Cluster, cfg Config) *Scheduler {
	s := &Scheduler{
		cluster:      cluster,
		policy:       cfg.Policy,
		resync:       cfg.Resync,
		readyTimeout: cfg.ReadyTimeout,
		now:          time.Now,
	}
	if s.policy == "" {
		s.policy = Spread
	}
	if s.resync <= 0 {
		s.resync = 30 * time.Second
	}
	if s.readyTimeout <= 0 {
		s.readyTimeout = 45 * time.Second
	}
	if cfg.Logger != nil {
		s.log = *cfg.Logger
	} else {
		s.log = zerolog.Nop()
	}
	return s
}

// Run drives the scheduler until ctx is cancelled, waking on each change (if the
// Cluster is a Watcher) and on the resync timer.
func (s *Scheduler) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.resync)
	defer ticker.Stop()

	var changed <-chan struct{}
	if w, ok := s.cluster.(Watcher); ok {
		if ch, err := w.Watch(ctx); err != nil {
			s.log.Warn().Err(err).Msg("scheduler: watch unavailable; polling on resync only")
		} else {
			changed = ch
		}
	}

	for {
		s.scheduleOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-changed:
		}
	}
}

// scheduleOnce places every pending Application it can, once.
func (s *Scheduler) scheduleOnce(ctx context.Context) {
	apps, err := s.cluster.Applications(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("scheduler: list applications")
		return
	}
	nodes, err := s.cluster.Nodes(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("scheduler: list nodes")
		return
	}

	fit := newFitState(nodes, apps, s.now(), s.readyTimeout)
	for _, app := range pending(apps) {
		node, ok := fit.choose(app, s.policy)
		if !ok {
			s.log.Info().Str("app", app.Name).Msg("scheduler: no node fits; leaving pending")
			continue
		}
		if err := s.cluster.Assign(ctx, app.Name, node); err != nil {
			s.log.Warn().Str("app", app.Name).Str("node", node).Err(err).
				Msg("scheduler: assign rejected; leaving pending")
			continue
		}
		fit.place(node, app) // debit the node so the next pending app this pass sees it
		s.log.Info().Str("app", app.Name).Str("node", node).Msg("scheduler: scheduled")
	}
}
