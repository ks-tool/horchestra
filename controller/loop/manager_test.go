package loop

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ks-tool/horchestra/api/types"
)

// countReconciler counts ReconcileOnce calls and pokes woke on each, so a test can wait
// for a reconcile deterministically instead of sleeping.
type countReconciler struct {
	n     atomic.Int64
	kinds []types.ObjectMeta
	woke  chan struct{}
}

func (r *countReconciler) Name() string                { return "count" }
func (r *countReconciler) Watches() []types.ObjectMeta { return r.kinds }
func (r *countReconciler) ReconcileOnce(context.Context) {
	r.n.Add(1)
	select {
	case r.woke <- struct{}{}:
	default:
	}
}

func TestAlwaysLeaderLeadsImmediately(t *testing.T) {
	ctx := t.Context()
	leading, resign, err := AlwaysLeader{}.Lead(ctx)
	if err != nil {
		t.Fatalf("Lead: %v", err)
	}
	defer resign()
	select {
	case <-leading.Done():
		t.Fatal("leading ctx should be live immediately")
	default:
	}
}

// TestManagerReconcilesOnStartAndWake covers the loop lifecycle: the Manager reconciles
// once on start, then again on a coalesced watch signal for a Kind the loop watches.
func TestManagerReconcilesOnStartAndWake(t *testing.T) {
	kind := types.ObjectMeta{ApiVersion: "core/v1", Kind: "Widget"}
	r := &countReconciler{kinds: []types.ObjectMeta{kind}, woke: make(chan struct{}, 8)}

	signals := make(chan struct{}, 1)
	watch := func(_ context.Context, k types.ObjectMeta) (<-chan struct{}, error) {
		if k.Kind != "Widget" {
			t.Errorf("unexpected kind watched: %q", k.Kind)
		}
		return signals, nil
	}

	m := NewManager(watch, Config{Resync: time.Hour}) // long resync: the wake, not the timer, drives the 2nd pass
	m.Add(r)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	waitWake(t, r.woke)   // initial reconcile
	signals <- struct{}{} // a change signal...
	waitWake(t, r.woke)   // ...drives another reconcile

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Manager.Run did not return after cancel")
	}
	if got := r.n.Load(); got < 2 {
		t.Fatalf("want >=2 reconciles, got %d", got)
	}
}

func waitWake(t *testing.T, woke <-chan struct{}) {
	t.Helper()
	select {
	case <-woke:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reconcile")
	}
}
