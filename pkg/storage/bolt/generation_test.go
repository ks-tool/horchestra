package bolt

import (
	"testing"
)

// TestGenerationTracksTheSpecAlone: generation is what a spec-watcher gates on — the node dedups
// its pushes by it and a rollout names the version it waits for with it — so it must move when,
// and only when, the desired state moves. Labelling an object used to bump it, which pushed a
// whole spec back down to a node already running exactly that spec.
func TestGenerationTracksTheSpecAlone(t *testing.T) {
	b := newTestBolt(t)
	w := newWidget("Widget", "db")
	w.Spec = widgetSpec{Node: "node-1", Image: "postgres:16"}
	cur := mustWidget(t, mustCreate(t, b, w))
	if cur.Generation != 1 {
		t.Fatalf("a created object starts at generation %d, want 1", cur.Generation)
	}

	// Metadata only: a label, then an annotation.
	cur.Labels = map[string]string{"tier": "db"}
	cur = mustWidget(t, mustUpdate(t, b, cur))
	if cur.Generation != 1 {
		t.Errorf("labelling moved generation to %d", cur.Generation)
	}
	cur.Annotations = map[string]string{"note": "on call"}
	cur = mustWidget(t, mustUpdate(t, b, cur))
	if cur.Generation != 1 {
		t.Errorf("annotating moved generation to %d", cur.Generation)
	}

	// The spec: this is the write every watcher exists for.
	cur.Spec.Image = "postgres:17"
	cur = mustWidget(t, mustUpdate(t, b, cur))
	if cur.Generation != 2 {
		t.Errorf("a spec change left generation at %d, want 2", cur.Generation)
	}

	// Writing the same spec back is not a change to it.
	cur = mustWidget(t, mustUpdate(t, b, cur))
	if cur.Generation != 2 {
		t.Errorf("rewriting an unchanged spec moved generation to %d", cur.Generation)
	}
}
