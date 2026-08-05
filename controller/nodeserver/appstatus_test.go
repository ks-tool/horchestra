package nodeserver

import (
	"context"
	"encoding/json"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	nodeapipb "github.com/ks-tool/horchestra/api/node"
	apischeme "github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/internal/memory"
)

// TestDesiredState_IgnoresStatusUpdates locks down the fix for the status-heartbeat feedback loop.
// The agent re-reports an application's status every reconcile; each report is a status-subresource
// write that fires the Application watch driving pushLoop. If that re-pushed desired state to the
// node, the node would reconcile and report again — a loop that spun the controller and agent at
// network speed (observed live: ~360 writes/s). status is a subresource, so a status write must not
// move the desired-state signature (it does not advance metadata.generation); only a spec change,
// which does, may.
func TestDesiredState_IgnoresStatusUpdates(t *testing.T) {
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	ctl := &fakeController{store: store, sch: sch}
	srv := New(ctl)
	mustCreateApp(t, ctl, "pg", nodeName)

	ctx := context.Background()
	sig := func() string {
		_, s, err := srv.desiredState(ctx, nodeName)
		if err != nil {
			t.Fatalf("desiredState: %v", err)
		}
		return s
	}
	base := sig()

	// A status-only update (UpdateSubresource) must NOT move the signature — repeated reports of the
	// same or a changed phase all leave it put, so pushLoop skips the re-push and the loop is broken.
	for _, phase := range []string{corev1.AppPhaseRunning, corev1.AppPhaseRunning, corev1.AppPhaseFailed} {
		as := &nodeapipb.AppStatus{Name: "pg", Phase: phase}
		if err := srv.applyAppStatus(ctx, nodeName, as); err != nil {
			t.Fatalf("applyAppStatus(%s): %v", phase, err)
		}
		if got := sig(); got != base {
			t.Fatalf("status update (phase=%s) moved the desired-state signature %s -> %s; a status subresource must not wake a spec-watcher", phase, base, got)
		}
	}

	// A spec change (new image, via Update) advances generation and MUST move the signature, so the
	// node is re-pushed.
	obj, err := store.Get(ctx, types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Application", Name: "pg"})
	if err != nil {
		t.Fatalf("get pg: %v", err)
	}
	app := obj.(*corev1.Application)
	app.Spec.Image = "reg/pg:v2"
	b, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.Update(ctx, corev1.GroupVersion.WithKind("Application"), b, "", ""); err != nil {
		t.Fatalf("update pg spec: %v", err)
	}
	if got := sig(); got == base {
		t.Fatalf("a spec change did not move the desired-state signature %s; the node would never be re-pushed", base)
	}
}
