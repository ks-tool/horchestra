package nodeserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	apischeme "github.com/ks-tool/horchestra/api/scheme"

	"github.com/ks-tool/horchestra/controller/internal/memory"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// seedJob creates a run-to-completion Application pinned to this node and reports the given
// phase for it, as its node would.
func seedJob(t *testing.T, ctl *fakeController, name, phase string) *corev1.Application {
	t.Helper()
	body := `{"metadata":{"name":"` + name + `"},"spec":{"image":"reg/` + name +
		`:v1","placement":{"nodeName":"` + nodeName + `"},"lifecycle":{"restartPolicy":"Never"}}}`
	obj, err := ctl.Create(context.Background(), corev1.GroupVersion.WithKind("Application"), []byte(body), "")
	if err != nil {
		t.Fatalf("seed job %s: %v", name, err)
	}
	app, ok := obj.(*corev1.Application)
	if !ok {
		t.Fatalf("seed job %s: got %T", name, obj)
	}
	if phase == "" {
		return app
	}
	app.Status = corev1.ApplicationStatus{
		Phase: phase, ObservedGeneration: app.Generation,
	}
	b, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.UpdateSubresource(context.Background(),
		corev1.GroupVersion.WithKind("Application"), "status", b, app.Namespace); err != nil {
		t.Fatalf("report %s for %s: %v", phase, name, err)
	}
	return app
}

func desiredAppNames(t *testing.T, ctl *fakeController) []string {
	t.Helper()
	ds, _, err := New(ctl).desiredState(context.Background(), nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	var names []string
	for _, b := range ds.Applications {
		var app corev1.Application
		if err := json.Unmarshal(b, &app); err != nil {
			t.Fatal(err)
		}
		names = append(names, app.Name)
	}
	return names
}

func newFakeController(t *testing.T) *fakeController {
	t.Helper()
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	return &fakeController{store: store, sch: sch}
}

// TestFinishedJobIsNotSentDown is what makes a job run once rather than once per boot. Its unit
// is transient — it dies with the node's manager, and nothing on the node is durable by design —
// so a node told about a completed job would run it again after every reboot. The record that it
// already ran is the object, and this is where that record is read.
func TestFinishedJobIsNotSentDown(t *testing.T) {
	ctl := newFakeController(t)
	seedJob(t, ctl, "done", corev1.AppPhaseSucceeded)
	seedJob(t, ctl, "crashed", corev1.AppPhaseFailed) // a job that failed is equally over
	seedJob(t, ctl, "working", corev1.AppPhaseRunning)
	seedJob(t, ctl, "fresh", "") // never reported

	got := desiredAppNames(t, ctl)
	want := map[string]bool{"working": true, "fresh": true}
	for _, name := range got {
		if !want[name] {
			t.Errorf("%q was sent to the node after it had finished", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("%q was withheld from the node but has not finished", name)
	}
}

// TestFinishedServiceIsStillSentDown: Failed means opposite things for the two shapes of
// workload. A service that crashed is exactly the workload a node must be told about — it is
// what the node restarts — and withholding it would turn one crash into a permanent outage.
func TestFinishedServiceIsStillSentDown(t *testing.T) {
	ctl := newFakeController(t)
	body := `{"metadata":{"name":"web"},"spec":{"image":"reg/web:v1","placement":{"nodeName":"` + nodeName + `"}}}`
	obj, err := ctl.Create(context.Background(), corev1.GroupVersion.WithKind("Application"), []byte(body), "")
	if err != nil {
		t.Fatal(err)
	}
	app := obj.(*corev1.Application)
	app.Status = corev1.ApplicationStatus{Phase: corev1.AppPhaseFailed, ObservedGeneration: app.Generation}
	b, _ := json.Marshal(app)
	if _, err := ctl.UpdateSubresource(context.Background(),
		corev1.GroupVersion.WithKind("Application"), "status", b, app.Namespace); err != nil {
		t.Fatal(err)
	}

	if got := desiredAppNames(t, ctl); len(got) != 1 || got[0] != "web" {
		t.Errorf("a crashed service must still reach its node, got %v", got)
	}
}

// TestEditingAFinishedJobRunsItAgain: without the generation term a job would be finished
// forever, and editing its spec — the one way anything else in this system is re-triggered —
// could never run it again.
func TestEditingAFinishedJobRunsItAgain(t *testing.T) {
	ctl := newFakeController(t)
	app := seedJob(t, ctl, "done", corev1.AppPhaseSucceeded)
	if got := desiredAppNames(t, ctl); len(got) != 0 {
		t.Fatalf("the finished job is still being sent: %v", got)
	}

	app.Spec.Image = "reg/done:v2" // a new spec: a new generation, and the old outcome is stale
	b, _ := json.Marshal(app)
	if _, err := ctl.Update(context.Background(), corev1.GroupVersion.WithKind("Application"), b, app.Namespace, app.Name); err != nil {
		t.Fatal(err)
	}

	if got := desiredAppNames(t, ctl); len(got) != 1 || got[0] != "done" {
		t.Errorf("an edited job must run again, got %v", got)
	}
}

// TestDeletionMovesTheDesiredStateSignature: a stamped object must reach its node promptly, and
// the thing that normally moves a push — metadata.generation — deliberately does NOT move for a
// deletion, since a teardown is not a spec change. So without the deletion in the signature the
// push was deduplicated away and the node found out on the unconditional five-minute sweep: an
// app asking for a 5s grace period took 284s to go, measured on the stand.
func TestDeletionMovesTheDesiredStateSignature(t *testing.T) {
	ctl := newFakeController(t)
	app := seedJob(t, ctl, "doomed", corev1.AppPhaseRunning)

	_, before, err := New(ctl).desiredState(context.Background(), nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}

	now := metav1.Now()
	app.DeletionTimestamp = &now
	b, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.Update(context.Background(),
		corev1.GroupVersion.WithKind("Application"), b, app.Namespace, app.Name); err != nil {
		t.Fatalf("stamp: %v", err)
	}

	_, after, err := New(ctl).desiredState(context.Background(), nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if after == before {
		t.Error("stamping a deletion did not move the signature, so the node is not pushed until the periodic sweep")
	}
}

// TestAFinishedJobStillReachesTheNodeToBeDeleted: a finished job is withheld from the push so it
// does not run again on the next boot — but a DELETION has to get through, or nothing on the node
// tears it down, nothing reports it gone, and the node-teardown finalizer is never released. The
// object then sits undeletable forever and holds its name.
func TestAFinishedJobStillReachesTheNodeToBeDeleted(t *testing.T) {
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	ctl := &fakeController{store: store, sch: sch}

	app := seedJob(t, ctl, "done", "Succeeded")
	if got := desiredAppNames(t, ctl); len(got) != 0 {
		t.Fatalf("a finished job is still pushed: %v", got)
	}

	// Deleting is a deletionTimestamp on the object, which is what the service stamps.
	app.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	b, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.Update(context.Background(), corev1.GroupVersion.WithKind("Application"), b, app.Namespace, ""); err != nil {
		t.Fatalf("mark deleting: %v", err)
	}
	if got := desiredAppNames(t, ctl); len(got) != 1 || got[0] != "done" {
		t.Fatalf("a finished job being deleted did not reach the node: %v — its finalizer would never be released", got)
	}
}
