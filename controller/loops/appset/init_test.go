package appset

import (
	"context"
	"slices"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// initComp is a run-to-completion component: inside a set, that IS the init role.
func initComp(name, image string) corev1.NamedApplicationSpec {
	c := comp(name, image)
	c.Spec.Lifecycle.RestartPolicy = corev1.RestartNever
	return c
}

// finishJob marks a child as its node would once the job ended.
func finishJob(f *fakeCluster, name, phase string, exit int32) {
	app := f.apps[name]
	app.Generation = 1
	app.Spec.Placement.NodeName = "n1"
	app.Status = corev1.ApplicationStatus{
		Phase: phase, ObservedGeneration: 1, ExitCode: &exit,
	}
	f.apps[name] = app
}

func initCluster(set *corev1.ApplicationSet) *fakeCluster {
	return &fakeCluster{
		sets:  []corev1.ApplicationSet{*set},
		nodes: []corev1.Node{readyNode("n1")},
		apps:  map[string]corev1.Application{},
	}
}

func reconcile(f *fakeCluster) {
	New(f, Config{}).reconcileOnce(context.Background())
}

func setStatus(f *fakeCluster) corev1.ApplicationSetStatus { return f.sets[0].Status }

// TestServicesWaitForTheInitStep is the whole reason a job in a set is an init step: a migration
// that runs beside the service it migrates for races it. The service is not created at all —
// not created-and-held — because a created child is one the scheduler places and a node starts.
func TestServicesWaitForTheInitStep(t *testing.T) {
	f := initCluster(bundleSet("web", "team", initComp("migrate", "migrate:v1"), comp("api", "api:v1")))

	reconcile(f)
	if slices.Contains(f.created, "web-api") {
		t.Fatal("the service was created before the init step finished")
	}
	if !slices.Contains(f.created, "web-migrate") {
		t.Fatalf("the init step itself was not created: %v", f.created)
	}
	if st := setStatus(f); st.Phase != "Initializing" {
		t.Errorf("set phase = %q, want Initializing", st.Phase)
	}

	finishJob(f, "web-migrate", corev1.AppPhaseSucceeded, 0)
	reconcile(f)
	if !slices.Contains(f.created, "web-api") {
		t.Errorf("the service was not created after the init step succeeded: %v", f.created)
	}
}

// TestInitStepsRunInDeclarationOrder: a set's author wrote two steps in an order, and that order
// is the one thing a second step can rely on. Running them together would make the second one's
// preconditions a race.
func TestInitStepsRunInDeclarationOrder(t *testing.T) {
	f := initCluster(bundleSet("web", "team",
		initComp("schema", "schema:v1"), initComp("seed", "seed:v1"), comp("api", "api:v1")))

	reconcile(f)
	if slices.Contains(f.created, "web-seed") {
		t.Fatal("the second init step started before the first finished")
	}

	finishJob(f, "web-schema", corev1.AppPhaseSucceeded, 0)
	reconcile(f)
	if !slices.Contains(f.created, "web-seed") {
		t.Fatalf("the second init step did not start: %v", f.created)
	}
	if slices.Contains(f.created, "web-api") {
		t.Fatal("the service started while an init step was still running")
	}

	finishJob(f, "web-seed", corev1.AppPhaseSucceeded, 0)
	reconcile(f)
	if !slices.Contains(f.created, "web-api") {
		t.Errorf("the service did not start after every init step succeeded: %v", f.created)
	}
}

// TestFailedInitStepBlocksTheSetAndSaysWhy: the step will not be retried — restartPolicy Never
// means the node will not run it again, and recreating the child would be this controller
// overruling that — so the object has to explain the stop, exit status and all.
func TestFailedInitStepBlocksTheSetAndSaysWhy(t *testing.T) {
	f := initCluster(bundleSet("web", "team", initComp("migrate", "migrate:v1"), comp("api", "api:v1")))
	reconcile(f)
	finishJob(f, "web-migrate", corev1.AppPhaseFailed, 7)
	reconcile(f)

	if slices.Contains(f.created, "web-api") {
		t.Fatal("the service started after its init step failed")
	}
	st := setStatus(f)
	if st.Phase != "InitFailed" {
		t.Errorf("set phase = %q, want InitFailed", st.Phase)
	}
	var msg string
	for _, c := range st.Conditions {
		if c.Reason == "InitFailed" {
			msg = c.Message
		}
	}
	if !strings.Contains(msg, "migrate") || !strings.Contains(msg, "exit 7") {
		t.Errorf("message %q names neither the step nor how it failed", msg)
	}
}

// TestInitStepIsNotAMissingReplica: a finished job is a thing that happened, not a replica that
// is absent. Counting it would leave every set with an init step permanently one short of Ready.
func TestInitStepIsNotAMissingReplica(t *testing.T) {
	f := initCluster(bundleSet("web", "team", initComp("migrate", "migrate:v1"), comp("api", "api:v1")))
	reconcile(f)
	finishJob(f, "web-migrate", corev1.AppPhaseSucceeded, 0)
	reconcile(f)

	// The service exists now; report it running, as its node would.
	api := f.apps["web-api"]
	api.Generation = 1
	api.Spec.Placement.NodeName = "n1"
	api.Status = corev1.ApplicationStatus{Phase: corev1.AppPhaseRunning, ObservedGeneration: 1}
	f.apps["web-api"] = api
	reconcile(f)

	st := setStatus(f)
	if st.Desired != 1 || st.Current != 1 || st.Running != 1 {
		t.Errorf("desired=%d current=%d running=%d, want 1/1/1 — the init step is not a replica",
			st.Desired, st.Current, st.Running)
	}
	if st.Phase != corev1.AppSetPhaseReady {
		t.Errorf("set phase = %q, want Ready", st.Phase)
	}
	// It is still LISTED, with the outcome an operator went looking for.
	var found bool
	for _, ch := range st.Children {
		if ch.Name == "web-migrate" {
			found = true
			if ch.Phase != corev1.AppPhaseSucceeded {
				t.Errorf("the init child reads %q, want Succeeded", ch.Phase)
			}
		}
	}
	if !found {
		t.Error("the init child vanished from the set's status")
	}
}
