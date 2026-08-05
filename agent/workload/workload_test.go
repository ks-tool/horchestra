package workload

import (
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWorkloadID(t *testing.T) {
	if got := corev1.WorkloadID("team-a", "web"); got != "team-a_web" {
		t.Fatalf("WorkloadID = %q, want team-a_web", got)
	}
	if got := corev1.WorkloadID("", "web"); got != "web" {
		t.Fatalf("WorkloadID(no ns) = %q, want web", got)
	}

}

// TestAppIDIsTheObjectUID: a workload's identity on the node is the object's uid, not its name.
//
// The distinction is what a name-keyed node got wrong. Two applications recreated under the SAME
// name are different objects — the second must get its own unit, its own config and its own
// overlay state rather than inherit the first's, and it must not be mistaken for already
// converged. Conversely a name is not even unique after sanitizing, while a uid needs no
// escaping, no separator convention and no collision check to survive being a unit name.
func TestAppIDIsTheObjectUID(t *testing.T) {
	const uid = "b4e95624-75d6-4639-9f6d-2a4aa651df6f"
	app := App{UID: uid, Name: "web", Namespace: "team-a"}
	if app.ID() != uid {
		t.Fatalf("ID = %q, want the object uid %q", app.ID(), uid)
	}

	// Same name, recreated: a different object, and so a different workload here.
	recreated := App{UID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", Name: "web", Namespace: "team-a"}
	if app.ID() == recreated.ID() {
		t.Fatal("an application recreated under the same name kept the old workload's id")
	}

	// FromApplication is the only place the uid enters, so a projection that drops it would
	// leave every workload sharing the empty id.
	projected := FromApplication(corev1.Application{
		ObjectMeta: metav1.ObjectMeta{UID: uid, Name: "web", Namespace: "team-a"},
	})
	if projected.ID() != uid {
		t.Fatalf("FromApplication dropped the uid: ID = %q", projected.ID())
	}
}
