package nodeserver

import (
	"encoding/json"
	"reflect"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	nodeapipb "github.com/ks-tool/horchestra/api/node"
	apischeme "github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/internal/memory"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newFake(t *testing.T) *fakeController {
	t.Helper()
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	return &fakeController{store: store, sch: sch}
}

// TestSelfRegistrationIsCordoned: a node whose Node object is absent — a first join, or a
// machine an operator has just deleted from the fleet — re-creates it from its own reported
// status. It must come back CORDONED: the reported status alone (Ready, capacity, a heartbeat
// stamped by the controller) is enough for the scheduler to place other tenants' Applications,
// and push their Secrets, within one heartbeat, so `kubectl delete node` would otherwise be
// undone silently and the removed machine would keep collecting new work.
func TestSelfRegistrationIsCordoned(t *testing.T) {
	ctl := newFake(t)
	srv := New(ctl)
	ctx := t.Context()

	// The agent reports a spec too — a credential-less path where NodeRestriction is a no-op.
	reported := `{"metadata":{"name":"` + nodeName + `"},` +
		`"spec":{"unschedulable":false,"labels":{"role":"forged"}},` +
		`"status":{"ready":true,"capacity":{"cpu":"8","memory":"16Gi"}}}`
	if err := srv.applyStatus(ctx, nodeName, []byte(reported)); err != nil {
		t.Fatalf("applyStatus: %v", err)
	}

	obj, err := ctl.Get(ctx, nodeMeta(nodeName))
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	n, ok := obj.(*corev1.Node)
	if !ok {
		t.Fatalf("stored object is %T, want *corev1.Node", obj)
	}
	if !n.Spec.Unschedulable {
		t.Fatal("a self-registered node must be cordoned; an operator admits it explicitly")
	}
	if len(n.Labels) != 0 {
		t.Fatalf("spec.labels = %v; the node must not seed its own spec", n.Labels)
	}
	if !n.Status.Ready {
		t.Fatal("the reported status must be kept: the node is registered, only unschedulable")
	}
}

// TestPushFreezesWithoutNodeObject: deleting a Node has to be a real containment lever — the
// machine stops receiving newly placed Applications and their Secrets. The push is FROZEN
// rather than emptied, so a mistaken delete does not tear down what is already running there.
func TestPushFreezesWithoutNodeObject(t *testing.T) {
	ctl := newFake(t)
	srv := New(ctl)
	ctx := t.Context()
	mustCreateApp(t, ctl, "web", nodeName)

	sess := &session{send: make(chan *nodeapipb.ControllerMessage, 4)}
	if !srv.push(ctx, nodeName, sess) {
		t.Fatal("push must keep the session alive")
	}
	if len(sess.send) != 0 {
		t.Fatal("an unregistered node must be served nothing, not an empty desired state")
	}
	if !sess.frozen {
		t.Fatal("the session must record the freeze")
	}

	mustCreateNode(t, ctl, nodeName)
	if !srv.push(ctx, nodeName, sess) {
		t.Fatal("push must keep the session alive")
	}
	if len(sess.send) != 1 {
		t.Fatalf("a registered node must be served its desired state, got %d messages", len(sess.send))
	}
	if sess.frozen {
		t.Fatal("the freeze must clear once the node is registered again")
	}
}

// TestDesiredStateSignatureIncludesUID: the push dedup key must be identity-complete. Storage
// resets metadata.generation to 1 on create and reuses the (namespace, name) slot, so without
// the uid a delete-and-recreate under the same name reproduced a byte-identical signature: the
// push was skipped as "unchanged" and the node kept running the OLD spec while the API reported
// the new one.
func TestDesiredStateSignatureIncludesUID(t *testing.T) {
	ctl := newFake(t)
	srv := New(ctl)
	ctx := t.Context()

	mustCreateApp(t, ctl, "web", nodeName)
	_, before, err := srv.desiredState(ctx, nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}

	if err := ctl.store.Delete(ctx, types.ObjectMeta{
		ApiVersion: corev1.GroupVersion.String(), Kind: "Application", Name: "web",
	}); err != nil {
		t.Fatalf("delete web: %v", err)
	}
	mustCreateApp(t, ctl, "web", nodeName) // same name, fresh uid, generation back to 1

	_, after, err := srv.desiredState(ctx, nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if after == before {
		t.Fatal("a recreated application must move the desired-state signature, or the node is never re-pushed")
	}
}

// TestDesiredStateRedactsForeignVolumes: the agent needs the whole PersistentVolume NAME set to
// tell a deleted volume (reclaim the data) from one reassigned to another node (just detach),
// but nothing else about a volume it does not back. A node holding one certificate must not
// learn every other tenant's volume size, mode, driver and reclaim policy.
func TestDesiredStateRedactsForeignVolumes(t *testing.T) {
	ctl := newFake(t)
	ctx := t.Context()

	for _, pv := range []*corev1.PersistentVolume{
		{
			TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "PersistentVolume"},
			ObjectMeta: metav1.ObjectMeta{Name: "mine", Namespace: "team-a"},
			Spec:       corev1.PersistentVolumeSpec{Node: nodeName, Mode: "0770"},
		},
		{
			TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "PersistentVolume"},
			ObjectMeta: metav1.ObjectMeta{Name: "theirs", Namespace: "team-b"},
			Spec:       corev1.PersistentVolumeSpec{Node: "node-2", Mode: "0777"},
		},
	} {
		data, err := json.Marshal(pv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ctl.Create(ctx, corev1.GroupVersion.WithKind("PersistentVolume"), data, pv.Namespace); err != nil {
			t.Fatalf("create pv %s: %v", pv.Name, err)
		}
	}

	ds, _, err := New(ctl).desiredState(ctx, nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if len(ds.PersistentVolumes) != 2 {
		t.Fatalf("both volumes must be present (delete-vs-reassign), got %d", len(ds.PersistentVolumes))
	}
	got := map[string]corev1.PersistentVolume{}
	for _, b := range ds.PersistentVolumes {
		var pv corev1.PersistentVolume
		if err := json.Unmarshal(b, &pv); err != nil {
			t.Fatalf("decode pushed pv: %v", err)
		}
		got[pv.Name] = pv
	}
	if mine := got["mine"]; mine.Spec.Node != nodeName || mine.Spec.Mode != "0770" {
		t.Fatalf("this node's own volume must be pushed in full, got %+v", mine.Spec)
	}
	theirs, ok := got["theirs"]
	if !ok {
		t.Fatal("a foreign volume's identity must still be pushed")
	}
	if theirs.Namespace != "team-b" || theirs.Name != "theirs" {
		t.Fatalf("a foreign volume's identity must be intact, got %s/%s", theirs.Namespace, theirs.Name)
	}
	if !reflect.DeepEqual(theirs.Spec, corev1.PersistentVolumeSpec{}) {
		t.Fatalf("a foreign volume must be reduced to its identity, got spec %+v", theirs.Spec)
	}
}
