package appset

import (
	"context"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func setWithPorts(comps ...corev1.NamedApplicationSpec) *corev1.ApplicationSet {
	return &corev1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a", UID: "u1"},
		Spec:       corev1.ApplicationSetSpec{Applications: comps},
	}
}

func component(name string, ports ...corev1.Port) corev1.NamedApplicationSpec {
	return corev1.NamedApplicationSpec{
		Name: name,
		Spec: corev1.ApplicationSpec{Image: "reg/" + name + ":v1", Ports: ports},
	}
}

// TestASetRendersAServicePerComponent: the replicas of one component are instances of one thing to
// call, which a per-node registration cannot express — they are on different nodes by design. So
// the set renders the name rather than leaving every author to write the same object by hand.
func TestASetRendersAServicePerComponent(t *testing.T) {
	set := setWithPorts(
		component("api", corev1.Port{Name: "http", Port: 8080}),
		component("worker"), // no ports: nothing to register
	)
	svcs := ExpandServices(set)
	if len(svcs) != 1 {
		t.Fatalf("services = %+v, want one (the component with ports)", svcs)
	}
	svc := svcs[0]
	if svc.Name != "web-api" || svc.Namespace != "team-a" {
		t.Errorf("service = %s/%s, want team-a/web-api", svc.Namespace, svc.Name)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 8080 || svc.Spec.Ports[0].Name != "http" {
		t.Errorf("ports = %+v, want the component's own", svc.Spec.Ports)
	}
	if ref := corev1.AppsetOwnerOf(svc.OwnerReferences); ref == nil || ref.Name != "web" {
		t.Errorf("ownerReferences = %+v, want the set's controller reference", svc.OwnerReferences)
	}
	if svc.Spec.ClusterIP != "" {
		t.Error("the set invented an address; whoever runs what answers on it declares one")
	}

	// And the children join it without anyone writing the name twice.
	children, err := Expand(set, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range children {
		want := ""
		if child.Labels[corev1.LabelComponent] == "api" {
			want = "web-api"
		}
		if child.Spec.ServiceName != want {
			t.Errorf("child %s serviceName = %q, want %q", child.Name, child.Spec.ServiceName, want)
		}
	}
}

// TestANamedServiceIsJoinedNotRendered: naming a service is joining one, and the name may be
// somebody else's object — rendering it would mean this loop creating, rewriting and pruning what
// it does not own.
func TestANamedServiceIsJoinedNotRendered(t *testing.T) {
	comp := component("api", corev1.Port{Port: 8080})
	comp.Spec.ServiceName = "checkout"
	set := setWithPorts(comp)

	if svcs := ExpandServices(set); len(svcs) != 0 {
		t.Errorf("services = %+v, want none: the component joins an existing name", svcs)
	}
	children, err := Expand(set, nil)
	if err != nil {
		t.Fatal(err)
	}
	if children[0].Spec.ServiceName != "checkout" {
		t.Errorf("serviceName = %q, want the declared one", children[0].Spec.ServiceName)
	}
}

// TestAnInitStepGetsNoService: a run-to-completion component is finished, not reachable, and a
// catalog name resolving to nothing running is worse than no name.
func TestAnInitStepGetsNoService(t *testing.T) {
	comp := component("migrate", corev1.Port{Port: 9000})
	comp.Spec.Lifecycle.RestartPolicy = corev1.RestartNever
	if svcs := ExpandServices(setWithPorts(comp)); len(svcs) != 0 {
		t.Errorf("services = %+v, want none for an init step", svcs)
	}
}

// TestTheLoopCreatesServicesBeforeChildren: a child declares the service it joins and a
// declaration naming nothing is refused, so a set whose Services arrived second would fail every
// create on its first pass.
func TestTheLoopCreatesServicesBeforeChildren(t *testing.T) {
	set := setWithPorts(component("api", corev1.Port{Port: 8080}))
	f := &fakeCluster{sets: []corev1.ApplicationSet{*set}, apps: map[string]corev1.Application{}}
	New(f, Config{}).reconcileOnce(context.Background())

	if len(f.svcCreated) != 1 || f.svcCreated[0] != "web-api" {
		t.Fatalf("services created = %v, want [web-api]", f.svcCreated)
	}
	if len(f.created) != 1 {
		t.Fatalf("children created = %v, want one", f.created)
	}
	if f.apps[f.created[0]].Spec.ServiceName != "web-api" {
		t.Errorf("child joined %q, want web-api", f.apps[f.created[0]].Spec.ServiceName)
	}
	// Converged: a second pass writes nothing.
	f.svcCreated, f.svcUpdated = nil, nil
	New(f, Config{}).reconcileOnce(context.Background())
	if len(f.svcCreated) != 0 || len(f.svcUpdated) != 0 {
		t.Errorf("a converged set rewrote its services: created=%v updated=%v", f.svcCreated, f.svcUpdated)
	}
}

// TestAForeignNameIsJoinedNotWritten: a Service the set did not create is left alone even when the
// name is the one it would have rendered — adopting it would let the loop rewrite a tenant's ports
// or reap the object on the next prune.
func TestAForeignNameIsJoinedNotWritten(t *testing.T) {
	set := setWithPorts(component("api", corev1.Port{Port: 8080}))
	foreign := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web-api", Namespace: "team-a"},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 443}}},
	}
	f := &fakeCluster{
		sets:     []corev1.ApplicationSet{*set},
		apps:     map[string]corev1.Application{},
		services: map[string]corev1.Service{"web-api": foreign},
	}
	New(f, Config{}).reconcileOnce(context.Background())

	if len(f.svcCreated) != 0 || len(f.svcUpdated) != 0 || len(f.svcDeleted) != 0 {
		t.Errorf("the loop wrote a service it does not own: created=%v updated=%v deleted=%v",
			f.svcCreated, f.svcUpdated, f.svcDeleted)
	}
	if got := f.services["web-api"].Spec.Ports[0].Port; got != 443 {
		t.Errorf("the foreign service's ports were rewritten to %d", got)
	}
}

// TestAPrunedComponentTakesItsServiceWithIt — but only once nothing declares it: a Service its
// members still declare is refused by admission, so the delete is not even attempted while a child
// is still standing.
func TestAPrunedComponentTakesItsServiceWithIt(t *testing.T) {
	set := setWithPorts(component("api", corev1.Port{Port: 8080}))
	rendered := ExpandServices(set)[0]
	member := ownedChild("web-api-0", "web", "team-a")
	member.Spec.ServiceName = "web-api"

	f := &fakeCluster{
		sets:     []corev1.ApplicationSet{{ObjectMeta: set.ObjectMeta, Spec: corev1.ApplicationSetSpec{Applications: []corev1.NamedApplicationSpec{component("worker")}}}},
		apps:     map[string]corev1.Application{member.Name: member},
		services: map[string]corev1.Service{"web-api": rendered},
	}
	f.sets[0].OwnerReferences = nil
	New(f, Config{}).reconcileOnce(context.Background())
	if len(f.svcDeleted) != 0 {
		t.Errorf("a service was deleted while a member still declared it: %v", f.svcDeleted)
	}
	// The member is pruned by the same pass; once it is gone the name goes too.
	delete(f.apps, member.Name)
	New(f, Config{}).reconcileOnce(context.Background())
	if len(f.svcDeleted) != 1 || f.svcDeleted[0] != "web-api" {
		t.Errorf("services deleted = %v, want [web-api] once nothing declares it", f.svcDeleted)
	}
}
