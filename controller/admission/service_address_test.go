package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func addrAttrs(svc *corev1.Service) *Attributes {
	return &Attributes{GVK: corev1.GroupVersion.WithKind("Service"), Operation: Create, Object: svc}
}

// nsLister is the whole chain's minimum: referenceCheck resolves the namespace a Service is
// written into.
func nsLister() *fakeLister {
	return &fakeLister{namespaces: []corev1.Namespace{mkNamespace("team-a")}}
}

func svcAt(ns, name, ip string, ports ...int32) *corev1.Service {
	svc := svcObj(ns, name)
	svc.Spec.ClusterIP = ip
	svc.Spec.Ports = nil
	for _, p := range ports {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: p})
	}
	return svc
}

// TestNoAddressIsInvented: a Service without one is ordinary. Its names in the catalog are the
// discovery surface, and an address the control plane made up would be a value nothing in the
// fleet has heard of — there is no allocator until the datapath that makes an address real
// without anything binding it.
func TestNoAddressIsInvented(t *testing.T) {
	svc := svcObj("team-a", "api")
	if err := DefaultChain(nsLister(), nil).Run(context.Background(), addrAttrs(svc)); err != nil {
		t.Fatal(err)
	}
	if svc.Spec.ClusterIP != "" {
		t.Errorf("clusterIP = %q, want none: nothing allocates one", svc.Spec.ClusterIP)
	}
}

// TestADeclaredAddressIsKept: the address belongs to whatever answers on it — a balancer that
// already has one — so the author writes it and the control plane carries it, unchanged.
func TestADeclaredAddressIsKept(t *testing.T) {
	svc := svcAt("team-a", "api", "127.64.0.1", 8080)
	if err := DefaultChain(nsLister(), nil).Run(context.Background(), addrAttrs(svc)); err != nil {
		t.Fatal(err)
	}
	if svc.Spec.ClusterIP != "127.64.0.1" {
		t.Errorf("clusterIP = %q, want the declared one", svc.Spec.ClusterIP)
	}
}

func TestAnAddressHasToBeOne(t *testing.T) {
	for _, tc := range []struct{ ip, want string }{
		{"cache.example.com", "not an IP"},
		{"10.0.0.256", "not an IP"},
		{"0.0.0.0", "cannot connect"},
		{"224.0.0.1", "multicast"},
	} {
		err := serviceAddress{}.Validate(context.Background(), addrAttrs(svcAt("team-a", "api", tc.ip, 8080)))
		if err == nil {
			t.Errorf("clusterIP %q was accepted (%s)", tc.ip, tc.want)
		}
	}
}

// TestAnAddressIsOneServices: unique cluster-wide, and the address itself rather than
// (address, port) — an address that identifies only half a service is one that DNS, a datapath map
// and an operator all have to qualify with a port before it means anything. The check spans
// namespaces because an address does.
func TestAnAddressIsOneServices(t *testing.T) {
	l := &fakeLister{services: []corev1.Service{*svcAt("team-a", "api", "10.92.16.10", 8080)}}
	err := (serviceAddress{lister: l}).Validate(context.Background(),
		addrAttrs(svcAt("team-b", "other", "10.92.16.10", 5432)))
	if err == nil {
		t.Fatal("two services claimed 10.92.16.10")
	}
	if !strings.Contains(err.Error(), "10.92.16.10") {
		t.Errorf("refusal = %v, want the address that collides", err)
	}
	// Naming the other service would tell a namespace what another namespace runs; the address
	// is enough to act on.
	if strings.Contains(err.Error(), "team-a") {
		t.Errorf("refusal names the other namespace: %v", err)
	}
}

// TestAServiceKeepsItsOwnAddressOnUpdate: the object under review is in the list it is compared
// against, and must not collide with itself.
func TestAServiceKeepsItsOwnAddressOnUpdate(t *testing.T) {
	stored := svcAt("team-a", "api", "10.92.16.10", 8080)
	l := &fakeLister{services: []corev1.Service{*stored}}
	a := addrAttrs(svcAt("team-a", "api", "10.92.16.10", 8080))
	a.Operation, a.OldObject = Update, stored
	if err := (serviceAddress{lister: l}).Validate(context.Background(), a); err != nil {
		t.Fatalf("a service collided with itself: %v", err)
	}
}

// TestANodesAddressIsNotAServices: a node is a service — everything placed on it registers under
// its name, at its address — so a Service claiming that address is the same collision as claiming
// another Service's, and it is also unnecessary: a flat workload there is already published without
// anyone writing the address down.
func TestANodesAddressIsNotAServices(t *testing.T) {
	l := &fakeLister{nodes: []corev1.Node{{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status:     corev1.NodeStatus{IP: "10.0.0.7"},
	}}}
	err := (serviceAddress{lister: l}).Validate(context.Background(), addrAttrs(svcAt("team-a", "api", "10.0.0.7", 443)))
	if err == nil {
		t.Fatal("a service took node-1's own address")
	}
	if !strings.Contains(err.Error(), "node-1") {
		t.Errorf("refusal = %v, want the node named — an operator has to know which host it is", err)
	}
}
