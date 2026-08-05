package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func svcObj(ns, name string) *corev1.Service {
	return &corev1.Service{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
	}
}

func appJoining(ns, name, service string) *corev1.Application {
	return &corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.ApplicationSpec{Image: "reg/x:v1", ServiceName: service},
	}
}

// TestServiceRefMustExist: membership is declared by the instance, which is what keeps a Service
// from asserting anything about a fleet it cannot see — but an unchecked declaration is a typo
// that yields a workload in no catalog, reachable by nothing, looking perfectly healthy.
func TestServiceRefMustExist(t *testing.T) {
	l := &fakeLister{services: []corev1.Service{*svcObj("team-a", "api")}}

	if err := checkServiceRef(context.Background(), &Attributes{Operation: Create,
		Object: appJoining("team-a", "web", "api")}, l); err != nil {
		t.Errorf("joining an existing service must be allowed: %v", err)
	}
	err := checkServiceRef(context.Background(), &Attributes{Operation: Create,
		Object: appJoining("team-a", "web", "typo")}, l)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("joining a service that does not exist = %v, want a refusal", err)
	}
	// A namespace is a boundary here too: the service exists, but not for this caller's namespace.
	if err := checkServiceRef(context.Background(), &Attributes{Operation: Create,
		Object: appJoining("team-b", "web", "api")}, l); err == nil {
		t.Error("an application joined a service in another namespace")
	}
	// Joining nothing is a normal thing to be — the edge itself is reached, not reaching.
	if err := checkServiceRef(context.Background(), &Attributes{Operation: Create,
		Object: appJoining("team-a", "edge", "")}, l); err != nil {
		t.Errorf("an application in no service must be allowed: %v", err)
	}
}

// TestServiceProtection: the address belongs to the object and dies with it, so deleting a
// Service out from under its members would take the name and the VIP from workloads that are
// still running and still expect to be reachable by them.
func TestServiceProtection(t *testing.T) {
	l := &fakeLister{
		services: []corev1.Service{*svcObj("team-a", "api")},
		apps:     []corev1.Application{*appJoining("team-a", "web", "api")},
	}

	err := checkServiceProtection(context.Background(), &Attributes{Operation: Delete,
		Object: svcObj("team-a", "api")}, l)
	if err == nil || !strings.Contains(err.Error(), "still declared") {
		t.Errorf("deleting a service with members = %v, want a refusal", err)
	}
	if err := checkServiceProtection(context.Background(), &Attributes{Operation: Delete,
		Object: svcObj("team-a", "unused")}, l); err != nil {
		t.Errorf("deleting a service nobody declares must be allowed: %v", err)
	}
}
