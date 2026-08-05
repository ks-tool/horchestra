package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func vipOf(t *testing.T, v serviceVIP, svc *corev1.Service) string {
	t.Helper()
	if err := v.Admit(context.Background(), &Attributes{Operation: Create, Object: svc}); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	return svc.Spec.ClusterIP
}

// TestNothingIsAllocatedWithoutARange: an address is only as real as whatever answers on it, and a
// deployment that has named no range has said nothing about who that would be. A declared address
// still works — whoever wrote it knows.
func TestNothingIsAllocatedWithoutARange(t *testing.T) {
	v := serviceVIP{lister: &fakeLister{}}
	if got := vipOf(t, v, svcObj("team-a", "api")); got != "" {
		t.Errorf("clusterIP = %q with no --service-cidr, want none", got)
	}
}

// TestVIPIsAllocatedFromTheRangeAndNeverTwice: the allocator's whole state is the addresses
// already in use, so "what is free" is answered by the objects themselves — there is no ledger
// beside them that could leak an address or hand one out twice.
func TestVIPIsAllocatedFromTheRangeAndNeverTwice(t *testing.T) {
	l := &fakeLister{}
	v := serviceVIP{lister: l, cidr: "10.243.0.0/16"}

	first := vipOf(t, v, svcObj("team-a", "api"))
	if first != "10.243.0.1" {
		t.Errorf("first address = %q, want the lowest usable one (the network address is not one)", first)
	}
	// Record it the way storage would, and the next allocation must step over it.
	l.services = append(l.services, corev1.Service{
		ObjectMeta: svcObj("team-a", "api").ObjectMeta,
		Spec:       corev1.ServiceSpec{ClusterIP: first},
	})
	if second := vipOf(t, v, svcObj("team-a", "db")); second == first {
		t.Fatalf("two services were handed %s", second)
	}
}

// TestADeclaredAddressIsNotOverwritten: allocation fills a gap, it does not take the decision back
// from an author who knows where their balancer listens.
func TestADeclaredAddressIsNotOverwritten(t *testing.T) {
	v := serviceVIP{lister: &fakeLister{}, cidr: "10.243.0.0/16"}
	svc := svcObj("team-a", "api")
	svc.Spec.ClusterIP = "10.92.16.10"
	if got := vipOf(t, v, svc); got != "10.92.16.10" {
		t.Errorf("clusterIP = %q, want the declared one", got)
	}
}

// TestANodesAddressIsNeverHandedOut: a workload on the host network is reached at its node's
// address, so node addresses are in the same space — allocating one would put a service in front
// of the node itself.
func TestANodesAddressIsNeverHandedOut(t *testing.T) {
	l := &fakeLister{nodes: []corev1.Node{{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status:     corev1.NodeStatus{IP: "10.243.0.1"},
	}}}
	v := serviceVIP{lister: l, cidr: "10.243.0.0/16"}
	if got := vipOf(t, v, svcObj("team-a", "api")); got == "10.243.0.1" {
		t.Errorf("clusterIP = %q, which is node-1's own address", got)
	}
}

// TestVIPSurvivesAnUpdate: the address belongs to the object for as long as the object lives, so
// an update that says nothing about it carries the stored one over — a merge patch must not be
// able to drop it.
func TestVIPSurvivesAnUpdate(t *testing.T) {
	v := serviceVIP{lister: &fakeLister{}, cidr: "10.243.0.0/16"}
	stored := svcObj("team-a", "api")
	stored.Spec.ClusterIP = "10.243.0.7"
	incoming := svcObj("team-a", "api") // a patch that says nothing about the address

	if err := v.Admit(context.Background(), &Attributes{
		Operation: Update, Object: incoming, OldObject: stored,
	}); err != nil {
		t.Fatal(err)
	}
	if incoming.Spec.ClusterIP != "10.243.0.7" {
		t.Errorf("clusterIP after update = %q, want the stored one carried over", incoming.Spec.ClusterIP)
	}
}

// TestAnExhaustedRangeSaysSo: a refusal a caller can read, never a Service that lands without an
// address and answers to nothing.
func TestAnExhaustedRangeSaysSo(t *testing.T) {
	used := map[string]bool{"10.0.0.1": true, "10.0.0.2": true}
	_, err := firstFree("10.0.0.0/30", used)
	if err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("err = %v, want an exhaustion refusal", err)
	}
	// /30 is network + 2 usable + broadcast: with both usable ones held there is nothing left,
	// and the broadcast address must not be offered as the way out.
	if _, err := firstFree("10.0.0.0/30", map[string]bool{"10.0.0.1": true}); err != nil {
		t.Fatalf("one address still free: %v", err)
	}
}
