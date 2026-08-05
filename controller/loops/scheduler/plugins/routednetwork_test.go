package plugins

import (
	"context"
	"testing"

	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func nodeWithRouting(name string, routed bool) *framework.NodeInfo {
	return &framework.NodeInfo{Node: corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     corev1.NodeStatus{Ready: true, RoutedNetwork: routed},
	}}
}

// TestIsolationIsPlacedWhereItCanBeGiven: without this the placement is made on capacity alone and
// the refusal happens on the node — a failure at the far end of the system from the decision that
// caused it, which an operator has to correlate back by hand.
func TestIsolationIsPlacedWhereItCanBeGiven(t *testing.T) {
	isolated := false
	app := &corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "team-a"},
		Spec:       corev1.ApplicationSpec{Image: "reg/api:v1", HostNetwork: &isolated},
	}
	p := NewRoutedNetwork()

	if st := p.Filter(context.Background(), nil, app, nodeWithRouting("wired", true)); st != nil {
		t.Errorf("a node that can wire one was filtered out: %v", st)
	}
	st := p.Filter(context.Background(), nil, app, nodeWithRouting("bare", false))
	if st == nil {
		t.Fatal("a node with no helper was offered an isolated workload")
	}
	if st.Message() == "" {
		t.Error("the refusal must say what is missing; a bare Unschedulable is unactionable")
	}
}

// TestHostNetworkFitsEverywhere: every workload on a fleet that runs no helper is this one, so the
// filter has to be silent there by construction rather than by a flag somebody remembers to set.
func TestHostNetworkFitsEverywhere(t *testing.T) {
	app := &corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Name: "flat", Namespace: "team-a"},
		Spec:       corev1.ApplicationSpec{Image: "reg/x:v1"},
	}
	if st := NewRoutedNetwork().Filter(context.Background(), nil, app, nodeWithRouting("bare", false)); st != nil {
		t.Errorf("a host-network workload was refused a node: %v", st)
	}
}
