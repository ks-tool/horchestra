package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func svcWith(ports ...corev1.ServicePort) *Attributes {
	return &Attributes{Operation: Create, Object: &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "api"},
		Spec:       corev1.ServiceSpec{Ports: ports},
	}}
}

// TestServiceShape locks the rules the input schema cannot state, because each is about the ports
// as a SET rather than about any one of them.
func TestServiceShape(t *testing.T) {
	for _, tc := range []struct {
		name string
		attr *Attributes
		want string // substring of the refusal; empty means accepted
	}{
		{"one unnamed port", svcWith(corev1.ServicePort{Port: 80}), ""},
		{"two named ports", svcWith(
			corev1.ServicePort{Name: "http", Port: 80},
			corev1.ServicePort{Name: "metrics", Port: 9090}), ""},
		{"no ports at all", svcWith(), "answers nothing"},
		{"a second port with no name", svcWith(
			corev1.ServicePort{Name: "http", Port: 80},
			corev1.ServicePort{Port: 9090}), "must name each of them"},
		{"a name that is not addressable", svcWith(
			corev1.ServicePort{Name: "HTTP_Main", Port: 80},
			corev1.ServicePort{Name: "metrics", Port: 9090}), "DNS-1123"},
		{"one name twice", svcWith(
			corev1.ServicePort{Name: "http", Port: 80},
			corev1.ServicePort{Name: "http", Port: 9090}), "used twice"},
		{"one port number twice", svcWith(
			corev1.ServicePort{Name: "http", Port: 80},
			corev1.ServicePort{Name: "alt", Port: 80}), "declared twice"},
		{"the instance's port said twice", svcWith(
			corev1.ServicePort{Port: 80, TargetName: "web", TargetPort: 8080}), "keep one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := servicePolicy{}.Validate(context.Background(), tc.attr)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("a well-formed service was refused: %v", err)
			case tc.want != "" && err == nil:
				t.Errorf("accepted, want a refusal mentioning %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Errorf("refusal = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestAServiceMayNotTakeANodesName: the catalog registers what runs on a node under that node's
// name, so the two share one namespace of names — and a collision would MERGE the entries rather
// than shadow them, handing a consumer the service's instances plus whatever else runs on that host.
func TestAServiceMayNotTakeANodesName(t *testing.T) {
	l := &fakeLister{nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}}}
	p := servicePolicy{lister: l}

	err := p.Validate(context.Background(), addrAttrs(svcAt("team-a", "node-1", "", 8080)))
	if err == nil {
		t.Fatal("a Service took a node's name")
	}
	// The named-port suffix is the name a consumer actually resolves, so it is checked too.
	svc := svcAt("team-a", "node", "", 8080)
	svc.Spec.Ports[0].Name = "1"
	if err := p.Validate(context.Background(), addrAttrs(svc)); err == nil {
		t.Error("a Service whose catalog name is node-1 (name + port) was accepted")
	}
	if err := p.Validate(context.Background(), addrAttrs(svcAt("team-a", "api", "", 8080))); err != nil {
		t.Errorf("an ordinary name was refused: %v", err)
	}
}
