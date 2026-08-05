package admission

import (
	"context"
	"fmt"
	"regexp"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// dns1123Label is what a port name has to be: it becomes part of the catalog's service name
// (`<service>-<port>`), which clients resolve and route by, so a name that is not addressable
// there is a name that produces an entry nobody can reach.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// serviceUnderReview returns the Service being written, or false for anything else — a deletion
// and a subresource write carry no shape to check.
func serviceUnderReview(a *Attributes) (*corev1.Service, bool) {
	if a.Operation == Delete || a.IsSubresource() {
		return nil, false
	}
	svc, ok := a.Object.(*corev1.Service)
	return svc, ok
}

// servicePolicy validates a Service's shape — the rules the input schema cannot state because
// they are about the ports as a SET rather than about any one of them, or about the name against
// the rest of the fleet.
type servicePolicy struct {
	lister Lister
}

func (servicePolicy) Admit(context.Context, *Attributes) error { return nil }

func (s servicePolicy) Validate(ctx context.Context, a *Attributes) error {
	svc, ok := serviceUnderReview(a)
	if !ok {
		return nil
	}
	if err := s.notANodeName(ctx, svc); err != nil {
		return err
	}
	if len(svc.Spec.Ports) == 0 {
		return fmt.Errorf("spec.ports: a service with no ports answers nothing — it would be a name and an address that refuse every connection")
	}
	named := len(svc.Spec.Ports) > 1
	seenName := map[string]bool{}
	seenPort := map[int32]bool{}
	for i, p := range svc.Spec.Ports {
		switch {
		case named && p.Name == "":
			// The catalog splits service names per port, so an unnamed second port has nothing
			// to be called and would collide with the first under the service's own name.
			return fmt.Errorf("spec.ports[%d].name: a service with more than one port must name each of them — the catalog registers one service name per port", i)
		case p.Name != "" && !dns1123Label.MatchString(p.Name):
			return fmt.Errorf("spec.ports[%d].name: %q is not a DNS-1123 label — it becomes part of the catalog name clients resolve", i, p.Name)
		case p.Name != "" && seenName[p.Name]:
			return fmt.Errorf("spec.ports[%d].name: %q is used twice — two ports would register under one catalog name", i, p.Name)
		case seenPort[p.Port]:
			return fmt.Errorf("spec.ports[%d].port: %d is declared twice — the datapath resolves (clusterIP, port) to one backend set and could not choose", i, p.Port)
		case p.TargetName != "" && p.TargetPort != 0:
			// One of them is dead text, and which one is dead is not obvious from reading the
			// manifest. Refused rather than silently precedence-ordered.
			return fmt.Errorf("spec.ports[%d]: targetName and targetPort both name the instance's port — keep one", i)
		}
		seenName[p.Name] = true
		seenPort[p.Port] = true
	}
	return nil
}

// notANodeName refuses a Service whose catalog name is a node's.
//
// The catalog registers everything placed on a node under that node's name — that is what makes a
// flat workload discoverable without a Service of its own — so the two share one namespace of
// names. A Service that took a node's name would not shadow it: the entries would MERGE, and a
// consumer building one backend would get the service's instances and whatever else happens to run
// on that host. The port suffix a named port adds is checked too, since that is the name a consumer
// actually resolves.
func (s servicePolicy) notANodeName(ctx context.Context, svc *corev1.Service) error {
	if s.lister == nil {
		return nil
	}
	nodes, err := s.lister.List(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, obj := range nodes {
		n, ok := obj.(*corev1.Node)
		if !ok {
			continue
		}
		for _, p := range svc.Spec.Ports {
			if svc.CatalogName(p) == n.Name {
				return Forbidden("metadata.name: %q is a node's name, and the catalog registers what runs on a node under it — "+
					"the two would merge into one service", n.Name)
			}
		}
	}
	return nil
}
