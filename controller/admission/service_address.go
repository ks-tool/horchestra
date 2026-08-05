package admission

import (
	"context"
	"net/netip"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// serviceAddress checks the address a Service carries: that it is one, and that it is nobody
// else's. It checks both the declared and the allocated kind, which is what keeps the two from
// disagreeing — the allocator skips what is in use, and this refuses what it did not skip.
//
// A cluster address is UNIQUE cluster-wide, the address itself and not (address, port). Sharing one
// IP between services and separating them by port is a thing a single balancer can do, but it makes
// the address stop identifying the service: a name no longer resolves to a place, only to half of
// one, and everything downstream that wants to say "this service is at X" — DNS, a datapath map, an
// operator reading a status — has to carry the port to mean anything. One address, one service is
// the invariant those consumers can be written against.
//
// The check spans namespaces because an address does: an IP is a fleet-wide fact and a namespace
// confers no protection from another namespace's binding. The refusal deliberately does not name
// the other service — the collision is enough to act on, and the address is being taken by someone
// who may not be allowed to see the rest of the fleet.
type serviceAddress struct {
	lister Lister
}

func (serviceAddress) Admit(context.Context, *Attributes) error { return nil }

func (s serviceAddress) Validate(ctx context.Context, a *Attributes) error {
	svc, ok := serviceUnderReview(a)
	if !ok || svc.Spec.ClusterIP == "" {
		return nil
	}
	addr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		return Forbidden("spec.clusterIP: %q is not an IP address", svc.Spec.ClusterIP)
	}
	if addr.IsUnspecified() {
		// 0.0.0.0 is what a process BINDS to mean "every address"; as a destination it is not one,
		// so a client handed it has nowhere to connect.
		return Forbidden("spec.clusterIP: %s is not an address a caller can connect to", addr)
	}
	if addr.IsMulticast() {
		return Forbidden("spec.clusterIP: %s is a multicast address — a service answers one caller, not a group", addr)
	}
	if s.lister == nil {
		return nil
	}
	if err := s.notANodes(ctx, addr); err != nil {
		return err
	}
	return s.notTaken(ctx, svc, addr)
}

// notANodes refuses a node's own address.
//
// A node IS a service — everything placed on it registers under its name, at its address — so
// claiming that address for a Service is the same collision as claiming another Service's, and it
// is also unnecessary: a flat workload on that node is already published there without anyone
// writing the address down. The allocator skips these too, from the same list.
func (s serviceAddress) notANodes(ctx context.Context, addr netip.Addr) error {
	nodes, err := s.lister.List(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, obj := range nodes {
		n, ok := obj.(*corev1.Node)
		if !ok || n.Status.IP == "" {
			continue
		}
		if got, err := netip.ParseAddr(n.Status.IP); err == nil && got.Unmap() == addr.Unmap() {
			return Forbidden("spec.clusterIP: %s is node %q's own address, and the catalog already publishes "+
				"what runs there under the node's name — a service cannot take it as well", addr, n.Name)
		}
	}
	return nil
}

// notTaken refuses an address another Service already carries.
func (s serviceAddress) notTaken(ctx context.Context, svc *corev1.Service, addr netip.Addr) error {
	list, err := s.lister.List(ctx, resourceMeta("Service"), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, obj := range list {
		other, ok := obj.(*corev1.Service)
		if !ok || other.Spec.ClusterIP == "" {
			continue
		}
		if other.Namespace == svc.Namespace && other.Name == svc.Name {
			continue // itself, on an update
		}
		// Compared as parsed addresses so two spellings of one address (10.0.0.1 and
		// ::ffff:10.0.0.1) cannot both be claimed.
		got, err := netip.ParseAddr(other.Spec.ClusterIP)
		if err != nil || got.Unmap() != addr.Unmap() {
			continue
		}
		return Forbidden("spec.clusterIP: %s is already the address of another service — "+
			"a cluster address identifies one service, so the second would be reachable only by port", addr)
	}
	return nil
}
