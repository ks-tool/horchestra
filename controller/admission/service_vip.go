package admission

import (
	"context"
	"net/netip"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DefaultServiceCIDR is the range addresses are cut from when an operator turns allocation on
// without naming one. It is deliberately not Kubernetes' 10.96.0.0/12: a fleet is likely to sit
// beside a Kubernetes cluster, and two control planes handing out the same addresses on the same
// wire is the sort of thing that is discovered from a routing table at 3am.
const DefaultServiceCIDR = "10.243.0.0/16"

// serviceVIP fills in a Service's address when its author left it empty — and only where a
// deployment has said which addresses are its to hand out (--service-cidr; empty means no
// allocation at all).
//
// The switch exists because an allocated address is real only where something translates it
// without anything binding it: that is the eBPF socket-LB, which rewrites (clusterIP, port) at
// connect(). A declared address needs no such backing — whoever wrote it knows what answers there —
// which is why declaring works in every mode and allocating is the one that waits for a range to be
// named.
//
// There is no allocation table, and that is the point: the set of addresses in use IS the set
// recorded on the live Services, plus the addresses the fleet's Nodes already answer on. A restart
// re-reads the same answer, a deleted Service frees its address by ceasing to exist, and there is
// no second record that can leak or disagree with the first. The alternative — a ledger beside the
// objects — has to be reconciled against them, and every bug in that reconciliation is either a
// leaked address or one handed out twice.
//
// It runs at CREATE, because an address assigned later would mean a window in which a Service
// exists, is published, and answers to nothing. At update it carries the stored value over when the
// incoming object does not mention one, so a patch that never names the address cannot drop it.
type serviceVIP struct {
	lister Lister
	cidr   string
}

func (serviceVIP) Validate(context.Context, *Attributes) error { return nil }

func (v serviceVIP) Admit(ctx context.Context, a *Attributes) error {
	svc, ok := a.Object.(*corev1.Service)
	if !ok || v.lister == nil || v.cidr == "" {
		return nil
	}
	switch a.Operation {
	case Update:
		// The address belongs to the object for as long as the object lives. An author may move
		// it — a balancer moves — but silence is not a move: a merge patch that never mentions the
		// address must not be able to drop one that was allocated.
		if svc.Spec.ClusterIP != "" {
			return nil
		}
		if old, ok := a.OldObject.(*corev1.Service); ok {
			svc.Spec.ClusterIP = old.Spec.ClusterIP
		}
		return nil
	case Create:
		if svc.Spec.ClusterIP != "" {
			return nil // declared: the author knows what answers there
		}
		used, err := v.inUse(ctx)
		if err != nil {
			return err
		}
		addr, err := firstFree(v.cidr, used)
		if err != nil {
			return err
		}
		svc.Spec.ClusterIP = addr
	}
	return nil
}

// inUse is every address the cluster already answers on: those recorded on live Services and those
// the Nodes hold. Node addresses are in the same space now that a workload on the host network is
// reachable at its node's address — handing one out as a service address would put a service in
// front of the node itself.
func (v serviceVIP) inUse(ctx context.Context) (map[string]bool, error) {
	used := map[string]bool{}
	services, err := v.lister.List(ctx, resourceMeta("Service"), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, obj := range services {
		if svc, ok := obj.(*corev1.Service); ok && svc.Spec.ClusterIP != "" {
			used[svc.Spec.ClusterIP] = true
		}
	}
	nodes, err := v.lister.List(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, obj := range nodes {
		if n, ok := obj.(*corev1.Node); ok && n.Status.IP != "" {
			used[n.Status.IP] = true
		}
	}
	return used, nil
}

// firstFree returns the lowest address of cidr that nothing holds. The network address itself is
// skipped, as is the broadcast address of an IPv4 range — neither is usable, and handing one out
// would produce a service that is unreachable for reasons no operator would think to look for.
func firstFree(cidr string, used map[string]bool) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", Forbidden("service range %q is not a CIDR: %v", cidr, err)
	}
	prefix = prefix.Masked()
	last := lastAddr(prefix)
	for a := prefix.Addr().Next(); prefix.Contains(a); a = a.Next() {
		if a.Is4() && a == last {
			break // the broadcast address is not an address
		}
		if !used[a.String()] {
			return a.String(), nil
		}
	}
	return "", Forbidden("the service range %s is exhausted — %d addresses are in use; widen it or delete services that are gone",
		cidr, len(used))
}

// lastAddr is the highest address inside prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	b := prefix.Addr().As16()
	bits := prefix.Addr().BitLen()
	for i := prefix.Bits(); i < bits; i++ {
		octet := (16 - bits/8) + i/8
		b[octet] |= 1 << (7 - i%8)
	}
	a := netip.AddrFrom16(b)
	if prefix.Addr().Is4() {
		return a.Unmap()
	}
	return a
}
