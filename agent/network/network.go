// Package network is the agent's network port: the seam between "this workload wants a network"
// and whoever can actually give it one.
//
// It exists because the agent CANNOT. It holds no capability, and a user namespace grants none of
// the ones this needs: creating a veth into the host's namespace wants CAP_NET_ADMIN there, and
// `bpf()` is gated on capabilities in the INITIAL user namespace — with the distro default
// `kernel.unprivileged_bpf_disabled=2`, even a map update needs CAP_BPF. There is no rootless
// arrangement of the agent that changes any of that. So the network is not something the agent
// does; it is something the agent ASKS FOR, and this package is the asking.
//
// Two implementations, and the honest one is the default: Host, which reports that a workload uses
// the node's own namespace because that is what happens today, and Netd, which speaks to the
// privileged helper. Nothing here has an opinion about eBPF — the datapath lives entirely on the
// far side of the seam, which is what lets the node run without one and say so.
package network

import (
	"context"

	netdapi "github.com/ks-tool/horchestra/api/netd"
)

// Network is what the agent asks of whatever provides node networking.
//
// The verbs are deliberately few and total: a workload's network is set up or torn down, the
// node's forwarding state is REPLACED wholesale, and everything the agent no longer names is
// reclaimed. There is no "apply this" and no delta — a delta would need both sides to agree about
// what was applied before, which is the second record this design refuses to keep.
type Network interface {
	// Status is what this node can actually do, asked before anything is promised.
	Status(ctx context.Context) (*netdapi.StatusResponse, error)
	// Setup gives one workload a network namespace and returns the handle the sandbox joins.
	// Idempotent: asked twice for the same workload it answers with the same namespace.
	Setup(ctx context.Context, wl *netdapi.Workload, pid int) (WorkloadNet, error)
	// Teardown reclaims one workload's network.
	Teardown(ctx context.Context, id string) error
	// Configure replaces the node's whole forwarding state: where workload addresses live, and what
	// the datapath balances onto.
	Configure(ctx context.Context, routes []*netdapi.Route, services []*netdapi.ServiceRule) error
	// GC reclaims every network the agent no longer names. keep may be empty — a node running
	// nothing is an ordinary state.
	GC(ctx context.Context, keep []string) error
}

// WorkloadNet is one workload's network as the agent knows it: the namespace handle the sandbox joins,
// and the node-side interface an operator can find it by. An EMPTY NetnsPath is the host network —
// not an error and not a failure, but the ordinary answer on a node with no helper.
type WorkloadNet struct {
	NetnsPath     string
	HostInterface string
	Address       string
}

// Host is the network every workload has today: the node's own. It is not a stub — it is the
// truthful implementation of "there is no workload network here", and it is what a fleet that will run
// no privileged unit keeps running forever. Setup gives back an empty handle, which the caller
// reads as "share the node's namespace"; there is nothing to reclaim, so teardown and GC succeed
// by doing nothing rather than by pretending.
type Host struct{}

func (Host) Status(context.Context) (*netdapi.StatusResponse, error) {
	return &netdapi.StatusResponse{
		RoutedNetwork: false,
		Datapath:      false,
		Reason:        "this node has no network helper: every workload runs in the host's network namespace",
	}, nil
}

// Setup on the host network is a no-op with an empty handle. It is NOT an error: a workload on the
// host network is the ordinary case, and returning one here would make every reconcile fail on a
// node that is working exactly as configured.
func (Host) Setup(context.Context, *netdapi.Workload, int) (WorkloadNet, error) {
	return WorkloadNet{}, nil
}

func (Host) Teardown(context.Context, string) error { return nil }

func (Host) Configure(context.Context, []*netdapi.Route, []*netdapi.ServiceRule) error { return nil }

func (Host) GC(context.Context, []string) error { return nil }
