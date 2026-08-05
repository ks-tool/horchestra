package network

import (
	"context"
	"fmt"
	"sync"
	"time"

	netdapi "github.com/ks-tool/horchestra/api/netd"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// callTimeout bounds one call. It is short because every verb is a local netlink or map write: a
// call that takes seconds is a helper in trouble, and an agent waiting on it is a reconcile that is
// converging nothing else meanwhile.
const callTimeout = 15 * time.Second

// Netd is the client half of the split-privilege design: the agent, holding nothing, asking the
// helper, holding exactly CAP_NET_ADMIN/CAP_BPF and no generic verb.
//
// The agent DIALS and never listens — the recorded architecture invariant, and the reason the
// helper owns the rendezvous point: a privileged process connecting into a path an unprivileged
// user controls would take its orders from whoever won the race to create it.
//
// It authenticates nothing about the helper and needs to: the socket is in a root-owned directory,
// so reaching it at all is the proof that root put it there. The helper, which has something to
// lose, authenticates the agent by the kernel's own answer (SO_PEERCRED).
type Netd struct {
	// Path is the helper's socket; empty uses the shared default.
	Path string

	mu   sync.Mutex
	conn *grpc.ClientConn
}

// ErrUnavailable reports that the helper cannot be reached at all — a node with no network helper,
// or a unit that failed to start. It is distinct from a refusal ON PURPOSE: "no helper here" is a
// deployment fact an agent reports as a capability it lacks, while "the helper said no" is a
// decision about one request, and a caller that cannot tell them apart cannot report either.
var ErrUnavailable = fmt.Errorf("network helper unavailable")

func (n *Netd) socket() string {
	if n.Path != "" {
		return n.Path
	}
	return netdapi.SocketPath
}

// client returns the shared connection, dialing lazily. grpc.NewClient does not connect eagerly
// and reconnects on its own, so a helper that was restarted is simply reached on the next call —
// which is exactly how the rest of this level-driven agent already behaves, and why there is no
// reconnect state machine here to get wrong.
func (n *Netd) client() (netdapi.NetdServiceClient, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn == nil {
		conn, err := grpc.NewClient("unix://"+n.socket(),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("%w at %s: %w", ErrUnavailable, n.socket(), err)
		}
		n.conn = conn
	}
	return netdapi.NewNetdServiceClient(n.conn), nil
}

// Close releases the connection. The agent holds one for its lifetime; this exists so a test does
// not leak one per case.
func (n *Netd) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn == nil {
		return nil
	}
	err := n.conn.Close()
	n.conn = nil
	return err
}

func (n *Netd) Status(ctx context.Context) (*netdapi.StatusResponse, error) {
	c, err := n.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	st, err := c.Status(ctx, &netdapi.StatusRequest{})
	return st, unavailable(err)
}

// Setup asks the helper to wire the namespace the workload already lives in.
//
// Nothing is created here and nothing is pinned, because nothing can be: entering a network
// namespace needs CAP_SYS_ADMIN in BOTH the owning user namespace and the caller's current one, so
// a namespace made anywhere else is one the workload could never join — measured, EPERM, on both
// arrangements that looked plausible. The sandbox unshares its user namespace and its network
// namespace together and is therefore already inside; what it cannot do is give itself a veth,
// which is what this call is for.
//
// pid is that sandbox, waiting to exec the workload. The helper resolves /proc/<pid>/ns/net and
// refuses a process that is not this agent's own user's — an agent wires its workloads and nothing
// else on the host.
func (n *Netd) Setup(ctx context.Context, workload *netdapi.Workload, pid int) (WorkloadNet, error) {
	c, err := n.client()
	if err != nil {
		return WorkloadNet{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := c.SetupWorkloadNetwork(ctx, &netdapi.SetupWorkloadNetworkRequest{Workload: workload, NetnsPid: int32(pid)})
	if err != nil {
		return WorkloadNet{}, unavailable(err)
	}
	return WorkloadNet{HostInterface: resp.GetHostInterface(), Address: resp.GetAddress()}, nil
}

// Teardown unwires the workload: the helper's half, the veth pair. The namespace itself needs no
// teardown — it lives exactly as long as the workload in it, and dies with the unit.
func (n *Netd) Teardown(ctx context.Context, id string) error {
	c, err := n.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, err = c.TeardownWorkloadNetwork(ctx, &netdapi.TeardownWorkloadNetworkRequest{Id: id})
	return unavailable(err)
}

// Configure replaces the node's forwarding state. Two calls rather than one because they are two
// maps, and a single call taking both would have to answer what "half applied" means. Routes go
// first: a service backend that is not yet routable is a connection that fails, while a route to
// nothing is inert.
func (n *Netd) Configure(ctx context.Context, routes []*netdapi.Route, services []*netdapi.ServiceRule) error {
	c, err := n.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, err := c.ProgramRoutes(ctx, &netdapi.ProgramRoutesRequest{Routes: routes}); err != nil {
		return unavailable(err)
	}
	_, err = c.ProgramServices(ctx, &netdapi.ProgramServicesRequest{Services: services})
	return unavailable(err)
}

// GC reclaims every network the agent no longer names. keep may be empty — a node running nothing
// is an ordinary state — and the proto carries it as a list either way, so there is no "absent"
// that could read as "reclaim everything".
// GC reclaims what the agent no longer names: the helper's host-side interfaces. keep may be empty
// — a node running nothing is an ordinary state — and the proto carries it as a list either way, so
// there is no "absent" that could read as "reclaim everything". There are no namespaces to reclaim:
// each one lives exactly as long as the workload in it.
func (n *Netd) GC(ctx context.Context, keep []string) error {
	c, err := n.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, err = c.GC(ctx, &netdapi.GCRequest{Keep: keep})
	return unavailable(err)
}

// unavailable turns "there is no helper" into ErrUnavailable and leaves every other failure as the
// helper's own words. The distinction is what lets the agent report a node without a datapath as a
// capability it lacks rather than as an error it hit.
func unavailable(err error) error {
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.Unavailable {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return err
}
