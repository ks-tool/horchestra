//go:build linux

package netd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	netdapi "github.com/ks-tool/horchestra/api/netd"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Handler is the helper's half of the network: it wires the namespace a workload already lives in,
// and reclaims what it wired.
//
// Nobody hands a namespace to anybody, because the kernel does not allow it. setns into a network
// namespace requires CAP_SYS_ADMIN in BOTH the user namespace that owns it and the caller's
// CURRENT one — measured on a live kernel, twice: an unprivileged process cannot enter a
// root-created namespace, and cannot enter one owned by its own user's namespace either. The only
// arrangement where nothing has to enter is the one where the process that will live there creates
// it: the sandbox unshares a user namespace and a network namespace together, and this helper —
// root, holding CAP_SYS_ADMIN in an ancestor — reaches in.
//
// It keeps NO record of what it did. The host-side interfaces ARE the state: they are named by a
// digest of the workload id, so the same workload always maps to the same name, a reboot clears
// everything with the network stack, and the agent's keep-list is the only authority on what
// should still exist. The namespaces need no record at all — each one lives exactly as long as the
// workload in it.
type Handler struct {
	netdapi.UnimplementedNetdServiceServer

	// Link wires a namespace: the veth pair, the address, the routes. Without one this helper
	// cannot deliver a workload network and says so rather than accepting calls it would half-answer.
	Link Linker
	// Datapath is the loaded eBPF half, nil on a node where it could not be loaded. A ClusterIP
	// answers only where this is set.
	Datapath *SockLB
	// Forward is the other half: where a workload address lives. Without it a workload reaches its
	// own node and nothing beyond it.
	Forward *Forwarder
	// DatapathReason is why Datapath is nil, in the words an operator needs — the error from the
	// load attempt itself, so what Status reports is what actually happened rather than a guess
	// made later from a different question.
	DatapathReason string
	// Version is what Status reports, for an operator staring at a version mismatch.
	Version string
}

// Linker is the layer that makes a namespace usable. An interface because the datapath's own
// version of it (an eBPF-programmed link rather than a plain veth) is a later slice, and naming
// the seam keeps SetupWorkloadNetwork from being written twice.
type Linker interface {
	Attach(ctx context.Context, workload *netdapi.Workload, netnsPath string) (Wiring, error)
	Detach(ctx context.Context, id string) error
	// HostInterface is the node-side name for a workload, computed and never remembered — the
	// same workload has to map to the same interface after a restart.
	HostInterface(id string) string
	// Interfaces is everything this linker has wired, read back out of the kernel — the record the
	// datapath is rebuilt from after a restart, since the interfaces and the routes are the only
	// record there is.
	Interfaces() ([]Wiring, error)
	// Reclaim removes the host-side ends of every workload not named in keep.
	Reclaim(ctx context.Context, keep []string) error
}

// Wiring is what a Linker made, and it exists because the datapath needs a fact the wiring alone
// knows: which interface to put a packet into for this address. It no longer carries the MAC the
// namespace will accept — that is derived from the address now, by both sides, and deriving it is
// what let this stop being a value read from inside a namespace and carried back out.
type Wiring struct {
	Interface string
	Index     int
	Address   netip.Addr
}

// Status reports what this host can actually do — asked of the kernel, never inferred from the
// fact that this code exists. An agent that learns the workload network is unavailable keeps its
// workloads on the host network and says so; the failure this prevents is a workload started in a
// namespace with no way out, which looks like a hung application rather than a missing feature.
func (h *Handler) Status(context.Context, *netdapi.StatusRequest) (*netdapi.StatusResponse, error) {
	st := &netdapi.StatusResponse{Version: h.Version}
	if h.Link == nil {
		st.Reason = "this helper has no link layer: it cannot give a namespace an address"
		return st, nil
	}
	if missing := missingCaps(); missing != "" {
		// A unit file with an AmbientCapabilities typo reports this once, instead of failing one
		// workload at a time for the rest of the node's life.
		st.Reason = "this helper is missing " + missing + ": it cannot wire a namespace"
		return st, nil
	}
	st.RoutedNetwork = true
	// The datapath is a separate fact: a host may have namespaces and no BTF. It is TWO programs
	// and both are named, because they fail apart and an operator chasing one of them should not
	// have to guess which is missing.
	switch {
	case h.Datapath == nil && h.Forward == nil:
		st.Reason = "the eBPF datapath is not loaded: a ClusterIP has nothing answering on it, " +
			"and workload addresses are reachable on this node only"
	case h.Datapath == nil:
		st.Reason = "the service half of the datapath is not loaded: a ClusterIP has nothing answering on it"
	case h.Forward == nil:
		st.Reason = "the forwarding half of the datapath is not loaded: workload addresses are reachable on this node only"
	default:
		st.Datapath = true
		return st, nil
	}
	if h.DatapathReason != "" {
		st.Reason += " (" + h.DatapathReason + ")"
	}
	return st, nil
}

func (h *Handler) SetupWorkloadNetwork(ctx context.Context, req *netdapi.SetupWorkloadNetworkRequest) (*netdapi.SetupWorkloadNetworkResponse, error) {
	workload := req.GetWorkload()
	if workload == nil || workload.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "no workload")
	}
	if h.Link == nil {
		// Refusing beats wiring nothing: a workload would start, isolated, and fail every
		// connection with a timeout nobody can trace back to here.
		return nil, status.Error(codes.FailedPrecondition, "this helper cannot give a namespace an address; "+
			"run the workload on the host network")
	}
	ns, err := h.netnsOfPeer(ctx, req.GetNetnsPid())
	if err != nil {
		return nil, err
	}
	defer func() { _ = ns.Close() }()
	// What the workload may actually carry, decided here because this is where both numbers are
	// known: the node's uplink MTU and whether its traffic is encapsulated. A workload given the
	// full 1500 on an overlay learns the difference from a TLS handshake that hangs.
	if h.Forward != nil {
		workload.Mtu = h.Forward.WorkloadMTU(workload.GetMtu())
	}
	// The namespace is named by this helper's OWN descriptor from here on, so nothing downstream
	// can be redirected by a pid that changed hands in the meantime.
	wiring, err := h.Link.Attach(ctx, workload, fmt.Sprintf("/proc/self/fd/%d", ns.Fd()))
	if err != nil {
		// Leave nothing half-wired: the next pass should find either a working namespace or an
		// empty one, never a pair with an address on one end.
		_ = h.Link.Detach(ctx, workload.GetId())
		return nil, fmt.Errorf("attach %s: %w", workload.GetId(), err)
	}
	// The datapath learns where this address lives from the wiring itself — the only thing that
	// knows. It is not fatal: a node whose datapath is absent still has a wired workload that
	// reaches its own node, and Status is where that shortfall is reported, once, rather than here
	// per workload.
	if h.Forward != nil {
		if err := h.Forward.Attach(wiring.Interface); err != nil {
			return nil, fmt.Errorf("attach the datapath to %s: %w", wiring.Interface, err)
		}
		if err := h.Forward.Local(wiring.Address, wiring.Index); err != nil {
			return nil, fmt.Errorf("record %s in the datapath: %w", wiring.Address, err)
		}
	}
	return &netdapi.SetupWorkloadNetworkResponse{
		HostInterface: wiring.Interface,
		Address:       workload.GetAddress(),
	}, nil
}

// Rewire rebuilds the datapath from what the node still has. It is called at startup and is what
// replaces a pin under /sys/fs/bpf: the programs and their attachments died with the previous
// process, the interfaces and the routes did not, and rebuilding from what exists needs no second
// record to be kept correct.
//
// It restores BOTH halves, and the second one is the half a stand had to teach: the attachments
// alone are not enough. A workload's own entry in the table is written by SetupWorkloadNetwork, and
// that runs once, when the workload starts — it does not run again for a workload that is already
// running, and the control plane's push deliberately does not touch the local half either. So a
// helper that only re-attached came back with an empty local table and a node that had quietly
// stopped delivering to its own workloads, while reporting a loaded datapath. Measured, not
// reasoned: the ClusterIP and the workload-to-workload dial both went silent after a netd restart.
func (h *Handler) Rewire() error {
	if h.Forward == nil || h.Link == nil {
		return nil
	}
	wired, err := h.Link.Interfaces()
	if err != nil {
		return err
	}
	var errs []error
	names := make([]string, 0, len(wired))
	for _, w := range wired {
		names = append(names, w.Interface)
	}
	// Attachments left pinned for interfaces this node no longer has: a workload torn down while
	// netd was DOWN leaves one, because a pin outlives the process that made it.
	if err := h.Forward.ReclaimPins(names); err != nil {
		errs = append(errs, fmt.Errorf("reclaim stale attachments: %w", err))
	}
	// And the addresses of workloads that went the same way. Both are the same fact one level
	// apart: what this node still has is what it still wires.
	live := make(map[int]struct{}, len(wired))
	for _, w := range wired {
		live[w.Index] = struct{}{}
	}
	if err := h.Forward.ReclaimLocal(live); err != nil {
		errs = append(errs, fmt.Errorf("reclaim stale addresses: %w", err))
	}
	for _, w := range wired {
		if err := h.Forward.Attach(w.Interface); err != nil {
			errs = append(errs, fmt.Errorf("attach the datapath to %s: %w", w.Interface, err))
			continue
		}
		if !w.Address.IsValid() {
			continue // half-wired: on the datapath, but with no address to claim
		}
		if err := h.Forward.Local(w.Address, w.Index); err != nil {
			errs = append(errs, fmt.Errorf("restore %s behind %s: %w", w.Address, w.Interface, err))
		}
	}
	return errors.Join(errs...)
}

func (h *Handler) TeardownWorkloadNetwork(ctx context.Context, req *netdapi.TeardownWorkloadNetworkRequest) (*netdapi.TeardownWorkloadNetworkResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "no workload id")
	}
	if h.Link == nil {
		return &netdapi.TeardownWorkloadNetworkResponse{}, nil // nothing was ever wired
	}
	// The datapath first, while the interface still exists to be named: an address left in the map
	// pointing at an ifindex the kernel has reused is a packet delivered to somebody else's veth.
	h.forget(h.Link.HostInterface(req.GetId()))
	return &netdapi.TeardownWorkloadNetworkResponse{}, h.Link.Detach(ctx, req.GetId())
}

// forget takes one interface out of the datapath: the address it delivered to, and the attachment
// itself. Both are looked up from the interface, which is the only handle a teardown carries.
func (h *Handler) forget(iface string) {
	if h.Forward == nil {
		return
	}
	if dev, err := net.InterfaceByName(iface); err == nil {
		_ = h.Forward.Forget(dev.Index)
	}
	h.Forward.Detach(iface)
}

// GC reclaims the host-side end of every workload the agent no longer names. The keep list is the
// whole authority — this helper holds no opinion about what should exist, which is what stops it
// from disagreeing with the control plane that does.
func (h *Handler) GC(ctx context.Context, req *netdapi.GCRequest) (*netdapi.GCResponse, error) {
	if h.Link == nil {
		return &netdapi.GCResponse{}, nil
	}
	// The datapath is swept from the same keep list and BEFORE the interfaces go, for the reason
	// teardown gives: an ifindex outlives nothing, and a stale one is a delivery to whatever
	// inherits the number.
	if h.Forward != nil {
		keep := make(map[string]struct{}, len(req.GetKeep()))
		for _, id := range req.GetKeep() {
			keep[h.Link.HostInterface(id)] = struct{}{}
		}
		present, err := h.Link.Interfaces()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read this node's interfaces: %v", err)
		}
		for _, w := range present {
			if _, ok := keep[w.Interface]; !ok {
				h.forget(w.Interface)
			}
		}
	}
	return &netdapi.GCResponse{}, h.Link.Reclaim(ctx, req.GetKeep())
}

// ProgramRoutes replaces the node's whole view of where workload addresses live. It refuses on a
// node with no forwarding datapath rather than accepting silently: an agent that believed its
// routes were programmed would report a converged node whose workloads reach nothing but it.
func (h *Handler) ProgramRoutes(_ context.Context, req *netdapi.ProgramRoutesRequest) (*netdapi.ProgramRoutesResponse, error) {
	if h.Forward == nil {
		msg := "no datapath: routes cannot be programmed on this node"
		if h.DatapathReason != "" {
			msg += " (" + h.DatapathReason + ")"
		}
		return nil, status.Error(codes.FailedPrecondition, msg)
	}
	if err := h.Forward.Routes(req.GetRoutes()); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &netdapi.ProgramRoutesResponse{}, nil
}

// ProgramServices replaces the datapath's whole service table. It refuses on a node with no
// datapath rather than accepting silently, for the reason above: a ClusterIP that was never
// programmed fails at connect time, on the workload, far from here.
func (h *Handler) ProgramServices(_ context.Context, req *netdapi.ProgramServicesRequest) (*netdapi.ProgramServicesResponse, error) {
	if h.Datapath == nil {
		msg := "no datapath: services cannot be programmed on this node"
		if h.DatapathReason != "" {
			msg += " (" + h.DatapathReason + ")"
		}
		return nil, status.Error(codes.FailedPrecondition, msg)
	}
	if err := h.Datapath.Services(req.GetServices()); err != nil {
		// InvalidArgument would be wrong for a map that is full or a kernel that refused a write,
		// and the caller cannot tell them apart from here — it retries either way, and the message
		// is what an operator reads.
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &netdapi.ProgramServicesResponse{}, nil
}

// netnsOfPeer resolves the namespace to wire from a pid, and refuses one that is not the caller's
// to name.
//
// The check is ownership, and it is the reason a pid is safe to accept at all: /proc/<pid> is owned
// by the uid the process runs as, and the caller's uid comes from the KERNEL (SO_PEERCRED), never
// from the message. So an agent may wire the namespace of a process of its own user — its own
// sandboxes — and nothing else on the host. Without it, a pid would be a way to ask a root process
// to reach into any namespace on the machine.
//
// The path is /proc/<pid>/ns/net rather than a pinned handle: there is nothing to pin, because the
// namespace lives exactly as long as the workload in it, and a helper that kept a handle would be
// keeping a namespace alive past the workload it belonged to.
func (h *Handler) netnsOfPeer(ctx context.Context, pid int32) (*os.File, error) {
	if pid <= 1 {
		return nil, status.Error(codes.InvalidArgument, "no netns pid: the workload's own process is what names its namespace")
	}
	auth, err := peerOf(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	// The pid is opened ONCE and everything after refers to that open directory, never to the
	// path again. A pid is a name the kernel reuses, so checking /proc/<pid>'s owner and then
	// opening /proc/<pid>/ns/net by path is a race with a decision in the middle: a workload that
	// exits between the two hands the namespace of whatever inherits its number — a race made
	// visible on a stand by a flapping unit, where the second lookup found a root process.
	dir, err := os.OpenFile(fmt.Sprintf("/proc/%d", pid), os.O_RDONLY|unix.O_DIRECTORY|unix.O_PATH, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, status.Errorf(codes.NotFound, "process %d is gone: its namespace went with it", pid)
		}
		return nil, status.Errorf(codes.Internal, "open /proc/%d: %v", pid, err)
	}
	defer func() { _ = dir.Close() }()

	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return nil, status.Errorf(codes.Internal, "stat /proc/%d: %v", pid, err)
	}
	if st.Uid != auth.UID {
		return nil, status.Errorf(codes.PermissionDenied,
			"process %d belongs to uid %d, not to the caller (%d): an agent wires its own workloads and nothing else",
			pid, st.Uid, auth.UID)
	}
	// Reading a namespace link of another process goes through ptrace_may_access, so this helper
	// needs CAP_SYS_PTRACE — measured on a stand, where a bounding set of NET_ADMIN/NET_RAW alone
	// answered EACCES to root.
	fd, err := unix.Openat(int(dir.Fd()), "ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "open the namespace of process %d: %v", pid, err)
	}
	ns := os.NewFile(uintptr(fd), "netns")
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(ns.Fd()), &fs); err != nil || fs.Type != unix.NSFS_MAGIC {
		_ = ns.Close()
		return nil, status.Errorf(codes.FailedPrecondition, "process %d names no network namespace", pid)
	}
	return ns, nil
}

// hostInterfaces is every interface this helper could have created, for GC. Matching by PREFIX is
// what lets the helper own its own leftovers without a record: nothing else on the node is named
// this way, and a name it does not recognise is not touched.
func hostInterfaces(prefix string) ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, i := range ifaces {
		if strings.HasPrefix(i.Name, prefix) {
			out = append(out, i.Name)
		}
	}
	slices.Sort(out)
	return out, nil
}
