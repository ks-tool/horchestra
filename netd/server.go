// Package netd is the privileged network helper: the one process on a node that holds
// CAP_NET_ADMIN and (once the datapath lands) CAP_BPF, so that the agent can hold nothing.
//
// The whole design is in what it REFUSES to accept. Every method is a closed, typed RPC carrying
// data — a workload id, an address, map contents. There is no verb that takes a netlink message, a
// command line, or a BPF program: a program is arbitrary kernel code, and accepting one from the
// agent would hand root back through a typed-looking door. The helper loads what is embedded in
// its own binary and lets the agent say only WHAT it wants, never HOW.
//
// It listens and the agent connects, never the reverse — which is also the recorded architecture
// invariant (the agent opens no listening socket; it is a gRPC client only). A privileged process
// that dialed into a path an unprivileged user controls would take its orders from whoever won the
// race to create that path.
package netd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	netdapi "github.com/ks-tool/horchestra/api/netd"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// NewServer builds the helper's gRPC server: peer-credential transport, one interceptor that
// admits the agent's uid alone, and the handler that does the work.
//
// The uid check is an interceptor rather than a check inside each method because it is not about
// any method: it is the boundary. A method added later inherits it by construction, which is the
// only way a boundary of this kind stays true as the service grows.
func NewServer(handler netdapi.NetdServiceServer, allowUID uint32, log zerolog.Logger) *grpc.Server {
	srv := grpc.NewServer(
		grpc.Creds(PeerCredentials()),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
			next grpc.UnaryHandler) (any, error) {
			auth, err := peerOf(ctx)
			if err != nil {
				log.Warn().Err(err).Str("method", info.FullMethod).Msg("netd: refusing an unidentifiable peer")
				return nil, status.Error(codes.Unauthenticated, "no peer credentials")
			}
			if auth.UID != allowUID {
				// Logged, not silent: a wrong SocketGroup shows up here or nowhere until
				// somebody reads the source.
				log.Warn().Uint32("uid", auth.UID).Uint32("allowed", allowUID).Int32("pid", auth.PID).
					Str("method", info.FullMethod).Msg("netd: refusing a peer that is not this node's agent")
				return nil, status.Error(codes.PermissionDenied, "not this node's agent")
			}
			return next(ctx, req)
		}),
	)
	netdapi.RegisterNetdServiceServer(srv, handler)
	return srv
}

// peerOf is the kernel's answer about who is calling.
func peerOf(ctx context.Context) (PeerAuth, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return PeerAuth{}, errors.New("no peer information on the call")
	}
	auth, ok := p.AuthInfo.(PeerAuth)
	if !ok {
		return PeerAuth{}, fmt.Errorf("peer authenticated as %T, not by its kernel credentials", p.AuthInfo)
	}
	return auth, nil
}

// Listen returns the socket to serve on: the one systemd passed under socket activation, or a
// freshly created one at path.
//
// Activation is the better half of this. With `horchestra-netd.socket` the permissions live in a
// unit file an operator can read (SocketUser/SocketGroup/SocketMode), the helper is not running
// until something asks, and there is no window where the socket exists with the wrong mode because
// the process had not chmod'ed it yet.
func Listen(path string) (net.Listener, error) {
	if l, ok, err := activationListener(); ok || err != nil {
		return l, err
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return nil, err
	}
	// A stale socket from a killed helper would make Listen fail with EADDRINUSE forever. It is
	// removed only when nothing is listening on it — otherwise this would be how one helper takes
	// a live node away from another.
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func dirOf(path string) string {
	for i := len(path) - 1; i > 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// removeStaleSocket unlinks a socket file nothing is listening on. A live one is left alone and
// reported, so two helpers cannot silently take turns owning a node's network.
func removeStaleSocket(path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	conn, err := net.Dial("unix", path)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("netd: %s is already served by a live helper", path)
	}
	return os.Remove(path)
}
