//go:build linux

package netd

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc/credentials"

	"golang.org/x/sys/unix"
)

// PeerAuth is who the kernel says is on the other end of a unix socket. It is an identity nobody
// can present — it is recorded at connect() time and cannot be changed by the peer afterwards, not
// by exec, not by dropping privilege — which is what makes it the right credential for a local
// helper: there is no key on disk to steal, nothing to expire, and no rotation that can fail at
// three in the morning and take the datapath with it.
type PeerAuth struct {
	UID uint32
	GID uint32
	PID int32
}

func (PeerAuth) AuthType() string { return "so_peercred" }

// peerCredentials authenticates a unix peer by its kernel-attested credentials.
//
// gRPC's credential machinery is transport-agnostic — mTLS over this socket would work exactly as
// it does over TCP — so this is a CHOICE about what to authenticate, not a workaround for the
// wire. A certificate would prove "someone holding the agent's key", which on this host is anyone
// running as the agent's user; the kernel's answer is that same authority stated directly, with no
// key material and no expiry in the path of a node's networking.
type peerCredentials struct{}

func (peerCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		// The helper serves a unix socket and nothing else. A connection that is not one has no
		// peer credential to read, and guessing would be the one mistake this type exists to
		// prevent.
		return nil, nil, fmt.Errorf("netd: peer credentials need a unix socket, got %T", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, nil, err
	}
	if credErr != nil {
		return nil, nil, credErr
	}
	return conn, PeerAuth{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

// ClientHandshake is never called: the agent dials with insecure credentials because there is
// nothing for it to verify — the socket lives in a root-owned directory, so reaching it at all is
// the proof that the helper put it there.
func (peerCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("netd: peer credentials are the server's side of the socket")
}

func (peerCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "so_peercred"}
}

func (c peerCredentials) Clone() credentials.TransportCredentials { return c }

func (peerCredentials) OverrideServerName(string) error { return nil }

// PeerCredentials is the server-side credential for a unix socket.
func PeerCredentials() credentials.TransportCredentials { return peerCredentials{} }
