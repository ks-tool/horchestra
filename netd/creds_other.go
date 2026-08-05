//go:build !linux

package netd

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc/credentials"

	"google.golang.org/grpc/credentials/insecure"
)

// PeerAuth exists off Linux only so the server compiles there and `go vet ./...` on a mac keeps
// checking this package. There is no SO_PEERCRED to read, so the handshake refuses every peer:
// a credential check that cannot be performed must fail closed, never default to a plausible uid.
type PeerAuth struct {
	UID uint32
	GID uint32
	PID int32
}

func (PeerAuth) AuthType() string { return "so_peercred" }

type peerCredentials struct {
	credentials.TransportCredentials
}

func (peerCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("netd: peer credentials are a Linux facility; this helper serves nothing here")
}

func (peerCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("netd: peer credentials are the server's side of the socket")
}

func PeerCredentials() credentials.TransportCredentials {
	return peerCredentials{TransportCredentials: insecure.NewCredentials()}
}
