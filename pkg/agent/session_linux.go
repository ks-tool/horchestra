//go:build linux

package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/nodeapi"
)

// grpcEndpoint splits a controller URL into the gRPC dial target (host:port) and
// the server name to verify its certificate against.
func grpcEndpoint(controllerURL string) (endpoint, serverName string, err error) {
	u, err := url.Parse(controllerURL)
	if err != nil {
		return "", "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("controller URL %q has no host", controllerURL)
	}
	port := u.Port()
	if port == "" {
		port = DefaultControllerPort
	}
	return net.JoinHostPort(host, port), host, nil
}

// grpcCreds builds mTLS transport credentials from the node's certificate, key
// and the CA that signed the controller's serving certificate.
func grpcCreds(certPEM, keyPEM, caPEM []byte, serverName string) (credentials.TransportCredentials, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no CA certificates in node config")
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
	}), nil
}

// RunSession maintains the controller session until ctx is cancelled: it opens a
// gRPC bidirectional stream, reconciles this node off the pushed desired state and
// reports status on the heartbeat interval, reconnecting with backoff on failure.
func (r *Reconciler) RunSession(ctx context.Context, heartbeat time.Duration) error {
	const backoff = 5 * time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := r.session(ctx, heartbeat); err != nil && ctx.Err() == nil {
			log.Error().Err(err).Str("controller", r.endpoint).Msg("session ended; reconnecting")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
	}
}

// session runs one connection: dial, open the stream, then report status up
// (initial + heartbeat + after each apply) while applying the desired state pushed
// down. It returns when the stream breaks or ctx is cancelled.
func (r *Reconciler) session(ctx context.Context, heartbeat time.Duration) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, err := grpc.NewClient(r.endpoint, grpc.WithTransportCredentials(r.creds))
	if err != nil {
		return fmt.Errorf("dial controller: %w", err)
	}
	defer func() { _ = conn.Close() }()

	stream, err := nodeapi.NewNodeServiceClient(conn).Session(sctx)
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	log.Info().Str("controller", r.endpoint).Str("node", r.Node).Msg("node-agent session established")

	// A single sender goroutine serializes stream.Send (a gRPC stream is not safe
	// for concurrent Send).
	sendCh := make(chan *nodeapi.NodeMessage, 8)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-sctx.Done():
				return
			case msg := <-sendCh:
				if err := stream.Send(msg); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// latest is the most recent desired state; the worker applies it both on a push
	// (trigger) and on the heartbeat (a periodic self-heal that repairs a unit that
	// died or drifted between pushes). Running every Apply from this one goroutine
	// serializes them, so there is no need to lock the reconciler's state.
	var mu sync.Mutex
	var latest *desiredState
	trigger := make(chan struct{}, 1)
	signal := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(heartbeat)
		defer t.Stop()
		enqueue(sctx, sendCh, r.statusMessage()) // register
		for {
			select {
			case <-sctx.Done():
				return
			case <-trigger:
			case <-t.C:
			}
			mu.Lock()
			d := latest
			mu.Unlock()
			if d != nil {
				if err := r.Apply(sctx, d.apps, d.pvs); err != nil {
					log.Error().Err(err).Msg("apply desired state")
				}
			}
			enqueue(sctx, sendCh, r.statusMessage())
		}
	}()

	// In-progress log streams, cancelled individually on LogCancel and all at once
	// when the session ends (via sctx).
	var logMu sync.Mutex
	logs := map[string]context.CancelFunc{}

	var recvErr error
	for {
		msg, err := stream.Recv()
		if err != nil {
			recvErr = err
			break
		}
		switch {
		case msg.GetDesired() != nil:
			apps, pvs := decodeDesired(msg.GetDesired())
			mu.Lock()
			latest = &desiredState{apps: apps, pvs: pvs}
			mu.Unlock()
			signal()
		case msg.GetLogRequest() != nil:
			req := msg.GetLogRequest()
			lctx, lcancel := context.WithCancel(sctx)
			logMu.Lock()
			logs[req.GetId()] = lcancel
			logMu.Unlock()
			go func() {
				r.streamUnitLogs(lctx, sendCh, req)
				logMu.Lock()
				delete(logs, req.GetId())
				logMu.Unlock()
				lcancel()
			}()
		case msg.GetLogCancel() != nil:
			logMu.Lock()
			if c := logs[msg.GetLogCancel().GetId()]; c != nil {
				c()
			}
			logMu.Unlock()
		}
	}
	cancel()
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return recvErr
}

// desiredState is the last set the controller pushed, applied by the worker.
type desiredState struct {
	apps []App
	pvs  []v1.PersistentVolume
}

// enqueue offers msg to the sender, giving up if the session is ending (so the
// heartbeat never blocks on a full channel during teardown).
func enqueue(ctx context.Context, ch chan<- *nodeapi.NodeMessage, msg *nodeapi.NodeMessage) {
	select {
	case ch <- msg:
	case <-ctx.Done():
	}
}

// streamUnitLogs runs journalctl on the application's unit and forwards its
// output up the session as LogChunks tagged with the request id, ending with an
// eof chunk (or an error chunk if journalctl could not start). Cancelling ctx (a
// LogCancel, or the session ending) kills journalctl.
func (r *Reconciler) streamUnitLogs(ctx context.Context, sendCh chan<- *nodeapi.NodeMessage, req *nodeapi.LogRequest) {
	args := []string{"-u", r.unitName(req.GetApp()), "-o", "cat", "--no-pager"}
	if n := req.GetTailLines(); n > 0 {
		args = append(args, "-n", strconv.FormatInt(n, 10))
	}
	if req.GetFollow() {
		args = append(args, "-f")
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		enqueueLog(ctx, sendCh, req.GetId(), nil, true, err.Error())
		return
	}
	buf := make([]byte, 8192)
	for {
		n, rerr := stdout.Read(buf)
		if n > 0 {
			enqueueLog(ctx, sendCh, req.GetId(), append([]byte(nil), buf[:n]...), false, "")
		}
		if rerr != nil {
			break
		}
	}
	_ = cmd.Wait()
	enqueueLog(ctx, sendCh, req.GetId(), nil, true, "")
}

func enqueueLog(ctx context.Context, sendCh chan<- *nodeapi.NodeMessage, id string, data []byte, eof bool, errMsg string) {
	enqueue(ctx, sendCh, &nodeapi.NodeMessage{Body: &nodeapi.NodeMessage_LogChunk{
		LogChunk: &nodeapi.LogChunk{Id: id, Data: data, Eof: eof, Error: errMsg},
	}})
}

// statusMessage is this node's current status as a NodeMessage carrying the full
// Node object (metadata + status) as JSON.
func (r *Reconciler) statusMessage() *nodeapi.NodeMessage {
	node := v1.Node{
		TypeMeta:   v1.NodeResource.TypeMeta(),
		ObjectMeta: metav1.ObjectMeta{Name: r.Node},
		Status:     r.nodeStatus(),
	}
	b, _ := json.Marshal(&node)
	return &nodeapi.NodeMessage{Body: &nodeapi.NodeMessage_Status{Status: &nodeapi.NodeStatus{Node: b}}}
}

// decodeDesired projects the pushed desired state into the reconciler's forms.
func decodeDesired(d *nodeapi.DesiredState) ([]App, []v1.PersistentVolume) {
	apps := make([]App, 0, len(d.GetApplications()))
	for _, b := range d.GetApplications() {
		var a v1.Application
		if err := json.Unmarshal(b, &a); err != nil {
			continue
		}
		apps = append(apps, appFromV1(a))
	}
	pvs := make([]v1.PersistentVolume, 0, len(d.GetPersistentVolumes()))
	for _, b := range d.GetPersistentVolumes() {
		var pv v1.PersistentVolume
		if err := json.Unmarshal(b, &pv); err != nil {
			continue
		}
		pvs = append(pvs, pv)
	}
	return apps, pvs
}
