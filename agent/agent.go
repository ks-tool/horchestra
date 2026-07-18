package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/pb"
)

// Agent is the node agent: it maintains an mTLS session to the controller, applies
// the resources pinned to this node onto it through its backends (Images, Mounts,
// Units) and streams service logs back on request. The backends are injected at
// construction, so the agent owns the reconcile algorithm but none of the
// OS-specific implementations.
type Agent struct {
	// controller session (transport)
	endpoint   string
	creds      credentials.TransportCredentials
	node       string
	controller string

	// reconcile config and in-memory state — never persisted; actual state is read
	// back from the node's own services, so a reboot self-heals.
	stateDir    string
	limits      corev1.ResourceAmounts
	want        map[string]App
	provisioned map[string]bool

	// backends implementing this module's ports, injected by the application.
	images Images
	mounts Mounts
	units  Units
}

// NewAgent builds a node agent from the node's REST client config (its kubeconfig)
// and its backends. It normalizes the controller URL from the config's host,
// derives the node identity from the client certificate (falling back to node),
// prepares the mTLS dialer via the standard client-go TLS config, and loads the set
// of volumes this node has provisioned. The images/mounts/units implementations are
// the application's — a systemd + oci-layout + overlay stack today.
func NewAgent(cfg *rest.Config, node, stateDir string, nodeCfg NodeConfig, images Images, mounts Mounts, units Units) (*Agent, error) {
	controller, err := NormalizeControllerURL(cfg.Host)
	if err != nil {
		return nil, err
	}
	endpoint, serverName, err := grpcEndpoint(controller)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := rest.TLSConfigFor(cfg)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return nil, fmt.Errorf("agent: controller config has no TLS client credentials")
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = serverName
	}
	name := node
	if certPEM, err := clientCertPEM(cfg); err != nil {
		return nil, err
	} else if len(certPEM) > 0 {
		if name, err = certCN(certPEM); err != nil {
			return nil, err
		}
	}
	a := &Agent{
		endpoint:   endpoint,
		creds:      credentials.NewTLS(tlsConfig),
		node:       name,
		controller: controller,
		stateDir:   stateDir,
		limits:     nodeCfg.Resources,
		images:     images,
		mounts:     mounts,
		units:      units,
	}
	a.provisioned = loadSet(a.provisionedFile())
	return a, nil
}

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

// Start maintains the controller session until ctx is cancelled: it opens a gRPC
// bidirectional stream, reconciles this node off the pushed desired state via the
// registered Reconciler and reports status on the heartbeat interval, reconnecting
// with backoff on failure.
func (a *Agent) Start(ctx context.Context, heartbeat time.Duration) error {
	const backoff = 5 * time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := a.session(ctx, heartbeat); err != nil && ctx.Err() == nil {
			log.Error().Err(err).Str("controller", a.endpoint).Msg("session ended; reconnecting")
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
func (a *Agent) session(ctx context.Context, heartbeat time.Duration) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, err := grpc.NewClient(a.endpoint, grpc.WithTransportCredentials(a.creds))
	if err != nil {
		return fmt.Errorf("dial controller: %w", err)
	}
	defer func() { _ = conn.Close() }()

	stream, err := pb.NewNodeServiceClient(conn).Session(sctx)
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	log.Info().Str("controller", a.endpoint).Str("node", a.node).Msg("node-agent session established")

	// A single sender goroutine serializes stream.Send (a gRPC stream is not safe
	// for concurrent Send).
	sendCh := make(chan *pb.NodeMessage, 8)
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
	// died or drifted between pushes). Running every Reconcile from this one
	// goroutine serializes them, so there is no need to lock the reconciler's state.
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
		enqueue(sctx, sendCh, a.statusMessage()) // register
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
				if err := a.Reconcile(sctx, d.apps, d.pvs); err != nil {
					log.Error().Err(err).Msg("apply desired state")
				}
			}
			enqueue(sctx, sendCh, a.statusMessage())
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
				a.streamUnitLogs(lctx, sendCh, req)
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
	apps []corev1.Application
	pvs  []corev1.PersistentVolume
}

// enqueue offers msg to the sender, giving up if the session is ending (so the
// heartbeat never blocks on a full channel during teardown).
func enqueue(ctx context.Context, ch chan<- *pb.NodeMessage, msg *pb.NodeMessage) {
	select {
	case ch <- msg:
	case <-ctx.Done():
	}
}

// streamUnitLogs opens the application service's log stream through the Units port
// and forwards its output up the session as LogChunks tagged with the request id,
// ending with an eof chunk (or an error chunk if the stream could not be opened).
// Cancelling ctx (a LogCancel, or the session ending) stops the stream.
func (a *Agent) streamUnitLogs(ctx context.Context, sendCh chan<- *pb.NodeMessage, req *pb.LogRequest) {
	rc, err := a.units.Logs(ctx, req.GetApp(), req.GetFollow(), req.GetTailLines())
	if err != nil {
		enqueueLog(ctx, sendCh, req.GetId(), nil, true, err.Error())
		return
	}
	defer func() { _ = rc.Close() }()
	buf := make([]byte, 8192)
	for {
		n, rerr := rc.Read(buf)
		if n > 0 {
			enqueueLog(ctx, sendCh, req.GetId(), append([]byte(nil), buf[:n]...), false, "")
		}
		if rerr != nil {
			break
		}
	}
	enqueueLog(ctx, sendCh, req.GetId(), nil, true, "")
}

func enqueueLog(ctx context.Context, sendCh chan<- *pb.NodeMessage, id string, data []byte, eof bool, errMsg string) {
	enqueue(ctx, sendCh, &pb.NodeMessage{Body: &pb.NodeMessage_LogChunk{
		LogChunk: &pb.LogChunk{Id: id, Data: data, Eof: eof, Error: errMsg},
	}})
}

// statusMessage is this node's current status as a NodeMessage carrying the full
// Node object (metadata + status) as JSON.
func (a *Agent) statusMessage() *pb.NodeMessage {
	node := corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{Name: a.node},
		Status:     a.nodeStatus(),
	}
	b, _ := json.Marshal(&node)
	return &pb.NodeMessage{Body: &pb.NodeMessage_Status{Status: &pb.NodeStatus{Node: b}}}
}

// decodeDesired decodes the pushed desired state into the API kinds the Reconciler
// consumes.
func decodeDesired(d *pb.DesiredState) ([]corev1.Application, []corev1.PersistentVolume) {
	apps := make([]corev1.Application, 0, len(d.GetApplications()))
	for _, b := range d.GetApplications() {
		var a corev1.Application
		if err := json.Unmarshal(b, &a); err != nil {
			continue
		}
		apps = append(apps, a)
	}
	pvs := make([]corev1.PersistentVolume, 0, len(d.GetPersistentVolumes()))
	for _, b := range d.GetPersistentVolumes() {
		var pv corev1.PersistentVolume
		if err := json.Unmarshal(b, &pv); err != nil {
			continue
		}
		pvs = append(pvs, pv)
	}
	return apps, pvs
}
