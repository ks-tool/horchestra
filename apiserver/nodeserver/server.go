// Package nodeserver is the controller side of the controller<->node-agent gRPC
// transport. Each agent opens one bidirectional stream (mTLS; the peer certificate
// CN is the node name); the controller pushes the node's desired state and log
// requests down, and receives the node's status and log output up. Its Server
// satisfies the apiserver's LogStreamer, so `kubectl logs` is served over the same
// transport.
package nodeserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/pb"
	"github.com/ks-tool/horchestra/api/types"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// nodeGroup is the certificate Organization a peer must carry to open a node
// session — only identities in this group are node agents.
const nodeGroup = "system:nodes"

// nodeGVK is the only kind the transport writes (a node's reported status);
// Applications and PersistentVolumes are read via resourceMeta.
var nodeGVK = corev1.GroupVersion.WithKind("Node")

// Controller is the slice of the apiserver service the node transport needs: read
// the desired objects, watch them for changes, and persist a node's reported
// status. The concrete service satisfies it.
type Controller interface {
	List(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error)
	Watch(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) (<-chan metav1.WatchEvent, error)
	Create(ctx context.Context, gvk schema.GroupVersionKind, data []byte) (types.Object, error)
	Update(ctx context.Context, gvk schema.GroupVersionKind, data []byte) (types.Object, error)
}

type Server struct {
	pb.UnimplementedNodeServiceServer
	svc      Controller
	reqSeq   atomic.Uint64
	mu       sync.Mutex
	sessions map[string]*session // node name -> its open stream
}

func New(svc Controller) *Server {
	return &Server{svc: svc, sessions: map[string]*session{}}
}

// session is one node-agent's open stream: send serializes messages down to it,
// and logs correlates in-flight log requests to the sinks awaiting their chunks.
type session struct {
	send chan *pb.ControllerMessage
	mu   sync.Mutex
	logs map[string]*logSink
}

// logSink buffers one log request's chunks for the HTTP handler streaming them to
// the client; it is closed (with err, if any) when the node signals EOF.
type logSink struct {
	ch   chan []byte
	once sync.Once
	mu   sync.Mutex
	err  error
}

func (s *logSink) push(b []byte) {
	select {
	case s.ch <- b:
	default: // slow reader: drop rather than stall the shared receive loop
	}
}

func (s *logSink) finish(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
		close(s.ch)
	})
}

func (s *logSink) finalErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Session handles one node-agent's bidirectional stream: it authenticates the
// node, registers the stream, pushes desired state (and log requests routed to
// it), and dispatches the node's status and log output.
func (s *Server) Session(stream grpc.BidiStreamingServer[pb.NodeMessage, pb.ControllerMessage]) error {
	ctx := stream.Context()
	node, groups, err := peerIdentity(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if !hasGroup(groups, nodeGroup) {
		return status.Errorf(codes.PermissionDenied, "identity %q is not a node (group %q required)", node, nodeGroup)
	}
	sess := &session{send: make(chan *pb.ControllerMessage, 16), logs: map[string]*logSink{}}
	s.register(node, sess)
	defer s.deregister(node, sess)
	log.Info().Str("node", node).Msg("node session opened")
	defer log.Info().Str("node", node).Msg("node session closed")

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// One sender goroutine serializes stream.Send across the push loop and the log
	// handlers.
	go func() {
		for {
			select {
			case <-sctx.Done():
				return
			case msg := <-sess.send:
				if err := stream.Send(msg); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	go s.pushLoop(sctx, node, sess)

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		switch {
		case msg.GetStatus() != nil:
			if err := s.applyStatus(ctx, node, msg.GetStatus().GetNode()); err != nil {
				log.Error().Err(err).Str("node", node).Msg("apply node status")
			}
		case msg.GetLogChunk() != nil:
			sess.deliverLog(msg.GetLogChunk())
		}
	}
}

func (s *Server) register(node string, sess *session) {
	s.mu.Lock()
	s.sessions[node] = sess
	s.mu.Unlock()
}

func (s *Server) deregister(node string, sess *session) {
	s.mu.Lock()
	if s.sessions[node] == sess {
		delete(s.sessions, node)
	}
	s.mu.Unlock()
	// Fail any log streams still waiting on this node.
	sess.mu.Lock()
	for _, sink := range sess.logs {
		sink.finish(errors.New("node disconnected"))
	}
	sess.logs = map[string]*logSink{}
	sess.mu.Unlock()
}

// deliverLog routes a log chunk to the sink awaiting it, closing the sink on EOF
// or a node-side error.
func (sess *session) deliverLog(c *pb.LogChunk) {
	sess.mu.Lock()
	sink := sess.logs[c.GetId()]
	sess.mu.Unlock()
	if sink == nil {
		return
	}
	if len(c.GetData()) > 0 {
		sink.push(c.GetData())
	}
	if c.GetEof() || len(c.GetError()) > 0 {
		var err error
		if e := c.GetError(); len(e) > 0 {
			err = errors.New(e)
		}
		sink.finish(err)
		sess.mu.Lock()
		delete(sess.logs, c.GetId())
		sess.mu.Unlock()
	}
}

// StreamLogs asks the agent on node to stream app's unit logs. It returns a
// channel of log bytes (closed on EOF), a cancel func (which stops the node-side
// stream and reports any final error), and an error if the node is not connected.
// It satisfies the apiserver's LogStreamer.
func (s *Server) StreamLogs(ctx context.Context, node, app string, follow bool, tail int64) (<-chan []byte, func() error, error) {
	s.mu.Lock()
	sess := s.sessions[node]
	s.mu.Unlock()
	if sess == nil {
		return nil, nil, fmt.Errorf("node %q is not connected", node)
	}
	id := strconv.FormatUint(s.reqSeq.Add(1), 10)
	sink := &logSink{ch: make(chan []byte, 1024)}
	sess.mu.Lock()
	sess.logs[id] = sink
	sess.mu.Unlock()

	req := &pb.ControllerMessage{Body: &pb.ControllerMessage_LogRequest{
		LogRequest: &pb.LogRequest{Id: id, App: app, Follow: follow, TailLines: tail},
	}}
	select {
	case sess.send <- req:
	case <-ctx.Done():
		sess.removeLog(id)
		return nil, nil, ctx.Err()
	}

	cancel := func() error {
		sess.mu.Lock()
		_, inflight := sess.logs[id]
		delete(sess.logs, id)
		sess.mu.Unlock()
		if inflight {
			// Still streaming (the client disconnected): tell the node to stop.
			select {
			case sess.send <- &pb.ControllerMessage{Body: &pb.ControllerMessage_LogCancel{LogCancel: &pb.LogCancel{Id: id}}}:
			default:
			}
		}
		return sink.finalErr()
	}
	return sink.ch, cancel, nil
}

func (sess *session) removeLog(id string) {
	sess.mu.Lock()
	delete(sess.logs, id)
	sess.mu.Unlock()
}

// pushLoop sends the node its desired state once, then re-sends it whenever an
// Application or PersistentVolume changes. It watches before the initial send so a
// change racing the first list is not lost.
func (s *Server) pushLoop(ctx context.Context, node string, sess *session) {
	appCh, err := s.svc.Watch(ctx, resourceMeta("Application"), metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("watch applications")
		return
	}
	pvCh, err := s.svc.Watch(ctx, resourceMeta("PersistentVolume"), metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("watch persistentvolumes")
		return
	}
	if !s.push(ctx, node, sess) {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-appCh:
			if !ok || !s.push(ctx, node, sess) {
				return
			}
		case _, ok := <-pvCh:
			if !ok || !s.push(ctx, node, sess) {
				return
			}
		}
	}
}

// push enqueues the node's desired state; it returns false when the session is
// gone but keeps it alive on a transient list error.
func (s *Server) push(ctx context.Context, node string, sess *session) bool {
	desired, err := s.desiredState(ctx, node)
	if err != nil {
		log.Error().Err(err).Str("node", node).Msg("build desired state")
		return true
	}
	select {
	case sess.send <- &pb.ControllerMessage{Body: &pb.ControllerMessage_Desired{Desired: desired}}:
		return true
	case <-ctx.Done():
		return false
	}
}

// desiredState is the node's applications (those pinned to it via spec.nodeName)
// and every PersistentVolume (the agent needs the full set to tell a deleted volume
// from one reassigned to another node), each a JSON kind.
func (s *Server) desiredState(ctx context.Context, node string) (*pb.DesiredState, error) {
	apps, err := s.svc.List(ctx, resourceMeta("Application"), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pvs, err := s.svc.List(ctx, resourceMeta("PersistentVolume"), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	ds := &pb.DesiredState{}
	for _, obj := range apps {
		app, ok := obj.(*corev1.Application)
		if !ok || app.Spec.NodeName != node {
			continue
		}
		if b, err := json.Marshal(app); err == nil {
			ds.Applications = append(ds.Applications, b)
		}
	}
	for _, obj := range pvs {
		if b, err := json.Marshal(obj); err == nil {
			ds.PersistentVolumes = append(ds.PersistentVolumes, b)
		}
	}
	return ds, nil
}

// applyStatus persists the Node object the agent reported, creating it if it was
// deleted. The write goes through the service, so admission (defaulting, …) still
// applies. A node may only report its own Node.
func (s *Server) applyStatus(ctx context.Context, node string, nodeJSON []byte) error {
	var probe struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(nodeJSON, &probe); err != nil {
		return fmt.Errorf("decode node status: %w", err)
	}
	if probe.Metadata.Name != node {
		return fmt.Errorf("reported node %q does not match identity %q", probe.Metadata.Name, node)
	}
	_, err := s.svc.Update(ctx, nodeGVK, nodeJSON)
	if apierrors.IsNotFound(err) {
		_, err = s.svc.Create(ctx, nodeGVK, nodeJSON)
	}
	return err
}

// resourceMeta addresses a core-group resource by kind for List/Watch.
func resourceMeta(kind string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: kind}
}

// peerIdentity reads the node name (certificate CN) and groups (Organization)
// from the stream's mTLS client certificate.
func peerIdentity(ctx context.Context) (string, []string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", nil, errors.New("no peer information")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", nil, errors.New("connection is not mTLS")
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return "", nil, errors.New("no client certificate presented")
	}
	cn := certs[0].Subject.CommonName
	if len(cn) == 0 {
		return "", nil, errors.New("client certificate has no common name")
	}
	return cn, certs[0].Subject.Organization, nil
}

func hasGroup(groups []string, want string) bool {
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}
