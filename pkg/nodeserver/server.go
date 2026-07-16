// Package nodeserver is the controller side of the controller<->node-agent gRPC
// transport. Each agent opens one bidirectional stream (mTLS; the peer
// certificate CN is the node name); the controller pushes the node's desired
// state and log requests down, and receives the node's status and log output up.
package nodeserver

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/admission"
	"ks-tool.dev/horchestra/pkg/authn"
	"ks-tool.dev/horchestra/pkg/nodeapi"
)

// Controller is the slice of the service the node transport needs: read the
// desired objects, watch them for changes, and persist a node's reported status.
type Controller interface {
	List(ctx context.Context, gvk schema.GroupVersionKind) (*unstructured.UnstructuredList, error)
	Watch(ctx context.Context, gvk schema.GroupVersionKind) (<-chan metav1.WatchEvent, error)
	Get(ctx context.Context, gvk schema.GroupVersionKind, name string) (*unstructured.Unstructured, error)
	Create(ctx context.Context, gvk schema.GroupVersionKind, obj *unstructured.Unstructured) (*unstructured.Unstructured, error)
	Update(ctx context.Context, gvk schema.GroupVersionKind, obj *unstructured.Unstructured) (*unstructured.Unstructured, error)
}

type Server struct {
	nodeapi.UnimplementedNodeServiceServer
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
	send chan *nodeapi.ControllerMessage
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
func (s *Server) Session(stream grpc.BidiStreamingServer[nodeapi.NodeMessage, nodeapi.ControllerMessage]) error {
	ctx := stream.Context()
	node, groups, err := peerIdentity(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if !hasGroup(groups, admission.NodeGroup) {
		return status.Errorf(codes.PermissionDenied, "identity %q is not a node (group %q required)", node, admission.NodeGroup)
	}
	sess := &session{send: make(chan *nodeapi.ControllerMessage, 16), logs: map[string]*logSink{}}
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

	nctx := authn.WithIdentity(ctx, &authn.Identity{Name: node, Groups: groups})
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
			if err := s.applyStatus(nctx, node, msg.GetStatus().GetNode()); err != nil {
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
func (s *session) deliverLog(c *nodeapi.LogChunk) {
	s.mu.Lock()
	sink := s.logs[c.GetId()]
	s.mu.Unlock()
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
		s.mu.Lock()
		delete(s.logs, c.GetId())
		s.mu.Unlock()
	}
}

// StreamLogs asks the agent on node to stream app's unit logs. It returns a
// channel of log bytes (closed on EOF), a cancel func (which stops the node-side
// stream and reports any final error), and an error if the node is not connected.
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

	req := &nodeapi.ControllerMessage{Body: &nodeapi.ControllerMessage_LogRequest{
		LogRequest: &nodeapi.LogRequest{Id: id, App: app, Follow: follow, TailLines: tail},
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
			case sess.send <- &nodeapi.ControllerMessage{Body: &nodeapi.ControllerMessage_LogCancel{LogCancel: &nodeapi.LogCancel{Id: id}}}:
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
	appCh, err := s.svc.Watch(ctx, v1.ApplicationResource.GVK)
	if err != nil {
		log.Error().Err(err).Msg("watch applications")
		return
	}
	pvCh, err := s.svc.Watch(ctx, v1.PersistentVolumeResource.GVK)
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
	case sess.send <- &nodeapi.ControllerMessage{Body: &nodeapi.ControllerMessage_Desired{Desired: desired}}:
		return true
	case <-ctx.Done():
		return false
	}
}

// desiredState is the node's applications (those pinned to it via spec.node) and
// every PersistentVolume (the agent needs the full set to tell a deleted volume
// from one reassigned to another node), each a JSON api/v1 object.
func (s *Server) desiredState(ctx context.Context, node string) (*nodeapi.DesiredState, error) {
	apps, err := s.svc.List(ctx, v1.ApplicationResource.GVK)
	if err != nil {
		return nil, err
	}
	pvs, err := s.svc.List(ctx, v1.PersistentVolumeResource.GVK)
	if err != nil {
		return nil, err
	}
	ds := &nodeapi.DesiredState{}
	for i := range apps.Items {
		if pinned, _, _ := unstructured.NestedString(apps.Items[i].Object, "spec", "nodeName"); pinned != node {
			continue
		}
		if b, err := apps.Items[i].MarshalJSON(); err == nil {
			ds.Applications = append(ds.Applications, b)
		}
	}
	for i := range pvs.Items {
		if b, err := pvs.Items[i].MarshalJSON(); err == nil {
			ds.PersistentVolumes = append(ds.PersistentVolumes, b)
		}
	}
	return ds, nil
}

// applyStatus persists the Node object the agent reported, creating it if it was
// deleted. The write goes through the service as the node's identity, so admission
// still applies.
func (s *Server) applyStatus(ctx context.Context, node string, nodeJSON []byte) error {
	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(nodeJSON); err != nil {
		return fmt.Errorf("decode node status: %w", err)
	}
	if obj.GetName() != node {
		return fmt.Errorf("reported node %q does not match identity %q", obj.GetName(), node)
	}
	_, err := s.svc.Update(ctx, v1.NodeResource.GVK, obj)
	if apierrors.IsNotFound(err) {
		_, err = s.svc.Create(ctx, v1.NodeResource.GVK, obj)
	}
	return err
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
