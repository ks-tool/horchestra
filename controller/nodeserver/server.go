// Package nodeserver is the controller side of the controller<->node-agent gRPC
// transport. Each agent opens one bidirectional stream (mTLS; the peer certificate
// CN is the node name); the controller pushes the node's desired state and log
// requests down, and receives the node's status and log output up. Its Server
// satisfies the apiserver's LogStreamer, so `kubectl logs` is served over the same
// transport.
package nodeserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	netdapi "github.com/ks-tool/horchestra/api/netd"
	nodeapipb "github.com/ks-tool/horchestra/api/node"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"
	"github.com/ks-tool/horchestra/api/types"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
)

// nodeGroup is the certificate Organization a peer must carry to open a node
// session — only identities in this group are node agents.
const nodeGroup = "system:nodes"

// nodeGVK is the only kind the transport writes (a node's reported status);
// Applications and PersistentVolumes are read via resourceMeta.
var nodeGVK = corev1.GroupVersion.WithKind("Node")
var appGVK = corev1.GroupVersion.WithKind("Application")

const (
	// logSinkChunks is the per-stream controller-side buffer, in agent chunks (8 KiB each). A
	// client that stops reading blocks the handler in Write, so the buffer stays pinned for as
	// long as that request lives; the fill rate is bounded by the node's single Session, and the
	// push already drops chunks for a slow reader, so a deep buffer bought nothing but a ~8 MiB
	// heap amplification per cheap request.
	logSinkChunks = 64
	// maxLiveLogSinks bounds the log streams in flight across the whole controller, so the
	// per-identity limit in the HTTP layer cannot be multiplied by the number of identities.
	maxLiveLogSinks = 256
	// pushResyncInterval forces a desired-state re-push even when the signature is unchanged, so
	// any transition a watch missed converges within one interval instead of waiting for the next
	// unrelated write.
	pushResyncInterval = 5 * time.Minute
)

// Controller is the slice of the apiserver service the node transport needs: read
// the desired objects, watch them for changes, and persist a node's reported
// status. The concrete service satisfies it.
type Controller interface {
	Get(ctx context.Context, m types.ObjectMeta) (types.Object, error)
	List(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error)
	Watch(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) (<-chan metav1.WatchEvent, error)
	Create(ctx context.Context, gvk schema.GroupVersionKind, data []byte, ns string) (types.Object, error)
	UpdateSubresource(ctx context.Context, gvk schema.GroupVersionKind, subresource string, data []byte, ns string) (types.Object, error)
	// Update and Delete are here for one thing: releasing the node-teardown finalizer when a
	// node reports its workload gone, and erasing the object once nothing else holds it. They
	// are a WRITE of spec-adjacent metadata, which is why they are not the status subresource —
	// and the reason a node's report may drive them at all is that the finalizer names this very
	// node's teardown, which only this node can witness.
	Update(ctx context.Context, gvk schema.GroupVersionKind, data []byte, ns, name string) (types.Object, error)
	Delete(ctx context.Context, m types.ObjectMeta, opts metav1.DeleteOptions) error
}

type Server struct {
	nodeapipb.UnimplementedNodeServiceServer
	svc Controller
	// resolver, when set, enables the strict registration check (WithStrictRegistration). Nil
	// disables it, and a node registers on its certificate alone.
	resolver Resolver
	// staleAfter is how long a session may be silent before another stream from the same node may
	// take it over (see register).
	staleAfter time.Duration
	reqSeq     atomic.Uint64
	liveSinks  atomic.Int64 // log streams in flight, bounded by maxLiveLogSinks
	mu         sync.Mutex
	sessions   map[string]*session // node name -> its open stream
	// metrics is the last measured sample per workload, held in memory and never stored.
	metrics *metricsStore

	// tokens, when set (WithTokenMinter), mints the workload-identity JWTs pushed beside
	// desired state for apps whose vault secrets use a jwt-method SecretStore. Nil means
	// no tokens are pushed and such apps fail closed at the node's Vault login.
	tokens     TokenMinter
	tokenMu    sync.Mutex
	tokenCache map[tokenKey]mintedToken // (workload id, audience) -> its live token
	// addrChoice remembers a routed address between choosing it and the node reporting it wired.
	// Not a ledger: the node's report is the record, and this only covers the window before it.
	addrMu     sync.Mutex
	addrChoice map[string]string
	// routedCIDR is the fleet's whole workload range; empty means every workload is on the host
	// network and no address is ever chosen.
	routedCIDR string
}

// TokenMinter mints a short-lived identity token for one namespace-qualified workload id
// (uid is the workload's object UID, stamped into the token's claims). The
// controller/oidc issuer implements it; nodeserver stays crypto-free.
type TokenMinter interface {
	MintWorkloadToken(workload, uid, audience string) (token string, exp time.Time, err error)
}

// tokenKey is what a minted token is FOR: one workload at one audience. Two audiences are two
// credentials, never one cached under a name that forgets which door it opens.
type tokenKey struct{ workload, audience string }

type mintedToken struct {
	token string
	exp   time.Time
}

// tokenRefreshMargin is how much lifetime a cached token may have left before the next
// push re-mints it — the refresh must outpace expiry by enough for a push and a fetch.
const tokenRefreshMargin = 5 * time.Minute

// WithTokenMinter enables workload-identity tokens in the desired-state push.
func WithTokenMinter(m TokenMinter) Option {
	return func(s *Server) { s.tokens = m }
}

// workloadToken returns a live token for the workload, re-minting when the cached one is
// inside the refresh margin. Caching keeps the push signature stable between mints, so
// token delivery does not turn every push into a "changed" push.
func (s *Server) workloadToken(workload, uid, audience string) (string, error) {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	key := tokenKey{workload: workload, audience: audience}
	if t, ok := s.tokenCache[key]; ok && time.Until(t.exp) > tokenRefreshMargin {
		return t.token, nil
	}
	token, exp, err := s.tokens.MintWorkloadToken(workload, uid, audience)
	if err != nil {
		return "", err
	}
	if s.tokenCache == nil {
		s.tokenCache = map[tokenKey]mintedToken{}
	}
	s.tokenCache[key] = mintedToken{token: token, exp: exp}
	return token, nil
}

func New(svc Controller, opts ...Option) *Server {
	srv := &Server{svc: svc, sessions: map[string]*session{}, staleAfter: defaultSessionStale, metrics: newMetricsStore()}
	for _, opt := range opts {
		opt(srv)
	}
	return srv
}

// Option configures the Server.
type Option func(*Server)

// Resolver performs the reverse lookup the strict registration check needs;
// net.DefaultResolver satisfies it.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// defaultSessionStale is how long a session may say nothing before another stream may take the node
// over. It has to exceed the agent's heartbeat by a comfortable margin — the agent reports on
// connect, on every heartbeat and after every apply — so a live but quiet node is never taken over.
const defaultSessionStale = 60 * time.Second

// WithRoutedCIDR names the range workload addresses are cut from. One range for the whole fleet:
// which node an address lives on is the datapath's business, not the allocator's.
func WithRoutedCIDR(cidr string) Option {
	return func(s *Server) { s.routedCIDR = cidr }
}

// WithSessionStaleAfter sets how long a node's session may be silent before a new stream from that
// node may replace it. Below the agent's heartbeat interval it would let one node's two agents (or
// an impostor) trade the session back and forth, so it is bounded to defaultSessionStale at the
// least; pass the node-ready timeout to keep takeover and readiness on the same clock.
func WithSessionStaleAfter(d time.Duration) Option {
	return func(s *Server) {
		if d > defaultSessionStale {
			s.staleAfter = d
		}
	}
}

// WithStrictRegistration makes a node's FIRST registration prove that its certificate belongs to
// the host presenting it: the address the session comes from is reverse-resolved, and the
// certificate CN must name that host (see nameCoversPTR). A node that fails is not registered, so
// it never becomes a fleet member — no Node object, and therefore no desired state and no Secrets.
//
// The check is at registration and nowhere else, because that is the moment the cluster decides a
// name belongs to a machine; afterwards the Node object is the record of that decision, and
// re-checking on every reconnect would make a DNS outage evict a running fleet. It does mean DNS
// (forward and reverse) has to be working while a node joins.
//
// Off by default: the node's displayed name is its certificate CN either way, and without the check
// that name is simply whatever the operator issued — it need not resolve at all.
func WithStrictRegistration(r Resolver) Option {
	return func(s *Server) { s.resolver = r }
}

// session is one node-agent's open stream: send serializes messages down to it,
// and logs correlates in-flight log requests to the sinks awaiting their chunks.
type session struct {
	send chan *nodeapipb.ControllerMessage
	mu   sync.Mutex
	logs map[string]*logSink
	// pushSig is the signature of the desired state last sent to this node, used to skip a re-push
	// when nothing the node cares about changed. Touched only by the single pushLoop goroutine.
	pushSig string
	// frozen records that this node's Node object is absent, so the "not serving it" warning is
	// logged on the transition rather than on every watch event. Also pushLoop-only.
	frozen bool
	// cancel tears this session down. register calls it on a session that has gone silent, when
	// another stream takes the node over.
	cancel context.CancelFunc
	// lastSeen is when this session last received anything from the node, in unix nanoseconds. It
	// is what makes "one node, one stream" survive an unclean drop: a session that stopped talking
	// can be taken over, a live one cannot. Atomic — the Recv loop writes it, register reads it.
	lastSeen atomic.Int64
}

// touch records that the node just sent something on this session.
func (sess *session) touch() { sess.lastSeen.Store(time.Now().UnixNano()) }

// seen is when the node last sent anything on this session.
func (sess *session) seen() time.Time { return time.Unix(0, sess.lastSeen.Load()) }

// logSink buffers one log request's chunks for the HTTP handler streaming them to
// the client; it is closed (with err, if any) when the node signals EOF. release
// returns its slot in the server-wide live-stream budget and is idempotent, so
// whichever of the HTTP cancel, the EOF dispatch or the node's disconnect gets
// there first accounts for it exactly once.
type logSink struct {
	ch      chan []byte
	once    sync.Once
	release func()
	mu      sync.Mutex
	err     error
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
		if s.release != nil {
			s.release()
		}
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
func (s *Server) Session(stream grpc.BidiStreamingServer[nodeapipb.NodeMessage, nodeapipb.ControllerMessage]) (err error) {
	// grpc-go does not recover handler panics, so without this one malformed node message would
	// take the whole control plane down — REST included, they share the process.
	defer func() {
		if v := recover(); v != nil {
			log.Error().Interface("panic", v).Bytes("stack", debug.Stack()).
				Msg("recovered from a panic serving a node session")
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	ctx := stream.Context()
	node, groups, perr := peerIdentity(ctx)
	if perr != nil {
		return status.Error(codes.Unauthenticated, perr.Error())
	}
	if !slices.Contains(groups, nodeGroup) {
		return status.Errorf(codes.PermissionDenied, "identity %q is not a node (group %q required)", node, nodeGroup)
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sess := &session{send: make(chan *nodeapipb.ControllerMessage, 16), logs: map[string]*logSink{}, cancel: cancel}
	sess.touch() // a connecting node counts as alive from the handshake, not from its first message
	if err := s.register(node, sess); err != nil {
		log.Warn().Err(err).Str("node", node).Msg("refusing a second node session")
		return status.Error(codes.AlreadyExists, err.Error())
	}
	defer s.deregister(node, sess)
	log.Info().Str("node", node).Msg("node session opened")
	defer log.Info().Str("node", node).Msg("node session closed")
	// One sender goroutine serializes stream.Send across the push loop and the log
	// handlers.
	go func() {
		defer recoverSession(node, cancel)
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
	go func() {
		defer recoverSession(node, cancel)
		s.pushLoop(sctx, node, sess)
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		sess.touch()
		switch {
		case msg.GetStatus() != nil:
			if err := s.applyStatus(ctx, node, msg.GetStatus().GetNode()); err != nil {
				log.Error().Err(err).Str("node", node).Msg("apply node status")
			}
		case msg.GetAppMetrics() != nil:
			s.metrics.put(node, msg.GetAppMetrics())
		case msg.GetNodeUsage() != nil:
			s.metrics.putNode(node, msg.GetNodeUsage())
		case msg.GetAppStatus() != nil:
			if err := s.applyAppStatus(ctx, node, msg.GetAppStatus()); err != nil {
				log.Warn().Err(err).Str("node", node).Msg("apply application status")
			}
		case msg.GetLogChunk() != nil:
			sess.deliverLog(msg.GetLogChunk())
		}
	}
}

// recoverSession contains a panic in one node session's goroutines: it tears that session down
// (the agent reconnects on its 5s backoff) instead of taking the whole control plane with it.
// These goroutines process node-supplied messages, so a panic here is reachable from a node
// credential — the one input on this path the controller does not author.
func recoverSession(node string, cancel context.CancelFunc) {
	if v := recover(); v != nil {
		log.Error().Interface("panic", v).Str("node", node).Bytes("stack", debug.Stack()).
			Msg("recovered from a panic in a node session; dropping the session")
		cancel()
	}
}

// register makes sess the node's only session, and REFUSES a second one while the first is alive.
//
// One node certificate means one live stream. It used to mean "the newest stream", with the
// previous one evicted — which handed anything holding a copy of the certificate a takeover: run a
// tool on the node (or anywhere with the key), connect, and the real agent is kicked off while the
// impostor receives that node's desired state and every Secret its workloads reference. The agent
// reconnects, evicts the impostor, the impostor reconnects, and the flip-flop is indistinguishable
// from a flapping network while both sides keep getting the credentials.
//
// Eviction existed for a real reason, though: after an unclean drop the old session can still be
// registered while its transport is already dead, and a flat refusal would lock the node out until
// something noticed. So the rule is by LIVENESS, not by arrival order — a session that has said
// nothing for staleAfter is presumed dead and may be taken over; one that is talking may not. The
// refusal is logged, because a second connection from a node that is already connected is exactly
// what an impersonation attempt looks like.
//
// It does not adjudicate WHICH holder of a duplicated certificate is legitimate: whoever is
// connected keeps the session. Rotation and the registration check are the answers to a stolen
// credential; this is what stops it from being a silent takeover.
func (s *Server) register(node string, sess *session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev := s.sessions[node]; prev != nil && prev != sess {
		if idle := time.Since(prev.seen()); idle < s.staleAfter {
			return fmt.Errorf("node %q already has a live session (last message %s ago); one node, one stream",
				node, idle.Round(time.Millisecond))
		}
		log.Warn().Str("node", node).Dur("idle", time.Since(prev.seen())).
			Msg("taking over a node session that stopped reporting")
		if prev.cancel != nil {
			prev.cancel()
		}
	}
	s.sessions[node] = sess
	return nil
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
func (sess *session) deliverLog(c *nodeapipb.LogChunk) {
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
	return s.streamLogs(ctx, node, app, false, follow, tail)
}

// StreamNodeLogs streams the AGENT'S OWN unit journal from a node — not a workload's, and not the
// host's. The host journal carries every workload's output, so one call to it would hand over what
// pods/log serves one workload at a time with a permission check on each.
func (s *Server) StreamNodeLogs(ctx context.Context, node string, follow bool, tail int64) (<-chan []byte, func() error, error) {
	return s.streamLogs(ctx, node, "", true, follow, tail)
}

func (s *Server) streamLogs(ctx context.Context, node, app string, nodeUnit, follow bool, tail int64) (<-chan []byte, func() error, error) {
	s.mu.Lock()
	sess := s.sessions[node]
	s.mu.Unlock()
	if sess == nil {
		return nil, nil, fmt.Errorf("node %q is not connected", node)
	}
	if live := s.liveSinks.Add(1); live > maxLiveLogSinks {
		s.liveSinks.Add(-1)
		return nil, nil, fmt.Errorf("too many log streams in flight (%d); retry later", maxLiveLogSinks)
	}
	var released sync.Once
	id := strconv.FormatUint(s.reqSeq.Add(1), 10)
	sink := &logSink{
		ch:      make(chan []byte, logSinkChunks),
		release: func() { released.Do(func() { s.liveSinks.Add(-1) }) },
	}
	sess.mu.Lock()
	sess.logs[id] = sink
	sess.mu.Unlock()

	req := &nodeapipb.ControllerMessage{Body: &nodeapipb.ControllerMessage_LogRequest{
		LogRequest: &nodeapipb.LogRequest{Id: id, App: app, Follow: follow, TailLines: tail, NodeUnit: nodeUnit},
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
		sink.release()
		if inflight {
			// Still streaming (the client disconnected): tell the node to stop.
			select {
			case sess.send <- &nodeapipb.ControllerMessage{Body: &nodeapipb.ControllerMessage_LogCancel{LogCancel: &nodeapipb.LogCancel{Id: id}}}:
			default:
			}
		}
		return sink.finalErr()
	}
	return sink.ch, cancel, nil
}

func (sess *session) removeLog(id string) {
	sess.mu.Lock()
	sink := sess.logs[id]
	delete(sess.logs, id)
	sess.mu.Unlock()
	if sink != nil && sink.release != nil {
		sink.release()
	}
}

// pushLoop sends the node its desired state once, then re-sends it whenever an
// Application, PersistentVolume, Secret or Node changes, and unconditionally every
// pushResyncInterval. It watches before the initial send so a change racing the first list is
// not lost. The Node watch is what makes a removal from the fleet take effect at once rather
// than at the next unrelated write.
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
	secretCh, err := s.svc.Watch(ctx, resourceMeta("Secret"), metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("watch secrets")
		return
	}
	// Best-effort: a control plane that never registered the secrets group still serves
	// sessions — vault stores then never re-push (a nil channel never fires), and a vault
	// secret fails the push loudly at desiredState instead.
	storeCh, err := s.svc.Watch(ctx, secretStoreMeta(), metav1.ListOptions{})
	if err != nil {
		log.Warn().Err(err).Msg("watch secretstores disabled")
		storeCh = nil
	}
	nodeCh, err := s.svc.Watch(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("watch nodes")
		return
	}
	resync := time.NewTicker(pushResyncInterval)
	defer resync.Stop()
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
		case _, ok := <-secretCh:
			// A secret rotation (or ref change) re-pushes so the node re-materializes it.
			if !ok || !s.push(ctx, node, sess) {
				return
			}
		case _, ok := <-storeCh:
			// A store reconfiguration (server moved, CA rotated) re-pushes so the node
			// re-resolves its vault secrets against the new connection info.
			if !ok || !s.push(ctx, node, sess) {
				return
			}
		case ev, ok := <-nodeCh:
			if !ok {
				return
			}
			// Only this node's own object matters here (its existence decides whether the node is
			// served at all), and every node heartbeats, so an unfiltered re-push would make each
			// heartbeat wake every other node's loop — quadratic in fleet size.
			if !isNodeEvent(ev, node) {
				continue
			}
			if !s.push(ctx, node, sess) {
				return
			}
		case <-resync.C:
			sess.pushSig = "" // force the send: a resync must not be swallowed by the dedup
			if !s.push(ctx, node, sess) {
				return
			}
		}
	}
}

// checkRegistration decides whether a name may be registered for the machine presenting it. With
// no resolver configured the certificate is the whole claim: whoever holds a system:nodes cert for
// CN X registers node X, and the displayed name is that CN whether or not it resolves anywhere.
//
// Configured, the claim has to agree with DNS: the peer address is reverse-resolved and the CN must
// name the host that comes back. That is what stops a certificate from being used on a machine it
// was not issued for — the machine would register under the name in its certificate, receive the
// Applications pinned to it and the Secrets those reference, all while being some other host.
func (s *Server) checkRegistration(ctx context.Context, node string) error {
	if s.resolver == nil {
		return nil
	}
	addr, err := peerAddr(ctx)
	if err != nil {
		return fmt.Errorf("refusing to register %q: the peer address is unknown: %w", node, err)
	}
	lookup, cancel := context.WithTimeout(ctx, dnsCheckTimeout)
	defer cancel()
	names, err := s.resolver.LookupAddr(lookup, addr)
	if err != nil {
		return fmt.Errorf("refusing to register %q: %s has no reverse name (DNS must be working while a node joins): %w",
			node, addr, err)
	}
	for _, name := range names {
		if nameCoversPTR(node, name) {
			log.Info().Str("node", node).Str("peer", addr).Str("ptr", name).
				Msg("registering a node whose certificate name matches its reverse DNS")
			return nil
		}
	}
	return fmt.Errorf("refusing to register %q: %s reverse-resolves to %v, which the certificate name does not cover",
		node, addr, names)
}

// nameCoversPTR reports whether cn names the host whose reverse record is ptr.
//
// The rule is one thing at any depth: cn must be a LABEL-ALIGNED PREFIX of ptr — the whole name, or
// any number of its leading labels. For a PTR of "n1.rack2.dc3.example.org" that admits "n1",
// "n1.rack2", "n1.rack2.dc3", "n1.rack2.dc3.example" and the full name, and no other string. The
// "cn+\".\"" is what keeps it label-aligned: "n1" covers "n1.rack2…" but "n" and "n1.rac" do not,
// because the boundary has to fall on a dot. Nothing here counts labels or bounds their number, so
// a five-label FQDN and a two-label one go through the same two comparisons.
//
// A trailing dot is stripped from either side (resolvers hand back the rooted form) and both are
// compared case-insensitively, as DNS names are.
func nameCoversPTR(cn, ptr string) bool {
	cn = strings.ToLower(strings.TrimSuffix(cn, "."))
	ptr = strings.ToLower(strings.TrimSuffix(ptr, "."))
	if cn == "" || ptr == "" {
		return false
	}
	return cn == ptr || strings.HasPrefix(ptr, cn+".")
}

// dnsCheckTimeout bounds the reverse lookup, so a slow resolver cannot stall a registration; the
// timeout then refuses it, which is the safe direction.
const dnsCheckTimeout = 5 * time.Second

// peerAddr is the IP the session comes from.
func peerAddr(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "", errors.New("no peer information")
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String(), nil // an address with no port (a bufconn pipe in tests)
	}
	return host, nil
}

// isNodeEvent reports whether a Node watch event is about the node named node. The event body is
// decoded to the typed Node rather than probed for a metadata key, the same rule the status path
// follows: encoding/json folds field names, so a raw probe and the typed decode can disagree
// about which object an event names.
func isNodeEvent(ev metav1.WatchEvent, node string) bool {
	var n corev1.Node
	if err := json.Unmarshal(ev.Object.Raw, &n); err != nil {
		return true // undecodable: re-push rather than miss a membership change
	}
	return n.Name == node
}

// push enqueues the node's desired state; it returns false when the session is
// gone but keeps it alive on a transient list error. A push whose signature matches the last one
// sent to this node is skipped: an Application status update fires the Application watch that drives
// pushLoop, but it does not change the spec-generation signature, so it does not re-push — which is
// what stops the agent's status report from looping back into another desired-state push.
//
// A node whose Node object does not exist is served nothing: the push is FROZEN, not emptied.
// That is what makes `kubectl delete node X` a containment lever — X stops receiving newly
// placed Applications and their Secrets from that moment — without a mistaken delete tearing
// down every workload already running there, which an empty desired state would do.
func (s *Server) push(ctx context.Context, node string, sess *session) bool {
	registered, err := s.nodeRegistered(ctx, node)
	if err != nil {
		log.Error().Err(err).Str("node", node).Msg("read node object")
		return true
	}
	if !registered {
		if !sess.frozen {
			sess.frozen = true
			log.Warn().Str("node", node).
				Msg("node has no Node object; freezing its desired state until it registers again")
		}
		return true
	}
	sess.frozen = false
	desired, sig, err := s.desiredState(ctx, node)
	if err != nil {
		log.Error().Err(err).Str("node", node).Msg("build desired state")
		return true
	}
	if sig == sess.pushSig {
		return true // desired state unchanged (e.g. a status-only update) — no re-push needed
	}
	select {
	case sess.send <- &nodeapipb.ControllerMessage{Body: &nodeapipb.ControllerMessage_Desired{Desired: desired}}:
		sess.pushSig = sig
		return true
	case <-ctx.Done():
		return false
	}
}

// desiredState is the node's applications (those pinned to it via spec.nodeName), the
// PersistentVolumes assigned to it in full plus every other one as a bare identity stub (the
// agent needs to know a foreign volume still EXISTS to tell a deleted volume from one
// reassigned to another node, but nothing about it), and only the Secrets those apps
// reference (node-scoped least-exposure — a node never sees a secret no app of its mounts),
// each a JSON kind.
// workloadAddress is the address this workload is to be wired at: the one the node already
// reported, else the one chosen last time and not yet reported, else the lowest address in the
// cluster's range that nothing holds.
//
// One range, no per-node slice. Which node an address lives on is the datapath's business — it maps
// address to node — so carving the range per node would only mean renumbering a workload whenever
// it moved, and would make the range's size a per-node limit instead of a fleet-wide one.
//
// The cache is the only state, and it is deliberately weak: it holds a choice between the moment it
// is made and the moment a node confirms it, which is the same window the token cache covers. A
// controller that restarts in that window simply chooses again — nothing was wired yet, because
// nothing was told.
func (s *Server) workloadAddress(appID, reportedAddr string, inUse map[string]bool) (string, error) {
	if reportedAddr != "" {
		return reportedAddr, nil
	}
	p, err := netip.ParsePrefix(s.routedCIDR)
	if err != nil {
		return "", fmt.Errorf("routed range %q: %w", s.routedCIDR, err)
	}
	p = p.Masked()
	s.addrMu.Lock()
	defer s.addrMu.Unlock()
	if a, ok := s.addrChoice[appID]; ok {
		return a, nil
	}
	taken := map[string]bool{}
	maps.Copy(taken, inUse)
	for _, a := range s.addrChoice {
		taken[a] = true
	}
	bits := p.Addr().BitLen()
	for a := p.Addr().Next(); p.Contains(a); a = a.Next() {
		host := netip.PrefixFrom(a, bits).String()
		if !taken[host] {
			if s.addrChoice == nil {
				s.addrChoice = map[string]string{}
			}
			s.addrChoice[appID] = host
			return host, nil
		}
	}
	return "", fmt.Errorf("the routed range %s is exhausted: every address in it is on a workload", p)
}

func (s *Server) desiredState(ctx context.Context, node string) (*nodeapipb.DesiredState, string, error) {
	apps, err := s.svc.List(ctx, resourceMeta("Application"), metav1.ListOptions{})
	if err != nil {
		return nil, "", err
	}
	pvs, err := s.svc.List(ctx, resourceMeta("PersistentVolume"), metav1.ListOptions{})
	if err != nil {
		return nil, "", err
	}
	ds := &nodeapipb.DesiredState{}
	referenced := map[string]struct{}{}   // namespace-qualified names of the secrets this node's apps consume
	appRefs := map[string][]string{}      // workload id -> its referenced secret ids (for token gating)
	appAudiences := map[string][]string{} // workload id -> the audiences its token volumes ask for
	appUIDs := map[string]string{}        // workload id -> its object UID (stamped into its token)
	routedApps := map[string]string{}     // workload id -> the address it already reported, if any
	reported := map[string]bool{}         // every address this node's workloads say they are wired at
	// sig is signed by each included object's (kind, name, generation) — NOT its marshaled bytes.
	// generation advances only on a spec write, so an Application status update leaves the signature
	// unchanged and the push is skipped; a real spec change, a PV change or a secret rotation moves
	// it and re-pushes. This is the seam that keeps status (a subresource) from waking a spec-watcher.
	// Every address the fleet says it is using, from every node's reports — the range is one and
	// so is the set of what is taken.
	for _, obj := range apps {
		if app, ok := obj.(*corev1.Application); ok && app.Status.Address != "" {
			reported[app.Status.Address] = true
		}
	}
	var sig []string
	for _, obj := range apps {
		app, ok := obj.(*corev1.Application)
		if !ok || app.Spec.Placement.NodeName != node {
			continue // the node-scoped least-exposure filter: only apps pinned to this node
		}
		// A job that already ran to completion on this exact spec is not sent again. Its unit
		// is transient — nothing on the node remembers it across a reboot — so withholding it
		// here is what makes a job run once rather than once per boot.
		//
		// A DELETION still goes through, and that exception is the whole point: without it a
		// finished job never reached the node, so the node never tore it down, never reported it
		// gone, and its node-teardown finalizer was never released. The object sat undeletable
		// forever, holding its name against anything that tried to reuse it. Found on a stand,
		// where one had to have its finalizer stripped by hand.
		if app.Finished() && !app.Deleting() {
			continue
		}
		b, err := json.Marshal(app)
		if err != nil {
			// Fail the push rather than silently drop the app from desired state — a dropped
			// app would silently never run on the node. The push retries on the next tick.
			return nil, "", fmt.Errorf("marshal application %q: %w", app.Name, err)
		}
		ds.Applications = append(ds.Applications, b)
		if !app.OnHostNetwork() {
			appID := corev1.WorkloadID(app.Namespace, app.Name)
			routedApps[appID] = app.Status.Address
			appUIDs[appID] = string(app.UID)
		}
		// The generation is the spec's version and a DELETION deliberately does not move it —
		// a teardown is not a spec change and must not wake a spec-watcher. That is exactly why
		// the deletion has to enter the signature on its own: without it the stamped object
		// hashed identically to the live one, the push was deduplicated away, and the node
		// learned it had a workload to tear down only on the unconditional five-minute sweep.
		// Measured on the stand: an app asking for a 5s grace period took 284s to go.
		sig = append(sig, sigPart("a", app.Namespace, app.Name, string(app.UID), app.Generation))
		if app.Deleting() {
			sig = append(sig, sigPart("d", app.Namespace, app.Name, string(app.UID), 1))
		}
		// Application.SecretRefs is the one definition of what an app consumes — volume mounts
		// AND spec.env secretRefs. A secret this misses is a secret the node never receives, and
		// an app that never converges.
		for _, name := range app.SecretRefs() {
			ref := corev1.WorkloadID(app.Namespace, name)
			referenced[ref] = struct{}{}
			appID := corev1.WorkloadID(app.Namespace, app.Name)
			appRefs[appID] = append(appRefs[appID], ref)
			appUIDs[appID] = string(app.UID)
		}
		// A token volume asks for the workload's own identity at a named audience. It is
		// independent of the Vault path below: an app may mount a catalog token and reference no
		// secret at all, which is exactly what an edge does.
		if auds := app.TokenAudiences(); len(auds) > 0 {
			appID := corev1.WorkloadID(app.Namespace, app.Name)
			appUIDs[appID] = string(app.UID)
			appAudiences[appID] = auds
		}
	}
	// A PersistentVolume assigned to this node is pushed in full; every other one is reduced to
	// its identity. The full set has to be present — the agent distinguishes a DELETED volume
	// (reclaim the data) from one reassigned to another node (just detach) by whether its name
	// is still in the list, and a node-scoped list would make the two indistinguishable — but
	// only the name is load-bearing there, so a node holding one certificate no longer learns
	// every other tenant's volume size, mode, driver and reclaim policy. The stub's empty
	// spec.node also keeps it out of the node's own provisioning set by construction.
	for _, obj := range pvs {
		pv, ok := obj.(*corev1.PersistentVolume)
		if !ok {
			continue
		}
		out, tag := pv, "p"
		if pv.Spec.Node != node {
			stub := &corev1.PersistentVolume{TypeMeta: pv.TypeMeta}
			stub.Namespace, stub.Name = pv.Namespace, pv.Name
			out, tag = stub, "P"
		}
		b, err := json.Marshal(out)
		if err != nil {
			return nil, "", fmt.Errorf("marshal persistentvolume %q: %w", pv.Name, err)
		}
		ds.PersistentVolumes = append(ds.PersistentVolumes, b)
		// A stub carries no spec, so a foreign volume's spec edits must not re-push to this node;
		// its identity and the own/foreign tag are the only things that can change what it sees.
		gen := pv.Generation
		if tag == "P" {
			gen = 0
		}
		sig = append(sig, sigPart(tag, pv.Namespace, pv.Name, string(pv.UID), gen))
	}
	// Secrets are node-scoped least-exposure: only those referenced by an app pinned to this
	// node are pushed, so a node never receives credentials no workload of its uses. The set
	// is rebuilt on every push, so a rotation or a changed ref re-scopes automatically.
	storeRefs := map[string]struct{}{}      // namespace-qualified names of the SecretStores the pushed vault secrets name
	vaultSecretStore := map[string]string{} // vault-secret id -> its SecretStore id (for token gating)
	tokenStores := map[string]struct{}{}    // SecretStore ids whose auth method needs a workload token
	if len(referenced) > 0 {
		secrets, err := s.svc.List(ctx, resourceMeta("Secret"), metav1.ListOptions{})
		if err != nil {
			return nil, "", err
		}
		for _, obj := range secrets {
			sec, ok := obj.(*corev1.Secret)
			if !ok {
				continue
			}
			if _, want := referenced[corev1.WorkloadID(sec.Namespace, sec.Name)]; !want {
				continue
			}
			b, err := json.Marshal(sec)
			if err != nil {
				return nil, "", fmt.Errorf("marshal secret %q: %w", sec.Name, err)
			}
			ds.Secrets = append(ds.Secrets, b)
			sig = append(sig, sigPart("s", sec.Namespace, sec.Name, string(sec.UID), sec.Generation))
			if sec.Type == corev1.SecretTypeVault {
				if store := sec.Annotations[corev1.AnnExternalSecretStore]; store != "" {
					storeRefs[corev1.WorkloadID(sec.Namespace, store)] = struct{}{}
					vaultSecretStore[corev1.WorkloadID(sec.Namespace, sec.Name)] = corev1.WorkloadID(sec.Namespace, store)
				}
			}
		}
	}
	// SecretStores ride the same least-exposure rule one level down: only the stores a pushed
	// vault secret names, in that secret's own namespace. A store carries connection info only —
	// the value a vault secret stands for never transits this stream in either direction.
	if len(storeRefs) > 0 {
		stores, err := s.svc.List(ctx, secretStoreMeta(), metav1.ListOptions{})
		if err != nil {
			return nil, "", err
		}
		for _, obj := range stores {
			st, ok := obj.(*secretsv1.SecretStore)
			if !ok {
				continue
			}
			if _, want := storeRefs[corev1.WorkloadID(st.Namespace, st.Name)]; !want {
				continue
			}
			b, err := json.Marshal(st)
			if err != nil {
				return nil, "", fmt.Errorf("marshal secretstore %q: %w", st.Name, err)
			}
			ds.SecretStores = append(ds.SecretStores, b)
			sig = append(sig, sigPart("t", st.Namespace, st.Name, string(st.UID), st.Generation))
			if st.Spec.Auth.Method == secretsv1.AuthMethodKubernetes {
				tokenStores[corev1.WorkloadID(st.Namespace, st.Name)] = struct{}{}
			}
		}
	}
	// The routed address of every isolated workload on this node, chosen here and delivered with
	// the push. It is not stored on the Application: a workload's object is its author's
	// manifest, and this is the control plane's decision — the same reason a workload token
	// rides here rather than on the object.
	//
	// ONE range for the whole cluster, and no slice per node. An address is not tied to where it
	// runs: the datapath maps it to a node, and outside the fleet the flat range is announced as
	// one prefix. Slicing per node would have bought nothing the datapath does not already do,
	// and cost a renumbering every time a workload moved.
	//
	// Durability is the NODE's report: once a workload is wired, the node says so in its status,
	// and that is what a restarted control plane reads back to know which addresses are in use.
	// The in-memory map below only has to survive between the choice and that first report, which
	// is what the token cache beside it does too.
	if s.routedCIDR != "" {
		for _, appID := range slices.Sorted(maps.Keys(routedApps)) {
			addr, err := s.workloadAddress(appID, routedApps[appID], reported)
			if err != nil {
				log.Error().Err(err).Str("workload", appID).Msg("choose a routed address")
				continue
			}
			ds.WorkloadNetworks = append(ds.WorkloadNetworks, &nodeapipb.WorkloadNetwork{
				Workload: appUIDs[appID], Address: addr, Gateway: corev1.RoutedGateway,
			})
			sig = append(sig, sigPart("n", "", appID, addr, 0))
		}
	}
	// Workload-identity tokens: one per pinned app whose vault secrets ride a
	// kubernetes-method store — per-workload parity with the push filter (a token for path X
	// exists on node N only while an app using X is scheduled there). Minted by the controller
	// (the node must not self-mint), cached until the refresh margin so pushes stay
	// dedup-stable, and a mint failure holds back only that app's token — the app then fails
	// closed at login.
	if s.tokens != nil {
		// What each app is owed: the Vault audience when its secrets ride a kubernetes-method
		// store, plus every audience it mounts a token volume for. Gathered into one set so an
		// app asking for both is minted one token per door and not one token for two.
		wanted := map[string]map[string]struct{}{}
		if len(tokenStores) > 0 {
			for appID, refs := range appRefs {
				for _, ref := range refs {
					if st, ok := vaultSecretStore[ref]; ok {
						if _, tok := tokenStores[st]; tok {
							if wanted[appID] == nil {
								wanted[appID] = map[string]struct{}{}
							}
							wanted[appID][corev1.TokenAudienceVault] = struct{}{}
							break
						}
					}
				}
			}
		}
		for appID, auds := range appAudiences {
			if wanted[appID] == nil {
				wanted[appID] = map[string]struct{}{}
			}
			for _, a := range auds {
				wanted[appID][a] = struct{}{}
			}
		}
		for _, appID := range slices.Sorted(maps.Keys(wanted)) {
			for _, audience := range slices.Sorted(maps.Keys(wanted[appID])) {
				token, err := s.workloadToken(appID, appUIDs[appID], audience)
				if err != nil {
					log.Error().Err(err).Str("workload", appID).Str("audience", audience).
						Msg("mint workload token")
					continue
				}
				// Addressed by object UID because that is the node's key for a workload; the
				// token's own subject stays the namespace/name form a policy is written against.
				ds.WorkloadTokens = append(ds.WorkloadTokens, &nodeapipb.WorkloadToken{
					Workload: appUIDs[appID], Token: token, Audience: audience,
				})
				sum := sha256.Sum256([]byte(token))
				sig = append(sig, sigPart("w", audience, appID, hex.EncodeToString(sum[:8]), 0))
			}
		}
	}
	// The fleet's addressing, which is every node's business and not only this one's. It enters the
	// signature per entry rather than per object, because what it is built from is STATUS: a
	// workload's address is written by the node that wired it, and a status write deliberately does
	// not move a generation. Without these parts a new address on node B would change node A's
	// desired state without changing its signature, and A would learn where B's workload lives on
	// the next unconditional sweep — five minutes of a ClusterIP answering nothing.
	routes, services, err := s.fleetNetwork(ctx, apps)
	if err != nil {
		return nil, "", err
	}
	ds.Routes, ds.Services = routes, services
	for _, r := range routes {
		sig = append(sig, sigPart("r", "", r.GetCidr(), r.GetNodeIp(), 0))
	}
	for _, svc := range services {
		for _, b := range svc.GetBackends() {
			sig = append(sig, sigPart("v", svc.GetClusterIp(), fmt.Sprintf("%d/%s", svc.GetPort(), svc.GetProtocol()),
				fmt.Sprintf("%s:%d", b.GetAddress(), b.GetPort()), 0))
		}
	}
	return ds, desiredSignature(sig), nil
}

// fleetNetwork is what the datapath on ANY node needs to know: where each workload address lives,
// and what each ClusterIP balances onto. Both are computed per push from the objects rather than
// stored, for the reason the catalog gives — the inputs are already the source of truth, and a
// cached copy would be a second answer to "what is running" that can be wrong.
//
// A workload's address comes from its STATUS, because that is where it becomes durable: the control
// plane chooses one and delivers it in the push, and the node that wired it reports it back. So a
// workload appears here once it is actually wired somewhere, which is exactly when it is worth
// forwarding to.
//
// Readiness is not modelled, here or in the catalog: an instance that is scheduled and has an
// address is a backend. A failing workload therefore keeps receiving connections, which is the same
// answer service discovery gives today and is a single change to both when it stops being enough.
func (s *Server) fleetNetwork(ctx context.Context, apps []types.Object) ([]*netdapi.Route, []*netdapi.ServiceRule, error) {
	nodes, err := s.svc.List(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	nodeIP := map[string]string{}
	for _, obj := range nodes {
		if n, ok := obj.(*corev1.Node); ok {
			nodeIP[n.Name] = n.Status.IP
		}
	}

	// address is where an instance ANSWERS: its own routed address, or its node's when it is on the
	// host network. Both are cluster addresses and a Service fronts either — which is what makes a
	// ClusterIP work on a fleet that runs both kinds.
	address := func(app *corev1.Application) string {
		if app.Spec.Placement.NodeName == "" {
			return "" // unplaced: nothing is listening anywhere yet
		}
		if app.OnHostNetwork() {
			return nodeIP[app.Spec.Placement.NodeName]
		}
		return bareAddress(app.Status.Address)
	}

	var routes []*netdapi.Route
	for _, obj := range apps {
		app, ok := obj.(*corev1.Application)
		if !ok || app.OnHostNetwork() {
			continue // a workload on the host network is at its node's address and needs no route
		}
		cidr := hostRoute(app.Status.Address)
		if cidr == "" {
			continue // not wired yet, or wired at something this cannot route to
		}
		routes = append(routes, &netdapi.Route{Cidr: cidr, NodeIp: nodeIP[app.Spec.Placement.NodeName]})
	}
	slices.SortFunc(routes, func(a, b *netdapi.Route) int { return strings.Compare(a.GetCidr(), b.GetCidr()) })

	svcs, err := s.svc.List(ctx, resourceMeta("Service"), metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	var rules []*netdapi.ServiceRule
	for _, obj := range svcs {
		svc, ok := obj.(*corev1.Service)
		if !ok || svc.Spec.ClusterIP == "" {
			continue // a service with no address of its own is a catalog name and nothing to program
		}
		for _, port := range svc.Spec.Ports {
			var backends []*netdapi.Backend
			for _, ao := range apps {
				app, ok := ao.(*corev1.Application)
				if !ok || app.Namespace != svc.Namespace || app.Spec.ServiceName != svc.Name {
					continue
				}
				if addr := address(app); addr != "" {
					backends = append(backends, &netdapi.Backend{Address: addr, Port: port.TargetFor(app)})
				}
			}
			if len(backends) == 0 {
				// Left out rather than programmed empty: both make a connection to the ClusterIP
				// fail, and the smaller table is the one that says what exists.
				continue
			}
			slices.SortFunc(backends, func(a, b *netdapi.Backend) int {
				if c := strings.Compare(a.GetAddress(), b.GetAddress()); c != 0 {
					return c
				}
				return int(a.GetPort() - b.GetPort())
			})
			rules = append(rules, &netdapi.ServiceRule{
				ClusterIp: svc.Spec.ClusterIP, Port: port.Port, Protocol: port.Protocol, Backends: backends,
			})
		}
	}
	slices.SortFunc(rules, func(a, b *netdapi.ServiceRule) int {
		if c := strings.Compare(a.GetClusterIp(), b.GetClusterIp()); c != 0 {
			return c
		}
		return int(a.GetPort() - b.GetPort())
	})
	return routes, rules, nil
}

// bareAddress and hostRoute read the address a NODE reported, which is in CIDR form — the same form
// it was handed in the push, because a workload's address and the prefix it is configured with are
// one field on the wire.
//
// They normalise rather than assume. Appending "/32" to what already carried one produced
// "10.244.0.1/32/32", and netd refused the node's WHOLE forwarding state over it: every route and
// every service, on every node, for one malformed string. Found on a stand and not in a test,
// because the test had agreed with the code about the shape instead of with what a node sends.
//
// Empty is the answer for anything unparseable, including the empty string a workload has before it
// is wired. Both are the same fact — there is no address to route to — and neither is an error
// worth failing a push for.
func bareAddress(reported string) string {
	if p, err := netip.ParsePrefix(reported); err == nil {
		return p.Addr().String()
	}
	if a, err := netip.ParseAddr(reported); err == nil {
		return a.String()
	}
	return ""
}

// hostRoute is that address as the route to it: always a single host, never a block. The addresses
// are one flat range with no per-node slice, so a wider prefix would be a claim that a whole block
// sits behind one node — which is the arrangement the datapath exists to avoid, and which netd
// refuses on arrival anyway.
func hostRoute(reported string) string {
	addr := bareAddress(reported)
	if addr == "" {
		return ""
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	return netip.PrefixFrom(a, a.BitLen()).String()
}

// sigPart formats one object's contribution to the desired-state signature: kind tag, identity,
// uid and generation, NUL-separated so no name/namespace boundary can be forged by a crafted
// value. The uid is what makes the identity complete: generation restarts at 1 on create and a
// (namespace, name) slot is reused, so a delete-and-recreate under the same name reproduced a
// byte-identical part and the push was skipped as "unchanged" — the node kept running the old
// spec, old image and old secret while the API reported the new one.
func sigPart(kind, namespace, name, uid string, generation int64) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d", kind, corev1.WorkloadID(namespace, name), uid, generation)
}

// desiredSignature hashes the (order-independent) set of object signature parts into a stable token:
// the desired state is a set, so the parts are sorted before hashing and adding/removing an object
// moves the token.
func desiredSignature(parts []string) string {
	slices.Sort(parts)
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// applyStatus persists the status the agent reported, creating the Node on first
// registration. The write goes through the service, so admission (defaulting, …) still
// applies. Two confinements guard this credential-less stream, where NodeRestriction is
// a no-op: a node may only report its own Node (the name-vs-CN check), and a heartbeat is
// routed through the status subresource so it writes only Node.status and can never
// clobber Node.spec — an operator's cordon (Unschedulable), Maintenance or net-config.
func (s *Server) applyStatus(ctx context.Context, node string, nodeJSON []byte) error {
	// Decode to the TYPED Node and check that, rather than probing the raw JSON for
	// metadata.name. A raw probe reads one exact key while encoding/json folds field names, so a
	// body carrying both "name" and a folded spelling of it passes a probe that sees the honest
	// one and then decodes to the other — on this path that would let a node report status for a
	// DIFFERENT node, and the CN comparison is the only thing standing here.
	var n corev1.Node
	if err := json.Unmarshal(nodeJSON, &n); err != nil {
		return fmt.Errorf("decode node status: %w", err)
	}
	if n.Name != node {
		return fmt.Errorf("reported node %q does not match identity %q", n.Name, node)
	}
	// The heartbeat is stamped HERE, not taken from the node. Receipt of this message is the
	// heartbeat — the node's own clock carries nothing the controller does not already know — and
	// an unbounded node-supplied timestamp was a liveness bypass: both staleness checks compare a
	// signed duration against a timeout, so a value in the FUTURE is never stale. A node could
	// pin itself permanently Ready and schedulable, in the scheduler and in `kubectl get nodes`
	// alike, then disconnect and keep attracting work. There is no liveness controller to notice.
	n.Status.Heartbeat = metav1.Now()
	// Capacity is self-reported and believed by the scheduler's Filter and Score — and by the
	// admission capacity check, which reads this same number and so can never contradict it. A
	// ceiling stops one compromised node certificate from becoming a placement oracle that wins
	// every cycle in every namespace and collects the Secrets of everything placed on it.
	clampCapacity(&n)
	// The derived placement labels are COMPUTED here, for the same reason the heartbeat is
	// stamped here: a node able to send its own would be choosing which workloads it attracts.
	// Recomputed on every report rather than only at registration, so a machine re-imaged onto
	// another architecture stops matching the rules that named the old one — and so the set
	// stays correct when the derivation later gains a label it does not have today.
	n.Status.Labels = corev1.DerivedNodeLabels(&n)
	nodeJSON, err := json.Marshal(&n)
	if err != nil {
		return err
	}
	// "" is the namespace this path is authoritative about: Node is cluster-scoped. A body
	// carrying one is refused rather than quietly accepted — that is how a node used to create an
	// unaddressable namespaced shadow of its own Node, which no API route can reach and which
	// therefore takes cordon and delete away as containment levers.
	_, err = s.svc.UpdateSubresource(ctx, nodeGVK, "status", nodeJSON, "")
	if apierrors.IsNotFound(err) {
		// This is the node's FIRST registration — the moment the cluster decides that this name
		// belongs to this machine. Under strict registration it has to prove it (reverse DNS);
		// otherwise the certificate alone is the claim.
		if err := s.checkRegistration(ctx, node); err != nil {
			return err
		}
		// The node self-creates its Node from the reported STATUS only.
		// Strip any spec the agent sent so this credential-less path (where NodeRestriction is
		// a no-op) cannot seed spec.labels/unschedulable/networks — the fields an operator owns
		// and NodeRestriction exists to protect. The invariant is enforced, not trusted.
		//
		// It is created CORDONED. The controller cannot tell a first join from a machine an
		// operator has just removed from the fleet — the deleted object took the only record of
		// either with it — and the reported status alone (Ready, capacity, a heartbeat stamped
		// here) is enough for the scheduler to start placing other tenants' Applications, and
		// their Secrets, on it within one heartbeat. So an unrecognised machine joins
		// unschedulable and an operator admits it explicitly (`kubectl uncordon <node>`); a
		// cordon on a LIVE Node is untouched by this path, since a heartbeat writes only status.
		n.Spec = corev1.NodeSpec{Unschedulable: true}
		statusOnly, merr := json.Marshal(n)
		if merr != nil {
			return merr
		}
		if _, err = s.svc.Create(ctx, nodeGVK, statusOnly, ""); err == nil {
			log.Warn().Str("node", node).
				Msg("node registered itself and is cordoned; uncordon it to admit it to the fleet")
		}
	}
	return err
}

// nodeRegistered reports whether node's Node object exists. It is the fleet-membership check on
// the desired-state path: a node the operator has deleted is not served until it registers again
// (and it registers cordoned, see applyStatus).
func (s *Server) nodeRegistered(ctx context.Context, node string) (bool, error) {
	_, err := s.svc.Get(ctx, types.ObjectMeta{
		ApiVersion: corev1.GroupVersion.String(), Kind: "Node", Name: node,
	})
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	default:
		return false, err
	}
}

// applyAppStatus persists the runtime status a node reported for one of its Applications, through
// the status subresource so admission runs. Own-node confinement: a node may only report status
// for an application actually pinned to it (spec.nodeName == the peer CN), so it cannot forge or
// clobber the status of another node's workload.
func (s *Server) applyAppStatus(ctx context.Context, node string, as *nodeapipb.AppStatus) error {
	meta := types.ObjectMeta{
		ApiVersion: corev1.GroupVersion.String(), Kind: "Application",
		Namespace: as.GetNamespace(), Name: as.GetName(),
	}
	obj, err := s.svc.Get(ctx, meta)
	if err != nil {
		return nil // app deleted between the push and the report; nothing to update
	}
	app, ok := obj.(*corev1.Application)
	if !ok {
		return nil
	}
	if app.Spec.Placement.NodeName != node {
		return fmt.Errorf("reported application %s/%s is pinned to %q, not the reporting node %q",
			as.GetNamespace(), as.GetName(), app.Spec.Placement.NodeName, node)
	}
	app.Status = corev1.ApplicationStatus{
		ObservedGeneration: as.GetObservedGeneration(),
		Phase:              as.GetPhase(),
		Message:            as.GetMessage(),
		// What the node says it wired the workload at. The control plane chose it and sent it
		// down; this is the confirmation, and the only durable record of the choice.
		Address: as.GetAddress(),
		// The retry budget's ledger, stored even while the job is still running: this is the
		// only record that outlives the transient unit, so writing it once at the end would
		// hand a job interrupted mid-budget — by a reboot, or by the agent restarting — a
		// fresh budget every time.
		Attempts: as.GetAttempts(),
	}
	// How it finished, kept only for a workload that HAS finished: the node sends zeroes for a
	// running one, and a stored exitCode of 0 would read as a success that never happened.
	if corev1.TerminalPhase(as.GetPhase(), app.Spec.Lifecycle, as.GetAttempts()) {
		code := as.GetExitCode()
		app.Status.ExitCode = &code
		if ns := as.GetFinishedAtUnixNano(); ns > 0 {
			app.Status.FinishedAt = metav1.NewTime(time.Unix(0, ns))
		}
	}
	b, err := json.Marshal(app)
	if err != nil {
		return err
	}
	if _, err := s.svc.UpdateSubresource(ctx, appGVK, "status", b, app.Namespace); err != nil {
		return err
	}
	return s.releaseTeardown(ctx, meta, app, as.GetPhase())
}

// releaseTeardown drops the node-teardown finalizer once the node says the workload is gone, and
// erases the object when nothing else is holding it.
//
// This is the moment the two-phase deletion exists for: the object is removed because a node
// REPORTED the workload gone, not because a controller assumed it would be. Until this report the
// object stayed, carrying the spec — which is how the node still had the author's grace period to
// stop with, and how an operator could see a Terminating workload at all.
//
// The finalizer write goes through the normal update path: the node-server carries no authn
// identity, so the guard that keeps finalizers out of client hands is a no-op for it, and the
// erase then reuses Delete, which finds an empty list and erases for real.
func (s *Server) releaseTeardown(ctx context.Context, meta types.ObjectMeta, app *corev1.Application, phase string) error {
	if phase != corev1.AppPhaseTerminated || !app.Deleting() {
		return nil
	}
	kept := slices.DeleteFunc(slices.Clone(app.Finalizers),
		func(f string) bool { return f == corev1.FinalizerNodeTeardown })
	if len(kept) == len(app.Finalizers) {
		return nil // this node was not what the object was waiting for
	}
	app.Finalizers = kept
	b, err := json.Marshal(app)
	if err != nil {
		return err
	}
	if _, err := s.svc.Update(ctx, appGVK, b, app.Namespace, app.Name); err != nil {
		return err
	}
	if len(kept) > 0 {
		return nil // something else still holds it; whoever that is will erase it
	}
	return s.svc.Delete(ctx, meta, metav1.DeleteOptions{})
}

// resourceMeta addresses a core-group resource by kind for List/Watch.
func resourceMeta(kind string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: kind}
}

// secretStoreMeta addresses the secrets-group SecretStore resource for List/Watch.
func secretStoreMeta() types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: secretsv1.GroupVersion.String(), Kind: "SecretStore"}
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
	// Read identity from the CA-VERIFIED chain, not the raw PeerCertificates (which are populated
	// even for an unverified/self-signed cert): the CN/Organization must come from a cert the
	// controller's client CA actually vouched for.
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", nil, errors.New("client certificate was not verified against the CA")
	}
	leaf := chains[0][0]
	cn := leaf.Subject.CommonName
	if len(cn) == 0 {
		return "", nil, errors.New("client certificate has no common name")
	}
	// The CN becomes a Node's metadata.name: it is what the status path is checked against and
	// what every desired-state push is keyed by. So it has to be a name the API could have
	// addressed in the first place — a mis-issued cert whose CN carries a slash or a traversal
	// would otherwise name an object no route can reach, or a different one than it appears to.
	if msgs := validation.IsDNS1123Subdomain(cn); len(msgs) > 0 {
		return "", nil, fmt.Errorf("certificate common name %q is not a valid node name: %s", cn, msgs[0])
	}
	return cn, leaf.Subject.Organization, nil
}

// clampCapacity holds a node's self-reported capacity to a sanity ceiling, so an absurd value
// cannot make the node look infinitely free to the scheduler. Clamped rather than rejected: a
// node that reports nonsense should stop dominating placement, not stop reporting at all.
func clampCapacity(n *corev1.Node) {
	if cpu := n.Status.Capacity.CPU.Value(); cpu > corev1.MaxReportedCPU {
		log.Warn().Str("node", n.Name).Int64("reported", cpu).Int64("ceiling", corev1.MaxReportedCPU).
			Msg("node reported more CPU than the ceiling; clamping")
		n.Status.Capacity.CPU = *resource.NewQuantity(corev1.MaxReportedCPU, resource.DecimalSI)
	}
	if mem := n.Status.Capacity.Memory.Value(); mem > corev1.MaxReportedMemory {
		log.Warn().Str("node", n.Name).Int64("reported", mem).Int64("ceiling", corev1.MaxReportedMemory).
			Msg("node reported more memory than the ceiling; clamping")
		n.Status.Capacity.Memory = *resource.NewQuantity(corev1.MaxReportedMemory, resource.BinarySI)
	}
}
