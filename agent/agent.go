package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ks-tool/horchestra/agent/network"
	"github.com/ks-tool/horchestra/agent/runtime"
	"github.com/ks-tool/horchestra/agent/secret"
	"github.com/ks-tool/horchestra/agent/volume"
	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	netdapi "github.com/ks-tool/horchestra/api/netd"
	nodeapipb "github.com/ks-tool/horchestra/api/node"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// Agent is the node agent: it maintains an mTLS session to the controller, applies
// the resources pinned to this node onto it through its two injected mechanisms (the
// Runtime that runs workloads and the Volumes that back their storage) and streams
// service logs back on request. The mechanisms are injected at construction, so the
// agent owns the reconcile algorithm but none of the OS-specific implementations.
type Agent struct {
	// controller session (transport)
	endpoint   string
	creds      credentials.TransportCredentials
	node       string
	controller string

	// reconcile config and in-memory state — never persisted; actual state is read
	// back from the runtime itself, so a reboot self-heals.
	limits corev1.ResourceAmounts
	want   map[string]workload.App
	// applied is the metadata.generation the runtime last CONVERGED for each workload id —
	// set only after a successful Apply, so a node that cannot bring a new spec up keeps
	// reporting the generation it is actually running. It is what lets the control plane
	// tell "running the new spec" from "still running the old one"; phase cannot, because
	// the previous workload stays up while the new one fails to start.
	applied map[string]int64
	// unmeasured is the workloads whose usage the runtime could not sample, so the reason is
	// logged on the transition rather than on every heartbeat.
	unmeasured map[string]struct{}
	// observed is what the runtime last reported holding, keyed by workload id. Both halves of
	// a report read it — each application's phase and this node's own allocation — so the two
	// cannot disagree about what is running.
	observed map[string]workload.State
	// stateMu guards want, applied and observed. They are written by the converge goroutine and
	// read by the heartbeat one, which is the price of the two no longer being the same
	// goroutine — and a price worth paying, since what they used to share was a stall.
	stateMu sync.Mutex

	// the mechanisms this module drives, injected by the application: the Runtime
	// (agent/runtime) that runs workloads, the Volumes (agent/volume) that back storage, and the
	// Secrets (agent/secret) that materialize referenced credentials.
	runtime runtime.Runtime
	volumes volume.Volumes
	secrets secret.Secrets
	// network gives an isolated workload an address, through the privileged helper. Nil on a node
	// with no helper, which is every node today: every workload shares the host's network.
	network network.Network
}

// NewAgent builds a node agent from the node's REST client config (its kubeconfig)
// and its two mechanisms. It normalizes the controller URL from the config's host,
// takes the node identity from the client certificate (see nodeIdentity), and
// prepares the mTLS dialer via the standard client-go TLS config. The runtime and
// volumes implementations are the application's — an OCI+overlay+systemd runtime and
// a local-directory volume driver today (agent/runtime, agent/volume).
func NewAgent(cfg *rest.Config, nodeCfg NodeConfig, runtime runtime.Runtime, volumes volume.Volumes, secrets secret.Secrets, net network.Network) (*Agent, error) {
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
	name, err := nodeIdentity(cfg)
	if err != nil {
		return nil, err
	}
	// Bind the Secrets mechanism to the identity the CONTROLLER authorized: from here on it
	// unseals a Secret only for an Application whose spec.nodeName is this CN.
	if nb, ok := secrets.(secret.NodeBound); ok {
		nb.BindNode(name)
	}
	// And to the CA it verifies its own connection with, which is what a workload holding a
	// projected token needs to verify the same control plane. One bundle, not a second copy
	// somebody keeps in step by hand.
	if cb, ok := secrets.(secret.CABound); ok {
		cb.BindCA(clusterCA(cfg))
	}
	a := &Agent{
		endpoint:   endpoint,
		creds:      credentials.NewTLS(tlsConfig),
		node:       name,
		controller: controller,
		limits:     nodeCfg.Resources,
		runtime:    runtime,
		volumes:    volumes,
		secrets:    secrets,
		network:    net,
	}
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
	// The reaper runs on the OUTER context, deliberately outside every session. Finishing a stop
	// that has already outstayed its own budget needs no desired state — the unit is one this
	// agent decided to end — and a workload that discards SIGTERM (which is every workload
	// without a signal handler: it is PID 1 of its namespace) would otherwise stand in
	// final-sigterm for as long as the controller is unreachable, holding its name, its cgroup
	// and its rootfs mount, with nothing on the node ever coming back for it.
	go a.reap(ctx, heartbeat)
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

// reap asks the runtime to finish stalled stops, on the same interval the node reports itself.
// A failure is logged at debug and nothing else: the pass is a repair, not an obligation, and a
// runtime that cannot answer right now will be asked again on the next tick.
func (a *Agent) reap(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.runtime.Reap(ctx); err != nil && ctx.Err() == nil {
				log.Debug().Err(err).Msg("agent: could not finish stalled stops this pass")
			}
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

	stream, err := nodeapipb.NewNodeServiceClient(conn).Session(sctx)
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	log.Info().Str("controller", a.endpoint).Str("node", a.node).Msg("node-agent session established")

	// A single sender goroutine serializes stream.Send (a gRPC stream is not safe
	// for concurrent Send).
	sendCh := make(chan *nodeapipb.NodeMessage, 8)
	var wg sync.WaitGroup
	wg.Go(func() {
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
	})

	// latest is the most recent desired state; the converge goroutine applies it both on a push
	// (trigger) and on a tick (a periodic self-heal that repairs a unit that died or drifted
	// between pushes). Every Reconcile runs from that one goroutine, so they serialize; what it
	// shares with the heartbeat goroutine is guarded by stateMu.
	var mu sync.Mutex
	var latest *desiredState
	trigger := make(chan struct{}, 1)
	signal := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}

	// The heartbeat is its OWN goroutine, and that is the whole point of it being one.
	//
	// It used to be the last statement of the converge loop, which made a node's liveness a
	// hostage of its slowest workload: one unit whose stop never completed blocked the converge,
	// the heartbeat never went out, the controller aged the node out as unreachable, and the
	// scheduler stopped placing work on the WHOLE FLEET because no node looked alive. A node
	// that is up must say so even while it is failing to converge — those are different facts,
	// and reporting the second as the first cost a live cluster its ability to schedule.
	wg.Go(func() {
		t := time.NewTicker(heartbeat)
		defer t.Stop()
		enqueue(sctx, sendCh, a.statusMessage()) // register
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
			}
			enqueue(sctx, sendCh, a.statusMessage())
		}
	})

	wg.Go(func() {
		t := time.NewTicker(heartbeat)
		defer t.Stop()
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
				// The node's forwarding state first, then the workloads that use it: a workload
				// started before its ClusterIPs are programmed spends its first connections
				// failing, and a workload is what starts, not what is programmed.
				a.configureNetwork(sctx, d.routes, d.services)
				if err := a.Reconcile(sctx, d.apps, d.pvs, d.secrets, d.stores, d.tokens, d.networks); err != nil {
					log.Error().Err(err).Msg("apply desired state")
				}
				for _, m := range a.appStatusMessages(sctx) {
					enqueue(sctx, sendCh, m)
				}
				for _, m := range a.appMetricsMessages(sctx) {
					enqueue(sctx, sendCh, m)
				}
				if u, ok := nodeUsage(); ok {
					enqueue(sctx, sendCh, &nodeapipb.NodeMessage{Body: &nodeapipb.NodeMessage_NodeUsage{NodeUsage: &nodeapipb.NodeUsage{
						CpuUsec: u.CPUUsec, MemoryUsedBytes: u.MemoryBytes, MemoryTotalBytes: u.MemoryPeakBytes,
						TimestampUnixNano: u.At.UnixNano(),
					}}})
				}
			}
		}
	})

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
			d, decodeErr := decodeDesired(msg.GetDesired())
			if decodeErr != nil {
				log.Error().Err(decodeErr).Msg("decode desired state")
				break
			}
			mu.Lock()
			latest = d
			mu.Unlock()
			signal()
		case msg.GetLogRequest() != nil:
			req := msg.GetLogRequest()
			lctx, lcancel := context.WithCancel(sctx)
			logMu.Lock()
			logs[req.GetId()] = lcancel
			logMu.Unlock()
			go func() {
				a.streamUnitLogs(lctx, sctx, sendCh, req)
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
	apps    []corev1.Application
	pvs     []corev1.PersistentVolume
	secrets []corev1.Secret
	stores  []secretsv1.SecretStore
	tokens  map[string]map[string]string // workload id -> audience -> its identity JWT (in memory only)
	// networks is what the control plane chose for each isolated workload, keyed by workload id.
	// It arrives with the push and is never stored: the node wires it and reports it back, and
	// that report is what makes the choice durable.
	networks map[string]*nodeapipb.WorkloadNetwork
	// routes and services are the node's whole forwarding state, passed to the helper untouched.
	// The agent reads neither: it holds no capability to act on them and no opinion about them.
	routes   []*netdapi.Route
	services []*netdapi.ServiceRule
}

// enqueue offers msg to the sender, giving up if the session is ending (so the
// heartbeat never blocks on a full channel during teardown).
func enqueue(ctx context.Context, ch chan<- *nodeapipb.NodeMessage, msg *nodeapipb.NodeMessage) {
	select {
	case ch <- msg:
	case <-ctx.Done():
	}
}

// streamUnitLogs opens the application service's log stream through the Units port and forwards
// its output up the session as LogChunks tagged with the request id, ending with an eof chunk (or
// an error chunk if the stream could not be opened). reqCtx (a LogCancel, or the session ending)
// stops the read and the data chunks; the terminating eof/error chunk is enqueued against sessCtx
// so a LogCancel still delivers the eof that closes the controller-side stream — it is dropped
// only when the whole session is ending.
func (a *Agent) streamUnitLogs(reqCtx, sessCtx context.Context, sendCh chan<- *nodeapipb.NodeMessage, req *nodeapipb.LogRequest) {
	logs := a.runtime.Logs
	if req.GetNodeUnit() {
		logs = agentUnitLogs
	}
	rc, err := logs(reqCtx, req.GetApp(), req.GetFollow(), req.GetTailLines())
	if err != nil {
		enqueueLog(sessCtx, sendCh, req.GetId(), nil, true, err.Error())
		return
	}
	defer func() { _ = rc.Close() }()
	buf := make([]byte, 8192)
	for {
		n, rerr := rc.Read(buf)
		if n > 0 {
			enqueueLog(reqCtx, sendCh, req.GetId(), append([]byte(nil), buf[:n]...), false, "")
		}
		if rerr != nil {
			break
		}
	}
	enqueueLog(sessCtx, sendCh, req.GetId(), nil, true, "")
}

func enqueueLog(ctx context.Context, sendCh chan<- *nodeapipb.NodeMessage, id string, data []byte, eof bool, errMsg string) {
	enqueue(ctx, sendCh, &nodeapipb.NodeMessage{Body: &nodeapipb.NodeMessage_LogChunk{
		LogChunk: &nodeapipb.LogChunk{Id: id, Data: data, Eof: eof, Error: errMsg},
	}})
}

// appStatusMessages reports the runtime status of every application pinned to this node, as the
// runtime observes it: Running, Succeeded for a job that ran and exited zero, Failed when the
// workload is wanted and the node is not running it (a crash, a failed job, or a converge error).
// The controller persists each onto its Application's status.
//
// A workload the runtime holds no unit for at all is Failed rather than absent: it is wanted, and
// the node is not running it, which is the same fact however it came about.
func (a *Agent) appStatusMessages(ctx context.Context) []*nodeapipb.NodeMessage {
	observed := a.observe(ctx)
	out := make([]*nodeapipb.NodeMessage, 0, len(a.want))
	for id, app := range a.want {
		state, held := observed[id]
		phase := corev1.AppPhaseFailed
		if state.Phase != "" {
			phase = state.Phase
		}
		// A workload whose object is going away reports on the teardown, not on the workload:
		// Failed would be a lie about a stop that is proceeding exactly as asked. Terminated is
		// what releases the object — it says this node holds nothing for it any more — so it is
		// reported only once the runtime lists no unit at all.
		if app.Deleting {
			phase = corev1.AppPhaseTerminating
			if !held {
				phase = corev1.AppPhaseTerminated
			}
		}
		msg := ""
		// A credential the node could not refresh does not stop the workload — it keeps
		// running on the last good value — so nothing else would say it happened. Reported
		// here, on the object an operator looks at, rather than only in this node's journal.
		if stale, ok := a.secrets.(secret.Stale); ok {
			if d, aging := stale.StaleApps()[id]; aging {
				msg = fmt.Sprintf("running on a stale secret: the node has not refreshed it for %s", d.Round(time.Second))
			}
		}
		// A job's own message says why it is over when the runtime can tell — the reason is
		// otherwise unreachable: a deadline kill and a crash both land on a non-zero exit.
		if state.Reason != "" {
			msg = state.Reason
		}
		st := &nodeapipb.AppStatus{
			Namespace: app.Namespace, Name: app.Name, Phase: phase, Message: msg,
			ObservedGeneration: a.applied[id], Attempts: state.Attempts,
			// What this node actually wired it at. Reported only while the workload is up: an
			// address on a workload that is not running would read as a place to reach it.
			Address: wiredAddress(app, phase),
		}
		if corev1.TerminalPhase(phase, app.Lifecycle, state.Attempts) {
			st.ExitCode = state.ExitCode
			if !state.FinishedAt.IsZero() {
				st.FinishedAtUnixNano = state.FinishedAt.UnixNano()
			}
		}
		out = append(out, &nodeapipb.NodeMessage{Body: &nodeapipb.NodeMessage_AppStatus{AppStatus: st}})
	}
	return out
}

// observe asks the runtime what it actually holds, keyed by workload id. It is the one question
// both halves of a heartbeat answer from — each application's phase and the node's own
// allocation — so they cannot disagree about what this node is running.
func (a *Agent) observe(ctx context.Context) map[string]workload.State {
	states, _ := a.runtime.States(ctx)
	out := make(map[string]workload.State, len(states))
	for _, s := range states {
		out[s.ID] = s
	}
	a.stateMu.Lock()
	a.observed = out
	a.stateMu.Unlock()
	return out
}

// statusMessage is this node's current status as a NodeMessage carrying the full
// Node object (metadata + status) as JSON.
func (a *Agent) statusMessage() *nodeapipb.NodeMessage {
	node := corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{Name: a.node},
		Status:     a.nodeStatus(),
	}
	b, _ := json.Marshal(&node)
	return &nodeapipb.NodeMessage{Body: &nodeapipb.NodeMessage_Status{Status: &nodeapipb.NodeStatus{Node: b}}}
}

// wiredAddress is the routed address this workload runs at, or empty for one on the host network
// or one that is not running. It is the node's OBSERVATION — the control plane chose it and sent it
// down, and this is the node saying it is so, which is what makes the choice durable.
func wiredAddress(app workload.App, phase string) string {
	if app.HostNetwork || phase != corev1.AppPhaseRunning {
		return ""
	}
	return app.Address
}

// decodeDesired decodes the pushed desired state into the API kinds the Reconciler
// consumes.
// clusterCA is the CA PEM the agent's own client config trusts, inline or from its file. Empty
// when neither is set, in which case a token volume simply carries no ca.crt — a mount that is
// missing a file is debuggable, one carrying an empty trust bundle is not.
func clusterCA(cfg *rest.Config) []byte {
	if len(cfg.TLSClientConfig.CAData) > 0 {
		return cfg.TLSClientConfig.CAData
	}
	if cfg.TLSClientConfig.CAFile != "" {
		if b, err := os.ReadFile(cfg.TLSClientConfig.CAFile); err == nil {
			return b
		}
	}
	return nil
}

func decodeDesired(d *nodeapipb.DesiredState) (*desiredState, error) {
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
	secrets := make([]corev1.Secret, 0, len(d.GetSecrets()))
	for _, b := range d.GetSecrets() {
		var sec corev1.Secret
		if err := json.Unmarshal(b, &sec); err != nil {
			continue
		}
		secrets = append(secrets, sec)
	}
	stores := make([]secretsv1.SecretStore, 0, len(d.GetSecretStores()))
	for _, b := range d.GetSecretStores() {
		var st secretsv1.SecretStore
		if err := json.Unmarshal(b, &st); err != nil {
			continue
		}
		stores = append(stores, st)
	}
	networks := make(map[string]*nodeapipb.WorkloadNetwork, len(d.GetWorkloadNetworks()))
	for _, n := range d.GetWorkloadNetworks() {
		networks[n.GetWorkload()] = n
	}
	tokens := make(map[string]map[string]string, len(d.GetWorkloadTokens()))
	for _, t := range d.GetWorkloadTokens() {
		if tokens[t.GetWorkload()] == nil {
			tokens[t.GetWorkload()] = map[string]string{}
		}
		tokens[t.GetWorkload()][t.GetAudience()] = t.GetToken()
	}
	return &desiredState{
		apps: apps, pvs: pvs, secrets: secrets, stores: stores, tokens: tokens, networks: networks,
		routes: d.GetRoutes(), services: d.GetServices(),
	}, nil
}

// appMetricsMessages samples what each workload on this node has consumed.
//
// Sampled on the heartbeat rather than on demand, because a cgroup dies with its unit: a
// workload OOM-killed between two ticks leaves nothing to ask afterwards, and the last sample
// before it went is the only evidence of why. A workload the runtime cannot measure — not
// running, or a runtime with no accounting — contributes nothing, since a zero sample is
// indistinguishable from a workload using nothing at all.
func (a *Agent) appMetricsMessages(ctx context.Context) []*nodeapipb.NodeMessage {
	out := make([]*nodeapipb.NodeMessage, 0, len(a.want))
	for id, app := range a.want {
		u, err := a.runtime.Metrics(ctx, id)
		if err != nil {
			// Skipped, not failed — but SAID ONCE. A collector that is broken for every
			// workload looks exactly like a fleet nobody is measuring, and silence is how a
			// wrong D-Bus interface went unnoticed until a live run had no numbers at all.
			if a.unmeasured == nil {
				a.unmeasured = map[string]struct{}{}
			}
			if _, said := a.unmeasured[id]; !said {
				a.unmeasured[id] = struct{}{}
				log.Warn().Err(err).Str("app", app.Namespace+"/"+app.Name).Msg("no usage sample for this workload")
			}
			continue
		}
		delete(a.unmeasured, id)
		out = append(out, &nodeapipb.NodeMessage{Body: &nodeapipb.NodeMessage_AppMetrics{AppMetrics: &nodeapipb.AppMetrics{
			Namespace: app.Namespace, Name: app.Name,
			CpuUsec: u.CPUUsec, CpuThrottledUsec: u.CPUThrottledUsec,
			MemoryBytes: u.MemoryBytes, MemoryPeakBytes: u.MemoryPeakBytes,
			Pids: u.PIDs, OomKills: u.OOMKills,
			TimestampUnixNano: u.At.UnixNano(),
		}}})
	}
	return out
}

// nodeIdentity is the node's name, and its ONLY source is the CN of the client certificate the
// control plane authenticates the session with. There is no flag and no fallback on purpose: the
// name decides which Applications this node is served, which Node object its status writes, and —
// since the Secrets mechanism is bound to it — whose credentials it may unseal. A host-supplied
// name would be the node naming itself, while the CN is what the cluster CA vouched for and what
// the controller independently reads off the same certificate.
//
// The CN must be a DNS name (RFC1123), because that is what a node name is: the controller refuses
// a session whose CN is not one, and an operator has to be able to reach the host by it. A CN that
// is not this host's own hostname is warned about here and nothing more: a node cannot be trusted
// to police its own name, so enforcing that a node's CN really is the host's DNS name is the
// CONTROLLER's job (see its --require-node-dns), which resolves the name against the address the
// session comes from.
func nodeIdentity(cfg *rest.Config) (string, error) {
	certPEM, err := clientCertPEM(cfg)
	if err != nil {
		return "", err
	}
	if len(certPEM) == 0 {
		return "", fmt.Errorf("agent: the node credentials carry no client certificate, so this node has no identity")
	}
	cn, err := certCN(certPEM)
	if err != nil {
		return "", err
	}
	if msgs := validation.IsDNS1123Subdomain(cn); len(msgs) > 0 {
		return "", fmt.Errorf("agent: certificate common name %q is not a DNS name: %s", cn, msgs[0])
	}
	warnHostnameMismatch(cn)
	return cn, nil
}

// warnHostnameMismatch reports a CN that is not this host's hostname. It is a warning, never a
// refusal: the check that matters is the controller's, which resolves the CN and compares it with
// the address the session arrives from — something the node cannot fake by editing its own config.
func warnHostnameMismatch(cn string) {
	host, err := os.Hostname()
	if err != nil || host == "" || sameHost(cn, host) {
		return
	}
	log.Warn().Str("cn", cn).Str("hostname", host).
		Msg("the node certificate's CN is not this host's hostname; a node name should be the host's real DNS name")
}

// sameHost reports whether cn names this host: equal, or one is the other's first label (a short
// hostname against an FQDN).
func sameHost(cn, hostname string) bool {
	cn, hostname = strings.ToLower(cn), strings.ToLower(hostname)
	if cn == hostname {
		return true
	}
	shortCN, _, _ := strings.Cut(cn, ".")
	shortHost, _, _ := strings.Cut(hostname, ".")
	return shortCN == shortHost
}
