package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	nodeapipb "github.com/ks-tool/horchestra/api/node"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
)

// fakeServer is an in-process NodeService: it pushes ControllerMessages down to the
// agent (via push) and surfaces the NodeMessages the agent sends up (Status/LogChunk)
// on buffered channels the tests drain.
type fakeServer struct {
	nodeapipb.UnimplementedNodeServiceServer
	push     chan *nodeapipb.ControllerMessage
	statuses chan *nodeapipb.NodeStatus
	chunks   chan *nodeapipb.LogChunk
}

func newFakeServer() *fakeServer {
	return &fakeServer{
		push:     make(chan *nodeapipb.ControllerMessage, 8),
		statuses: make(chan *nodeapipb.NodeStatus, 256),
		chunks:   make(chan *nodeapipb.LogChunk, 256),
	}
}

func (s *fakeServer) Session(stream grpc.BidiStreamingServer[nodeapipb.NodeMessage, nodeapipb.ControllerMessage]) error {
	ctx := stream.Context()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			case msg := <-s.push:
				if err := stream.Send(msg); err != nil {
					return
				}
			}
		}
	})
	err := func() error {
		for {
			msg, err := stream.Recv()
			if err != nil {
				return err
			}
			switch {
			case msg.GetStatus() != nil:
				select {
				case s.statuses <- msg.GetStatus():
				case <-ctx.Done():
					return ctx.Err()
				}
			case msg.GetLogChunk() != nil:
				select {
				case s.chunks <- msg.GetLogChunk():
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}()
	close(done)
	wg.Wait()
	return err
}

// fakeRuntime records Apply and Logs calls (both surfaced on a buffered channel via a
// non-blocking send, so the reconcile/heartbeat worker never stalls on an undrained
// test) and returns a canned log stream.
type fakeRuntime struct {
	mu      sync.Mutex
	applied []workload.App
	// states is what the runtime reports holding, so a test can make a workload look running,
	// finished or failed without an init system.
	states    []workload.State
	logged    []string
	applyCh   chan workload.App
	logCh     chan string
	logClosed chan struct{} // closed when a follow stream's reader is torn down
	// reaps counts the local-teardown passes, which run outside every session.
	reaps     int
	closeOnce sync.Once
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		applyCh:   make(chan workload.App, 1),
		logCh:     make(chan string, 1),
		logClosed: make(chan struct{}),
	}
}

func (r *fakeRuntime) Name() string { return "fake" }

func (r *fakeRuntime) Apply(_ context.Context, app workload.App, _ []workload.Volume) error {
	r.mu.Lock()
	r.applied = append(r.applied, app)
	r.mu.Unlock()
	select {
	case r.applyCh <- app:
	default:
	}
	return nil
}

func (r *fakeRuntime) Remove(context.Context, string, time.Duration) error { return nil }

func (r *fakeRuntime) States(context.Context) ([]workload.State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.states), nil
}

func (r *fakeRuntime) GC(context.Context, []string) ([]string, error) { return nil, nil }

func (r *fakeRuntime) Reap(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reaps++
	return nil
}

func (r *fakeRuntime) Metrics(context.Context, string) (workload.Usage, error) {
	return workload.Usage{}, nil
}

func (r *fakeRuntime) Logs(ctx context.Context, name string, follow bool, _ int64) (io.ReadCloser, error) {
	r.mu.Lock()
	r.logged = append(r.logged, name)
	r.mu.Unlock()
	select {
	case r.logCh <- name:
	default:
	}
	if follow {
		return &ctxReader{ctx: ctx, data: []byte("streaming\n"), onClose: func() {
			r.closeOnce.Do(func() { close(r.logClosed) })
		}}, nil
	}
	return io.NopCloser(strings.NewReader("hello-logs\n")), nil
}

// ctxReader yields its payload once, then blocks until ctx is cancelled — modelling a
// `follow` log stream the agent stops by cancelling (a LogCancel or the session ending).
// onClose fires when streamUnitLogs tears the reader down, so the test can observe the
// stream ending deterministically (the terminating eof chunk is best-effort and dropped
// once the per-request ctx is already cancelled).
type ctxReader struct {
	ctx     context.Context
	sent    bool
	data    []byte
	onClose func()
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if !c.sent {
		c.sent = true
		return copy(p, c.data), nil
	}
	<-c.ctx.Done()
	return 0, io.EOF
}

func (c *ctxReader) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

type fakeVolumes struct{}

func (fakeVolumes) Provision(context.Context, map[string]corev1.PersistentVolume) error { return nil }
func (fakeVolumes) Fits(workload.App, map[string]corev1.PersistentVolume) bool          { return true }
func (fakeVolumes) Resolve(workload.App, map[string]corev1.PersistentVolume) ([]workload.Volume, error) {
	return nil, nil
}
func (fakeVolumes) Reclaim(context.Context, map[string]bool, map[string]workload.App) error {
	return nil
}

type fakeSecrets struct{}

func (fakeSecrets) Materialize(context.Context, workload.App, []corev1.Secret, []secretsv1.SecretStore) ([]workload.Volume, error) {
	return nil, nil
}

func (fakeSecrets) MaterializeEnv(context.Context, workload.App, []corev1.Secret, []secretsv1.SecretStore) ([]string, error) {
	return nil, nil
}

// newHarness stands up a real insecure gRPC NodeService on a loopback listener and an
// Agent pointed at it (built directly — NewAgent needs TLS the fake server does not).
func newHarness(t *testing.T) (*fakeServer, *fakeRuntime, *Agent) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	fs := newFakeServer()
	nodeapipb.RegisterNodeServiceServer(srv, fs)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	rt := newFakeRuntime()
	a := &Agent{
		endpoint:   lis.Addr().String(),
		creds:      insecure.NewCredentials(),
		node:       "node1",
		controller: "https://127.0.0.1:8443",
		limits:     corev1.ResourceAmounts{},
		runtime:    rt,
		volumes:    fakeVolumes{},
		secrets:    fakeSecrets{},
	}
	return fs, rt, a
}

// startAgent runs Start in the background and returns its cancel and a channel carrying
// its return value.
func startAgent(a *Agent, heartbeat time.Duration) (context.CancelFunc, <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- a.Start(ctx, heartbeat) }()
	return cancel, errCh
}

// assertStopped cancels the session and asserts Start returns nil promptly.
func assertStopped(t *testing.T, cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error on cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
}

// appJSON renders a pushed Application. The uid is what the node keys the workload by, and the
// storage layer stamps one on every create, so a fixture without it is not a realistic push —
// the agent drops it as having no identity.
func appJSON(t *testing.T, namespace, name, nodeName string) []byte {
	t.Helper()
	app := corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{UID: apitypes.UID("uid-" + namespace + "-" + name), Name: name, Namespace: namespace},
		Spec:       corev1.ApplicationSpec{Image: "reg.io/ns/app:v1", Placement: corev1.Placement{NodeName: nodeName}},
	}
	b, err := json.Marshal(&app)
	if err != nil {
		t.Fatalf("marshal application: %v", err)
	}
	return b
}

// TestSessionReconcilesPushedDesiredState drives a Desired push through decodeDesired →
// Reconcile → Runtime.Apply and checks the node reports its Status back up.
func TestSessionReconcilesPushedDesiredState(t *testing.T) {
	fs, rt, a := newHarness(t)
	cancel, errCh := startAgent(a, 50*time.Millisecond)

	// A node1-pinned app plus one pinned elsewhere: only the former must be applied.
	fs.push <- &nodeapipb.ControllerMessage{Body: &nodeapipb.ControllerMessage_Desired{Desired: &nodeapipb.DesiredState{
		Applications: [][]byte{
			appJSON(t, "default", "web", "node1"),
			appJSON(t, "default", "elsewhere", "node2"),
		},
	}}}

	select {
	case got := <-rt.applyCh:
		if want := "uid-default-web"; got.ID() != want {
			t.Fatalf("Apply called for %q, want %q", got.ID(), want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Runtime.Apply was not called for the pushed desired state")
	}

	select {
	case st := <-fs.statuses:
		var n corev1.Node
		if err := json.Unmarshal(st.GetNode(), &n); err != nil {
			t.Fatalf("unmarshal reported node: %v", err)
		}
		if n.Name != "node1" {
			t.Fatalf("status reported node %q, want %q", n.Name, "node1")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no Status message received from the agent")
	}

	// Only the node1 app was applied (self-heal re-applies it every heartbeat).
	rt.mu.Lock()
	for _, app := range rt.applied {
		if app.Node != "node1" {
			t.Errorf("applied app pinned to %q, want only node1", app.Node)
		}
	}
	rt.mu.Unlock()

	assertStopped(t, cancel, errCh)
}

// TestSessionStreamsLogs drives a non-following LogRequest through streamUnitLogs and
// checks the payload plus the terminating eof chunk stream back up.
func TestSessionStreamsLogs(t *testing.T) {
	fs, rt, a := newHarness(t)
	cancel, errCh := startAgent(a, 50*time.Millisecond)
	defer assertStopped(t, cancel, errCh)

	fs.push <- &nodeapipb.ControllerMessage{Body: &nodeapipb.ControllerMessage_LogRequest{LogRequest: &nodeapipb.LogRequest{
		Id: "log-1", App: "default_web", Follow: false, TailLines: 10,
	}}}

	select {
	case app := <-rt.logCh:
		if app != "default_web" {
			t.Fatalf("Logs called for %q, want %q", app, "default_web")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Runtime.Logs was not called")
	}

	var data []byte
	deadline := time.After(3 * time.Second)
	for {
		select {
		case c := <-fs.chunks:
			if c.GetId() != "log-1" {
				t.Fatalf("log chunk id %q, want %q", c.GetId(), "log-1")
			}
			data = append(data, c.GetData()...)
			if c.GetEof() {
				if c.GetError() != "" {
					t.Fatalf("eof chunk carried error %q", c.GetError())
				}
				if string(data) != "hello-logs\n" {
					t.Fatalf("streamed logs %q, want %q", string(data), "hello-logs\n")
				}
				return
			}
		case <-deadline:
			t.Fatalf("did not receive terminating eof chunk (got %q)", string(data))
		}
	}
}

// TestSessionLogCancel drives a following LogRequest and then a LogCancel, checking the
// agent stops the stream (the cancel propagates through the per-request ctx to the eof).
func TestSessionLogCancel(t *testing.T) {
	fs, rt, a := newHarness(t)
	cancel, errCh := startAgent(a, 50*time.Millisecond)
	defer assertStopped(t, cancel, errCh)

	fs.push <- &nodeapipb.ControllerMessage{Body: &nodeapipb.ControllerMessage_LogRequest{LogRequest: &nodeapipb.LogRequest{
		Id: "log-2", App: "default_web", Follow: true,
	}}}

	// First chunk arrives while the follow stream is live; no eof yet.
	select {
	case c := <-fs.chunks:
		if c.GetEof() {
			t.Fatal("follow stream ended before LogCancel")
		}
		if string(c.GetData()) != "streaming\n" {
			t.Fatalf("first chunk %q, want %q", string(c.GetData()), "streaming\n")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no chunk from the follow stream")
	}

	fs.push <- &nodeapipb.ControllerMessage{Body: &nodeapipb.ControllerMessage_LogCancel{LogCancel: &nodeapipb.LogCancel{Id: "log-2"}}}

	// LogCancel cancels the per-request ctx, which unblocks the reader; the terminating eof is
	// enqueued against the SESSION ctx, so it still reaches the controller (closing its stream)
	// rather than being dropped on the cancelled per-request ctx.
	select {
	case c := <-fs.chunks:
		if !c.GetEof() {
			t.Fatalf("after LogCancel, want the terminating eof chunk, got data %q", string(c.GetData()))
		}
		if c.GetId() != "log-2" {
			t.Fatalf("eof chunk id = %q, want log-2", c.GetId())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no terminating eof chunk after LogCancel")
	}
	// The underlying reader is also closed (torn down).
	select {
	case <-rt.logClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("follow log stream was not torn down after LogCancel")
	}
}

// TestSessionHeartbeatStatus checks the heartbeat worker reports Status periodically
// with no desired state pushed (the initial register plus at least one tick).
func TestSessionHeartbeatStatus(t *testing.T) {
	fs, _, a := newHarness(t)
	cancel, errCh := startAgent(a, 50*time.Millisecond)
	defer assertStopped(t, cancel, errCh)

	for i := range 3 {
		select {
		case st := <-fs.statuses:
			if len(st.GetNode()) == 0 {
				t.Fatal("heartbeat Status carried no node payload")
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("received only %d Status messages, want at least 3", i)
		}
	}
}
