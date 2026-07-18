package nodeserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/pb"
	apischeme "github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/apiserver/internal/memory"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// --- Controller backed by the fake store -----------------------------------

// fakeController is a minimal nodeserver.Controller over the in-memory store: it
// decodes (gvk, json) writes through the scheme and maps the storage sentinels to
// the API errors the server's applyStatus expects (Update-then-Create). It lets
// this transport test exercise the real server without the full service/admission
// stack.
type fakeController struct {
	store *memory.Storage
	sch   *apischeme.Scheme
}

func (f *fakeController) List(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error) {
	return f.store.List(ctx, m, opts)
}

func (f *fakeController) Watch(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) (<-chan metav1.WatchEvent, error) {
	return f.store.Watch(ctx, m, opts)
}

func (f *fakeController) Create(ctx context.Context, gvk schema.GroupVersionKind, data []byte) (types.Object, error) {
	obj, err := f.decode(gvk, data)
	if err != nil {
		return nil, err
	}
	out, err := f.store.Create(ctx, obj)
	return out, mapStorageErr(gvk, err)
}

func (f *fakeController) Update(ctx context.Context, gvk schema.GroupVersionKind, data []byte) (types.Object, error) {
	obj, err := f.decode(gvk, data)
	if err != nil {
		return nil, err
	}
	out, err := f.store.Update(ctx, obj)
	return out, mapStorageErr(gvk, err)
}

func (f *fakeController) decode(gvk schema.GroupVersionKind, data []byte) (types.Object, error) {
	obj, err := f.sch.New(gvk)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, obj); err != nil {
		return nil, err
	}
	obj.GetObjectKind().SetGroupVersionKind(gvk) // the service's defaulting stamps this
	return obj, nil
}

func mapStorageErr(gvk schema.GroupVersionKind, err error) error {
	gr := schema.GroupResource{Group: gvk.Group, Resource: gvk.Kind}
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return apierrors.NewNotFound(gr, "")
	case errors.Is(err, storage.ErrAlreadyExists):
		return apierrors.NewAlreadyExists(gr, "")
	}
	return err
}

// --- mTLS test PKI ---------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue signs a leaf cert with the given CN and Organization (groups). When server
// is true it is a serving cert for "localhost"; otherwise a client cert (the node
// identity the server reads from the mTLS peer).
func (ca *testCA) issue(t *testing.T, cn string, orgs []string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn, Organization: orgs},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// --- harness ---------------------------------------------------------------

const nodeName = "node-1"

// harness runs the NodeService server over an in-memory (bufconn) mTLS listener,
// backed by the fake store, and lets a test dial it with an arbitrary client cert.
type harness struct {
	ctl *fakeController
	srv *Server
	ca  *testCA
	lis *bufconn.Listener
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	ctl := &fakeController{store: store, sch: sch}

	// Two applications: one pinned to this node, one to another — only the first
	// must reach the agent.
	mustCreateApp(t, ctl, "web", nodeName)
	mustCreateApp(t, ctl, "other", "node-2")

	ca := newTestCA(t)
	srv := New(ctl)
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{ca.issue(t, "localhost", nil, true)},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})))
	pb.RegisterNodeServiceServer(gs, srv)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return &harness{ctl: ctl, srv: srv, ca: ca, lis: lis}
}

// session dials the server with a client cert carrying cn/orgs and opens the
// bidirectional stream.
func (h *harness) session(t *testing.T, ctx context.Context, cn string, orgs []string) grpc.BidiStreamingClient[pb.NodeMessage, pb.ControllerMessage] {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return h.lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{h.ca.issue(t, cn, orgs, false)},
			RootCAs:      h.ca.pool,
			ServerName:   "localhost",
		})),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	stream, err := pb.NewNodeServiceClient(conn).Session(ctx)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	return stream
}

func mustCreateApp(t *testing.T, ctl *fakeController, name, node string) {
	t.Helper()
	body := `{"metadata":{"name":"` + name + `"},"spec":{"image":"reg/` + name + `:v1","nodeName":"` + node + `"}}`
	if _, err := ctl.Create(context.Background(), corev1.GroupVersion.WithKind("Application"), []byte(body)); err != nil {
		t.Fatalf("seed application %s: %v", name, err)
	}
}

func nodeMeta(name string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Node", Name: name}
}

// --- tests -----------------------------------------------------------------

// TestSession_PushesDesiredStateAndPersistsStatus is the happy path: an
// authenticated node agent connects, receives exactly the desired state pinned to
// it, and its reported status is persisted back through the controller.
func TestSession_PushesDesiredStateAndPersistsStatus(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := h.session(t, ctx, nodeName, []string{nodeGroup})

	// The first message down is the desired state: only "web" (pinned here), never
	// "other" (pinned to node-2).
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv desired: %v", err)
	}
	desired := msg.GetDesired()
	if desired == nil {
		t.Fatalf("first message was not a desired state: %+v", msg)
	}
	if got := len(desired.GetApplications()); got != 1 {
		t.Fatalf("pushed %d applications, want 1 (only the node's own)", got)
	}
	if name := nameOf(t, desired.GetApplications()[0]); name != "web" {
		t.Fatalf("pushed application %q, want web", name)
	}

	// Report status up; the server persists the Node through the controller.
	nodeJSON := `{"metadata":{"name":"` + nodeName + `"},"status":{"os":"test-os","ready":true}}`
	if err := stream.Send(&pb.NodeMessage{Body: &pb.NodeMessage_Status{
		Status: &pb.NodeStatus{Node: []byte(nodeJSON)},
	}}); err != nil {
		t.Fatalf("send status: %v", err)
	}

	waitFor(t, 3*time.Second, func() bool {
		obj, err := h.ctl.store.Get(context.Background(), nodeMeta(nodeName))
		if err != nil {
			return false
		}
		n, ok := obj.(*corev1.Node)
		return ok && n.Status.Ready && n.Status.OS == "test-os"
	})
}

// TestSession_RefusesNonNodeIdentity checks that a valid mTLS peer that is not in
// the system:nodes group is refused at the application layer.
func TestSession_RefusesNonNodeIdentity(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := h.session(t, ctx, "operator", []string{"dev"}) // valid cert, wrong group
	_, err := stream.Recv()
	if err == nil {
		t.Fatal("expected the session to be refused, got nil error")
	}
	if st, _ := status.FromError(err); st.Code() != codes.PermissionDenied {
		t.Fatalf("refusal code = %v, want PermissionDenied", st.Code())
	}
}

// TestSession_StreamsLogs checks the log path: a StreamLogs request reaches the
// connected agent as a LogRequest, and the chunks the agent sends back surface on
// the returned channel until EOF.
func TestSession_StreamsLogs(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := h.session(t, ctx, nodeName, []string{nodeGroup})
	if _, err := stream.Recv(); err != nil { // drain the initial desired state (also registers the session)
		t.Fatalf("recv desired: %v", err)
	}

	// Ask for the app's logs; the request is routed to this agent's stream.
	ch, done, err := h.srv.StreamLogs(ctx, nodeName, "web", false, 0)
	if err != nil {
		t.Fatalf("stream logs: %v", err)
	}
	defer func() { _ = done() }()

	req := recvLogRequest(t, stream)
	if req.GetApp() != "web" {
		t.Fatalf("log request app = %q, want web", req.GetApp())
	}
	// Agent answers with a chunk then EOF.
	send := func(m *pb.NodeMessage) {
		if err := stream.Send(m); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	send(&pb.NodeMessage{Body: &pb.NodeMessage_LogChunk{LogChunk: &pb.LogChunk{Id: req.GetId(), Data: []byte("hello\n")}}})
	send(&pb.NodeMessage{Body: &pb.NodeMessage_LogChunk{LogChunk: &pb.LogChunk{Id: req.GetId(), Eof: true}}})

	got, ok := <-ch
	if !ok || string(got) != "hello\n" {
		t.Fatalf("log chunk = %q ok=%v, want %q", got, ok, "hello\n")
	}
	if _, ok := <-ch; ok { // EOF closes the channel
		t.Fatal("log channel not closed after EOF")
	}
}

// --- helpers ---------------------------------------------------------------

// recvLogRequest reads stream messages until a LogRequest arrives (desired-state
// pushes may be interleaved).
func recvLogRequest(t *testing.T, stream grpc.BidiStreamingClient[pb.NodeMessage, pb.ControllerMessage]) *pb.LogRequest {
	t.Helper()
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if r := msg.GetLogRequest(); r != nil {
			return r
		}
	}
}

func nameOf(t *testing.T, appJSON []byte) string {
	t.Helper()
	obj := &corev1.Application{}
	if err := json.Unmarshal(appJSON, obj); err != nil {
		t.Fatalf("decode pushed application: %v", err)
	}
	return obj.Name
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
