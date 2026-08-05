package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/admission"
	"github.com/ks-tool/horchestra/controller/authz"
	"github.com/ks-tool/horchestra/controller/internal/memory"
	"github.com/ks-tool/horchestra/controller/service"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func catalogServer(t *testing.T) *APIServer {
	t.Helper()
	sch := scheme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	srv := New(sch, service.New(store, sch, admission.DefaultChain(nil, nil)))
	create := func(obj any) {
		t.Helper()
		data, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		var meta metav1.TypeMeta
		_ = json.Unmarshal(data, &meta)
		ns := ""
		if o, ok := obj.(interface{ GetNamespace() string }); ok {
			ns = o.GetNamespace()
		}
		if _, err := srv.svc.Create(context.Background(),
			corev1.GroupVersion.WithKind(meta.Kind), data, ns); err != nil {
			t.Fatalf("seed %s: %v", meta.Kind, err)
		}
	}
	create(&corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	})
	create(&corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status:     corev1.NodeStatus{IP: "10.0.0.7"},
	})
	create(&corev1.Service{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "cache",
			// Nobody writes a tag: they are derived. Annotations are ServiceMeta and nothing else.
			Annotations: map[string]string{
				"traefik.http.routers.cache.rule": "Host(`cache.example.com`)",
			},
		},
		// The address is declared, the way whoever runs the balancer would declare it; the
		// catalog's job is to carry it to the clients that resolve this name.
		Spec: corev1.ServiceSpec{ClusterIP: "10.243.0.1", Ports: []corev1.ServicePort{{Port: 6379}}},
	})
	for _, name := range []string{"cache-0", "cache-1"} {
		create(&corev1.Application{
			TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
			Spec: corev1.ApplicationSpec{
				Image:       "reg/cache:v1",
				ServiceName: "cache",
				Ports:       []corev1.Port{{Name: "redis", Port: 6379}},
				Placement:   corev1.Placement{NodeName: "node-1"},
			},
		})
	}
	// A flat workload with no Service of its own: a port and a placement are all it has, and the
	// catalog has to be able to answer where it is anyway.
	create(&corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "node-exporter"},
		Spec: corev1.ApplicationSpec{
			Image:     "reg/node-exporter:v1",
			Ports:     []corev1.Port{{Port: 9100}},
			Placement: corev1.Placement{NodeName: "node-1"},
		},
	})
	return srv
}

// TestTheNodeIsAService: a workload on the host network is reachable at its node's address, and the
// control plane knows that address the moment the scheduler picks one — so a flat workload needs no
// Service object and no declared address to be discoverable. It declares a port, it is placed, and
// it is in the catalog under the node it landed on.
func TestTheNodeIsAService(t *testing.T) {
	s := catalogServer(t)

	w := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/service/node-1", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("catalog/service/node-1 = %d (%s)", w.Code, w.Body.String())
	}
	var got []catalogService
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// Everything placed on the node with a port: the two cache replicas AND the workload that
	// declared no service at all.
	if len(got) != 3 {
		t.Fatalf("entries = %d, want everything placed on the node: %+v", len(got), got)
	}
	var found bool
	for _, e := range got {
		if e.ServiceName != "node-1" {
			t.Errorf("ServiceName = %q, want the node's name", e.ServiceName)
		}
		if e.ServiceAddress != "10.0.0.7" || e.ServiceMeta["clusterIP"] != "10.0.0.7" {
			t.Errorf("entry address = %s / clusterIP = %s, want the node's address in both",
				e.ServiceAddress, e.ServiceMeta["clusterIP"])
		}
		if e.ServiceMeta["application"] == "node-exporter" {
			found = true
			if e.ServicePort != 9100 {
				t.Errorf("port = %d, want the workload's own", e.ServicePort)
			}
			if !contains(e.ServiceTags, "application=node-exporter") {
				t.Errorf("tags = %v, want the workload's name: it is the only thing distinguishing entries here", e.ServiceTags)
			}
		}
	}
	if !found {
		t.Error("the workload with no serviceName is not in the catalog at all")
	}
}

// TestANodeServiceDoesNotSwallowARealOne: being in one's own service and being on a host are two
// facts, and an instance that declares a Service is in both. Neither answer loses an entry to the
// other.
func TestANodeServiceDoesNotSwallowARealOne(t *testing.T) {
	s := catalogServer(t)

	w := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/service/cache", "", "")
	var got []catalogService
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("cache entries = %d, want the two replicas: %+v", len(got), got)
	}
	for _, e := range got {
		if e.ServiceName != "cache" {
			t.Errorf("ServiceName = %q under the service's own name", e.ServiceName)
		}
	}
}

// TestCatalogGroupsTheRepicasOfOneService is the whole reason the catalog is shaped like Consul's:
// the instances of one ServiceName are ONE backend pool. Registration is per (Application, port),
// so two replicas are two entries — with the same name and different IDs, which is what lets
// Traefik build one backend from them instead of two.
func TestCatalogGroupsTheReplicasOfOneService(t *testing.T) {
	s := catalogServer(t)

	w := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/service/cache", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("catalog/service = %d (%s)", w.Code, w.Body.String())
	}
	var got []catalogService
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("entries = %d, want one per replica: %+v", len(got), got)
	}
	if got[0].ServiceID == got[1].ServiceID {
		t.Error("two instances share a ServiceID — Consul would treat them as one registration")
	}
	for _, e := range got {
		if e.ServiceName != "cache" {
			t.Errorf("ServiceName = %q, want the grouping key shared by both", e.ServiceName)
		}
		if e.ServiceAddress != "10.0.0.7" || e.ServicePort != 6379 {
			t.Errorf("instance address = %s:%d, want the node's address and the service port",
				e.ServiceAddress, e.ServicePort)
		}
		if e.ServiceMeta["clusterIP"] == "" {
			t.Error("the VIP is not published in ServiceMeta, so nothing can find it")
		}
		if e.ServiceMeta["traefik.http.routers.cache.rule"] == "" {
			t.Error("annotations did not reach ServiceMeta")
		}
		if len(e.ServiceTags) == 0 {
			t.Error("a registration carries no derived tags")
		}
	}
}

// TestCatalogServicesIndexesNameToTags: the index Traefik polls first, and the tags are its whole
// routing configuration.
func TestCatalogServicesIndexesNameToTags(t *testing.T) {
	s := catalogServer(t)

	w := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/services", "", "")
	var got map[string][]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v (%s)", err, w.Body.String())
	}
	tags, ok := got["cache"]
	if !ok {
		t.Fatalf("index = %+v, want cache in it", got)
	}
	// Every tag is derived from what the control plane knows for certain, so a consumer can
	// filter on facts rather than on a free string nobody validated.
	for _, want := range []string{"namespace=default", "service=cache", "protocol=tcp"} {
		if !contains(tags, want) {
			t.Errorf("tags = %v, want %q among them", tags, want)
		}
	}
}

// TestAnUnplacedInstanceIsNotInTheCatalog: an Application the scheduler has not placed is
// listening nowhere, so publishing it would hand a client an address to fail against.
func TestAnUnplacedInstanceIsNotInTheCatalog(t *testing.T) {
	s := catalogServer(t)
	data, _ := json.Marshal(&corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cache-2"},
		Spec:       corev1.ApplicationSpec{Image: "reg/cache:v1", ServiceName: "cache"},
	})
	if _, err := s.svc.Create(context.Background(),
		corev1.GroupVersion.WithKind("Application"), data, "default"); err != nil {
		t.Fatal(err)
	}

	w := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/service/cache", "", "")
	var got []catalogService
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got) != 2 {
		t.Fatalf("entries = %d, want the unplaced instance left out: %+v", len(got), got)
	}
}

// TestHealthServesTheSameSet: Traefik reads health instead of catalog as soon as it is asked to
// filter on it, so one without the other works until somebody sets that flag.
func TestHealthServesTheSameSet(t *testing.T) {
	s := catalogServer(t)

	w := doReq(t, s, http.MethodGet, "/servicediscovery/v1/health/service/cache", "", "")
	var got []healthEntry
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v (%s)", err, w.Body.String())
	}
	if len(got) != 2 {
		t.Fatalf("health entries = %d, want one per instance", len(got))
	}
	if got[0].Checks[0].Status != "passing" {
		t.Errorf("check status = %q", got[0].Checks[0].Status)
	}
}

// TestCatalogAnswersWithABlockingIndex: without X-Consul-Index a client has no way to make its
// next call a blocking one, so it falls back to polling on a timer — which is the load the
// blocking-query protocol exists to remove.
func TestCatalogAnswersWithABlockingIndex(t *testing.T) {
	s := catalogServer(t)

	w := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/services", "", "")
	idx := w.Header().Get("X-Consul-Index")
	if idx == "" || idx == "0" {
		t.Fatalf("X-Consul-Index = %q, want the projection's version", idx)
	}
	// Asking again from an index the server has already passed must answer at once, not block:
	// the client is behind, and there is something to tell it.
	w2 := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/services?index=1&wait=30s", "", "")
	if w2.Code != http.StatusOK {
		t.Fatalf("a client behind the index was not answered: %d", w2.Code)
	}
}

// TestABlockingQueryWaitsAndGivesUpQuietly: a wait that expires with nothing changed is not an
// error — Consul answers the unchanged state with the same index and the client simply asks again.
func TestABlockingQueryWaitsAndGivesUpQuietly(t *testing.T) {
	s := catalogServer(t)
	cur := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/services", "", "").
		Header().Get("X-Consul-Index")

	start := time.Now()
	w := doReq(t, s, http.MethodGet,
		"/servicediscovery/v1/catalog/services?index="+cur+"&wait=1s", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expired blocking query = %d, want 200 with the unchanged state", w.Code)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Errorf("returned after %s — it did not block at all", elapsed)
	}
}

// TestTargetPortResolvesByName: a service says "http"; the instance says which number that is.
// The point is that the workload can move its port — a rebuild, a base-image change — without the
// service or anything calling it being edited, which a number in the Service would have pinned to
// today's value of somebody else's implementation detail.
func TestTargetPortResolvesByName(t *testing.T) {
	app := &corev1.Application{Spec: corev1.ApplicationSpec{
		Ports: []corev1.Port{{Name: "web", Port: 8081}, {Name: "metrics", Port: 9100}},
	}}

	named := corev1.ServicePort{Name: "http", Port: 80, TargetName: "web"}
	if got := named.TargetFor(app); got != 8081 {
		t.Errorf("named target = %d, want the instance's own `web` port", got)
	}
	// An explicit number still wins — somebody had to say it for a reason.
	pinned := corev1.ServicePort{Name: "http", Port: 80, TargetName: "web", TargetPort: 8080}
	if got := pinned.TargetFor(app); got != 8080 {
		t.Errorf("explicit target = %d, want it honoured", got)
	}
	// A name nothing answers to falls back to the service's own port rather than to zero, which
	// would publish an instance on port 0 and look like a working registration.
	unmatched := corev1.ServicePort{Name: "grpc", Port: 50051, TargetName: "nope"}
	if got := unmatched.TargetFor(app); got != 50051 {
		t.Errorf("unmatched name = %d, want the service port", got)
	}
	// The two namespaces are NOT joined: a service port called `http` does not silently reach an
	// instance port called `http`, or a rename on either side would move traffic.
	unlinked := corev1.ServicePort{Name: "metrics", Port: 9090}
	if got := unlinked.TargetFor(app); got != 9090 {
		t.Errorf("same-name match leaked through: got %d, want the service port", got)
	}
}

// TestAnIsolatedWorkloadIsNotOnTheNode: the node's service is the service of what BINDS the node,
// so the condition is the workload's network and not whether a datapath is running. A workload with
// a namespace of its own does not listen on the node's address, and publishing it there would
// advertise a port nothing on that host has open.
//
// Built directly rather than through the API because admission refuses `hostNetwork: false` today —
// no netns exists to give it. This is the projection's half of that future, written now so the
// answer does not have to be remembered later.
func TestAnIsolatedWorkloadIsNotOnTheNode(t *testing.T) {
	isolated := false
	apps := []types.Object{&corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api"},
		Spec: corev1.ApplicationSpec{
			Image:       "reg/api:v1",
			HostNetwork: &isolated,
			Ports:       []corev1.Port{{Port: 8080}},
			Placement:   corev1.Placement{NodeName: "node-1"},
		},
	}}
	if got := nodeEntries(apps, map[string]string{"node-1": "10.0.0.7"}, ""); len(got) != 0 {
		t.Errorf("entries = %+v, want none: the workload does not listen on the node's address", got)
	}
}

// oneNamespace allows a read in exactly one namespace and denies everything else.
type oneNamespace struct{ allowed string }

func (a oneNamespace) Authorize(_ context.Context, at authz.Attributes) (bool, error) {
	return at.Namespace == a.allowed, nil
}

// TestTheCatalogIsScopedToTheCallersNamespaces: `nonResourceURLs` grants the catalog's PATH, and
// `?ns=` is a free parameter on it — so without this, a token meant for one tenant's balancer reads
// every tenant's services by changing a query string. Reading a namespace's catalog is listing the
// Services in it, and it is authorized as exactly that.
func TestTheCatalogIsScopedToTheCallersNamespaces(t *testing.T) {
	s := catalogServer(t)
	s.SetAuthorizer(oneNamespace{allowed: "team-a"})

	w := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/services?ns=default", "", "")
	if w.Code != http.StatusForbidden {
		t.Errorf("reading another namespace's catalog = %d, want 403 (%s)", w.Code, w.Body.String())
	}
	// The node's service is inside that scope, not beside it: it is namespaced by the workloads
	// it lists, so it cannot be used to read around the grant.
	w = doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/service/node-1?ns=default", "", "")
	if w.Code != http.StatusForbidden {
		t.Errorf("reading a node's service in another namespace = %d, want 403 (%s)", w.Code, w.Body.String())
	}
	w = doReq(t, s, http.MethodGet, "/servicediscovery/v1/health/service/cache?ns=team-a", "", "")
	if w.Code != http.StatusOK {
		t.Errorf("the caller's own namespace = %d, want 200 (%s)", w.Code, w.Body.String())
	}
}

// TestTheUnqualifiedNamespaceIsConfigurable: `default` is Consul's convention, not a fleet's. A
// deployment whose workloads live elsewhere would otherwise answer every client that cannot send
// `?ns=` with an empty catalog — which reads as "the service is gone", not "you asked the wrong
// question".
func TestTheUnqualifiedNamespaceIsConfigurable(t *testing.T) {
	s := catalogServer(t)
	s.SetCatalogNamespace("platform")

	w := doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/services", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("catalog/services = %d (%s)", w.Code, w.Body.String())
	}
	var got map[string][]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("services = %v, want the (empty) `platform` catalog rather than `default`'s", got)
	}
	// And the parameter still wins over the configured default.
	w = doReq(t, s, http.MethodGet, "/servicediscovery/v1/catalog/services?ns=default", "", "")
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["node-1"]; !ok {
		t.Errorf("services = %v, want the asked-for namespace's catalog", got)
	}
}
