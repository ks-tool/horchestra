package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Datacenter is the single datacenter this control plane reports. Consul's model has one per
// cluster and clients ask for it by name; a fleet is one datacenter until there is a second
// control plane to federate with, and inventing more names than there are things would only give
// a client somewhere wrong to point.
const Datacenter = "horchestra"

// catalogService is one registered instance in Consul's catalog shape. The field names are
// Consul's exactly — this is a wire format a foreign client parses, not a model of our own.
type catalogService struct {
	Node           string            `json:"Node"`
	Address        string            `json:"Address"`
	Datacenter     string            `json:"Datacenter"`
	Namespace      string            `json:"Namespace,omitempty"`
	ServiceID      string            `json:"ServiceID"`
	ServiceName    string            `json:"ServiceName"`
	ServiceAddress string            `json:"ServiceAddress"`
	ServicePort    int               `json:"ServicePort"`
	ServiceTags    []string          `json:"ServiceTags"`
	ServiceMeta    map[string]string `json:"ServiceMeta,omitempty"`
}

// healthEntry is what /health/service/<name> returns: the same registration wrapped with the node
// and its checks. Traefik reads health rather than catalog when it is asked to filter on it, so
// serving one without the other would work until somebody set that flag.
type healthEntry struct {
	Node    map[string]any `json:"Node"`
	Service map[string]any `json:"Service"`
	Checks  []healthCheck  `json:"Checks"`
}

type healthCheck struct {
	Node        string `json:"Node"`
	CheckID     string `json:"CheckID"`
	Name        string `json:"Name"`
	Status      string `json:"Status"`
	ServiceID   string `json:"ServiceID"`
	ServiceName string `json:"ServiceName"`
}

// registerCatalog binds the service-discovery projection. The paths are Consul's own, under a
// prefix of ours: a client that takes a base URL appends `/v1/catalog/...` to it and works
// unmodified, and one that cannot (Traefik points at a host:port and builds from the root) is a
// deployment problem for a reverse proxy, not a reason for the control plane to squat `/v1` at
// its own root.
//
// The list is closed on purpose — five handlers, not a wildcard. These are the calls a Consul
// client actually makes, and a prefix would promise the rest of an API this does not implement.
func (s *APIServer) registerCatalog() {
	s.router.GET("/servicediscovery/v1/catalog/datacenters", s.catalogDatacenters)
	s.router.GET("/servicediscovery/v1/catalog/services", s.catalogServices)
	s.router.GET("/servicediscovery/v1/catalog/service/:name", s.catalogService)
	s.router.GET("/servicediscovery/v1/health/service/:name", s.catalogHealth)
	s.router.GET("/servicediscovery/v1/agent/self", s.catalogAgentSelf)
}

// maxBlockingWait caps how long one request may be parked. Consul's own default is 5 minutes and
// clients ask for it explicitly; a request that outlived any proxy in front of it would come back
// as a broken connection the client reads as an error rather than as "nothing changed".
const maxBlockingWait = 5 * time.Minute

// serveCatalog answers one catalog read, honouring Consul's BLOCKING QUERY when the client asks
// for one: `?index=N&wait=…` means "do not answer until something after N happened", and the
// answer carries X-Consul-Index for the next call. This is how a Consul client watches — without
// it Traefik has no way to wait and falls back to hammering the endpoint on a timer.
//
// The index is the highest resourceVersion across the three Kinds the projection is computed from.
// That is not a coincidence of implementation: this storage already gives per-GVK monotonic
// versions and already has a watch bus, so Consul's contract — a number that only moves forward,
// and a way to sleep until it does — is a rename of machinery that exists rather than a mechanism
// to build.
func (s *APIServer) serveCatalog(w http.ResponseWriter, req bunrouter.Request, namespace string, body func(context.Context) (any, error)) error {
	ctx := req.Context()
	if err := s.allowCatalogNamespace(ctx, namespace); err != nil {
		return err
	}
	idx, err := s.catalogIndex(ctx)
	if err != nil {
		return err
	}
	if since, wait := blockingQuery(req); since > 0 && idx <= since {
		if err := s.awaitCatalogChange(ctx, wait); err != nil {
			return err
		}
		if idx, err = s.catalogIndex(ctx); err != nil {
			return err
		}
	}
	out, err := body(ctx)
	if err != nil {
		return err
	}
	// Set before the body: once writeJSON has written a status line the headers are gone, and a
	// client that reads no index has no way to make its next call a blocking one.
	w.Header().Set("X-Consul-Index", strconv.FormatInt(idx, 10))
	w.Header().Set("X-Consul-Knownleader", "true")
	return writeJSON(w, http.StatusOK, out)
}

// blockingQuery reads Consul's two blocking parameters. An unparseable or absent index means a
// plain read, which is what a client that does not know about blocking queries sends.
func blockingQuery(req bunrouter.Request) (since int64, wait time.Duration) {
	since, _ = strconv.ParseInt(req.URL.Query().Get("index"), 10, 64)
	wait = maxBlockingWait
	if d, err := time.ParseDuration(req.URL.Query().Get("wait")); err == nil && d > 0 && d < maxBlockingWait {
		wait = d
	}
	return since, wait
}

// catalogIndex is the highest resourceVersion among the Kinds the projection reads, so any change
// to any of them moves it and nothing else does.
func (s *APIServer) catalogIndex(ctx context.Context) (int64, error) {
	var idx int64
	for _, kind := range []string{"Service", "Application", "Node"} {
		list, err := s.listKind(ctx, kind, "")
		if err != nil {
			return 0, err
		}
		for _, obj := range list {
			acc, err := apimeta.Accessor(obj)
			if err != nil {
				continue
			}
			if rv, err := strconv.ParseInt(acc.GetResourceVersion(), 10, 64); err == nil && rv > idx {
				idx = rv
			}
		}
	}
	return idx, nil
}

// awaitCatalogChange parks the request until any of the three Kinds changes, the client goes away,
// or wait elapses. A timeout is not an error: Consul answers the unchanged state with the same
// index, and the client simply asks again.
func (s *APIServer) awaitCatalogChange(ctx context.Context, wait time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	var chans []<-chan metav1.WatchEvent
	for _, kind := range []string{"Service", "Application", "Node"} {
		ch, err := s.svc.Watch(ctx, types.ObjectMeta{
			ApiVersion: corev1.GroupVersion.String(), Kind: kind,
		}, metav1.ListOptions{})
		if err != nil {
			return apierrors.NewInternalError(err)
		}
		chans = append(chans, ch)
	}
	select {
	case <-ctx.Done():
	case <-chans[0]:
	case <-chans[1]:
	case <-chans[2]:
	}
	return nil
}

func (s *APIServer) catalogDatacenters(w http.ResponseWriter, _ bunrouter.Request) error {
	return writeJSON(w, http.StatusOK, []string{Datacenter})
}

// catalogAgentSelf is the handshake the Go API client makes to learn the datacenter. It answers
// the two fields that are read and nothing else — a fuller impersonation would be a promise about
// an agent that does not exist.
func (s *APIServer) catalogAgentSelf(w http.ResponseWriter, _ bunrouter.Request) error {
	return writeJSON(w, http.StatusOK, map[string]any{
		"Config": map[string]any{"Datacenter": Datacenter, "NodeName": "horchestra-controller"},
	})
}

// catalogServices is the name → tags index Traefik polls first.
func (s *APIServer) catalogServices(w http.ResponseWriter, req bunrouter.Request) error {
	ns := s.namespaceOf(req)
	return s.serveCatalog(w, req, ns, func(ctx context.Context) (any, error) {
		return s.servicesIndex(ctx, ns)
	})
}

// allowCatalogNamespace decides the ONE thing the path grant cannot: which tenant's catalog this
// caller may read.
//
// `nonResourceURLs` authorizes the catalog's PATH, and `?ns=` is a free parameter on it — so a
// grant meant to let an edge balancer read one namespace's services also read every other
// namespace's by changing a query string. The check that closes it needs no new vocabulary: reading
// the catalog of a namespace is listing the Services in it, so it is authorized as exactly that.
// The two grants compose — the path says whether this API surface is reachable at all, the namespace
// says how far it reaches.
//
// Unset (auth compiled out of a test server) allows every namespace, matching the pods alias.
func (s *APIServer) allowCatalogNamespace(ctx context.Context, namespace string) error {
	if s.authz == nil {
		return nil
	}
	ok, err := s.authz.Authorize(ctx, authz.Attributes{
		User:            authn.FromContext(ctx),
		Verb:            "list",
		Group:           corev1.GroupName,
		Resource:        "services",
		Namespace:       namespace,
		ResourceRequest: true,
	})
	if err != nil {
		return apierrors.NewInternalError(err)
	}
	if !ok {
		return apierrors.NewForbidden(schema.GroupResource{Group: corev1.GroupName, Resource: "services"},
			"", fmt.Errorf("the catalog of namespace %q is not readable by this caller", namespace))
	}
	return nil
}

func (s *APIServer) servicesIndex(ctx context.Context, namespace string) (any, error) {
	entries, err := s.catalogEntries(ctx, namespace, "")
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, e := range entries {
		tags, ok := out[e.ServiceName]
		if !ok {
			tags = []string{}
		}
		for _, t := range e.ServiceTags {
			if !contains(tags, t) {
				tags = append(tags, t)
			}
		}
		out[e.ServiceName] = tags
	}
	return out, nil
}

// catalogService is the instances of one service name.
func (s *APIServer) catalogService(w http.ResponseWriter, req bunrouter.Request) error {
	ns := s.namespaceOf(req)
	return s.serveCatalog(w, req, ns, func(ctx context.Context) (any, error) {
		entries, err := s.catalogEntries(ctx, ns, req.Param("name"))
		if err != nil {
			return nil, err
		}
		return filterByTag(entries, req.URL.Query().Get("tag")), nil
	})
}

// catalogHealth is the same set through the health endpoint. Every instance the control plane
// knows about is passing: a node whose heartbeat has gone stale stops reporting its workloads at
// all, so an entry that is here is one a node is currently standing behind.
func (s *APIServer) catalogHealth(w http.ResponseWriter, req bunrouter.Request) error {
	ns := s.namespaceOf(req)
	return s.serveCatalog(w, req, ns, func(ctx context.Context) (any, error) {
		return s.healthEntries(ctx, ns, req.Param("name"), req.URL.Query().Get("tag"))
	})
}

func (s *APIServer) healthEntries(ctx context.Context, namespace, name, tag string) (any, error) {
	entries, err := s.catalogEntries(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	entries = filterByTag(entries, tag)
	out := make([]healthEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, healthEntry{
			Node: map[string]any{"Node": e.Node, "Address": e.Address, "Datacenter": e.Datacenter},
			Service: map[string]any{
				"ID": e.ServiceID, "Service": e.ServiceName, "Tags": e.ServiceTags,
				"Address": e.ServiceAddress, "Port": e.ServicePort, "Meta": e.ServiceMeta,
			},
			Checks: []healthCheck{{
				Node: e.Node, CheckID: "serfHealth", Name: "node", Status: "passing",
				ServiceID: e.ServiceID, ServiceName: e.ServiceName,
			}},
		})
	}
	return out, nil
}

// catalogEntries builds the whole projection: every Service, joined to the Applications that
// DECLARED themselves members, placed on a node whose address the instance is reachable at — plus
// the node's own service, which every placed Application with a port is in whether it declared
// anything or not (see nodeEntries).
//
// It is computed on every read rather than stored. The inputs are already the source of truth and
// already watched; a cached copy would be a second answer to "what is running" that could be
// wrong, which is the failure this whole model is shaped to avoid.
func (s *APIServer) catalogEntries(ctx context.Context, namespace, name string) ([]catalogService, error) {
	services, err := s.listKind(ctx, "Service", namespace)
	if err != nil {
		return nil, err
	}
	apps, err := s.listKind(ctx, "Application", namespace)
	if err != nil {
		return nil, err
	}
	nodes, err := s.listKind(ctx, "Node", "")
	if err != nil {
		return nil, err
	}
	addr := map[string]string{}
	for _, o := range nodes {
		if n, ok := o.(*corev1.Node); ok {
			addr[n.Name] = n.Status.IP
		}
	}

	var out []catalogService
	for _, so := range services {
		svc, ok := so.(*corev1.Service)
		if !ok {
			continue
		}
		for _, po := range svc.Spec.Ports {
			catName := svc.CatalogName(po)
			if name != "" && catName != name {
				continue
			}
			for _, ao := range apps {
				app, ok := ao.(*corev1.Application)
				if !ok || app.Namespace != svc.Namespace || app.Spec.ServiceName != svc.Name {
					continue
				}
				node := app.Spec.Placement.NodeName
				if node == "" {
					continue // unplaced: nothing is listening anywhere yet
				}
				meta := map[string]string{"application": app.Name}
				if svc.Spec.ClusterIP != "" {
					meta["clusterIP"] = svc.Spec.ClusterIP
				}
				for k, v := range svc.Annotations {
					meta[k] = v
				}
				out = append(out, catalogService{
					Node: node, Address: addr[node], Datacenter: Datacenter, Namespace: svc.Namespace,
					ServiceID:      app.Name + "-" + portID(po),
					ServiceName:    catName,
					ServiceAddress: addr[node],
					ServicePort:    int(po.TargetFor(app)),
					ServiceTags:    tagsOf(svc, app, po),
					ServiceMeta:    meta,
				})
			}
		}
	}
	out = append(out, nodeEntries(apps, addr, name)...)
	// Deterministic order: a client diffing two polls must not see churn that is only map
	// iteration.
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServiceName != out[j].ServiceName {
			return out[i].ServiceName < out[j].ServiceName
		}
		return out[i].ServiceID < out[j].ServiceID
	})
	return out, nil
}

// nodeEntries is the node's own service: one registration per (Application, port) for everything on
// the HOST NETWORK placed on that node, under the node's name and at the node's address.
//
// It exists because such a workload is already reachable and the control plane already knows where:
// the address is the node's, known the moment the scheduler picks one. So a single flat workload
// needs no Service object and no declared address to be discoverable — it declares a port, it is
// scheduled, and it is in the catalog under the node it landed on. A Service stays what it is for:
// a name of one's own, shared by instances across nodes, with an address in front of them.
//
// Everything on the host network is here, including instances that also declare a Service — being
// in one's own service and being on a host are different facts, and the second is what
// `catalog/service/<node>` answers: what is running on this machine. The two never disagree, since
// both are read off the same Applications.
//
// The condition is the workload's NETWORK, not whether a datapath is running. An isolated workload
// (once the pod network exists) does not bind the node's ports, so publishing it at the node's
// address would advertise a port nothing there is listening on — the one lie this projection could
// tell. That is why it asks OnHostNetwork rather than asking about eBPF: with the datapath on, a
// flat workload is still flat and still registers here, and its Service's clusterIP is the other,
// independent way to it.
//
// The address is not COPIED anywhere. These entries are computed per read like the rest of the
// projection, so a node whose address changes publishes the new one at once and there is no second
// record of it to drift — which is the whole reason this is not a Service object per node.
func nodeEntries(apps []types.Object, addr map[string]string, name string) []catalogService {
	var out []catalogService
	for _, ao := range apps {
		app, ok := ao.(*corev1.Application)
		if !ok || len(app.Spec.Ports) == 0 || !app.OnHostNetwork() {
			continue
		}
		node := app.Spec.Placement.NodeName
		if node == "" || addr[node] == "" {
			continue // unplaced, or a node that has not reported an address yet
		}
		if name != "" && node != name {
			continue
		}
		for _, p := range app.Spec.Ports {
			out = append(out, catalogService{
				Node: node, Address: addr[node], Datacenter: Datacenter, Namespace: app.Namespace,
				ServiceID:      app.Name + "-" + appPortID(p),
				ServiceName:    node,
				ServiceAddress: addr[node],
				ServicePort:    p.Port,
				ServiceTags:    nodeTagsOf(app, node, p),
				// The node's address is the cluster address of everything flat on it, so it is
				// reported under the same key a Service's declared one is — a consumer reads
				// `clusterIP` and does not have to know which of the two it got.
				ServiceMeta: map[string]string{"application": app.Name, "clusterIP": addr[node], "node": node},
			})
		}
	}
	return out
}

// nodeTagsOf is the derived tag set of a node registration. `application=` is here and not on a
// Service registration because this is the one place the workload's own name is the only thing that
// distinguishes two entries — the service name is the node's, shared by everything on it.
func nodeTagsOf(app *corev1.Application, node string, p corev1.Port) []string {
	tags := []string{
		"namespace=" + app.Namespace,
		"node=" + node,
		"application=" + app.Name,
		"protocol=tcp",
	}
	if p.Name != "" {
		tags = append(tags, "port="+p.Name)
	}
	if set := app.Labels[corev1.LabelApplicationSet]; set != "" {
		tags = append(tags, "applicationset="+set)
	}
	if comp := app.Labels[corev1.LabelComponent]; comp != "" {
		tags = append(tags, "component="+comp)
	}
	if svc := app.Spec.ServiceName; svc != "" {
		tags = append(tags, "service="+svc)
	}
	sort.Strings(tags)
	return tags
}

// appPortID identifies one of a workload's ports inside its registration id. The NUMBER stands in
// for an unnamed port rather than a constant, because a workload may declare several and two
// registrations sharing an id would be one registration to every consumer.
func appPortID(p corev1.Port) string {
	if p.Name != "" {
		return p.Name
	}
	return strconv.Itoa(p.Port)
}

func (s *APIServer) listKind(ctx context.Context, kind, namespace string) ([]types.Object, error) {
	list, err := s.svc.List(ctx, types.ObjectMeta{
		ApiVersion: corev1.GroupVersion.String(), Kind: kind, Namespace: namespace,
	}, metav1.ListOptions{})
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	return list, nil
}

// DefaultCatalogNamespace is the namespace an unqualified catalog query answers when the operator
// names none — Consul Enterprise's own answer, and the name a fleet's first namespace has here.
const DefaultCatalogNamespace = "default"

// SetCatalogNamespace names the namespace an unqualified catalog query answers.
//
// It is configurable because `default` is Consul's convention and not necessarily a fleet's: a
// deployment that puts its workloads in `platform` and never uses `default` would otherwise answer
// every client that cannot send `?ns=` with an empty catalog — and an empty catalog reads as "the
// service is gone", not as "you asked the wrong question". The alternative, flattening every
// namespace into an unqualified answer, is the one thing this must not do: one tenant's `api` would
// shadow another's for a client with no way to ask better.
func (s *APIServer) SetCatalogNamespace(ns string) { s.catalogNamespace = ns }

// namespaceOf reads the Consul Enterprise namespace parameter, falling back to the configured
// default.
func (s *APIServer) namespaceOf(req bunrouter.Request) string {
	if ns := req.URL.Query().Get("ns"); ns != "" {
		return ns
	}
	if s.catalogNamespace != "" {
		return s.catalogNamespace
	}
	return DefaultCatalogNamespace
}

// tagsOf is the registration's tags, and every one of them is DERIVED. Nothing an author writes
// reaches this list.
//
// Tags are what a catalog consumer filters on, so the useful ones are the facts the control plane
// already knows for certain — where the service lives, what it is called, which port this
// registration is, and which bundle the instance came out of. An author-supplied tag adds nothing
// a consumer can trust: it is a free string nobody validates, it is one more place for the same
// fact to be stale, and the moment it carries an edge product's configuration the API has taken
// sides about which edge you run.
//
// The `key=value` spelling is ours here in a way it was not before: these are generated, so the
// encoding is consistent and self-describing. A bare `default` tag would say nothing about whether
// it named a namespace, a component or a datacenter.
func tagsOf(svc *corev1.Service, app *corev1.Application, p corev1.ServicePort) []string {
	tags := []string{
		"namespace=" + svc.Namespace,
		"service=" + svc.Name,
		"protocol=" + protocolOf(p),
	}
	if p.Name != "" {
		tags = append(tags, "port="+p.Name)
	}
	// Where the instance came from, when it came from a bundle. The two labels are
	// controller-owned, so unlike anything an author could write they cannot be forged.
	if set := app.Labels[corev1.LabelApplicationSet]; set != "" {
		tags = append(tags, "applicationset="+set)
	}
	if comp := app.Labels[corev1.LabelComponent]; comp != "" {
		tags = append(tags, "component="+comp)
	}
	sort.Strings(tags)
	return tags
}

func protocolOf(p corev1.ServicePort) string {
	if p.Protocol != "" {
		return strings.ToLower(p.Protocol)
	}
	return "tcp"
}

func portID(p corev1.ServicePort) string {
	if p.Name == "" {
		return "tcp"
	}
	return p.Name
}

func filterByTag(entries []catalogService, tag string) []catalogService {
	if tag == "" {
		return entries
	}
	out := make([]catalogService, 0, len(entries))
	for _, e := range entries {
		if contains(e.ServiceTags, tag) {
			out = append(out, e)
		}
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
