package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// pod is the read-only projection of an Application into the legacy core group, so
// `kubectl logs <app>` (which is pod-centric) resolves it and streams its unit
// logs. One application is one process is one container, so the pod has exactly
// one container named after the app.
type pod struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   podSpec   `json:"spec"`
	Status podStatus `json:"status"`
}

type podSpec struct {
	NodeName   string      `json:"nodeName,omitempty"`
	Containers []container `json:"containers,omitempty"`
}

type container struct {
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
}

type podStatus struct {
	Phase string `json:"phase,omitempty"`
}

type podList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []pod `json:"items"`
}

// podsGR shapes not-found errors as pod errors (what kubectl expects).
var podsGR = schema.GroupResource{Resource: "pods"}

// coreResourceList advertises the legacy core group's only resource: the
// read-only `pods` alias (with its `log` subresource), so kubectl can discover it
// and drive `kubectl logs`.
func (s *APIServer) coreResourceList(w http.ResponseWriter, _ bunrouter.Request) error {
	return bunrouter.JSON(w, &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{Name: "pods", SingularName: "pod", Namespaced: false, Kind: "Pod", Verbs: metav1.Verbs{"get", "list"}},
			{Name: "pods/log", Namespaced: false, Kind: "Pod", Verbs: metav1.Verbs{"get"}},
			// `nodes` is deliberately NOT advertised here, though the routes exist. A real Node
			// Kind lives in horchestra.io/v1, and listing an alias of it in the core group made
			// kubectl resolve the noun to THIS one: `kubectl get node` printed a projection with
			// no status, and `kubectl uncordon` answered "already uncordoned" about a node that
			// was cordoned — a write that silently did nothing. `kubectl top node` fetches
			// /api/v1/nodes by path with its built-in type and needs no discovery entry, so
			// leaving it out costs nothing and takes the ambiguity away.
		},
	})
}

// podGet returns the pod projection of the Application of the same name, so
// `kubectl logs <app>` resolves it and then requests pods/<app>/log.
func (s *APIServer) podGet(w http.ResponseWriter, req bunrouter.Request) error {
	app, err := s.application(req.Context(), req.Param("name"))
	if err != nil {
		return asPodError(err, req.Param("name"))
	}
	return bunrouter.JSON(w, syntheticPod(app))
}

// podList projects every Application the caller is authorized to list into a pod (for
// `kubectl get pods`), namespace by namespace — the pods alias is served under /api/v1 with no
// namespace in the path, so without this scoping any authenticated caller would read every
// tenant's Applications.
func (s *APIServer) podList(w http.ResponseWriter, req bunrouter.Request) error {
	mayList := s.appAuthorizer(req.Context(), "list")
	meta := types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Application"}
	list, err := s.svc.List(req.Context(), meta, metav1.ListOptions{})
	if err != nil {
		return err
	}

	node, nodeCaller := nodeConfinement(req.Context())
	only := req.Param("namespace") // empty on the cluster-wide route
	pods := podList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}}
	for _, item := range list {
		app, ok := item.(*corev1.Application)
		if !ok || !mayList(app.Namespace) {
			continue
		}
		if only != "" && app.Namespace != only {
			continue
		}
		if nodeCaller && app.Spec.Placement.NodeName != node {
			continue
		}
		pods.Items = append(pods.Items, *syntheticPod(app))
	}
	return bunrouter.JSON(w, &pods)
}

// nodeConfinement returns the node name a system:nodes caller is confined to, and whether the
// caller is one. A node identity may see only the workloads placed on its own node: this alias
// resolves an Application by name and then streams its unit logs from the node the OBJECT names,
// so an unconfined node credential taps the live output — "a sensitive read (it can carry another
// tenant's secrets)" — of workloads on nodes it does not own. It is the same own-node check
// controller/nodeserver makes on the status path, where the peer CN is the node name. The
// built-in node authorizer no longer grants Applications at all, so this is the second gate: it
// still binds if an operator grants a node identity `get applications` through RBAC.
func nodeConfinement(ctx context.Context) (string, bool) {
	id := authn.FromContext(ctx)
	if id == nil || !slices.Contains(id.Groups, authz.NodeGroup) {
		return "", false
	}
	return id.Name, true
}

// SetAuthorizer wires the engine that authorizes the pods alias. The alias is a legacy
// /api/v1 route, which AttributesFromRequest classifies as a non-resource request (it
// parses only /apis paths) and the Casbin engine then allows unconditionally — so the
// Authz middleware decides nothing here and the check has to happen in the handler,
// where the Application's namespace is finally known. Left unset (e.g. under
// auth compiled out), every namespace is allowed.
func (s *APIServer) SetAuthorizer(a authz.Authorizer) { s.authz = a }

// appAuthorizer returns a memoized predicate reporting whether the caller may perform verb
// on Applications in a namespace. Memoized because one pods request fans out over every
// Application in the store and would otherwise re-ask the engine per item.
func (s *APIServer) appAuthorizer(ctx context.Context, verb string) func(namespace string) bool {
	if s.authz == nil {
		return func(string) bool { return true }
	}
	id := authn.FromContext(ctx)
	decided := map[string]bool{}
	return func(namespace string) bool {
		if ok, seen := decided[namespace]; seen {
			return ok
		}
		ok, err := s.authz.Authorize(ctx, authz.Attributes{
			User:            id,
			Verb:            verb,
			Group:           corev1.GroupName,
			Resource:        "applications",
			Namespace:       namespace,
			ResourceRequest: true,
		})
		if err != nil {
			ok = false // fail closed: an engine error must not widen access
		}
		decided[namespace] = ok
		return ok
	}
}

const (
	// maxLogStreamsPerCaller bounds one identity's concurrent log streams. Each stream pins a
	// controller-side chunk buffer for as long as the request lives, and a client that never
	// reads its response body blocks the handler below in Write — so without a per-caller cap a
	// tenant holding nothing but `get applications` in its own namespace can hold an unbounded
	// number of them open.
	maxLogStreamsPerCaller = 8
	// logWriteTimeout is the deadline for a single chunk write. The streaming path deliberately
	// runs on a server with no WriteTimeout (a --follow stream is long-lived), and
	// HTTP2Config.WriteByteTimeout does not cover an HTTP/1.1 client, so the deadline is set per
	// write here instead. It bounds a client that opens the stream and then stops reading.
	logWriteTimeout = 30 * time.Second
)

// nodeLog streams a node agent's own unit journal. Registered only under the NodeLogs gate
// (see EnableNodeLogs), authorized by the middleware as `nodes/log` before it is reached.
//
// It streams the AGENT'S unit and not the host journal, deliberately. The host journal carries the
// output of every workload on that node, so serving it here would hand over in one call what
// pods/log serves one workload at a time with a permission check on each — an operator debugging a
// node wants to know why the agent cannot converge, which is what this answers.
func (s *APIServer) nodeLog(w http.ResponseWriter, req bunrouter.Request) error {
	if s.logs == nil {
		return apierrors.NewServiceUnavailable("log streaming is not available")
	}
	name := req.Param("name")
	if _, err := s.svc.Get(req.Context(), types.ObjectMeta{
		ApiVersion: corev1.GroupVersion.String(), Kind: "Node", Name: name,
	}); err != nil {
		return apierrors.NewNotFound(schema.GroupResource{Group: corev1.GroupName, Resource: "nodes"}, name)
	}
	q := req.URL.Query()
	follow := q.Get("follow") == "true"
	var tail int64
	if t := q.Get("tailLines"); len(t) > 0 {
		tail, _ = strconv.ParseInt(t, 10, 64)
	}

	release, err := s.acquireLogStream(req.Context())
	if err != nil {
		return err
	}
	defer release()

	ch, cancel, err := s.logs.StreamNodeLogs(req.Context(), name, follow, tail)
	if err != nil {
		return apierrors.NewServiceUnavailable(err.Error())
	}
	defer func() { _ = cancel() }()
	return streamChunks(w, req, ch)
}

// podLog streams the application's logs from the node it runs on. It resolves the
// Application to its spec.node, opens a stream over the agent transport, and
// forwards the bytes to the response (flushing, so `--follow` is live).
func (s *APIServer) podLog(w http.ResponseWriter, req bunrouter.Request) error {
	if s.logs == nil {
		return apierrors.NewServiceUnavailable("log streaming is not available")
	}
	name := req.Param("name")
	app, err := s.application(req.Context(), name)
	if err != nil {
		return asPodError(err, name)
	}
	if len(app.Spec.Placement.NodeName) == 0 {
		return apierrors.NewBadRequest("application " + name + " has no spec.placement.nodeName")
	}
	q := req.URL.Query()
	follow := q.Get("follow") == "true"
	var tail int64
	if t := q.Get("tailLines"); len(t) > 0 {
		tail, _ = strconv.ParseInt(t, 10, 64)
	}

	release, err := s.acquireLogStream(req.Context())
	if err != nil {
		return err
	}
	defer release()

	// Addressed by object UID: it is what names the workload's unit on the node.
	ch, cancel, err := s.logs.StreamLogs(req.Context(), app.Spec.Placement.NodeName, string(app.UID), follow, tail)
	if err != nil {
		return apierrors.NewServiceUnavailable(err.Error())
	}
	defer func() { _ = cancel() }()

	return streamChunks(w, req, ch)
}

// streamChunks writes a log stream to the response, flushing each chunk so `--follow` is live and
// `kubectl get --raw` prints as output arrives rather than at the end. One definition for both log
// routes: they differ in what they stream, never in how.
func streamChunks(w http.ResponseWriter, req bunrouter.Request, ch <-chan []byte) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	rc := http.NewResponseController(w)
	for {
		select {
		case <-req.Context().Done():
			return nil
		case b, ok := <-ch:
			if !ok {
				return nil // end of logs
			}
			// Ignored deliberately: a hijacked or wrapped ResponseWriter may not support
			// deadlines, and the stream is still correct without one.
			_ = rc.SetWriteDeadline(time.Now().Add(logWriteTimeout))
			if _, err := w.Write(b); err != nil {
				return nil // client gone, or the write deadline expired
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

// acquireLogStream takes one of the caller's log-stream slots, returning the release to defer.
// Streams are counted per identity, so one caller cannot exhaust the server-wide budget the
// node transport enforces underneath. An unauthenticated caller (a build with auth compiled out) counts as one
// identity.
func (s *APIServer) acquireLogStream(ctx context.Context) (func(), error) {
	who := "-"
	if id := authn.FromContext(ctx); id != nil {
		who = id.Name
	}
	s.logStreamsMu.Lock()
	defer s.logStreamsMu.Unlock()
	if s.logStreams[who] >= maxLogStreamsPerCaller {
		return nil, apierrors.NewTooManyRequests(
			fmt.Sprintf("at most %d concurrent log streams per caller", maxLogStreamsPerCaller), 1)
	}
	if s.logStreams == nil {
		s.logStreams = map[string]int{}
	}
	s.logStreams[who]++
	// The map is pruned back to empty by the release below, so it never grows with the number of
	// identities that have ever streamed.
	var once sync.Once
	return func() {
		once.Do(func() {
			s.logStreamsMu.Lock()
			defer s.logStreamsMu.Unlock()
			if s.logStreams[who] <= 1 {
				delete(s.logStreams, who)
				return
			}
			s.logStreams[who]--
		})
	}, nil
}

// application fetches an Application by name (the pods alias addresses one by name only) from a
// namespace the caller is authorized to read it in, and decodes it to its typed form. Requiring
// `get applications` in the owning namespace stops a tenant from resolving — and then
// log-streaming — another tenant's workload by name; a node caller is additionally confined to
// its own node. A match the caller may not read is treated as absent, so the endpoint does not
// confirm that the name exists elsewhere.
func (s *APIServer) application(ctx context.Context, name string) (*corev1.Application, error) {
	mayGet := s.appAuthorizer(ctx, "get")
	node, nodeCaller := nodeConfinement(ctx)
	items, err := s.svc.List(ctx, types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Application"}, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, obj := range items {
		app, ok := obj.(*corev1.Application)
		if !ok || app.Name != name || !mayGet(app.Namespace) {
			continue
		}
		if nodeCaller && app.Spec.Placement.NodeName != node {
			continue
		}
		return app, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: corev1.GroupName, Resource: "applications"}, name)
}

// syntheticPod projects an Application into a pod: a name, one container named
// after the app (its image the app's source), the node it is pinned to, and a
// Running phase.
func syntheticPod(app *corev1.Application) *pod {
	phase := app.Status.Phase
	if phase == "" {
		phase = corev1.AppPhasePending // placed but not yet reported, or unscheduled
	}
	return &pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: app.Name},
		Spec: podSpec{
			NodeName:   app.Spec.Placement.NodeName,
			Containers: []container{{Name: app.Name, Image: app.Spec.Image}},
		},
		Status: podStatus{Phase: phase},
	}
}

// asPodError re-shapes an application not-found as a pod not-found (what kubectl
// expects on the pods alias), passing other errors through.
func asPodError(err error, name string) error {
	if apierrors.IsNotFound(err) {
		return apierrors.NewNotFound(podsGR, name)
	}
	return err
}

// syntheticNode presents a horchestra Node as a core v1 Node, for the same reason
// syntheticPod presents an Application as a Pod: kubectl's node-facing commands are wired to
// the core group and will not look anywhere else. `kubectl top node` lists /api/v1/nodes to
// learn which nodes exist and what they are allocatable for, then asks metrics.k8s.io for
// each — so without this alias the metrics API is complete and the command still fails.
//
// Only what those commands read is filled in. This is a projection for a client, not a second
// representation of the object: the real Node lives in horchestra.io/v1 with its spec, and
// nothing writes through here.
func syntheticNode(n *corev1.Node) map[string]any {
	capacity := map[string]string{
		"cpu":    n.Status.Capacity.CPU.String(),
		"memory": n.Status.Capacity.Memory.String(),
	}
	ready := "False"
	if n.Status.Ready {
		ready = "True"
	}
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata": map[string]any{
			"name":              n.Name,
			"labels":            n.SchedulingLabels(),
			"creationTimestamp": n.CreationTimestamp,
		},
		"status": map[string]any{
			"capacity": capacity,
			// Allocatable is what `kubectl top node` divides by for its percentage. It is the
			// same number as capacity here: this control plane reserves nothing for itself on
			// a node, so claiming a smaller allocatable would be inventing a reservation.
			"allocatable": capacity,
			"conditions": []map[string]any{
				{"type": "Ready", "status": ready},
			},
			"nodeInfo": map[string]any{
				"operatingSystem": n.Status.Platform.OS,
				"architecture":    n.Status.Platform.Arch,
				"osImage":         n.Status.OS,
			},
		},
	}
}

func (s *APIServer) nodeAliasList(w http.ResponseWriter, req bunrouter.Request) error {
	meta := types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Node"}
	list, err := s.svc.List(req.Context(), meta, metav1.ListOptions{})
	if err != nil {
		return err
	}
	items := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if n, ok := item.(*corev1.Node); ok {
			items = append(items, syntheticNode(n))
		}
	}
	return bunrouter.JSON(w, map[string]any{
		"apiVersion": "v1", "kind": "NodeList", "metadata": map[string]any{}, "items": items,
	})
}

func (s *APIServer) nodeAliasGet(w http.ResponseWriter, req bunrouter.Request) error {
	meta := types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Node", Name: req.Param("name")}
	obj, err := s.svc.Get(req.Context(), meta)
	if err != nil {
		return err
	}
	n, ok := obj.(*corev1.Node)
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "nodes"}, req.Param("name"))
	}
	return bunrouter.JSON(w, syntheticNode(n))
}
