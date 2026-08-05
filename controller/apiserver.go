package apiserver

import (
	"net/http"
	"sync"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type APIServer struct {
	router  *bunrouter.Router
	scheme  *scheme.Scheme
	svc     Service
	logs    LogStreamer
	metrics MetricsSource
	rates   RateSource
	openapi openAPICache

	// nsFilter, when set, restricts the self-service Namespace listing to the
	// namespaces the caller can access (see SetNamespaceFilter). Unset (e.g. auth
	// disabled) returns every namespace.
	nsFilter NamespaceFilter

	// authz, when set, authorizes the pods alias per resolved namespace (see
	// SetAuthorizer). The alias is served under /api/v1 with no namespace in its
	// path, so the Authz middleware cannot decide it. Unset (e.g. auth disabled)
	// allows every namespace, matching the nsFilter convention above.
	authz authz.Authorizer

	// authn, when set, is what the not-found handler authenticates with — it is the one
	// handler the Auth middleware does not wrap (see notFound).
	authn authn.Authenticator

	// catalogNamespace is the namespace an unqualified catalog query answers (see
	// SetCatalogNamespace); empty means DefaultCatalogNamespace.
	catalogNamespace string

	// disc caches the discovery documents; they are derived from the scheme,
	// which is fixed once types are registered at startup. Built once on first
	// use (see discovery()).
	disc discoveryCache

	// logStreams counts each identity's in-flight log streams (see acquireLogStream), bounding
	// how much controller-side buffer one caller can pin.
	logStreamsMu sync.Mutex
	logStreams   map[string]int
}

// New builds an APIServer that serves the Kinds registered in sch, backed by svc
// for all resource operations. Optional middleware (authn/authz, logging) wraps
// every route. It registers the typed /apis routes and the legacy /api discovery;
// mount the returned server with http.Handle or ServeHTTP.
func New(sch *scheme.Scheme, svc Service, mws ...bunrouter.MiddlewareFunc) *APIServer {
	s := &APIServer{scheme: sch, svc: svc}
	s.router = bunrouter.New(
		// Registered BEFORE the middleware, and the order is the whole point: bunrouter binds
		// the not-found handler to the stack that exists at that moment (config.go, group.wrap),
		// so declaring it first leaves it outside the chain. See notFound for why it must be.
		bunrouter.WithNotFoundHandler(s.notFound),
		bunrouter.Use(mws...),
	)
	s.build()
	return s
}

// SetAuthenticator wires the identity check the not-found handler makes on its own behalf.
// Pass the same Authenticator the Auth middleware holds: the two must not be able to disagree
// about who a caller is, and a path that no route serves is the one place the middleware's
// answer never arrives.
func (s *APIServer) SetAuthenticator(a authn.Authenticator) { s.authn = a }

// SetLogStreamer wires the backend that `pods/<app>/log` streams through (the
// controller↔agent gRPC transport satisfies it). Without it the log endpoint
// reports unavailable. Call before serving.
func (s *APIServer) SetLogStreamer(ls LogStreamer) { s.logs = ls }

// EnableNodeLogs registers the node-log route. It is called only when the NodeLogs feature gate
// is on, and that is the whole enforcement: with the gate off the route DOES NOT EXIST, so the
// answer is the router's ordinary 404 for an unknown path — indistinguishable from a typo, with no
// handler behind a permission check to get past and nothing about the fleet to probe by asking.
//
// The path is a real /apis path, which is what makes the authorization ordinary rather than a
// special case: the middleware classifies it as a `get` on the `log` subresource of the
// cluster-scoped `nodes` resource, so RBAC decides it before the handler runs. Nobody holding
// namespace-scoped rights comes near it — which is the reason this is NOT a fallback inside
// pods/log, where a namespaced path would have led to a cluster-scoped object.
//
// It is read with `kubectl get --raw /apis/horchestra.io/v1/nodes/<name>/log`, which streams the
// body, so follow works with any kubectl and no client-side support at all.
func (s *APIServer) EnableNodeLogs() {
	s.router.GET("/apis/horchestra.io/v1/nodes/:name/log", s.nodeLog)
}

func (s *APIServer) EmulatePodsAPI() {
	// Legacy core group: it carries only a read-only `pods` alias of Application,
	// so `kubectl logs <app>` resolves and streams (pods/<name>/log ->
	// applications/<name>/log on the app's node).
	s.router.GET("/api", s.apiVersions)
	s.router.GET("/api/v1", s.coreResourceList)
	s.router.GET("/api/v1/pods", s.podList)
	s.router.GET("/api/v1/pods/:name", s.podGet)
	s.router.GET("/api/v1/pods/:name/log", s.podLog)
	// The same three under a namespace. A Pod IS namespaced, so a client asks for it by
	// namespace whenever it has one to ask with — `kubectl top pod` does exactly that as soon
	// as the metrics list comes back empty and it goes looking for the pods themselves. The
	// cluster-wide paths above stay for --all-namespaces.
	s.router.GET("/api/v1/namespaces/:namespace/pods", s.podList)
	s.router.GET("/api/v1/namespaces/:namespace/pods/:name", s.podGet)
	s.router.GET("/api/v1/namespaces/:namespace/pods/:name/log", s.podLog)
	// `kubectl top node` reads the core-group node list before it asks for metrics, so the
	// alias is what makes a complete metrics API actually usable from the command.
	s.router.GET("/api/v1/nodes", s.nodeAliasList)
	s.router.GET("/api/v1/nodes/:name", s.nodeAliasGet)
}

func (s *APIServer) build() {
	// The schemas the server validates writes against, published where a Kubernetes client
	// looks for them. Without them kubectl refuses to send anything it could not check first.
	s.router.GET("/openapi/v3", s.openAPIRoot)
	s.router.GET("/openapi/v3/apis/:group/:version", s.openAPIGroupVersion)

	s.router.GET("/version", s.serverVersion)

	s.registerCatalog()
	s.registerMetrics()
	s.registerMetricsAPI()

	s.router.GET("/apis", s.apiGroupList)
	s.router.GET("/apis/:group", s.apiGroup)

	gv := s.router.NewGroup("/apis/:group/:version")
	gv.GET("", s.apiResourceList)

	for gvk, r := range s.scheme.Resources() {
		crud := func(list bunrouter.HandlerFunc) func(*bunrouter.Group) {
			return func(gr *bunrouter.Group) {
				gr.GET("", s.bind(gvk, list))
				gr.POST("", s.bind(gvk, s.create))
				gr.GET("/:name", s.bind(gvk, s.get))
				gr.PUT("/:name", s.bind(gvk, s.update))
				gr.PATCH("/:name", s.bind(gvk, s.patch))
				gr.DELETE("/:name", s.bind(gvk, s.delete))
			}
		}
		if r.Namespaced {
			// full CRUD under the namespace, plus a cluster-wide read-only collection
			// for `kubectl get <res> --all-namespaces`.
			gv.WithGroup("/namespaces/:namespace/"+r.Plural, crud(s.listOrWatch))
			gv.WithGroup("/"+r.Plural, func(gr *bunrouter.Group) {
				gr.GET("", s.bind(gvk, s.listOrWatch))
			})
		} else {
			list := bunrouter.HandlerFunc(s.listOrWatch)
			if gvk.Kind == "Namespace" {
				list = s.namespaceList // self-service: filter to the caller's namespaces
			}
			gv.WithGroup("/"+r.Plural, crud(list))
		}
	}
}

// bind fixes the GVK of a route at registration time and injects it into the
// request context, so handlers never derive the kind from the URL.
func (s *APIServer) bind(gvk schema.GroupVersionKind, h bunrouter.HandlerFunc) bunrouter.HandlerFunc {
	return func(w http.ResponseWriter, req bunrouter.Request) error {
		return h(w, req.WithContext(withGVK(req.Context(), gvk)))
	}
}

func (s *APIServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if err := rejectEncodedPath(req); err != nil {
		writeError(w, err)
		return
	}
	if err := s.router.ServeHTTPError(w, req); err != nil {
		writeError(w, err)
	}
}

// rejectEncodedPath refuses a request-URI whose path is not already its own canonical
// encoding.
//
// It closes a routing/authorization split-brain: bunrouter matches routes and extracts
// :namespace/:name from req.URL.RawPath when it is set ("path := req.URL.RawPath; if
// path == \"\" { path = req.URL.Path }") and hands back raw, still-escaped substrings,
// whereas authz.AttributesFromRequest splits the percent-DECODED req.URL.Path. A %2F
// inside any segment therefore expands into extra segments for the authorizer while
// staying one opaque segment for the router, so the permission that is checked and the
// object that is served come from different namespaces — a full cross-namespace
// authorization bypass, reachable through the filler :version segment that no handler
// reads.
//
// net/http sets RawPath exactly when the escaped form differs from the canonical
// encoding of Path, and nothing this API addresses needs one (names, namespaces, groups
// and versions are all RFC1123-shaped), so rejecting it outright keeps the authorizer's
// view and the router's view the same string by construction.
func rejectEncodedPath(req *http.Request) error {
	if req.URL.RawPath == "" {
		return nil
	}
	return apierrors.NewBadRequest("request path must not contain percent-encoded characters")
}

func writeError(w http.ResponseWriter, err error) {
	statusErr, ok := err.(apierrors.APIStatus)
	if !ok {
		statusErr = apierrors.NewInternalError(err)
	}

	status := statusErr.Status()
	status.APIVersion, status.Kind = "v1", "Status"

	if err = writeJSON(w, int(status.Code), status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// notFound answers an unrouted path with a proper Kubernetes Status, and WRITES it rather than
// returning it.
//
// Returning was the bug: nothing renders an error on the not-found path — the middleware chain
// that does it never runs for a request that matched no route — so bunrouter fell back to its own
// `404 page not found`, plain text. A client then reports the shape it can make of that, which is
// not the shape of an API answer:
//
//	message: "the server could not find the requested resource"
//	details.causes: [{reason: UnexpectedServerResponse, message: "404 page not found"}]
//
// "Unexpected server response" is the client telling you the server is not speaking the protocol,
// which is a worse thing to read than a missing resource and sends you looking in the wrong place.
//
// The answer deliberately says nothing about WHY the path is unrouted. A route that exists only
// under a feature gate (NodeLogs) must answer identically for a node that exists and one that does
// not, or the 404 itself becomes a way to enumerate the fleet.
// notFound answers a path no route serves. It is the ONE handler outside the middleware chain,
// and it authenticates for itself instead.
//
// bunrouter resolves the route BEFORE running middleware — a miss selects this handler and the
// chain then wraps it — so an unrouted path was reaching an authorizer that had nothing to
// authorize: no resource, no verb, no object, only a string. It refused, as it must for a path
// no rule can name, and every typo came back 403. That is the wrong answer twice over: it says
// "you may not" where the truth is "there is nothing there", and it says it to the cluster admin
// as readily as to anyone else.
//
// What is left to check here is identity, because "no such path" is itself information about
// the server and must not be free to whoever can open a socket. So the handler asks the
// authenticator directly and answers 401 to a caller it cannot name — the same answer the Auth
// middleware would have given, arrived at without it. With no authenticator wired (tests, local
// runs) it answers 404, matching the unset-authorizer convention everywhere else in this file.
func (s *APIServer) notFound(w http.ResponseWriter, req bunrouter.Request) error {
	if s.authn != nil {
		if _, err := s.authn.Authenticate(req.Request); err != nil {
			writeError(w, apierrors.NewUnauthorized(err.Error()))
			return nil
		}
	}
	writeError(w, apierrors.NewGenericServerResponse(
		http.StatusNotFound, req.Method, schema.GroupResource{}, req.URL.Path,
		"the server could not find the requested resource", 0, false))
	return nil
}

func successStatus() *metav1.Status {
	return &metav1.Status{
		TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
		Status:   metav1.StatusSuccess,
	}
}
