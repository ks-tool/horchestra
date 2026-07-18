package apiserver

import (
	"net/http"
	"strings"

	"github.com/ks-tool/horchestra/api/scheme"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type APIServer struct {
	router *bunrouter.Router
	scheme *scheme.Scheme
	svc    Service
	logs   LogStreamer

	// disc caches the discovery documents; they are derived from the scheme,
	// which is fixed once types are registered at startup. Built once on first
	// use (see discovery()).
	disc discoveryCache
}

// New builds an APIServer that serves the Kinds registered in sch, backed by svc
// for all resource operations. Optional middleware (authn/authz, logging) wraps
// every route. It registers the typed /apis routes and the legacy /api discovery;
// mount the returned server with http.Handle or ServeHTTP.
func New(sch *scheme.Scheme, svc Service, mws ...bunrouter.MiddlewareFunc) *APIServer {
	s := &APIServer{scheme: sch, svc: svc}
	s.router = bunrouter.New(
		bunrouter.Use(mws...),
		bunrouter.WithNotFoundHandler(notFound),
	)
	s.build()
	return s
}

// SetLogStreamer wires the backend that `pods/<app>/log` streams through (the
// controller↔agent gRPC transport satisfies it). Without it the log endpoint
// reports unavailable. Call before serving.
func (s *APIServer) SetLogStreamer(ls LogStreamer) { s.logs = ls }

func (s *APIServer) EmulatePodsAPI() {
	// Legacy core group: it carries only a read-only `pods` alias of Application,
	// so `kubectl logs <app>` resolves and streams (pods/<name>/log ->
	// applications/<name>/log on the app's node).
	s.router.GET("/api", s.apiVersions)
	s.router.GET("/api/v1", s.coreResourceList)
	s.router.GET("/api/v1/pods", s.podList)
	s.router.GET("/api/v1/pods/:name", s.podGet)
	s.router.GET("/api/v1/pods/:name/log", s.podLog)
}

func (s *APIServer) build() {
	s.router.GET("/apis", s.apiGroupList)
	s.router.GET("/apis/:group", s.apiGroup)

	gv := s.router.NewGroup("/apis/:group/:version")
	gv.GET("", s.apiResourceList)

	for gvk, r := range s.scheme.Resources() {
		gv.WithGroup("/"+r.Plural, func(gr *bunrouter.Group) {
			gr.GET("", s.bind(gvk, s.listOrWatch))
			gr.POST("", s.bind(gvk, s.create))
			gr.GET("/:name", s.bind(gvk, s.get))
			gr.PUT("/:name", s.bind(gvk, s.update))
			gr.PATCH("/:name", s.bind(gvk, s.patch))
			gr.DELETE("/:name", s.bind(gvk, s.delete))
		})
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
	if err := s.router.ServeHTTPError(w, req); err != nil {
		writeError(w, err)
	}
}

func writeError(w http.ResponseWriter, err error) {
	status, ok := err.(apierrors.APIStatus)
	if !ok {
		status = apierrors.NewInternalError(err)
	}

	s := status.Status()
	// Stamp the Status TypeMeta so clients can decode the body as a
	// meta.k8s.io/v1 Status; without it kubectl reports "Object 'Kind' is
	// missing" and renders a generic "unknown" error instead of the message.
	s.APIVersion, s.Kind = "v1", "Status"
	_ = writeJSON(w, int(s.Code), s)
}

func notFound(_ http.ResponseWriter, req bunrouter.Request) error {
	name := req.Param("name")
	if len(name) == 0 {
		name = req.URL.Path
	}

	gvk := gvkFromContext(req.Context())
	return apierrors.NewNotFound(schema.GroupResource{
		Group:    gvk.Group,
		Resource: strings.ToLower(gvk.Kind),
	}, name)
}

func successStatus() *metav1.Status {
	return &metav1.Status{
		TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
		Status:   metav1.StatusSuccess,
	}
}
