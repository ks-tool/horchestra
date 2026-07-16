package apiserver

import (
	"context"
	"net/http"
	"time"

	"github.com/uptrace/bunrouter"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/service"
)

// LogStreamer streams an application's logs from the node it runs on (the
// controller<->agent gRPC transport satisfies it). Absent (nil), the log endpoint
// reports it is unavailable.
type LogStreamer interface {
	StreamLogs(ctx context.Context, node, app string, follow bool, tail int64) (<-chan []byte, func() error, error)
}

type Server struct {
	svc              *service.Service
	resources        []v1.Resource
	logs             LogStreamer
	router           *bunrouter.Router
	nodeReadyTimeout time.Duration
}

// New builds the API server. nodeReadyTimeout bounds how long a node's heartbeat
// may age before it reads NotReady; a non-positive value falls back to the
// package default. logs backs `kubectl logs` (nil disables it).
func New(svc *service.Service, resources []v1.Resource, nodeReadyTimeout time.Duration, logs LogStreamer, mws ...bunrouter.MiddlewareFunc) *Server {
	if nodeReadyTimeout <= 0 {
		nodeReadyTimeout = defaultNodeReadyTimeout
	}
	s := &Server{svc: svc, resources: resources, logs: logs, nodeReadyTimeout: nodeReadyTimeout}
	s.router = s.build(mws)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := s.router.ServeHTTPError(w, r); err != nil {
		writeError(w, err)
	}
}

func (s *Server) build(mws []bunrouter.MiddlewareFunc) *bunrouter.Router {
	r := bunrouter.New(bunrouter.Use(mws...), bunrouter.WithNotFoundHandler(notFound))
	for _, res := range s.resources {
		base := "/apis/:group/:version/" + res.Plural
		r.GET(base, s.bind(res.GVK, s.listOrWatch))
		r.POST(base, s.bind(res.GVK, s.create))
		r.GET(base+"/:name", s.bind(res.GVK, s.get))
		r.PUT(base+"/:name", s.bind(res.GVK, s.update))
		r.PATCH(base+"/:name", s.bind(res.GVK, s.patch))
		r.DELETE(base+"/:name", s.bind(res.GVK, s.delete))
	}
	// Legacy core group: it carries only a read-only `pods` alias of Application,
	// so `kubectl logs <app>` resolves and streams (pods/<name>/log ->
	// applications/<name>/log on the app's node).
	r.GET("/api", s.apiVersions)
	r.GET("/api/v1", s.coreResourceList)
	r.GET("/api/v1/pods", s.podList)
	r.GET("/api/v1/pods/:name", s.podGet)
	r.GET("/api/v1/pods/:name/log", s.podLog)
	r.GET("/apis", s.apiGroupList)
	r.GET("/apis/:group", s.apiGroup)
	r.GET("/apis/:group/:version", s.apiResourceList)
	// Service-discovery projection in Consul catalog format (no Enterprise
	// Namespace): the bare endpoint and Consul's own /v1/catalog paths both serve
	// applications' spec.expose ports, so a Consul-SD consumer can discover them.
	r.GET("/sd/consul", s.consulServiceList)
	r.GET("/sd/consul/v1/catalog/services", s.consulServiceList)
	r.GET("/sd/consul/v1/catalog/service/:name", s.consulService)
	return r
}

// bind fixes the GVK of a route at registration time and injects it into the
// request context, so handlers never derive the kind from the URL.
func (s *Server) bind(gvk schema.GroupVersionKind, h bunrouter.HandlerFunc) bunrouter.HandlerFunc {
	return func(w http.ResponseWriter, req bunrouter.Request) error {
		return h(w, req.WithContext(withGVK(req.Context(), gvk)))
	}
}
