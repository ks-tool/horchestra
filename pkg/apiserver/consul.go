package apiserver

import (
	"context"
	"net/http"
	"sort"

	"github.com/uptrace/bunrouter"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	v1 "ks-tool.dev/horchestra/api/v1"
)

// The /sd/consul endpoint projects the cluster's services into Consul's catalog
// JSON, so any Consul-catalog-aware consumer (Prometheus consul_sd, Traefik
// consulCatalog, …) can discover horchestra services without a Consul agent. Only
// the service-discovery subset of the fields is emitted, and the Enterprise
// Namespace field is omitted — horchestra OSS is single-project / cluster-wide.
//
// It is a pure read-only projection of Application.spec.expose (the same pattern
// as the pods alias): the orchestrator runs no data-plane of its own, so a service
// is reachable at its node's address on the exposed port and an external edge is
// what routes to it.

// catalogService is one service instance in Consul's /v1/catalog/service/:name
// shape (Namespace omitted).
type catalogService struct {
	Node           string   `json:"Node"`
	Address        string   `json:"Address"`
	ServiceID      string   `json:"ServiceID"`
	ServiceName    string   `json:"ServiceName"`
	ServiceAddress string   `json:"ServiceAddress"`
	ServicePort    int      `json:"ServicePort"`
	ServiceTags    []string `json:"ServiceTags"`
}

// consulServiceList serves Consul's /v1/catalog/services shape — a map of service
// name to its sorted, de-duplicated tags — for a consumer to enumerate services.
func (s *Server) consulServiceList(w http.ResponseWriter, req bunrouter.Request) error {
	svcs, err := s.consulServices(req.Context())
	if err != nil {
		return err
	}
	catalog := map[string][]string{}
	for _, c := range svcs {
		tags, ok := catalog[c.ServiceName]
		if !ok {
			tags = []string{} // Consul emits [] (not null) for an untagged service
		}
		for _, t := range c.ServiceTags {
			if !contains(tags, t) {
				tags = append(tags, t)
			}
		}
		sort.Strings(tags)
		catalog[c.ServiceName] = tags
	}
	return bunrouter.JSON(w, catalog)
}

// consulService serves Consul's /v1/catalog/service/:name shape — the instances of
// one service. One application is one node is one instance, so this is a single
// element (an unknown name yields [], as Consul returns rather than 404).
func (s *Server) consulService(w http.ResponseWriter, req bunrouter.Request) error {
	svcs, err := s.consulServices(req.Context())
	if err != nil {
		return err
	}
	name := req.Param("name")
	instances := []catalogService{}
	for _, c := range svcs {
		if c.ServiceName == name {
			instances = append(instances, c)
		}
	}
	return bunrouter.JSON(w, instances)
}

// consulServices builds the catalog from every Application's spec.expose, resolving
// each application's node to an address. An application contributes one service per
// exposed port: an unnamed port is the application's own name, a named port becomes
// "<app>-<port-name>" (with the port name as a tag). A port whose node has no
// address yet is skipped — there is nothing to advertise. Instances are ordered for
// a stable response.
func (s *Server) consulServices(ctx context.Context) ([]catalogService, error) {
	apps, err := s.svc.List(ctx, v1.ApplicationResource.GVK)
	if err != nil {
		return nil, err
	}
	nodes, err := s.svc.List(ctx, v1.NodeResource.GVK)
	if err != nil {
		return nil, err
	}
	addr := nodeAddrs(nodes)
	var out []catalogService
	for i := range apps.Items {
		obj, err := v1.Decode(v1.ApplicationResource.GVK, &apps.Items[i])
		if err != nil {
			continue
		}
		app, ok := obj.(*v1.Application)
		if !ok {
			continue
		}
		ip := addr[app.Spec.NodeName]
		if len(ip) == 0 {
			continue
		}
		for _, p := range app.Spec.Ports {
			name := app.Name
			tags := []string{}
			if len(p.Name) > 0 {
				name = app.Name + "-" + p.Name
				tags = []string{p.Name}
			}
			out = append(out, catalogService{
				Node:           app.Spec.NodeName,
				Address:        ip,
				ServiceID:      name,
				ServiceName:    name,
				ServiceAddress: ip,
				ServicePort:    p.Port,
				ServiceTags:    tags,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServiceName != out[j].ServiceName {
			return out[i].ServiceName < out[j].ServiceName
		}
		return out[i].Node < out[j].Node
	})
	return out, nil
}

// nodeAddrs maps each node's name to its reported address, skipping nodes that have
// not reported one yet.
func nodeAddrs(list *unstructured.UnstructuredList) map[string]string {
	m := make(map[string]string, len(list.Items))
	for i := range list.Items {
		obj, err := v1.Decode(v1.NodeResource.GVK, &list.Items[i])
		if err != nil {
			continue
		}
		if n, ok := obj.(*v1.Node); ok && len(n.Status.IP) > 0 {
			m[n.Name] = n.Status.IP
		}
	}
	return m
}

func contains(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}
