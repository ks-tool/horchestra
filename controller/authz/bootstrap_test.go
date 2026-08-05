package authz

import (
	"context"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/internal/memory"
)

// TestNodeAuthorizer covers the built-in node authorizer: a system:nodes identity gets its
// fixed node-agent grant (manage Node objects) natively, without any RBAC object; everything
// else is denied — including any read of Applications and PersistentVolumes, which a node
// receives on its gRPC Session already scoped to itself and never fetches over REST.
func TestNodeAuthorizer(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	cb := mustCasbin(t, ctx, store)
	node := &authn.Identity{Name: "node1", Groups: []string{NodeGroup}}

	at := func(verb, resource, name string) Attributes {
		return Attributes{User: node, Verb: verb, Group: corev1.GroupName, Resource: resource, Name: name, ResourceRequest: true}
	}
	cases := []struct {
		name string
		at   Attributes
		want bool
	}{
		{"node registers a Node", at("create", "nodes", "node1"), true},
		{"node reads a Node", at("get", "nodes", "node1"), true},
		// The fleet-wide read the node authorizer used to grant: no namespace, no own-node
		// predicate, so one stolen node credential inventoried every tenant's workloads.
		{"node cannot list applications cluster-wide", at("list", "applications", ""), false},
		{"node cannot watch applications", at("watch", "applications", ""), false},
		{"node cannot get an application", at("get", "applications", "app"), false},
		{"node cannot list persistentvolumes", at("list", "persistentvolumes", ""), false},
		{"node cannot create applications", at("create", "applications", "app"), false},
		{"node cannot delete a persistentvolume", at("delete", "persistentvolumes", "pv"), false},
		{"node cannot delete a Node", at("delete", "nodes", "node1"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := cb.Authorize(ctx, tc.at)
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("authorize = %v, want %v", ok, tc.want)
			}
		})
	}
}
