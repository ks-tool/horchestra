package authz

import (
	"context"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/authn"
	"ks-tool.dev/horchestra/pkg/storage/bolt"
)

func TestSeedDefaultsAuthorizesNode(t *testing.T) {
	store, err := bolt.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	// Idempotent: seeding twice must not error (the Role is upserted, the binding
	// hits ErrAlreadyExists).
	if err := SeedDefaults(ctx, store); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := SeedDefaults(ctx, store); err != nil {
		t.Fatalf("re-seed: %v", err)
	}

	rbac := &RBAC{Store: store, AdminGroups: []string{"system:masters"}}
	node := &authn.Identity{Name: "node1", Groups: []string{nodesGroup}}

	nodesAt := func(verb, name string) Attributes {
		return Attributes{User: node, Verb: verb, Group: v1.GroupName, Resource: "nodes", Name: name, ResourceRequest: true}
	}
	appsAt := func(verb, name string) Attributes {
		return Attributes{User: node, Verb: verb, Group: v1.GroupName, Resource: "applications", Name: name, ResourceRequest: true}
	}
	pvsAt := func(verb, name string) Attributes {
		return Attributes{User: node, Verb: verb, Group: v1.GroupName, Resource: "persistentvolumes", Name: name, ResourceRequest: true}
	}

	cases := []struct {
		name string
		at   Attributes
		want bool
	}{
		{"node registers a Node", nodesAt("create", "node1"), true},
		{"node reads a Node", nodesAt("get", "node1"), true},
		{"node lists applications", appsAt("list", ""), true},
		{"node watches applications", appsAt("watch", ""), true},
		{"node lists persistentvolumes", pvsAt("list", ""), true},
		// Least privilege: no application writes, no PV writes, no node deletes.
		{"node cannot create applications", appsAt("create", "app"), false},
		{"node cannot delete a persistentvolume", pvsAt("delete", "pv"), false},
		{"node cannot delete a Node", nodesAt("delete", "node1"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := rbac.Authorize(ctx, tc.at)
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("authorize = %v, want %v", ok, tc.want)
			}
		})
	}
}

// TestSeedDefaultsUpgradesStaleRole checks that SeedDefaults reconciles an
// existing node Role from an older version (missing the persistentvolumes grant)
// up to the current default, rather than leaving it stale — the upgrade hazard
// that would otherwise 403 the node on the PersistentVolume list.
func TestSeedDefaultsUpgradesStaleRole(t *testing.T) {
	store, err := bolt.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	// A cluster first seeded by an older controller: node Role without persistentvolumes.
	stale, err := toUnstructured(&v1.Role{
		TypeMeta:   v1.RoleResource.TypeMeta(),
		ObjectMeta: metav1.ObjectMeta{Name: NodeRoleName},
		Spec: v1.RoleSpec{Rules: []v1.PolicyRule{
			{APIGroups: []string{v1.GroupName}, Resources: []string{"nodes"}, Verbs: []string{"create", "get", "update", "patch"}},
			{APIGroups: []string{v1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"get", "list", "watch"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, v1.RoleResource.GVK, stale); err != nil {
		t.Fatalf("seed stale role: %v", err)
	}

	// Upgrade: SeedDefaults must update the existing Role, not skip it.
	if err := SeedDefaults(ctx, store); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rbac := &RBAC{Store: store, AdminGroups: []string{"system:masters"}}
	node := &authn.Identity{Name: "node1", Groups: []string{nodesGroup}}
	ok, err := rbac.Authorize(ctx, Attributes{User: node, Verb: "list", Group: v1.GroupName, Resource: "persistentvolumes", ResourceRequest: true})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !ok {
		t.Fatal("stale node Role was not upgraded with persistentvolumes access")
	}
}
