package authz

import (
	"context"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/authn"
	"ks-tool.dev/horchestra/pkg/storage"
	"ks-tool.dev/horchestra/pkg/storage/bolt"
)

func TestCasbinAuthorize(t *testing.T) {
	store, err := bolt.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	create(t, store, v1.RoleResource, "app-reader", map[string]any{
		"rules": []any{map[string]any{
			"apiGroups": []any{v1.GroupName},
			"resources": []any{"applications"},
			"verbs":     []any{"get", "list"},
		}},
	})
	create(t, store, v1.RoleBindingResource, "alice-reader", map[string]any{
		"subjects": []any{map[string]any{"kind": "User", "name": "alice"}},
		"roleRef":  map[string]any{"kind": "Role", "name": "app-reader"},
	})

	cb, err := NewCasbin([]string{"system:masters"})
	if err != nil {
		t.Fatalf("new casbin: %v", err)
	}
	if err := cb.LoadFromStore(ctx, store); err != nil {
		t.Fatalf("load: %v", err)
	}

	alice := &authn.Identity{Name: "alice"}
	admin := &authn.Identity{Name: "root", Groups: []string{"system:masters"}}
	bob := &authn.Identity{Name: "bob"}

	cases := []struct {
		name string
		user *authn.Identity
		at   Attributes
		want bool
	}{
		{"alice get application", alice, appAt("get", "app1"), true},
		{"alice list applications", alice, appAt("list", ""), true},
		{"alice delete forbidden", alice, appAt("delete", "app1"), false},
		{"alice nodes forbidden", alice, Attributes{Verb: "get", Group: v1.GroupName, Resource: "nodes", Name: "n1", ResourceRequest: true}, false},
		{"admin group allows anything", admin, appAt("delete", "app1"), true},
		{"bob denied", bob, appAt("get", "app1"), false},
		{"non-resource allowed", bob, Attributes{Verb: "get"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := tc.at
			at.User = tc.user
			ok, err := cb.Authorize(ctx, at)
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("authorize = %v, want %v", ok, tc.want)
			}
		})
	}
}

func appAt(verb, name string) Attributes {
	return Attributes{Verb: verb, Group: v1.GroupName, Resource: "applications", Name: name, ResourceRequest: true}
}

func create(t *testing.T, store storage.Storage, r v1.Resource, name string, spec map[string]any) {
	t.Helper()
	obj := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": name},
		"spec":     spec,
	}}
	if _, err := store.Create(context.Background(), r.GVK, obj); err != nil {
		t.Fatalf("create %s/%s: %v", r.GVK.Kind, name, err)
	}
}
