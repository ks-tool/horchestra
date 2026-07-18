package authz

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/apiserver/authn"
	"github.com/ks-tool/horchestra/apiserver/internal/memory"
)

func TestCasbinAuthorize(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	mustCreate(t, store, &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{Name: "app-reader"},
		Spec: rbacv1.RoleSpec{Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"get", "list"}},
		}},
	})
	mustCreate(t, store, &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: "alice-reader"},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}},
			RoleRef:  rbacv1.RoleRef{Kind: "Role", Name: "app-reader"},
		},
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
		{"alice nodes forbidden", alice, Attributes{Verb: "get", Group: corev1.GroupName, Resource: "nodes", Name: "n1", ResourceRequest: true}, false},
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
	return Attributes{Verb: verb, Group: corev1.GroupName, Resource: "applications", Name: name, ResourceRequest: true}
}

func mustCreate(t *testing.T, store *memory.Storage, obj types.Object) {
	t.Helper()
	if _, err := store.Create(context.Background(), obj); err != nil {
		t.Fatalf("create: %v", err)
	}
}
