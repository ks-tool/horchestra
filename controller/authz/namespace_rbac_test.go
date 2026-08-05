package authz

import (
	"context"
	"errors"
	"testing"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/internal/memory"
)

func role(namespace, name string, rules ...rbacv1.PolicyRule) *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       rbacv1.RoleSpec{Rules: rules},
	}
}

func binding(namespace, name, user, roleName string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.GroupVersion.String(), Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: user}},
			RoleRef:  rbacv1.RoleRef{Kind: "Role", Name: roleName},
		},
	}
}

func nsApp(user *authn.Identity, verb, namespace string) Attributes {
	return Attributes{User: user, Verb: verb, Group: corev1.GroupName, Resource: "applications", Namespace: namespace, ResourceRequest: true}
}

// TestNamespacedRBAC: a RoleBinding grants its Role's rules only within its own
// namespace — a user bound in team-a cannot reach team-b, nor any cluster-scoped
// resource.
func TestNamespacedRBAC(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	viewer := rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"get", "list"}}
	mustPut(t, store, role("team-a", "viewer", viewer))
	mustPut(t, store, binding("team-a", "alice-viewer", "alice", "viewer"))

	cb := mustCasbin(t, ctx, store)
	alice := &authn.Identity{Name: "alice"}

	cases := []struct {
		name string
		at   Attributes
		want bool
	}{
		{"alice lists apps in her namespace", nsApp(alice, "list", "team-a"), true},
		{"alice gets apps in her namespace", nsApp(alice, "get", "team-a"), true},
		{"alice cannot reach another namespace", nsApp(alice, "list", "team-b"), false},
		{"alice has no write even in her namespace", nsApp(alice, "create", "team-a"), false},
		{"alice cannot touch cluster-scoped resources", Attributes{User: alice, Verb: "list", Group: corev1.GroupName, Resource: "nodes", ResourceRequest: true}, false},
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

// TestSelfServiceNamespaceListing: any authenticated caller may list Namespaces (no
// cluster-wide right), and AccessibleNamespaces returns exactly the namespaces they
// are bound into — an admin sees all.
func TestSelfServiceNamespaceListing(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	mustPut(t, store, binding("team-a", "alice", "alice", "viewer"))
	mustPut(t, store, binding("team-c", "alice", "alice", "viewer"))
	mustPut(t, store, binding("team-b", "bob", "bob", "viewer"))

	cb := mustCasbin(t, ctx, store)
	alice := &authn.Identity{Name: "alice"}

	// list namespaces is allowed for a plain user (the result is filtered downstream).
	nsList := Attributes{User: alice, Verb: "list", Group: corev1.GroupName, Resource: "namespaces", ResourceRequest: true}
	if ok, err := cb.Authorize(ctx, nsList); err != nil || !ok {
		t.Fatalf("list namespaces = %v, %v; want allowed", ok, err)
	}

	accessible, seesAll, err := AccessibleNamespaces(ctx, store, testScheme(), alice)
	if err != nil {
		t.Fatalf("accessible: %v", err)
	}
	if seesAll {
		t.Fatal("a plain user must not see all namespaces")
	}
	if !accessible["team-a"] || !accessible["team-c"] || accessible["team-b"] || len(accessible) != 2 {
		t.Fatalf("accessible = %v, want {team-a, team-c}", accessible)
	}

	admin := &authn.Identity{Name: "root", Groups: []string{"system:masters"}}
	if _, seesAll, _ := AccessibleNamespaces(ctx, store, testScheme(), admin); !seesAll {
		t.Fatal("an admin must see all namespaces")
	}
}

// mustPut seeds obj, creating its Namespace first when obj is namespaced. The API cannot hold a
// namespaced object whose Namespace is absent — namespaceExistsRule rejects that on create, and a
// Namespace holding objects cannot be deleted — and the RBAC projection now relies on it: a
// binding whose namespace is gone grants nothing, so that a recycled namespace name does not hand
// the previous occupant's grants to the next tenant.
func mustPut(t *testing.T, store *memory.Storage, obj types.Object) {
	t.Helper()
	acc, err := apimeta.Accessor(obj)
	if err != nil {
		t.Fatalf("accessor %T: %v", obj, err)
	}
	if ns := acc.GetNamespace(); ns != "" {
		namespace := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Namespace"},
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		}
		if _, err := store.Create(context.Background(), namespace); err != nil && !errors.Is(err, storage.ErrAlreadyExists) {
			t.Fatalf("seed namespace %s: %v", ns, err)
		}
	}
	if _, err := store.Create(context.Background(), obj); err != nil {
		t.Fatalf("seed %T: %v", obj, err)
	}
}

// mustCasbin builds the Casbin authorizer and loads the store's Role/RoleBinding objects into
// it — the seeded objects must already exist, as Casbin compiles a snapshot at load time.
func mustCasbin(t *testing.T, ctx context.Context, store *memory.Storage) *Casbin {
	t.Helper()
	cb, err := NewCasbin()
	if err != nil {
		t.Fatalf("new casbin: %v", err)
	}
	if err := cb.LoadFromStore(ctx, store); err != nil {
		t.Fatalf("casbin load: %v", err)
	}
	return cb
}

// TestGrantDiesWithItsNamespace: a RoleBinding left behind by a deleted namespace must grant
// nothing and must not put that namespace back in the caller's listing. Namespace names are
// recycled, and the RBAC key is the NAME — so a surviving binding would hand the previous
// occupant full CRUD over everything the next tenant creates under the same name.
func TestGrantDiesWithItsNamespace(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	viewer := rbacv1.PolicyRule{APIGroups: []string{corev1.GroupName}, Resources: []string{"applications"}, Verbs: []string{"get", "list"}}
	mustPut(t, store, role("team-a", "viewer", viewer))
	mustPut(t, store, binding("team-a", "alice-viewer", "alice", "viewer"))
	mustPut(t, store, role("team-c", "viewer", viewer))
	mustPut(t, store, binding("team-c", "alice-viewer", "alice", "viewer"))

	alice := &authn.Identity{Name: "alice"}
	if ok, err := mustCasbin(t, ctx, store).Authorize(ctx, nsApp(alice, "list", "team-a")); err != nil || !ok {
		t.Fatalf("the grant must hold while the namespace exists: ok=%v err=%v", ok, err)
	}

	// The tenant is offboarded: the namespace goes, its RBAC objects are left behind.
	if err := store.Delete(ctx, types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Namespace", Name: "team-a"}); err != nil {
		t.Fatalf("delete namespace: %v", err)
	}

	cb := mustCasbin(t, ctx, store)
	if ok, err := cb.Authorize(ctx, nsApp(alice, "list", "team-a")); err != nil || ok {
		t.Fatalf("the leftover binding still grants in a deleted namespace: ok=%v err=%v", ok, err)
	}
	if ok, err := cb.Authorize(ctx, nsApp(alice, "list", "team-c")); err != nil || !ok {
		t.Fatalf("the surviving namespace's grant must be untouched: ok=%v err=%v", ok, err)
	}

	accessible, seesAll, err := AccessibleNamespaces(ctx, store, testScheme(), alice)
	if err != nil {
		t.Fatalf("accessible: %v", err)
	}
	if seesAll || accessible["team-a"] || !accessible["team-c"] || len(accessible) != 1 {
		t.Fatalf("accessible = %v (seesAll=%v), want exactly {team-c}", accessible, seesAll)
	}
}
