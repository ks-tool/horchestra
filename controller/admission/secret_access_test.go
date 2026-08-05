package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
)

// namedAuthorizer answers per (verb, resource, namespace, name), which is what the secret check
// asks: RBAC can grant get on one Secret and not its neighbour.
type namedAuthorizer struct{ allow map[string]bool }

func (f namedAuthorizer) Authorize(_ context.Context, at authz.Attributes) (bool, error) {
	return f.allow[at.Verb+" "+at.Resource+" "+at.Namespace+"/"+at.Name], nil
}

func envRef(name string) corev1.EnvVar {
	return corev1.EnvVar{Name: "PW", SecretRef: &corev1.EnvSecretRef{Name: name, Key: "password"}}
}

func secretMount(name string) corev1.VolumeMount {
	return corev1.VolumeMount{
		MountPath: "/creds",
		Volume:    corev1.VolumeSource{Type: corev1.VolumeTypeSecret, Name: name},
	}
}

func appIn(ns string, env []corev1.EnvVar, vols []corev1.VolumeMount) types.Object {
	app := &corev1.Application{Spec: corev1.ApplicationSpec{Image: "img", Env: env, Volumes: vols}}
	app.Namespace = ns
	return app
}

// TestMountingASecretRequiresReadingIt is the hole this closes. Reading a Secret over REST is
// RBAC-gated, but an Application is a request to put that Secret's value into a process, and the
// NODE resolves the reference — with its own authority, long after the author is gone. Without
// the check, `create applications` in a namespace is `read every secret` in it.
func TestMountingASecretRequiresReadingIt(t *testing.T) {
	s := secretAccess{authorizer: namedAuthorizer{allow: map[string]bool{
		"get secrets team-a/mine": true,
	}}}
	alice := authn.WithIdentity(context.Background(), &authn.Identity{Name: "alice"})
	attrs := func(obj types.Object) *Attributes { return &Attributes{Operation: Create, Object: obj} }

	if err := s.Validate(alice, attrs(appIn("team-a", []corev1.EnvVar{envRef("mine")}, nil))); err != nil {
		t.Errorf("referencing a readable secret must be allowed: %v", err)
	}

	// The same subject, the same namespace, a secret it cannot get.
	err := s.Validate(alice, attrs(appIn("team-a", []corev1.EnvVar{envRef("theirs")}, nil)))
	if err == nil {
		t.Fatal("mounting an unreadable secret was allowed")
	}
	if !strings.Contains(err.Error(), "theirs") {
		t.Errorf("the error must name the secret, got %v", err)
	}

	// A volume is the same request in a different shape.
	if err := s.Validate(alice, attrs(appIn("team-a", nil, []corev1.VolumeMount{secretMount("theirs")}))); err == nil {
		t.Error("mounting an unreadable secret as a VOLUME was allowed")
	}

	// And the grant is per namespace: the same name elsewhere is a different secret.
	if err := s.Validate(alice, attrs(appIn("team-b", []corev1.EnvVar{envRef("mine")}, nil))); err == nil {
		t.Error("a grant in one namespace authorized the same name in another")
	}
}

// TestSetCannotLaunderASecretReference: an ApplicationSet renders children through an internal
// writer with no identity, so if the set itself were not checked, wrapping the application in one
// would bypass the rule entirely. Both the shared block and the per-child specs are checked.
func TestSetCannotLaunderASecretReference(t *testing.T) {
	s := secretAccess{authorizer: namedAuthorizer{}} // grants nothing
	alice := authn.WithIdentity(context.Background(), &authn.Identity{Name: "alice"})

	viaChild := &corev1.ApplicationSet{Spec: corev1.ApplicationSetSpec{
		Applications: []corev1.NamedApplicationSpec{
			{Name: "web", Spec: corev1.ApplicationSpec{Image: "img", Env: []corev1.EnvVar{envRef("theirs")}}},
		},
	}}
	viaChild.Namespace = "team-a"
	if err := s.Validate(alice, &Attributes{Operation: Create, Object: viaChild}); err == nil {
		t.Error("a child spec smuggled an unreadable secret past the check")
	}

	viaCommon := &corev1.ApplicationSet{Spec: corev1.ApplicationSetSpec{
		Applications: []corev1.NamedApplicationSpec{{Name: "web", Spec: corev1.ApplicationSpec{Image: "img"}}},
		Common:       corev1.CommonMeta{Volumes: []corev1.VolumeMount{secretMount("theirs")}},
	}}
	viaCommon.Namespace = "team-a"
	if err := s.Validate(alice, &Attributes{Operation: Create, Object: viaCommon}); err == nil {
		t.Error("the shared block smuggled an unreadable secret past the check")
	}
}

// TestInternalWriterAndAdminBypass: the loops and the node transport carry no request identity —
// an ApplicationSet's children are created by the controller AFTER the set was checked with the
// author's identity, so re-checking them against nobody would only fail. An admin holds
// everything by definition.
func TestInternalWriterAndAdminBypass(t *testing.T) {
	s := secretAccess{authorizer: namedAuthorizer{}} // grants nothing
	app := appIn("team-a", []corev1.EnvVar{envRef("theirs")}, nil)

	if err := s.Validate(context.Background(), &Attributes{Operation: Create, Object: app}); err != nil {
		t.Errorf("an identity-less internal writer must not be blocked: %v", err)
	}
	admin := authn.WithIdentity(context.Background(), &authn.Identity{Name: "root", Groups: []string{authz.AdminGroup}})
	if err := s.Validate(admin, &Attributes{Operation: Create, Object: app}); err != nil {
		t.Errorf("an admin must not be blocked: %v", err)
	}
	// A delete does not reference anything.
	if err := s.Validate(authn.WithIdentity(context.Background(), &authn.Identity{Name: "alice"}),
		&Attributes{Operation: Delete, Object: app}); err != nil {
		t.Errorf("delete must not be checked: %v", err)
	}
}

// TestSecretRefsAreDeduped keeps the authorizer round trips proportional to distinct secrets, not
// to the length of a list a tenant writes.
func TestSecretRefsAreDeduped(t *testing.T) {
	var asked int
	s := secretAccess{authorizer: authorizerFunc(func(authz.Attributes) (bool, error) {
		asked++
		return true, nil
	})}
	env := []corev1.EnvVar{envRef("a"), envRef("a"), envRef("b"), envRef("a")}
	alice := authn.WithIdentity(context.Background(), &authn.Identity{Name: "alice"})
	if err := s.Validate(alice, &Attributes{Operation: Create, Object: appIn("ns", env, []corev1.VolumeMount{secretMount("b")})}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if asked != 2 {
		t.Errorf("asked the authorizer %d times for 2 distinct secrets", asked)
	}
}

type authorizerFunc func(authz.Attributes) (bool, error)

func (f authorizerFunc) Authorize(_ context.Context, at authz.Attributes) (bool, error) { return f(at) }
