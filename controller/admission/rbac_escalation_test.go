package admission

import (
	"context"
	"testing"

	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
)

type fakeAuthorizer struct{ allow map[string]bool }

func (f fakeAuthorizer) Authorize(_ context.Context, at authz.Attributes) (bool, error) {
	return f.allow[at.Verb+" "+at.Group+"/"+at.Resource], nil
}

func policyRule(group, resource string, verbs ...string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{APIGroups: []string{group}, Resources: []string{resource}, Verbs: verbs}
}

// TestRBACEscalation locks the privilege-escalation guard: a non-admin may grant only permissions
// it already holds (never a wildcard), while an admin and an internal (identity-less) writer bypass.
func TestRBACEscalation(t *testing.T) {
	e := rbacEscalation{authorizer: fakeAuthorizer{allow: map[string]bool{
		"get horchestra.io/applications":  true,
		"list horchestra.io/applications": true,
	}}}

	alice := authn.WithIdentity(context.Background(), &authn.Identity{Name: "alice"})
	admin := authn.WithIdentity(context.Background(), &authn.Identity{Name: "root", Groups: []string{authz.AdminGroup}})
	roleWith := func(rules ...rbacv1.PolicyRule) types.Object {
		return &rbacv1.Role{Spec: rbacv1.RoleSpec{Rules: rules}}
	}
	attrs := func(obj types.Object) *Attributes { return &Attributes{Operation: Create, Object: obj} }

	// alice holds get/list applications → may grant exactly those.
	if err := e.Validate(alice, attrs(roleWith(policyRule("horchestra.io", "applications", "get", "list")))); err != nil {
		t.Errorf("granting a held permission must be allowed: %v", err)
	}
	// alice does NOT hold delete → escalation, rejected.
	if err := e.Validate(alice, attrs(roleWith(policyRule("horchestra.io", "applications", "delete")))); err == nil {
		t.Error("granting an unheld permission must be rejected (escalation)")
	}
	// A wildcard cannot be verified → rejected for a non-admin.
	if err := e.Validate(alice, attrs(roleWith(policyRule("*", "*", "*")))); err == nil {
		t.Error("a non-admin may not grant a wildcard")
	}
	// An admin bypasses the whole check.
	if err := e.Validate(admin, attrs(roleWith(policyRule("*", "*", "*")))); err != nil {
		t.Errorf("an admin may grant anything: %v", err)
	}
	// An internal writer (no request identity) is trusted.
	if err := e.Validate(context.Background(), attrs(roleWith(policyRule("horchestra.io", "applications", "delete")))); err != nil {
		t.Errorf("an internal writer (no identity) must be trusted: %v", err)
	}
}
