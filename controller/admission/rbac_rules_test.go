package admission

import (
	"context"
	"strings"
	"testing"

	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func pathRule(verbs []string, urls ...string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{Verbs: verbs, NonResourceURLs: urls}
}

// TestRBACRuleShape: the authorizer projects the two halves of a rule separately, so a rule that
// mixes them or names neither does not fail there — it grants half of what its author read off
// the manifest, silently.
func TestRBACRuleShape(t *testing.T) {
	clusterRole := func(rules ...rbacv1.PolicyRule) types.Object {
		return &rbacv1.ClusterRole{Spec: rbacv1.RoleSpec{Rules: rules}}
	}
	role := func(rules ...rbacv1.PolicyRule) types.Object {
		return &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"},
			Spec:       rbacv1.RoleSpec{Rules: rules},
		}
	}

	for _, tc := range []struct {
		name string
		obj  types.Object
		want string // a substring of the refusal; empty means the write is accepted
	}{
		{"a path rule on a ClusterRole", clusterRole(pathRule([]string{"get"}, "/metrics")), ""},
		{"a resource rule", clusterRole(policyRule("horchestra.io", "applications", "get")), ""},
		{"both halves in one rule", clusterRole(rbacv1.PolicyRule{
			APIGroups: []string{"horchestra.io"}, Resources: []string{"applications"},
			Verbs: []string{"get"}, NonResourceURLs: []string{"/metrics"},
		}), "not both"},
		{"neither half", clusterRole(rbacv1.PolicyRule{Verbs: []string{"get"}}), "must name either"},
		{"resources without apiGroups", clusterRole(rbacv1.PolicyRule{
			Resources: []string{"applications"}, Verbs: []string{"get"},
		}), "either alone selects nothing"},
		{"no verbs", clusterRole(pathRule(nil, "/metrics")), "grants nothing"},
		{"a path rule on a namespaced Role", role(pathRule([]string{"get"}, "/metrics")), "not in any namespace"},
		{"a path that is not a path", clusterRole(pathRule([]string{"get"}, "metrics")), "is not a request path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := rbacRules{}.Validate(context.Background(), &Attributes{Operation: Create, Object: tc.obj})
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("a well-formed rule was refused: %v", err)
			case tc.want != "" && err == nil:
				t.Errorf("a malformed rule was accepted, want a refusal mentioning %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Errorf("refusal = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestNonResourceEscalation: a path grant escalates exactly as a resource one does — /metrics is
// the fleet's shape, and a wildcard path is every endpoint that will ever exist — so the same bar
// applies. The authorizer is asked with the path, which is how the requester's own grant is found.
func TestNonResourceEscalation(t *testing.T) {
	e := rbacEscalation{authorizer: pathAuthorizer{allow: map[string]bool{"get /metrics": true}}}
	alice := authn.WithIdentity(context.Background(), &authn.Identity{Name: "alice"})
	admin := authn.WithIdentity(context.Background(), &authn.Identity{Name: "root", Groups: []string{authz.AdminGroup}})
	cr := func(rules ...rbacv1.PolicyRule) *Attributes {
		return &Attributes{Operation: Create, Object: &rbacv1.ClusterRole{Spec: rbacv1.RoleSpec{Rules: rules}}}
	}

	if err := e.Validate(alice, cr(pathRule([]string{"get"}, "/metrics"))); err != nil {
		t.Errorf("granting a path she holds must be allowed: %v", err)
	}
	if err := e.Validate(alice, cr(pathRule([]string{"get"}, "/logs"))); err == nil {
		t.Error("granting a path she does not hold must be rejected (escalation)")
	}
	if err := e.Validate(alice, cr(pathRule([]string{"get"}, "/*"))); err == nil {
		t.Error("a non-admin may not grant a wildcard path")
	}
	if err := e.Validate(alice, cr(pathRule([]string{"*"}, "/metrics"))); err == nil {
		t.Error("a non-admin may not grant every method on a path")
	}
	if err := e.Validate(admin, cr(pathRule([]string{"*"}, "*"))); err != nil {
		t.Errorf("an admin may grant anything: %v", err)
	}
}

// pathAuthorizer answers for non-resource requests, keyed "verb path".
type pathAuthorizer struct{ allow map[string]bool }

func (p pathAuthorizer) Authorize(_ context.Context, at authz.Attributes) (bool, error) {
	if at.ResourceRequest {
		return false, nil
	}
	return p.allow[at.Verb+" "+at.Path], nil
}
