package admission

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
)

// rbacRules refuses a Role or ClusterRole whose rules cannot mean what they say. A rule is
// resources or paths, never both and never neither, and a path is cluster-scoped — the
// authorizer projects each half separately, so a malformed rule does not fail there, it
// silently grants half of what its author read off the manifest.
type rbacRules struct{}

func (rbacRules) Admit(context.Context, *Attributes) error { return nil }

func (rbacRules) Validate(_ context.Context, a *Attributes) error {
	if a.Operation == Delete || a.IsSubresource() {
		return nil
	}
	var rules []rbacv1.PolicyRule
	namespaced := false
	switch obj := a.Object.(type) {
	case *rbacv1.Role:
		rules, namespaced = obj.Spec.Rules, true
	case *rbacv1.ClusterRole:
		rules = obj.Spec.Rules
	default:
		return nil
	}
	for i, rule := range rules {
		resources := len(rule.APIGroups) > 0 || len(rule.Resources) > 0
		paths := len(rule.NonResourceURLs) > 0
		switch {
		case resources && paths:
			return fmt.Errorf("spec.rules[%d]: a rule grants resources or nonResourceURLs, not both — split it in two", i)
		case !resources && !paths:
			return fmt.Errorf("spec.rules[%d]: a rule must name either apiGroups and resources, or nonResourceURLs", i)
		case resources && (len(rule.APIGroups) == 0 || len(rule.Resources) == 0):
			return fmt.Errorf("spec.rules[%d]: a resource rule needs both apiGroups and resources — either alone selects nothing", i)
		}
		if len(rule.Verbs) == 0 {
			return fmt.Errorf("spec.rules[%d].verbs: a rule with no verbs grants nothing", i)
		}
		if paths && namespaced {
			return fmt.Errorf("spec.rules[%d].nonResourceURLs: a request path is not in any namespace — "+
				"grant it from a ClusterRole bound by a ClusterRoleBinding", i)
		}
		for _, u := range rule.NonResourceURLs {
			if u != "*" && !strings.HasPrefix(u, "/") {
				return fmt.Errorf("spec.rules[%d].nonResourceURLs: %q is not a request path — "+
					"it begins with / , or is * for every path", i, u)
			}
		}
	}
	return nil
}
