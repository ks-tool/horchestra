package admission

import (
	"context"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
)

// rbacEscalation prevents privilege escalation through RBAC writes (the Kubernetes escalation
// check): a non-admin may not create/update a Role or ClusterRole granting a permission it does
// not already hold, nor bind a subject to a role whose permissions it does not hold. system:masters
// bypasses it, and an internal writer (no request identity — the control-plane loops and the node
// transport) is trusted. A wildcard ("*") rule cannot be verified by a concrete authorization
// query, so only an admin may grant one.
type rbacEscalation struct {
	authorizer authz.Authorizer
	lister     Lister
}

func (rbacEscalation) Admit(context.Context, *Attributes) error { return nil }

func (e rbacEscalation) Validate(ctx context.Context, a *Attributes) error {
	if e.authorizer == nil || a.Operation == Delete || a.IsSubresource() {
		return nil
	}
	id := authn.FromContext(ctx)
	if id == nil {
		return nil // trusted internal writer (no HTTP identity); node identities cannot write rbac
	}
	if slices.Contains(id.Groups, authz.AdminGroup) {
		return nil // cluster admins may grant anything
	}

	var rules []rbacv1.PolicyRule
	var namespace string // "" = cluster-scoped
	switch obj := a.Object.(type) {
	case *rbacv1.Role:
		rules, namespace = obj.Spec.Rules, obj.Namespace
	case *rbacv1.ClusterRole:
		rules = obj.Spec.Rules
	case *rbacv1.RoleBinding:
		rules, namespace = e.referencedRules(ctx, obj.Spec.RoleRef, obj.Namespace), obj.Namespace
	case *rbacv1.ClusterRoleBinding:
		rules = e.referencedRules(ctx, obj.Spec.RoleRef, "")
	default:
		return nil
	}
	return e.check(ctx, id, namespace, rules)
}

// maxEscalationTuples caps the apiGroup x resource x verb combinations one write may ask the
// escalation check to evaluate. Generous for any real Role, and far below the point where the
// authorizer queries stop being interruptible work.
const maxEscalationTuples = 10000

// check rejects the write unless the requester already holds every concrete permission in rules
// (evaluated in namespace, "" for cluster scope). A wildcard cannot be verified, so it is refused.
func (e rbacEscalation) check(ctx context.Context, id *authn.Identity, namespace string, rules []rbacv1.PolicyRule) error {
	// Bound the work before doing any of it. The check is a cartesian product of
	// apiGroups x resources x verbs, each element an authorizer query, and all three are
	// unbounded []string on a Role a tenant may create in its own namespace — so one write could
	// ask for billions of uninterruptible Casbin evaluations. The tenant needs no second
	// permission for it: naming the very verb it is guaranteed to hold makes every tuple
	// self-evidently authorized, so the check runs to completion rather than failing early.
	tuples := 0
	for _, rule := range rules {
		tuples += max(len(rule.APIGroups), 1) * max(len(rule.Resources), 1) * max(len(rule.Verbs), 1)
		tuples += len(rule.NonResourceURLs) * max(len(rule.Verbs), 1)
	}
	if tuples > maxEscalationTuples {
		return Forbidden("rbac: the rules expand to %d apiGroup/resource/verb combinations, more than the %d this check will evaluate — split them into smaller rules",
			tuples, maxEscalationTuples)
	}
	for _, rule := range rules {
		// The same rule for paths. A non-resource grant escalates exactly as a resource one
		// does — /metrics is the fleet's shape and a wildcard path is every endpoint there
		// will ever be — so it is held to the same bar: the requester must already hold what
		// it is handing out, and a pattern nobody can verify by asking is an admin's to grant.
		for _, url := range rule.NonResourceURLs {
			for _, verb := range rule.Verbs {
				if verb == "*" || strings.HasSuffix(url, "*") {
					return Forbidden("rbac: only a cluster admin may grant a wildcard non-resource permission (verb=%q nonResourceURL=%q)", verb, url)
				}
				ok, err := e.authorizer.Authorize(ctx, authz.Attributes{User: id, Verb: verb, Path: url})
				if err != nil {
					return err
				}
				if !ok {
					return Forbidden("rbac: may not grant %q on %s — the requester does not hold it (privilege escalation)", verb, url)
				}
			}
		}
		for _, g := range rule.APIGroups {
			for _, res := range rule.Resources {
				for _, verb := range rule.Verbs {
					if g == "*" || res == "*" || verb == "*" {
						return Forbidden("rbac: only a cluster admin may grant a wildcard permission (apiGroup=%q resource=%q verb=%q)", g, res, verb)
					}
					ok, err := e.authorizer.Authorize(ctx, authz.Attributes{
						User: id, Verb: verb, Group: g, Resource: res, Namespace: namespace, ResourceRequest: true,
					})
					if err != nil {
						return err
					}
					if !ok {
						return Forbidden("rbac: may not grant %q on %s/%s in namespace %q — the requester does not hold it (privilege escalation)", verb, g, res, namespace)
					}
				}
			}
		}
	}
	return nil
}

// referencedRules resolves a binding's roleRef to the rules it grants: a namespaced Role in ns, or
// a cluster ClusterRole. An absent role grants nothing yet (nil) — the binding is allowed until the
// role exists, and the role is itself escalation-checked on its own write.
func (e rbacEscalation) referencedRules(ctx context.Context, ref rbacv1.RoleRef, ns string) []rbacv1.PolicyRule {
	if e.lister == nil {
		return nil
	}
	switch ref.Kind {
	case "Role":
		objs, _ := e.lister.List(ctx, rbacMeta("Role"), metav1.ListOptions{})
		for _, o := range objs {
			if r, ok := o.(*rbacv1.Role); ok && r.Name == ref.Name && r.Namespace == ns {
				return r.Spec.Rules
			}
		}
	case "ClusterRole":
		objs, _ := e.lister.List(ctx, rbacMeta("ClusterRole"), metav1.ListOptions{})
		for _, o := range objs {
			if cr, ok := o.(*rbacv1.ClusterRole); ok && cr.Name == ref.Name {
				return cr.Spec.Rules
			}
		}
	}
	return nil
}

// WithEscalationCheck appends the guards that need to ask the authorizer a question about the
// REQUESTER, which the rest of the chain cannot: whether a write grants a permission its author
// does not hold (rbacEscalation), whether it references a Secret its author cannot read
// (secretAccess), and whether it joins a Service its author cannot read (serviceJoin). All three
// are privilege escalation; they differ only in what is being escalated to.
// A nil authorizer disables them.
func WithEscalationCheck(chain Chain, authorizer authz.Authorizer, lister Lister) Chain {
	if authorizer == nil {
		return chain
	}
	return append(chain,
		rbacEscalation{authorizer: authorizer, lister: lister},
		secretAccess{authorizer: authorizer},
		serviceJoin{authorizer: authorizer},
	)
}

func rbacMeta(kind string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: rbacv1.GroupVersion.String(), Kind: kind}
}
