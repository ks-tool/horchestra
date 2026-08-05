package authz

import (
	"context"
	"fmt"
	"sync"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/controller/authn"
)

const rbacModel = `[request_definition]
r = sub, ns, grp, res, act

[policy_definition]
p = sub, ns, grp, res, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && (p.ns == "*" || r.ns == p.ns) && (p.grp == "*" || r.grp == p.grp) && (p.res == "*" || r.res == p.res) && (p.act == "*" || r.act == p.act)
`

// Casbin authorizes requests with a Casbin enforcer whose policy is projected from the
// declarative rbac.horchestra.io/v1 Role/RoleBinding objects. It does not query storage per
// request: it compiles the policy once (LoadFromStore) and refreshes it on every change (Watch).
// It is the control plane's only authorization engine.
type Casbin struct {
	mu sync.RWMutex
	e  *casbin.Enforcer
	// paths is the non-resource half of the same policy, projected from the nonResourceURLs
	// of every rule a ClusterRoleBinding confers, keyed by subject.
	paths map[string][]nonResourceGrant
}

// NewCasbin builds a Casbin authorizer with an empty policy. The AdminGroup always passes
// (checked before the enforcer) so a cluster admin cannot be locked out by a bad policy.
func NewCasbin() (*Casbin, error) {
	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		return nil, fmt.Errorf("parse casbin model: %w", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("build casbin enforcer: %w", err)
	}
	return &Casbin{e: e}, nil
}

// Authorize allows a request if the caller is in an admin group or any of its
// subjects (the user plus each group) matches a policy line.
func (c *Casbin) Authorize(_ context.Context, at Attributes) (bool, error) {
	if at.User == nil {
		return false, nil
	}
	// The admin bypass is decided before the two halves divide, so it covers a path as well as
	// an object. It used to sit inside the resource half only, which left the super-admin group
	// judged by the non-resource allowlist like anyone else — the one identity that is defined
	// by holding everything could be refused a path.
	if isAdmin(at.User.Groups) {
		return true, nil
	}
	// A path that addresses no object is served if it is discovery (the fixed allowlist every
	// authenticated caller gets) or if a rule names it in nonResourceURLs. The default is deny:
	// this used to return true for everything outside the resource tree.
	if !at.ResourceRequest {
		return AllowedNonResourcePath(at.Path) || c.allowsPath(at), nil
	}
	if nodeAuthorizes(at) || isPublicNamespaceRead(at) {
		return true, nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, sub := range subjectsOf(at.User) {
		ok, err := c.e.Enforce(sub, at.Namespace, at.Group, at.Target(), at.Verb)
		if err != nil {
			return false, fmt.Errorf("casbin enforce: %w", err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// LoadFromStore replaces the enforcer's policy with the rules projected from the
// current Role/RoleBinding objects.
func (c *Casbin) LoadFromStore(ctx context.Context, store storage.Storage) error {
	p, err := rulesFromStore(ctx, store)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.e.ClearPolicy()
	c.paths = p.paths
	if len(p.rules) == 0 {
		return nil
	}
	if _, err := c.e.AddPolicies(p.rules); err != nil {
		return fmt.Errorf("load casbin policies: %w", err)
	}
	return nil
}

// Watch reloads the whole policy on every Role/RoleBinding change until ctx is
// cancelled or a watch channel closes; a failed reload is logged, not fatal.
func (c *Casbin) Watch(ctx context.Context, store storage.Storage) error {
	roles, err := store.Watch(ctx, rbacMeta("Role", "", ""), metav1.ListOptions{})
	if err != nil {
		return err
	}
	bindings, err := store.Watch(ctx, rbacMeta("RoleBinding", "", ""), metav1.ListOptions{})
	if err != nil {
		return err
	}
	croles, err := store.Watch(ctx, rbacMeta("ClusterRole", "", ""), metav1.ListOptions{})
	if err != nil {
		return err
	}
	cbindings, err := store.Watch(ctx, rbacMeta("ClusterRoleBinding", "", ""), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-roles:
			if !ok {
				return nil
			}
		case _, ok := <-bindings:
			if !ok {
				return nil
			}
		case _, ok := <-croles:
			if !ok {
				return nil
			}
		case _, ok := <-cbindings:
			if !ok {
				return nil
			}
		}
		if err := c.LoadFromStore(ctx, store); err != nil {
			log.Error().Err(err).Msg("casbin: reload policy")
		}
	}
}

// rulesFromStore projects RoleBindings and ClusterRoleBindings (and the Roles/ClusterRoles
// they reference) into deduplicated (subject, namespace, apiGroup, resource, verb) policy lines.
// The apiGroup, resource and verb are stored verbatim — including the "*" wildcard — and the
// model's matcher treats "*" in any of those columns as "matches any" (Kubernetes "all"
// semantics). A RoleBinding emits lines in its own namespace; a ClusterRoleBinding emits lines
// with the namespace wildcard "*" (cluster-scoped requests carry an empty namespace, which only
// "*" lines match).
//
// A rule's nonResourceURLs are projected only from a ClusterRoleBinding (ns "*"): a path is not
// in any namespace, so a namespaced binding that names a ClusterRole grants its resource rules
// inside that namespace and none of its paths — otherwise one Role in a tenant's own namespace
// would have carried a cluster-wide grant on /metrics.
func rulesFromStore(ctx context.Context, store storage.Storage) (policy, error) {
	seen := map[string]bool{}
	p := policy{paths: map[string][]nonResourceGrant{}}
	emit := func(subjects []rbacv1.Subject, ns string, policyRules []rbacv1.PolicyRule) {
		for _, subj := range subjects {
			sub := subjectString(subj)
			if len(sub) == 0 {
				continue
			}
			for _, rule := range policyRules {
				if len(rule.NonResourceURLs) > 0 && ns == "*" {
					p.paths[sub] = append(p.paths[sub], nonResourceGrant{
						verbs: rule.Verbs, urls: rule.NonResourceURLs,
					})
				}
				for _, g := range rule.APIGroups {
					for _, res := range rule.Resources {
						for _, verb := range rule.Verbs {
							key := sub + "\x00" + ns + "\x00" + g + "\x00" + res + "\x00" + verb
							if seen[key] {
								continue
							}
							seen[key] = true
							p.rules = append(p.rules, []string{sub, ns, g, res, verb})
						}
					}
				}
			}
		}
	}

	bindings, err := store.List(ctx, rbacMeta("RoleBinding", "", ""), metav1.ListOptions{})
	if err != nil {
		return policy{}, err
	}
	live, err := existingNamespaces(ctx, store)
	if err != nil {
		return policy{}, err
	}
	for _, item := range bindings {
		if rb, ok := item.(*rbacv1.RoleBinding); ok {
			// A binding whose namespace is gone grants nothing. Namespace deletion is refused
			// while the namespace still holds objects, so this is the narrow race — a binding
			// written as the namespace went away — and it keeps the grant from coming back to
			// life around a recreated namespace of the same name, under a different tenant.
			// An empty namespace is not a namespace scope (it emits the cluster-wide line
			// below), so there is no namespace whose absence could stale it.
			if rb.Namespace != "" && !live[rb.Namespace] {
				continue
			}
			if pr := roleRefRules(ctx, store, rb.Spec.RoleRef, rb.Namespace); pr != nil {
				emit(rb.Spec.Subjects, rb.Namespace, pr)
			}
		}
	}

	cbindings, err := store.List(ctx, rbacMeta("ClusterRoleBinding", "", ""), metav1.ListOptions{})
	if err != nil {
		return policy{}, err
	}
	for _, item := range cbindings {
		if crb, ok := item.(*rbacv1.ClusterRoleBinding); ok && crb.Spec.RoleRef.Kind == "ClusterRole" {
			if pr := roleRefRules(ctx, store, crb.Spec.RoleRef, ""); pr != nil {
				emit(crb.Spec.Subjects, "*", pr)
			}
		}
	}
	return p, nil
}

// roleRefRules resolves a roleRef to its PolicyRules: a Role in the given namespace, or a
// cluster-scoped ClusterRole. Returns nil if the referenced object is absent.
func roleRefRules(ctx context.Context, store storage.Storage, ref rbacv1.RoleRef, namespace string) []rbacv1.PolicyRule {
	switch ref.Kind {
	case "Role":
		if obj, err := store.Get(ctx, rbacMeta("Role", namespace, ref.Name)); err == nil {
			if role, ok := obj.(*rbacv1.Role); ok {
				return role.Spec.Rules
			}
		}
	case "ClusterRole":
		if obj, err := store.Get(ctx, rbacMeta("ClusterRole", "", ref.Name)); err == nil {
			if cr, ok := obj.(*rbacv1.ClusterRole); ok {
				return cr.Spec.Rules
			}
		}
	}
	return nil
}

// policy is one projection of the RBAC objects, in the two shapes the two halves of a decision
// need: Casbin lines for resources, and per-subject grants for paths.
type policy struct {
	rules [][]string
	paths map[string][]nonResourceGrant
}

// subjectsOf is every policy subject an identity carries — itself and each of its groups. Both
// halves ask it, so neither can end up matching a different set than the other.
func subjectsOf(id *authn.Identity) []string {
	return append([]string{userSubject(id.Name)}, groupSubjects(id.Groups)...)
}

// userSubject and groupSubject are the single source of truth for the "user:"/"group:" subject
// prefixes: the projection side (subjectString) and the query side (Authorize, groupSubjects)
// must agree, or a request fails closed with no compile error.
func userSubject(name string) string  { return "user:" + name }
func groupSubject(name string) string { return "group:" + name }

func subjectString(s rbacv1.Subject) string {
	switch s.Kind {
	case "User":
		return userSubject(s.Name)
	case "Group":
		return groupSubject(s.Name)
	}
	return ""
}

func groupSubjects(groups []string) []string {
	subs := make([]string, 0, len(groups))
	for _, g := range groups {
		subs = append(subs, groupSubject(g))
	}
	return subs
}
