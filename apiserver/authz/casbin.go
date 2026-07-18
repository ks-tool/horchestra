package authz

import (
	"context"
	_ "embed"
	"fmt"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/storage"
)

//go:embed rbac_model.conf
var rbacModel string

// Casbin authorizes requests with a Casbin enforcer whose policy is projected from
// the declarative rbac.horchestra.io/v1 Role/RoleBinding objects. Unlike the live
// RBAC authorizer it does not query storage per request: it compiles the policy
// once (LoadFromStore) and refreshes it on every change (Watch).
type Casbin struct {
	adminGroups []string
	mu          sync.RWMutex
	e           *casbin.Enforcer
}

// NewCasbin builds a Casbin authorizer with an empty policy; adminGroups always
// pass (checked before the enforcer) to avoid locking out cluster admins.
func NewCasbin(adminGroups []string) (*Casbin, error) {
	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		return nil, fmt.Errorf("parse casbin model: %w", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("build casbin enforcer: %w", err)
	}
	return &Casbin{adminGroups: adminGroups, e: e}, nil
}

// Authorize allows a request if the caller is in an admin group or any of its
// subjects (the user plus each group) matches a policy line.
func (c *Casbin) Authorize(_ context.Context, at Attributes) (bool, error) {
	if !at.ResourceRequest {
		return true, nil
	}
	if at.User == nil {
		return false, nil
	}
	if isAdmin(at.User.Groups, c.adminGroups) {
		return true, nil
	}
	obj := at.Resource
	if len(at.Group) > 0 {
		obj = at.Group + "/" + at.Resource
	}
	subjects := append([]string{"user:" + at.User.Name}, groupSubjects(at.User.Groups)...)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, sub := range subjects {
		ok, err := c.e.Enforce(sub, obj, at.Verb)
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
	rules, err := rulesFromStore(ctx, store)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.e.ClearPolicy()
	if len(rules) == 0 {
		return nil
	}
	if _, err := c.e.AddPolicies(rules); err != nil {
		return fmt.Errorf("load casbin policies: %w", err)
	}
	return nil
}

// Watch reloads the whole policy on every Role/RoleBinding change until ctx is
// cancelled or a watch channel closes; a failed reload is logged, not fatal.
func (c *Casbin) Watch(ctx context.Context, store storage.Storage) error {
	roles, err := store.Watch(ctx, rbacMeta("Role", ""), metav1.ListOptions{})
	if err != nil {
		return err
	}
	bindings, err := store.Watch(ctx, rbacMeta("RoleBinding", ""), metav1.ListOptions{})
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
		}
		if err := c.LoadFromStore(ctx, store); err != nil {
			log.Error().Err(err).Msg("casbin: reload policy")
		}
	}
}

// rulesFromStore projects RoleBindings and their Roles into deduplicated
// (subject, group/resource, verb) policy lines.
func rulesFromStore(ctx context.Context, store storage.Storage) ([][]string, error) {
	bindings, err := store.List(ctx, rbacMeta("RoleBinding", ""), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var rules [][]string
	for _, item := range bindings {
		rb, ok := item.(*rbacv1.RoleBinding)
		if !ok || rb.Spec.RoleRef.Kind != "Role" {
			continue
		}
		roleObj, err := store.Get(ctx, rbacMeta("Role", rb.Spec.RoleRef.Name))
		if err != nil {
			continue
		}
		role, ok := roleObj.(*rbacv1.Role)
		if !ok {
			continue
		}
		for _, subj := range rb.Spec.Subjects {
			sub := subjectString(subj)
			if len(sub) == 0 {
				continue
			}
			for _, rule := range role.Spec.Rules {
				for _, g := range rule.APIGroups {
					for _, res := range rule.Resources {
						obj := res
						if len(g) > 0 {
							obj = g + "/" + res
						}
						for _, verb := range rule.Verbs {
							key := sub + "\x00" + obj + "\x00" + verb
							if seen[key] {
								continue
							}
							seen[key] = true
							rules = append(rules, []string{sub, obj, verb})
						}
					}
				}
			}
		}
	}
	return rules, nil
}

func subjectString(s rbacv1.Subject) string {
	switch s.Kind {
	case "User":
		return "user:" + s.Name
	case "Group":
		return "group:" + s.Name
	}
	return ""
}

func groupSubjects(groups []string) []string {
	subs := make([]string, 0, len(groups))
	for _, g := range groups {
		subs = append(subs, "group:"+g)
	}
	return subs
}
