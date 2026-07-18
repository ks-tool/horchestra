package authz

import (
	"context"
	"net/http"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/apiserver/authn"
)

type Attributes struct {
	User            *authn.Identity
	Verb            string
	Group           string
	Resource        string
	Name            string
	ResourceRequest bool
}

type Authorizer interface {
	Authorize(ctx context.Context, a Attributes) (bool, error)
}

type AllowAll struct{}

func (AllowAll) Authorize(context.Context, Attributes) (bool, error) { return true, nil }

type RBAC struct {
	Store       storage.Storage
	AdminGroups []string
}

// Authorize allows a request if the caller is in an admin group or a RoleBinding
// binds one of its subjects (the user or a group) to a Role whose rules cover the
// request. It reads the RoleBindings and Roles live from storage per request.
func (a *RBAC) Authorize(ctx context.Context, at Attributes) (bool, error) {
	if !at.ResourceRequest {
		return true, nil
	}
	if at.User == nil {
		return false, nil
	}
	if isAdmin(at.User.Groups, a.AdminGroups) {
		return true, nil
	}
	bindings, err := a.Store.List(ctx, rbacMeta("RoleBinding", ""), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, obj := range bindings {
		rb, ok := obj.(*rbacv1.RoleBinding)
		if !ok || !subjectMatches(rb.Spec.Subjects, at.User) || rb.Spec.RoleRef.Kind != "Role" {
			continue
		}
		roleObj, err := a.Store.Get(ctx, rbacMeta("Role", rb.Spec.RoleRef.Name))
		if err != nil {
			continue
		}
		if role, ok := roleObj.(*rbacv1.Role); ok && rulesAllow(role.Spec.Rules, at) {
			return true, nil
		}
	}
	return false, nil
}

func isAdmin(groups, adminGroups []string) bool {
	for _, g := range groups {
		for _, ag := range adminGroups {
			if g == ag {
				return true
			}
		}
	}
	return false
}

func subjectMatches(subjects []rbacv1.Subject, id *authn.Identity) bool {
	for _, s := range subjects {
		switch s.Kind {
		case "User":
			if s.Name == id.Name {
				return true
			}
		case "Group":
			for _, g := range id.Groups {
				if g == s.Name {
					return true
				}
			}
		}
	}
	return false
}

func rulesAllow(rules []rbacv1.PolicyRule, at Attributes) bool {
	for _, r := range rules {
		if matchList(r.APIGroups, at.Group) && matchList(r.Resources, at.Resource) && matchList(r.Verbs, at.Verb) {
			return true
		}
	}
	return false
}

func matchList(list []string, want string) bool {
	for _, x := range list {
		if x == "*" || x == want {
			return true
		}
	}
	return false
}

// rbacMeta addresses an rbac-group resource (name empty for List/Watch).
func rbacMeta(kind, name string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: rbacv1.GroupVersion.String(), Kind: kind, Name: name}
}

// AttributesFromRequest derives authorization attributes from the request path
// (/apis/{group}/{version}/{resource}[/{name}]) and method.
func AttributesFromRequest(r *http.Request, user *authn.Identity) Attributes {
	at := Attributes{User: user}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "apis" {
		return at
	}
	at.ResourceRequest = true
	at.Group = parts[1]
	rest := parts[3:]
	if len(rest) >= 1 {
		at.Resource = rest[0]
	}
	if len(rest) >= 2 {
		at.Name = rest[1]
	}
	switch r.Method {
	case http.MethodPost:
		at.Verb = "create"
	case http.MethodPut, http.MethodPatch:
		at.Verb = "update"
	case http.MethodDelete:
		at.Verb = "delete"
	default:
		switch {
		case r.URL.Query().Get("watch") == "true":
			at.Verb = "watch"
		case len(at.Name) == 0:
			at.Verb = "list"
		default:
			at.Verb = "get"
		}
	}
	return at
}
