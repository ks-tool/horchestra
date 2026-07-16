package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/authn"
	"ks-tool.dev/horchestra/pkg/storage"
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

func (a *RBAC) Authorize(ctx context.Context, at Attributes) (bool, error) {
	if !at.ResourceRequest {
		return true, nil
	}
	if at.User == nil {
		return false, nil
	}
	for _, g := range at.User.Groups {
		for _, ag := range a.AdminGroups {
			if g == ag {
				return true, nil
			}
		}
	}
	bindings, err := a.Store.List(ctx, v1.RBACGroupVersion.WithKind("RoleBinding"))
	if err != nil {
		return false, err
	}
	for i := range bindings.Items {
		var rb v1.RoleBindingSpec
		if !decodeSpec(&bindings.Items[i], &rb) || !subjectMatches(rb.Subjects, at.User) || rb.RoleRef.Kind != "Role" {
			continue
		}
		role, err := a.Store.Get(ctx, v1.RBACGroupVersion.WithKind("Role"), rb.RoleRef.Name)
		if err != nil {
			continue
		}
		var rs v1.RoleSpec
		if decodeSpec(role, &rs) && rulesAllow(rs.Rules, at) {
			return true, nil
		}
	}
	return false, nil
}

func decodeSpec(u *unstructured.Unstructured, out any) bool {
	sp, ok := u.Object["spec"]
	if !ok {
		return false
	}
	b, err := json.Marshal(sp)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, out) == nil
}

func subjectMatches(subjects []v1.Subject, id *authn.Identity) bool {
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

func rulesAllow(rules []v1.PolicyRule, at Attributes) bool {
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
