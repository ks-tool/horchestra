package authz

import (
	"context"
	"net/http"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
)

const (
	// NodeGroup is the group a node-agent authenticates with; it is granted its fixed
	// node-agent permissions by the built-in node authorizer, not by RBAC objects.
	NodeGroup = "system:nodes"
	// AdminGroup is the cluster super-admin group (the Kubernetes system:masters convention):
	// its members bypass RBAC and see every namespace. It is the only admin group the
	// authorizer knows; mapping an external directory's groups onto it is the authenticator's
	// job, not this package's.
	AdminGroup = "system:masters"
)

type Attributes struct {
	User      *authn.Identity
	Verb      string
	Group     string
	Resource  string
	Namespace string
	Name      string
	// Subresource is the segment after the object's name — "status", "log". It is a
	// SEPARATE permission from the object it hangs off, because it is a different thing: a
	// node's journal is not its capacity, and reading one says nothing about the right to
	// read the other. Rules name it as "resource/subresource", the Kubernetes spelling.
	Subresource string
	// ResourceRequest distinguishes an object request from a path like discovery or the
	// OpenAPI documents. A false one is NOT a free pass — see AllowedNonResourcePath.
	ResourceRequest bool
	// Path is the request path, which is the only thing a non-resource decision has to go on.
	Path string
}

// Target is what a rule names: the resource, or "resource/subresource" when the request is
// for one. Every decision compares against this, so a rule granting "nodes" cannot silently
// carry "nodes/log" with it.
func (a Attributes) Target() string {
	if a.Subresource == "" {
		return a.Resource
	}
	return a.Resource + "/" + a.Subresource
}

// AllowedNonResourcePath reports whether a path that addresses no object is served to EVERY
// authenticated caller with no rule behind it. It is an ALLOWLIST, and the default is deny —
// a path outside it is reachable only through a rule's nonResourceURLs.
//
// The default used to be allow: anything that was not /apis/{group}/{version}/... was served
// to whoever had a certificate. Nothing sensitive happened to live at such a path, so nothing
// was exposed — but the next endpoint added outside the resource tree would have been world
// readable to the whole fleet on the day it landed, with no line of code saying so. A node's
// journal was going to be exactly that endpoint.
//
// The list is Kubernetes' own system:discovery grant — the paths every authenticated caller
// there may read — plus the read-only pods alias, which is under /api and therefore not a
// resource request here, and which authorizes ITSELF per Application namespace (see
// APIServer.SetAuthorizer). Taking the set from upstream rather than inventing one is what
// keeps a client that works against Kubernetes working against this: /version is on it
// because `kubectl version` asks for it, which a first cut of this function found out the
// hard way.
//
// /metrics is deliberately NOT on it. It was, and its handler made up for the coarseness by
// authorizing itself against a resource permission that stood in for the path — a rule nobody
// could find from the path they were denied. It is now an ordinary nonResourceURLs grant, like
// every other path outside this list.
func AllowedNonResourcePath(path string) bool {
	switch path {
	case "/api", "/apis", "/version", "/version/", "/openapi", "/livez", "/readyz":
		return true
	}
	switch {
	case strings.HasPrefix(path, "/openapi/"):
		return true // the schemas kubectl validates against before it sends anything
	case strings.HasPrefix(path, "/api/"):
		// /api/v1 is discovery and /api/v1/pods... is the self-authorizing alias. Nothing
		// else is served under /api at all, so a deeper path 404s rather than reaching a
		// handler.
		return true
	case strings.HasPrefix(path, "/apis/"):
		// /apis/{group} and /apis/{group}/{version} are discovery; anything deeper IS a
		// resource request and never reaches here.
		return strings.Count(strings.Trim(path, "/"), "/") <= 2
	}
	return false
}

type Authorizer interface {
	Authorize(ctx context.Context, a Attributes) (bool, error)
}

// nodeAuthorizes is horchestra's built-in Node authorizer — the RBAC-independent grant
// a node-agent needs (Kubernetes' Node authorization mode, not a ClusterRole): a
// system:nodes identity may manage Node objects, and nodeRestriction admission then
// confines those writes to the node's own object.
//
// It deliberately grants NO read of Applications or PersistentVolumes. A node never reads
// them over REST — it receives desired state on its gRPC Session, where the push is
// already scoped to the node (only Applications whose spec.nodeName is its own, and only
// the Secrets those mount) and uses REST solely for its rotation CSR. The grant used to
// exist and had no own-node predicate and no namespace, so one stolen node credential
// read every tenant's Application in the fleet — images, argv, env values, which Secrets
// each mounts — and, through the pods/log alias authorizing itself with the same
// predicate, tapped the live output of workloads on nodes it did not own.
func nodeAuthorizes(at Attributes) bool {
	if at.User == nil || !slices.Contains(at.User.Groups, NodeGroup) {
		return false
	}
	// Compared against Target(), not Resource: this grant is the node's OWN registration and
	// status, and it must not widen to a subresource of the same object that nobody weighed.
	// A node reports status over the gRPC session, not this path, so there is nothing to add.
	switch at.Group {
	case corev1.GroupName:
		if at.Target() == "nodes" {
			switch at.Verb {
			case "create", "get", "update", "patch":
				return true
			}
		}
	case certv1.GroupName:
		// A node rotates its own certificate: create a CSR and read it back. The approval
		// loop's selfnodeclient predicate confines a node to a cert for its own CN.
		if at.Target() == "certificatesigningrequests" {
			switch at.Verb {
			case "create", "get", "list":
				return true
			}
		}
	}
	return false
}

// isPublicNamespaceRead is the self-service Namespace listing: any authenticated caller
// may list/watch Namespaces (the result is filtered to their accessible namespaces
// downstream), so no cluster-wide list permission is required.
func isPublicNamespaceRead(at Attributes) bool {
	return at.Group == corev1.GroupName && at.Resource == "namespaces" &&
		(at.Verb == "list" || at.Verb == "watch")
}

// AccessibleNamespaces returns the namespaces id may see in the self-service listing —
// those it has a RoleBinding in. seesAll is true for an admin (every namespace). It
// never requires a cluster-wide list permission.
func AccessibleNamespaces(ctx context.Context, store storage.Storage, sch *scheme.Scheme, id *authn.Identity) (accessible map[string]bool, seesAll bool, err error) {
	if id == nil {
		return map[string]bool{}, false, nil
	}
	if isAdmin(id.Groups) {
		return nil, true, nil
	}
	// A ClusterRoleBinding grants cluster-wide, so the caller sees every namespace — but
	// only if the ClusterRole it names actually confers cluster-wide read authority. The
	// existence of a binding proves nothing on its own: a roleRef that resolves to nothing,
	// one whose Kind is not ClusterRole (which the Casbin projection skips, so it grants no
	// permission at all), or a write-only ClusterRole would otherwise hand out the full
	// namespace inventory — and, through the pods alias, every tenant's workloads.
	crbs, err := store.List(ctx, rbacMeta("ClusterRoleBinding", "", ""), metav1.ListOptions{})
	if err != nil {
		return nil, false, err
	}
	for _, obj := range crbs {
		crb, ok := obj.(*rbacv1.ClusterRoleBinding)
		if !ok || crb.Spec.RoleRef.Kind != "ClusterRole" || !subjectMatches(crb.Spec.Subjects, id) {
			continue
		}
		if grantsClusterRead(sch, roleRefRules(ctx, store, crb.Spec.RoleRef, "")) {
			return nil, true, nil
		}
	}
	bindings, err := store.List(ctx, rbacMeta("RoleBinding", "", ""), metav1.ListOptions{})
	if err != nil {
		return nil, false, err
	}
	live, err := existingNamespaces(ctx, store)
	if err != nil {
		return nil, false, err
	}
	accessible = map[string]bool{}
	for _, obj := range bindings {
		// Same as the Casbin projection: a binding left over from a deleted namespace confers
		// nothing, so it must not put that name back in the caller's listing either.
		if rb, ok := obj.(*rbacv1.RoleBinding); ok && (rb.Namespace == "" || live[rb.Namespace]) &&
			subjectMatches(rb.Spec.Subjects, id) {
			accessible[rb.Namespace] = true
		}
	}
	return accessible, false, nil
}

// existingNamespaces is the set of Namespace names that exist, so a grant scoped to a namespace
// that is gone is not projected.
func existingNamespaces(ctx context.Context, store storage.Storage) (map[string]bool, error) {
	list, err := store.List(ctx, types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Namespace"}, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	live := make(map[string]bool, len(list))
	for _, obj := range list {
		if ns, ok := obj.(*corev1.Namespace); ok {
			live[ns.Name] = true
		}
	}
	return live, nil
}

// grantsClusterRead reports whether rules confer a cluster-wide read over a NAMESPACED
// resource. That is the bar for seesAll: a subject that may already read some resource in
// every namespace learns nothing new from the namespace names, whereas one holding a binding
// that grants no such read must not be handed the inventory. The namespaced predicate is
// load-bearing — the ordinary fleet-viewer grant (nodes: get,list) reads only cluster-scoped
// objects, whose contents say nothing about any tenant, so it must not unlock the namespace
// list or the admin-only unfiltered watch. A rule with no apiGroups or no resources selects
// nothing and is ignored; a nil scheme fails closed.
func grantsClusterRead(sch *scheme.Scheme, rules []rbacv1.PolicyRule) bool {
	if sch == nil {
		return false
	}
	for _, r := range rules {
		if len(r.APIGroups) == 0 || len(r.Resources) == 0 {
			continue
		}
		if !slices.ContainsFunc(r.Verbs, isReadVerb) {
			continue
		}
		if selectsNamespaced(sch, r.APIGroups, r.Resources) {
			return true
		}
	}
	return false
}

func isReadVerb(v string) bool {
	switch v {
	case "*", "get", "list", "watch":
		return true
	}
	return false
}

// selectsNamespaced reports whether (groups, resources) selects at least one namespaced
// resource. A "*" resource matches every Kind including namespaced ones; a named resource is
// resolved through the scheme by its plural, so a resource nothing registers selects nothing.
func selectsNamespaced(sch *scheme.Scheme, groups, resources []string) bool {
	for _, res := range resources {
		if res == "*" {
			return true
		}
		plural, _, _ := strings.Cut(res, "/") // a subresource inherits its parent's scope
		for gvk, r := range sch.Resources() {
			if r.Plural != plural || !r.Namespaced {
				continue
			}
			if slices.Contains(groups, "*") || slices.Contains(groups, gvk.Group) {
				return true
			}
		}
	}
	return false
}

func isAdmin(groups []string) bool { return slices.Contains(groups, AdminGroup) }

func subjectMatches(subjects []rbacv1.Subject, id *authn.Identity) bool {
	for _, s := range subjects {
		switch s.Kind {
		case "User":
			if s.Name == id.Name {
				return true
			}
		case "Group":
			if slices.Contains(id.Groups, s.Name) {
				return true
			}
		}
	}
	return false
}

// rbacMeta addresses an rbac-group resource (name empty for List/Watch; namespace
// scopes a namespaced Role/RoleBinding, empty = all namespaces).
func rbacMeta(kind, namespace, name string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: rbacv1.GroupVersion.String(), Kind: kind, Namespace: namespace, Name: name}
}

// AttributesFromRequest derives authorization attributes from the request path
// (/apis/{group}/{version}/{resource}[/{name}]) and method.
func AttributesFromRequest(r *http.Request, user *authn.Identity) Attributes {
	at := Attributes{User: user, Path: r.URL.Path}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "apis" {
		// A non-resource request has no object to act on, so its verb is the HTTP method
		// itself, lowercased — the Kubernetes spelling, and what a rule's `verbs: ["get"]`
		// is compared against. Without it every such request carried an empty verb and no
		// nonResourceURLs rule could ever match one.
		at.Verb = strings.ToLower(r.Method)
		return at
	}
	at.ResourceRequest = true
	at.Group = parts[1]
	rest := parts[3:] // segments after /apis/{group}/{version}
	// A namespaced request is /namespaces/{ns}/{resource}[/{name}] — three or more
	// segments; /namespaces or /namespaces/{name} is the cluster-scoped Namespace
	// resource itself.
	if len(rest) >= 3 && rest[0] == "namespaces" {
		at.Namespace = rest[1]
		rest = rest[2:]
	}
	if len(rest) >= 1 {
		at.Resource = rest[0]
	}
	if len(rest) >= 2 {
		at.Name = rest[1]
	}
	// The segment after the name is a SUBRESOURCE, not decoration. It used to be dropped,
	// which made every subresource inherit its parent's permission — so a rule granting
	// `get nodes`, an innocuous read of capacity and labels, would also have handed over the
	// node's journal the moment such an endpoint existed.
	if len(rest) >= 3 {
		at.Subresource = rest[2]
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
