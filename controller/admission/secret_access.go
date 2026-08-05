package admission

import (
	"context"
	"slices"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
)

// secretAccess closes the shortest path to another tenant's credentials in this API: mounting a
// Secret you are not allowed to read.
//
// Reading a Secret over REST is RBAC-gated like anything else. But an Application is a request to
// put a Secret's VALUE into a process — `spec.env[].secretRef` folds it into the workload's
// environment, a `type: secret` volume writes it into the workload's filesystem — and the node
// resolves that reference with the NODE's authority, not the author's. Without this check, a
// subject holding only `create applications` in a namespace reads every Secret in it: mount,
// start, print the environment. The namespace boundary held; the one inside it did not.
//
// So the rule is the same one Kubernetes applies to a Pod: to reference a Secret you must be able
// to `get` it. It is checked where the reference is written, because that is the last moment
// anyone knows who asked — by the time the node resolves it there is no requester left.
type secretAccess struct {
	authorizer authz.Authorizer
}

func (secretAccess) Admit(context.Context, *Attributes) error { return nil }

// maxSecretRefs bounds the authorization queries one write can ask for. spec.env and spec.volumes
// are unbounded lists a tenant writes, and each distinct name is an authorizer round trip; a real
// application names a handful.
const maxSecretRefs = 64

func (s secretAccess) Validate(ctx context.Context, a *Attributes) error {
	if s.authorizer == nil || a.Operation == Delete || a.IsSubresource() {
		return nil
	}
	id := authn.FromContext(ctx)
	if id == nil {
		// A trusted internal writer: the loops (an ApplicationSet rendering its children) and the
		// node transport. The set's own write was checked with the author's identity, which is
		// what makes it safe to skip here — otherwise the check would be trivially bypassed by
		// wrapping the application in a set.
		return nil
	}
	if slices.Contains(id.Groups, authz.AdminGroup) {
		return nil
	}

	var names []string
	var namespace string
	switch obj := a.Object.(type) {
	case *corev1.Application:
		namespace = obj.Namespace
		names = secretRefs(obj.Spec.Env, obj.Spec.Volumes)
	case *corev1.ApplicationSet:
		namespace = obj.Namespace
		// The shared block projects onto every child, so a reference there is a reference in
		// each of them — and the per-child specs carry their own.
		names = secretRefs(obj.Spec.Common.Env, obj.Spec.Common.Volumes)
		for _, child := range obj.Spec.Applications {
			names = append(names, secretRefs(child.Spec.Env, child.Spec.Volumes)...)
		}
	default:
		return nil
	}
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) > maxSecretRefs {
		return Forbidden("spec: %d distinct secrets are referenced, more than the %d this check will evaluate",
			len(names), maxSecretRefs)
	}
	for _, name := range names {
		ok, err := s.authorizer.Authorize(ctx, authz.Attributes{
			User: id, Verb: "get", Group: corev1.GroupName, Resource: "secrets",
			Namespace: namespace, Name: name, ResourceRequest: true,
		})
		if err != nil {
			return err
		}
		if !ok {
			return Forbidden("spec: may not reference secret %q in namespace %q — the requester cannot get it, "+
				"and mounting a secret is reading it", name, namespace)
		}
	}
	return nil
}

// secretRefs is every Secret named by an env list and a volume list, in either shape a reference
// takes. A wildcard env ref (key "*") names the whole Secret, which is if anything a stronger
// reason to require the read.
func secretRefs(env []corev1.EnvVar, volumes []corev1.VolumeMount) []string {
	var out []string
	for _, e := range env {
		if e.IsSecret() && e.SecretRef.Name != "" {
			out = append(out, e.SecretRef.Name)
		}
	}
	for _, v := range volumes {
		if v.IsSecret() && v.SecretName() != "" {
			out = append(out, v.SecretName())
		}
	}
	return out
}
