package admission

import (
	"context"
	"slices"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
)

// serviceJoin requires the author of an Application to be able to READ the Service it joins.
//
// Membership is self-declared — an instance says which service it belongs to and the Service
// asserts nothing about a fleet it cannot see — which is what keeps the model free of a selector
// that could drift or be squatted. The cost of that choice is this: without a check, anyone who
// can create an Application in a namespace can put themselves behind any service in it, taking a
// share of its traffic and its name.
//
// The rule is the directory's write permission in the filesystem sense the model is built on: you
// may put a file in a directory you can reach. It is the same shape secretAccess applies to a
// mounted Secret — referencing is using — and the same reasoning: the reference is resolved by the
// control plane long after the author is gone, with authority the author never had to prove.
//
// Removing an instance stays the instance's own business. A Service holds no list of its members,
// so there is nothing for its owner to edit and nobody to evict: the file's owner takes it out,
// which is the sticky bit exactly.
type serviceJoin struct {
	authorizer authz.Authorizer
}

func (serviceJoin) Admit(context.Context, *Attributes) error { return nil }

func (s serviceJoin) Validate(ctx context.Context, a *Attributes) error {
	if s.authorizer == nil || a.Operation == Delete || a.IsSubresource() {
		return nil
	}
	id := authn.FromContext(ctx)
	if id == nil {
		// A trusted internal writer — the loops and the node transport. An ApplicationSet
		// rendering children is checked on the SET's own write, with the author's identity,
		// which is what stops the check being bypassed by wrapping the workload in a set.
		return nil
	}
	if slices.Contains(id.Groups, authz.AdminGroup) {
		return nil
	}

	var namespace, service string
	switch obj := a.Object.(type) {
	case *corev1.Application:
		namespace, service = obj.Namespace, obj.Spec.ServiceName
	case *corev1.ApplicationSet:
		// Every child joins whatever its component declares, so the set's author is asked for
		// all of them at once.
		namespace = obj.Namespace
		for _, child := range obj.Spec.Applications {
			if err := s.check(ctx, id, namespace, child.Spec.ServiceName); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
	return s.check(ctx, id, namespace, service)
}

func (s serviceJoin) check(ctx context.Context, id *authn.Identity, namespace, service string) error {
	if service == "" {
		return nil
	}
	ok, err := s.authorizer.Authorize(ctx, authz.Attributes{
		User: id, Verb: "get", Group: corev1.GroupName, Resource: "services",
		Namespace: namespace, Name: service, ResourceRequest: true,
	})
	if err != nil {
		return err
	}
	if !ok {
		return Forbidden("spec.serviceName: may not join service %q in namespace %q — the requester cannot get it, "+
			"and joining a service is taking a share of its name and its traffic", service, namespace)
	}
	return nil
}
