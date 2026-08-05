package admission

import (
	"context"
	"reflect"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/authn"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// reservedChildLabels are the ApplicationSet's own child labels: the List selector it renders
// with. They are not the ownership authority (the controller ownerReference is), but they are
// reserved all the same, so a client cannot make a foreign object look like a set's child.
var reservedChildLabels = corev1.ReservedChildLabels()

// childOwnership makes an Application's ApplicationSet metadata controller-owned. Two signals
// the appset loop consumes as proof used to live in ordinary client-writable metadata, and
// nothing recomputed, stripped or pinned them:
//
// The controller ownerReference is a DELETE authority. The loop's GC-first sweep destroys any
// child whose owning set is gone, through the in-process clientset — so with no RBAC identity
// and no audit record. A caller holding only `update` on applications (not `delete`) could add
// `{"kind":"ApplicationSet","name":"no-such-set","controller":true}` to any Application, wake
// the loop with that very write, and have the control plane delete an object it was never
// authorized to delete, taking the pv/secret protection interlock with it.
//
// The rendered-spec hash is the CONVERGENCE signal. The loop compares the stored child's own
// annotation against the freshly rendered digest, and a merge patch applies to the stored
// object — so `kubectl patch application <child> -p '{"spec":{"image":"attacker/backdoor"}}'`
// left the annotation in place, `changed` was false forever, and the substitution survived
// every reconcile while the set still reported Rendered/Running. That is a fleet-wide daemon
// (a logging or security agent rendered by nodeSpread) silently replaced.
//
// So: an identified caller may set none of it at Create, may not edit it at Update (the stored
// values are carried over verbatim, the shape csrPolicy uses for its requester annotations),
// and may not write the spec of a child a set owns at all — that spec belongs to the set, and
// reverting drift after the fact leaves a window in which it ran. The in-process control loops
// carry no authn identity, so this plugin is a no-op for the appset loop's own writes.
type childOwnership struct{}

func (childOwnership) Admit(ctx context.Context, a *Attributes) error {
	app, ok := clientWrittenApp(ctx, a)
	if !ok {
		return nil
	}
	switch a.Operation {
	case Create:
		if ref := corev1.AppsetOwner(app); ref != nil {
			return Forbidden("metadata.ownerReferences: the controller reference to applicationset %q "+
				"is set by the ApplicationSet controller, not by a client", ref.Name)
		}
		if _, ok := app.Annotations[corev1.AnnAppsetSpecHash]; ok {
			return Forbidden("metadata.annotations[%q] is reserved to the ApplicationSet controller", corev1.AnnAppsetSpecHash)
		}
		for _, key := range reservedChildLabels {
			if _, ok := app.Labels[key]; ok {
				return Forbidden("metadata.labels[%q] is reserved to the ApplicationSet controller", key)
			}
		}
	case Update:
		old, ok := a.OldObject.(*corev1.Application)
		if !ok {
			return nil
		}
		// Carried over, not merely rejected: a merge patch that never mentions the ownership
		// metadata must not be able to drop it either.
		app.OwnerReferences = cloneRefs(old.OwnerReferences)
		carryOver(&app.Annotations, old.Annotations, corev1.AnnAppsetSpecHash)
		for _, key := range reservedChildLabels {
			carryOver(&app.Labels, old.Labels, key)
		}
	}
	return nil
}

func (childOwnership) Validate(ctx context.Context, a *Attributes) error {
	app, ok := clientWrittenApp(ctx, a)
	if !ok || a.Operation != Update {
		return nil
	}
	old, ok := a.OldObject.(*corev1.Application)
	if !ok {
		return nil
	}
	ref := corev1.AppsetOwner(old)
	if ref == nil {
		return nil
	}
	// Runs in the validation pass, so both specs have been through the same defaulting: the
	// stored one when it was written, the incoming one in the mutation pass just above.
	if !reflect.DeepEqual(app.Spec, old.Spec) {
		return Forbidden("spec: application %q is a child of applicationset %q and its spec is owned by that set; "+
			"edit the set instead", app.Name, ref.Name)
	}
	return nil
}

// clientWrittenApp returns the Application under review when the write is a client's write of
// the object itself. It reports false for a deletion, a subresource write (status carries none
// of this metadata) and for the in-process control loops, which run with no authn identity and
// are the legitimate authors of everything this plugin guards.
func clientWrittenApp(ctx context.Context, a *Attributes) (*corev1.Application, bool) {
	if a.Operation == Delete || a.IsSubresource() || authn.FromContext(ctx) == nil {
		return nil, false
	}
	app, ok := a.Object.(*corev1.Application)
	return app, ok
}

// carryOver restores one reserved key from the stored metadata, dropping a client-supplied
// override — and dropping the key entirely when the stored object does not carry it.
func carryOver(dst *map[string]string, old map[string]string, key string) {
	if v, ok := old[key]; ok {
		if *dst == nil {
			*dst = map[string]string{}
		}
		(*dst)[key] = v
		return
	}
	delete(*dst, key)
}

// cloneRefs copies the stored ownerReferences so the admitted object does not alias the stored
// one's backing array.
func cloneRefs(refs []metav1.OwnerReference) []metav1.OwnerReference {
	if refs == nil {
		return nil
	}
	out := make([]metav1.OwnerReference, len(refs))
	for i := range refs {
		out[i] = refs[i]
		if refs[i].Controller != nil {
			out[i].Controller = new(*refs[i].Controller)
		}
		if refs[i].BlockOwnerDeletion != nil {
			out[i].BlockOwnerDeletion = new(*refs[i].BlockOwnerDeletion)
		}
	}
	return out
}
