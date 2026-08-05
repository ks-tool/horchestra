package admission

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
)

// uidAllocation gives every namespace a private block of host ids and every Application a
// distinct id out of its own namespace's block — the OpenShift model, where the control plane
// decides a workload's uid and the image never does.
//
// It is a tenancy boundary, not hygiene. Workloads on a node share the host PID namespace, so
// while they all run as one id, /proc/<pid>/root walks straight into another tenant's rootfs,
// its volume data and its materialized secrets. Distinct ids are what make that uid mean
// something again.
//
// The id is assigned when the Application is created and never moves: everything the workload
// writes is owned by it, so reassigning would orphan that data. An id the manifest asks for
// explicitly is honoured only when it falls inside that namespace's own block — otherwise a
// tenant would simply name its neighbour's id and inherit the access that comes with it.
type uidAllocation struct{ lister Lister }

func (u uidAllocation) Admit(ctx context.Context, a *Attributes) error {
	if u.lister == nil || a.Operation == Delete || a.IsSubresource() {
		return nil // the identity is a spec decision; a status report cannot change it
	}
	switch obj := a.Object.(type) {
	case *corev1.Namespace:
		return u.assignBlock(ctx, obj)
	case *corev1.Application:
		return u.assignWorkloadID(ctx, obj)
	}
	return nil
}

// Validate keeps a workload inside its namespace's block. Admit only fills in an id that was
// left unset, so this is the gate an explicit runAsUser has to pass.
func (u uidAllocation) Validate(ctx context.Context, a *Attributes) error {
	if u.lister == nil || a.Operation == Delete || a.IsSubresource() {
		return nil
	}
	app, ok := a.Object.(*corev1.Application)
	if !ok {
		return nil
	}
	block, err := u.blockOf(ctx, app.Namespace)
	if err != nil {
		return err
	}
	if block.IsZero() {
		return nil // no block on this namespace: nothing to confine the workload to
	}
	sc := app.Spec.SecurityContext
	if sc == nil {
		return nil // the compiled floor rejects this on its own
	}
	for _, f := range []struct {
		what string
		id   *int64
	}{
		{"spec.securityContext.runAsUser", sc.RunAsUser},
		{"spec.securityContext.runAsGroup", sc.RunAsGroup},
	} {
		if f.id != nil && !block.Contains(*f.id) {
			return Forbidden("%s %d is outside namespace %q's id block %s — a workload may only run as an id "+
				"reserved for its own namespace, because that id is what separates its data from every other tenant's",
				f.what, *f.id, app.Namespace, block)
		}
	}
	return nil
}

// assignBlock reserves the namespace's id block on creation. The block is recorded as an
// annotation rather than a spec field because it is the control plane's decision, not a
// declaration by whoever created the namespace; the spelling matches OpenShift's
// "<min>/<size>". An annotation that is already present is left alone — the block is what
// existing data is owned by, so it must survive every later update of the object.
func (u uidAllocation) assignBlock(ctx context.Context, ns *corev1.Namespace) error {
	if cur := ns.Annotations[corev1.UIDRangeAnnotation]; cur != "" {
		if _, err := corev1.ParseIDRange(cur); err != nil {
			return Forbidden("%s: %s", corev1.UIDRangeAnnotation, err)
		}
		return nil
	}
	others, err := u.list(ctx, "Namespace")
	if err != nil {
		return err
	}
	taken := map[int64]bool{}
	for _, o := range others {
		other, ok := o.(*corev1.Namespace)
		if !ok || other.Name == ns.Name {
			continue
		}
		if r, err := corev1.ParseIDRange(other.Annotations[corev1.UIDRangeAnnotation]); err == nil {
			taken[r.Min] = true
		}
	}
	// Walk the blocks in order and take the first free one. Reusing a block a deleted namespace
	// once held is intended: its data is gone with it, and the alternative is a counter that only
	// ever climbs.
	for i := int64(0); ; i++ {
		lo := corev1.WorkloadUIDBase + i*corev1.WorkloadUIDBlock
		if lo+corev1.WorkloadUIDBlock-1 > corev1.MaxRunAsID {
			return Forbidden("no free uid block left below %d for namespace %q", corev1.MaxRunAsID, ns.Name)
		}
		if taken[lo] {
			continue
		}
		if ns.Annotations == nil {
			ns.Annotations = map[string]string{}
		}
		ns.Annotations[corev1.UIDRangeAnnotation] = corev1.IDRange{Min: lo, Size: corev1.WorkloadUIDBlock}.String()
		return nil
	}
}

// assignWorkloadID stamps the Application's identity out of its namespace's block: a uid of its
// own, and the namespace's shared group.
//
// The two halves are deliberately different. The uid is per-application, because that is what
// stops one workload reaching another's rootfs and secrets through /proc. The GROUP is shared by
// the whole namespace, because with distinct uids a uid can no longer be what lets two workloads
// use the same PersistentVolume — the group is. Volumes are chgrp'd to it and carry setgid, so a
// volume is shareable inside its namespace and unreachable from outside.
//
// An id the manifest already carries is left in place (Validate is what confines that one).
func (u uidAllocation) assignWorkloadID(ctx context.Context, app *corev1.Application) error {
	block, err := u.blockOf(ctx, app.Namespace)
	if err != nil || block.IsZero() {
		return err // no block: the compiled floor's sentinel stands in
	}
	// The namespace's own group is the first id of its block, so every workload in the namespace
	// lands on the same one without any coordination.
	nsGroup := block.Min
	if app.Spec.SecurityContext == nil {
		app.Spec.SecurityContext = &corev1.SecurityContext{}
	}
	sc := app.Spec.SecurityContext
	if sc.RunAsGroup == nil {
		sc.RunAsGroup = &nsGroup
	}
	if sc.RunAsUser != nil {
		return nil // already pinned — never move a running workload's id
	}
	apps, err := u.list(ctx, "Application")
	if err != nil {
		return err
	}
	taken := map[int64]bool{}
	for _, o := range apps {
		other, ok := o.(*corev1.Application)
		if !ok || other.Namespace != app.Namespace || other.Name == app.Name {
			continue
		}
		if sc := other.Spec.SecurityContext; sc != nil && sc.RunAsUser != nil {
			taken[*sc.RunAsUser] = true
		}
	}
	for id := block.Min; id < block.Min+block.Size; id++ {
		if taken[id] {
			continue
		}
		sc.RunAsUser = &id
		return nil
	}
	return Forbidden("namespace %q has no free id left in its block %s", app.Namespace, block)
}

// blockOf reads a namespace's reserved block. A namespace with no annotation yields the zero
// range, which every caller reads as "not allocated" rather than as an error.
func (u uidAllocation) blockOf(ctx context.Context, name string) (corev1.IDRange, error) {
	all, err := u.list(ctx, "Namespace")
	if err != nil {
		return corev1.IDRange{}, err
	}
	for _, o := range all {
		ns, ok := o.(*corev1.Namespace)
		if !ok || ns.Name != name {
			continue
		}
		raw := ns.Annotations[corev1.UIDRangeAnnotation]
		if raw == "" {
			return corev1.IDRange{}, nil
		}
		r, err := corev1.ParseIDRange(raw)
		if err != nil {
			return corev1.IDRange{}, Forbidden("namespace %q: %s", name, err)
		}
		return r, nil
	}
	return corev1.IDRange{}, nil
}

func (u uidAllocation) list(ctx context.Context, kind string) ([]types.Object, error) {
	objs, err := u.lister.List(ctx, resourceMeta(kind), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", kind, err)
	}
	return objs, nil
}
