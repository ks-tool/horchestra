package admission

import (
	"context"
	"fmt"
	"regexp"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/loops/appset"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var dns1123Name = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// applicationSet validates an ApplicationSet bundle at write time: at least one component
// with unique DNS-1123 names; a nodeSpread component must not pin spec.placement.nodeName (the set owns
// placement); and every materialized child is run through the real appPolicy so a gross child
// error is a 422 at set-create rather than a late per-child rejection. Admit is a no-op (a
// bundle has no template sugar to fold).
//
// The expansion is what catches a child-name collision, and it needs the live nodes to catch
// all of it. Two DISTINCT, both-valid components can derive one child name, because the name is
// composed rather than taken: `<set>-<component>[-<replica>][-<node>]`. Component "api" with
// replicas 3 and a second component named "api-1" both render "<set>-api-1"; a nodeSpread "api"
// on node "n1" and a component named "api-n1" both render "<set>-api-n1". The duplicate-
// component-name check above passes either way — the names differ, only what they render to
// does not.
//
// Expanding against nil nodes (the pre-lister behaviour) rendered no nodeSpread children at all,
// so only the replica half was reachable here. With the lister the node half is caught at
// set-write too, against the fleet as it stands. It cannot be caught for ALL time: a node that
// joins later can collide with a component admitted today, so Expand's own duplicate check stays
// the reconcile-time backstop — this moves the common case to the write, it does not replace it.
type applicationSet struct {
	lister Lister
	// routedNetwork mirrors the chain's, so a child is judged by the same rule a hand-written
	// Application would be — a set must not be a way around a refusal.
	routedNetwork bool
}

func (applicationSet) Admit(context.Context, *Attributes) error { return nil }

func (p applicationSet) Validate(ctx context.Context, a *Attributes) error {
	if a.Operation == Delete || a.IsSubresource() {
		return nil
	}
	set, ok := a.Object.(*corev1.ApplicationSet)
	if !ok {
		return nil
	}
	if len(set.Spec.Applications) == 0 {
		return fmt.Errorf("spec.applications: at least one application is required")
	}
	seen := map[string]bool{}
	for i := range set.Spec.Applications {
		comp := set.Spec.Applications[i]
		if !dns1123Name.MatchString(comp.Name) {
			return fmt.Errorf("spec.applications[%d].name %q is not a valid DNS-1123 name", i, comp.Name)
		}
		if seen[comp.Name] {
			return fmt.Errorf("spec.applications: duplicate component name %q", comp.Name)
		}
		seen[comp.Name] = true
		if comp.Scale.NodeSpread != nil && comp.Spec.Placement.NodeName != "" {
			return fmt.Errorf("spec.applications[%d]: a nodeSpread component must not set spec.placement.nodeName (the set assigns it)", i)
		}
		if err := validateReplicas(i, comp); err != nil {
			return err
		}
	}
	if err := validatePlacement(set); err != nil {
		return err
	}
	if mu := set.Spec.Rollout.MaxUnavailable; mu < 0 {
		return fmt.Errorf("spec.rollout.maxUnavailable: must not be negative, got %d", mu)
	}
	// Materialize the children and run the real appPolicy over each. Without a lister (unit
	// tests, and any caller that passed nil to DefaultChain) nodeSpread components render
	// nothing, exactly as before.
	nodes, err := p.nodes(ctx)
	if err != nil {
		return err
	}
	children, err := appset.Expand(set, nodes)
	if err != nil {
		return fmt.Errorf("spec.applications: %w", err)
	}
	for i := range children {
		attrs := &Attributes{GVK: corev1.GroupVersion.WithKind("Application"), Operation: Create, Object: &children[i]}
		// Default then validate the no-root floor too (not just appPolicy), so a child that
		// explicitly requests root is rejected at set-create, not only later at child-create.
		if err := (policyEnforcement{}).Admit(ctx, attrs); err != nil {
			return fmt.Errorf("child %q: %w", children[i].Name, err)
		}
		if err := (appPolicy{routedNetwork: p.routedNetwork}).Validate(ctx, attrs); err != nil {
			return fmt.Errorf("child %q: %w", children[i].Name, err)
		}
		if err := (policyEnforcement{}).Validate(ctx, attrs); err != nil {
			return fmt.Errorf("child %q: %w", children[i].Name, err)
		}
	}
	// The same for the Services the set renders, through the same plugin a hand-written one meets.
	// Without it a component with two unnamed ports would be accepted here and then fail forever
	// in the loop — the Service refused, and every child with it, since a child declares a service
	// that has to exist.
	services := appset.ExpandServices(set)
	for i := range services {
		attrs := &Attributes{GVK: corev1.GroupVersion.WithKind("Service"), Operation: Create, Object: &services[i]}
		if err := (servicePolicy{lister: p.lister}).Validate(ctx, attrs); err != nil {
			return fmt.Errorf("service %q: %w", services[i].Name, err)
		}
	}
	return nil
}

// nodes reads the fleet the nodeSpread components will render against. A nil lister yields no
// nodes rather than an error: the chain is explicitly constructible without one, and every check
// that needs it degrades instead of refusing the write.
func (p applicationSet) nodes(ctx context.Context) ([]corev1.Node, error) {
	if p.lister == nil {
		return nil, nil
	}
	list, err := p.lister.List(ctx, resourceMeta("Node"), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	nodes := make([]corev1.Node, 0, len(list))
	for _, obj := range list {
		if n, ok := obj.(*corev1.Node); ok {
			nodes = append(nodes, *n)
		}
	}
	return nodes, nil
}

// validateReplicas guards the replicas fan-out: a positive count, never combined with
// nodeSpread (two fan-outs would multiply into <set>-<component>-<i>-<node> children no one
// asked for; lift this when a per-node replica count is actually wanted).
//
// Storage is deliberately NOT policed here. A pv volume with no name is provisioned per
// child from the child's name, so replicas get a volume each (the StatefulSet-like shape);
// a NAMED pv volume is one volume every replica mounts, which is a first-class capability —
// shared data between workloads, subPath included — and refusing it would make a set's
// children obey stricter rules than the identical hand-authored Applications they compile to.
// validatePlacement checks the whole-set placement section: a known mode, and no component whose
// own fan-out contradicts it. sameNode co-locates every child on one node while a nodeSpread
// component deliberately spreads one child per node — a set cannot mean both.
func validatePlacement(set *corev1.ApplicationSet) error {
	switch set.Spec.Placement.Mode {
	case "", corev1.PlacementSameNode:
	default:
		return fmt.Errorf("spec.placement.mode %q is not a known mode (%q)",
			set.Spec.Placement.Mode, corev1.PlacementSameNode)
	}
	if !set.Spec.SameNode() {
		return nil
	}
	for i := range set.Spec.Applications {
		if set.Spec.Applications[i].Scale.NodeSpread != nil {
			return fmt.Errorf("spec.applications[%d]: nodeSpread spreads one child per node and contradicts placement.mode=%s, which co-locates the whole set",
				i, corev1.PlacementSameNode)
		}
	}
	return nil
}

func validateReplicas(i int, comp corev1.NamedApplicationSpec) error {
	if comp.Scale.Replicas == nil {
		return nil
	}
	if *comp.Scale.Replicas < 1 {
		return fmt.Errorf("spec.applications[%d].scale.replicas: must be at least 1, got %d", i, *comp.Scale.Replicas)
	}
	if comp.Scale.NodeSpread != nil {
		return fmt.Errorf("spec.applications[%d]: scale.replicas and scale.nodeSpread are mutually exclusive fan-outs (nodeSpread already yields one child per node)", i)
	}
	return nil
}
