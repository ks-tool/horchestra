package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func appsetAttrs(op Operation, set corev1.ApplicationSet) *Attributes {
	return &Attributes{GVK: corev1.GroupVersion.WithKind("ApplicationSet"), Operation: op, Object: &set}
}

func component(name, image string) corev1.NamedApplicationSpec {
	return corev1.NamedApplicationSpec{Name: name, Spec: corev1.ApplicationSpec{Image: image}}
}

func bundle(apps ...corev1.NamedApplicationSpec) corev1.ApplicationSet {
	return corev1.ApplicationSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet"},
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team"},
		Spec:       corev1.ApplicationSetSpec{Applications: apps},
	}
}

func TestApplicationSetValid(t *testing.T) {
	set := bundle(component("db", "reg/db:v1"), component("api", "reg/api:v1"))
	if err := (applicationSet{}).Validate(context.Background(), appsetAttrs(Create, set)); err != nil {
		t.Fatalf("a valid bundle must pass, got %v", err)
	}
}

func TestApplicationSetRejections(t *testing.T) {
	ctx := context.Background()
	p := applicationSet{}
	nodeSpreadPinned := func() corev1.ApplicationSet {
		s := bundle(component("a", "x:1"))
		s.Spec.Applications[0].Scale.NodeSpread = &corev1.NodeSpread{}
		s.Spec.Applications[0].Spec.Placement.NodeName = "n1"
		return s
	}()
	cases := []struct {
		name string
		set  corev1.ApplicationSet
		want string
	}{
		{"no applications", bundle(), "at least one application"},
		{"duplicate name", bundle(component("a", "x:1"), component("a", "y:1")), "duplicate component name"},
		{"bad dns name", bundle(component("A_B", "x:1")), "DNS-1123"},
		{"nodeSpread pins nodeName", nodeSpreadPinned, "must not set spec.placement.nodeName"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Validate(ctx, appsetAttrs(Create, tc.set))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestApplicationSetRunsChildAppPolicy(t *testing.T) {
	// A child whose request exceeds its limit must be rejected by the per-child appPolicy at
	// set-create, not only when the child is later created.
	bad := component("a", "reg/a:v1")
	bad.Spec.Resources = corev1.ResourceRequirements{Requests: cpu("2"), Limits: cpu("1")}
	err := (applicationSet{}).Validate(context.Background(), appsetAttrs(Create, bundle(bad)))
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("a child with request > limit must be rejected at set-create, got %v", err)
	}
}

// TestApplicationSetReplicas pins the fan-out guards: a positive count, no double fan-out —
// and NO storage policing, because a shared named PersistentVolume is a first-class
// capability (subPath sharing) that a set's children must not be refused for.
func TestApplicationSetReplicas(t *testing.T) {
	ctx := context.Background()
	p := applicationSet{}
	withReplicas := func(n int32, mutate func(*corev1.NamedApplicationSpec)) corev1.ApplicationSet {
		c := component("cache", "redis:7")
		c.Scale.Replicas = &n
		if mutate != nil {
			mutate(&c)
		}
		return bundle(c)
	}

	if err := p.Validate(ctx, appsetAttrs(Create, withReplicas(3, nil))); err != nil {
		t.Fatalf("replicas 3 must pass, got %v", err)
	}
	if err := p.Validate(ctx, appsetAttrs(Create, withReplicas(0, nil))); err == nil ||
		!strings.Contains(err.Error(), "at least 1") {
		t.Fatalf("want a positive-count rejection, got %v", err)
	}
	if err := p.Validate(ctx, appsetAttrs(Create, withReplicas(2, func(c *corev1.NamedApplicationSpec) {
		c.Scale.NodeSpread = &corev1.NodeSpread{}
	}))); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want a replicas+nodeSpread rejection, got %v", err)
	}
	// A named pv shared by every replica is ALLOWED: apps sharing one volume (subPath and
	// all) is a supported shape, and a set's children obey the same rules as hand-authored
	// Applications that mount the same volume.
	shared := withReplicas(2, func(c *corev1.NamedApplicationSpec) {
		c.Spec.Volumes = []corev1.VolumeMount{{
			Volume:    corev1.VolumeSource{Type: corev1.VolumeTypePV, Name: "shared-data"},
			MountPath: "/data",
		}}
	})
	if err := p.Validate(ctx, appsetAttrs(Create, shared)); err != nil {
		t.Fatalf("replicas sharing one named PV must be allowed, got %v", err)
	}
}

// TestApplicationSetScopeAndStrategy pins the whole-set blocks: a known placement mode, no
// contradiction with a component's own fan-out, and a non-negative rollout budget.
func TestApplicationSetScopeAndStrategy(t *testing.T) {
	ctx := context.Background()
	p := applicationSet{}

	ok := bundle(component("a", "x:1"), component("b", "y:1"))
	ok.Spec.Placement.Mode = corev1.PlacementSameNode
	ok.Spec.Rollout.MaxUnavailable = 1
	if err := p.Validate(ctx, appsetAttrs(Create, ok)); err != nil {
		t.Fatalf("sameNode + rollingUpdate must pass, got %v", err)
	}

	unknown := bundle(component("a", "x:1"))
	unknown.Spec.Placement.Mode = "spread"
	if err := p.Validate(ctx, appsetAttrs(Create, unknown)); err == nil ||
		!strings.Contains(err.Error(), "not a known mode") {
		t.Fatalf("want an unknown-mode rejection, got %v", err)
	}

	// sameNode co-locates the set; nodeSpread spreads one child per node — a set cannot mean both.
	conflict := bundle(component("a", "x:1"))
	conflict.Spec.Applications[0].Scale.NodeSpread = &corev1.NodeSpread{}
	conflict.Spec.Placement.Mode = corev1.PlacementSameNode
	if err := p.Validate(ctx, appsetAttrs(Create, conflict)); err == nil ||
		!strings.Contains(err.Error(), "contradicts") {
		t.Fatalf("want a sameNode+nodeSpread rejection, got %v", err)
	}

	negative := bundle(component("a", "x:1"))
	negative.Spec.Rollout.MaxUnavailable = -1
	if err := p.Validate(ctx, appsetAttrs(Create, negative)); err == nil ||
		!strings.Contains(err.Error(), "negative") {
		t.Fatalf("want a negative-budget rejection, got %v", err)
	}
}

// TestApplicationSetChildNameCollisions covers the collision the composed child name
// `<set>-<component>[-<replica>][-<node>]` makes reachable from two DISTINCT, both-valid
// components. The duplicate-component-name check cannot see it: the component names differ,
// only what they render to does not.
func TestApplicationSetChildNameCollisions(t *testing.T) {
	ctx := context.Background()
	three := int32(3)

	withReplicas := func(name string, n int32) corev1.NamedApplicationSpec {
		c := component(name, "x:1")
		c.Scale.Replicas = &n
		return c
	}
	spread := func(name string) corev1.NamedApplicationSpec {
		c := component(name, "x:1")
		c.Scale.NodeSpread = &corev1.NodeSpread{}
		return c
	}

	t.Run("replica index collides with a component name", func(t *testing.T) {
		// "api" replicas 3 renders web-api-0/1/2; "api-1" renders web-api-1.
		set := bundle(withReplicas("api", three), component("api-1", "x:1"))
		err := (applicationSet{}).Validate(ctx, appsetAttrs(Create, set))
		if err == nil || !strings.Contains(err.Error(), "web-api-1") {
			t.Fatalf("want a duplicate-child-name rejection naming web-api-1, got %v", err)
		}
	})

	t.Run("node name collides with a component name", func(t *testing.T) {
		// nodeSpread "api" over node n1 renders web-api-n1; "api-n1" renders web-api-n1.
		// Reachable only when the plugin expands against the live fleet.
		p := applicationSet{lister: fakeLister{nodes: []corev1.Node{mkNode("n1", corev1.ResourceAmounts{})}}}
		set := bundle(spread("api"), component("api-n1", "x:1"))
		err := p.Validate(ctx, appsetAttrs(Create, set))
		if err == nil || !strings.Contains(err.Error(), "web-api-n1") {
			t.Fatalf("want a duplicate-child-name rejection naming web-api-n1, got %v", err)
		}
	})

	t.Run("without a lister the node dimension is left to the reconciler", func(t *testing.T) {
		// Documents the limit deliberately: no fleet, no nodeSpread children, nothing to
		// collide. Expand's own check is what still catches it at reconcile time.
		set := bundle(spread("api"), component("api-n1", "x:1"))
		if err := (applicationSet{}).Validate(ctx, appsetAttrs(Create, set)); err != nil {
			t.Fatalf("want no rejection without a fleet to render against, got %v", err)
		}
	})

	t.Run("distinct renders still pass", func(t *testing.T) {
		p := applicationSet{lister: fakeLister{nodes: []corev1.Node{mkNode("n1", corev1.ResourceAmounts{})}}}
		set := bundle(withReplicas("api", three), spread("web"), component("db", "x:1"))
		if err := p.Validate(ctx, appsetAttrs(Create, set)); err != nil {
			t.Fatalf("a bundle whose children all render distinctly must pass, got %v", err)
		}
	})
}
