package admission

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"
)

// obj is a minimal typed object carrying just a name — enough for nodeRestriction,
// which keys off the name and the request's GVK, not the concrete type.
func obj(name string) types.Object {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func ctxAs(name string, groups ...string) context.Context {
	return authn.WithIdentity(context.Background(), &authn.Identity{Name: name, Groups: groups})
}

func TestNodeRestriction(t *testing.T) {
	nodeGVK := corev1.GroupVersion.WithKind("Node")
	appGVK := corev1.GroupVersion.WithKind("Application")

	cases := []struct {
		name      string
		ctx       context.Context
		attrs     *Attributes
		forbidden bool
	}{
		{
			name:  "node writes its own Node",
			ctx:   ctxAs("node1", NodeGroup),
			attrs: &Attributes{GVK: nodeGVK, Operation: Create, Object: obj("node1")},
		},
		{
			name:      "node writes another Node",
			ctx:       ctxAs("node1", NodeGroup),
			attrs:     &Attributes{GVK: nodeGVK, Operation: Create, Object: obj("node2")},
			forbidden: true,
		},
		{
			name:      "node deletes another Node",
			ctx:       ctxAs("node1", NodeGroup),
			attrs:     &Attributes{GVK: nodeGVK, Operation: Delete, Object: obj("node2")},
			forbidden: true,
		},
		{
			name:      "node writes an Application",
			ctx:       ctxAs("node1", NodeGroup),
			attrs:     &Attributes{GVK: appGVK, Operation: Create, Object: obj("app")},
			forbidden: true,
		},
		{
			name:  "admin writes any Node",
			ctx:   ctxAs("admin", "system:masters"),
			attrs: &Attributes{GVK: nodeGVK, Operation: Create, Object: obj("node2")},
		},
		{
			name:  "unauthenticated context is not restricted",
			ctx:   context.Background(),
			attrs: &Attributes{GVK: appGVK, Operation: Create, Object: obj("app")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := nodeRestriction{}.Validate(tc.ctx, tc.attrs)
			var fe *ForbiddenError
			if tc.forbidden {
				if !errors.As(err, &fe) {
					t.Fatalf("want ForbiddenError, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want allowed, got %v", err)
			}
		})
	}
}

// TestNodeRestrictionStatusOnly verifies the status-only tightening: a node identity may
// report its own Node's status but never change its own Node.spec (Unschedulable/Maintenance/
// machine-config are operator intent). The spec guard needs a lister; without one it is
// skipped, so unit tests of the own-node scoping keep passing.
func TestNodeRestrictionStatusOnly(t *testing.T) {
	nodeGVK := corev1.GroupVersion.WithKind("Node")
	lister := fakeLister{nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node1"}}}} // spec: Unschedulable=false
	ctx := ctxAs("node1", NodeGroup)

	node := func(unsched bool) types.Object {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node1"},
			Spec:       corev1.NodeSpec{Unschedulable: unsched},
		}
	}

	var fe *ForbiddenError
	// changing its own spec (self-cordon) is rejected
	err := nodeRestriction{lister: lister}.Validate(ctx, &Attributes{GVK: nodeGVK, Operation: Update, Object: node(true)})
	if !errors.As(err, &fe) {
		t.Fatalf("self-cordon: want ForbiddenError, got %v", err)
	}
	// a status-only update (spec unchanged) is allowed
	if err := (nodeRestriction{lister: lister}).Validate(ctx, &Attributes{GVK: nodeGVK, Operation: Update, Object: node(false)}); err != nil {
		t.Fatalf("status-only update: want allowed, got %v", err)
	}
	// without a lister the spec guard is skipped (own-node scoping still applies)
	if err := (nodeRestriction{}).Validate(ctx, &Attributes{GVK: nodeGVK, Operation: Update, Object: node(true)}); err != nil {
		t.Fatalf("no lister: want allowed, got %v", err)
	}
}

// TestNodeRestrictionInDefaultChain ensures the plugin is actually wired into the
// chain the controller runs, not just present in the package.
func TestNodeRestrictionInDefaultChain(t *testing.T) {
	ctx := ctxAs("node1", NodeGroup)
	app := &corev1.Application{ObjectMeta: metav1.ObjectMeta{Name: "app"}}
	a := &Attributes{GVK: corev1.GroupVersion.WithKind("Application"), Operation: Create, Object: app}
	err := DefaultChain(nil, nil).Run(ctx, a)
	var fe *ForbiddenError
	if !errors.As(err, &fe) {
		t.Fatalf("DefaultChain did not enforce NodeRestriction: %v", err)
	}
}

func TestNodeRestrictionAllowsRotationCSR(t *testing.T) {
	err := (nodeRestriction{}).Validate(ctxAs("node1", NodeGroup), &Attributes{
		GVK:       certv1.GroupVersion.WithKind("CertificateSigningRequest"),
		Operation: Create,
		Object:    &certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: "node1-abcd"}},
	})
	if err != nil {
		t.Fatalf("a node must be allowed to create its rotation CSR (confined by the approval loop), got %v", err)
	}
}

// TestNodeRestrictionCreateSpecMustBeEmpty: the status-only confinement has to hold on create
// too. Node.spec is operator intent — the labels the scheduler places on, Unschedulable,
// Maintenance — so a registering node that declares a spec is self-granting exactly what the
// update path already refuses it: a first-boot node could label itself into a placement pool
// it was never assigned to.
func TestNodeRestrictionCreateSpecMustBeEmpty(t *testing.T) {
	nodeGVK := corev1.GroupVersion.WithKind("Node")
	ctx := ctxAs("node1", NodeGroup)

	empty := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}}
	if err := (nodeRestriction{}).Validate(ctx, &Attributes{GVK: nodeGVK, Operation: Create, Object: empty}); err != nil {
		t.Fatalf("a node registering with an empty spec must be allowed, got %v", err)
	}

	labelled := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: map[string]string{"tier": "secure"}},
	}
	err := (nodeRestriction{}).Validate(ctx, &Attributes{GVK: nodeGVK, Operation: Create, Object: labelled})
	if err == nil {
		t.Fatal("a node must not create its own Node carrying spec.labels")
	}
	var forbidden *ForbiddenError
	if !errors.As(err, &forbidden) {
		t.Fatalf("error = %v, want a ForbiddenError", err)
	}

	cordoned := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
		Spec:       corev1.NodeSpec{Unschedulable: true},
	}
	if err := (nodeRestriction{}).Validate(ctx, &Attributes{GVK: nodeGVK, Operation: Create, Object: cordoned}); err == nil {
		t.Fatal("a node must not self-declare spec.unschedulable on create")
	}

	// An operator (not in system:nodes) is unaffected.
	opCtx := ctxAs("alice")
	if err := (nodeRestriction{}).Validate(opCtx, &Attributes{GVK: nodeGVK, Operation: Create, Object: labelled}); err != nil {
		t.Fatalf("an operator may create a Node with a spec, got %v", err)
	}
}
