package admission

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/apiserver/authn"
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

// TestNodeRestrictionInDefaultChain ensures the plugin is actually wired into the
// chain the controller runs, not just present in the package.
func TestNodeRestrictionInDefaultChain(t *testing.T) {
	ctx := ctxAs("node1", NodeGroup)
	app := &corev1.Application{ObjectMeta: metav1.ObjectMeta{Name: "app"}}
	a := &Attributes{GVK: corev1.GroupVersion.WithKind("Application"), Operation: Create, Object: app}
	err := DefaultChain(nil).Run(ctx, a)
	var fe *ForbiddenError
	if !errors.As(err, &fe) {
		t.Fatalf("DefaultChain did not enforce NodeRestriction: %v", err)
	}
}
