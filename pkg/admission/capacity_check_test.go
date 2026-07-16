package admission

import (
	"context"
	"errors"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "ks-tool.dev/horchestra/api/v1"
)

type fakeLister struct {
	apps  []v1.Application
	nodes []v1.Node
}

func (f fakeLister) List(_ context.Context, gvk schema.GroupVersionKind) (*unstructured.UnstructuredList, error) {
	list := &unstructured.UnstructuredList{}
	switch gvk.Kind {
	case "Application":
		for i := range f.apps {
			list.Items = append(list.Items, toU(&f.apps[i]))
		}
	case "Node":
		for i := range f.nodes {
			list.Items = append(list.Items, toU(&f.nodes[i]))
		}
	}
	return list, nil
}

func toU(obj any) unstructured.Unstructured {
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		panic(err)
	}
	return unstructured.Unstructured{Object: m}
}

// cpu is a CPU-only request/capacity; res is CPU + memory.
func cpu(s string) v1.ResourceAmounts { return v1.ResourceAmounts{CPU: resource.MustParse(s)} }
func res(c, m string) v1.ResourceAmounts {
	return v1.ResourceAmounts{CPU: resource.MustParse(c), Memory: resource.MustParse(m)}
}

func mkApp(name, node string, req v1.ResourceAmounts) v1.Application {
	return v1.Application{
		TypeMeta:   v1.ApplicationResource.TypeMeta(),
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v1.ApplicationSpec{Image: "reg/app:v1", NodeName: node, Resources: v1.ResourceRequirements{Requests: req}},
	}
}

func mkNode(name string, capacity v1.ResourceAmounts) v1.Node {
	return v1.Node{
		TypeMeta:   v1.NodeResource.TypeMeta(),
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     v1.NodeStatus{Capacity: capacity},
	}
}

func appAttrs(op Operation, app v1.Application) *Attributes {
	return &Attributes{GVK: v1.ApplicationResource.GVK, Operation: op, Object: &app}
}

func TestCapacityCheck(t *testing.T) {
	cap8 := res("8", "16Gi")
	cap4 := res("4", "8Gi")
	ctx := context.Background()

	t.Run("fits", func(t *testing.T) {
		c := capacityCheck{lister: fakeLister{
			apps:  []v1.Application{mkApp("a", "n1", cpu("2"))},
			nodes: []v1.Node{mkNode("n1", cap8)},
		}}
		// New app b on n1: 2 + existing 2 = 4 cores <= 8.
		if err := c.Validate(ctx, appAttrs(Create, mkApp("b", "n1", cpu("2")))); err != nil {
			t.Fatalf("want admitted, got %v", err)
		}
	})

	t.Run("exceeds is forbidden", func(t *testing.T) {
		c := capacityCheck{lister: fakeLister{
			apps:  []v1.Application{mkApp("a", "n1", cpu("3"))},
			nodes: []v1.Node{mkNode("n1", cap4)},
		}}
		// On n1: 3 + 2 = 5 cores > 4.
		err := c.Validate(ctx, appAttrs(Create, mkApp("b", "n1", cpu("2"))))
		var fe *ForbiddenError
		if !errors.As(err, &fe) {
			t.Fatalf("want ForbiddenError, got %v", err)
		}
		if !strings.Contains(err.Error(), "cpu") {
			t.Errorf("message should name the resource: %q", err.Error())
		}
	})

	t.Run("memory exceeds", func(t *testing.T) {
		c := capacityCheck{lister: fakeLister{nodes: []v1.Node{mkNode("n1", cap8)}}}
		// 20Gi memory request > 16Gi capacity of n1.
		err := c.Validate(ctx, appAttrs(Create, mkApp("b", "n1", v1.ResourceAmounts{Memory: resource.MustParse("20Gi")})))
		if err == nil || !strings.Contains(err.Error(), "memory") {
			t.Fatalf("want memory rejection, got %v", err)
		}
	})

	t.Run("another node's apps do not compete", func(t *testing.T) {
		c := capacityCheck{lister: fakeLister{
			apps:  []v1.Application{mkApp("a", "other", cpu("3"))},
			nodes: []v1.Node{mkNode("n1", cap4), mkNode("other", cap4)},
		}}
		// b on n1 needs 3; a's 3 sits on 'other', so n1 holds only b -> 3 <= 4.
		if err := c.Validate(ctx, appAttrs(Create, mkApp("b", "n1", cpu("3")))); err != nil {
			t.Fatalf("want admitted (a is on another node), got %v", err)
		}
	})

	t.Run("checked against its own node, not the smallest", func(t *testing.T) {
		c := capacityCheck{lister: fakeLister{
			nodes: []v1.Node{mkNode("big", cap8), mkNode("small", cap4)},
		}}
		// 5 cores fits 'big' (8) when pinned there...
		if err := c.Validate(ctx, appAttrs(Create, mkApp("b", "big", cpu("5")))); err != nil {
			t.Fatalf("want admitted on big, got %v", err)
		}
		// ...but not 'small' (4) when pinned there.
		if err := c.Validate(ctx, appAttrs(Create, mkApp("b", "small", cpu("5")))); err == nil {
			t.Fatal("want rejected on small")
		}
	})

	t.Run("update replaces, no double count", func(t *testing.T) {
		c := capacityCheck{lister: fakeLister{
			apps:  []v1.Application{mkApp("a", "n1", cpu("3"))},
			nodes: []v1.Node{mkNode("n1", cap4)},
		}}
		// Update a from 3 to 3500m on n1: total is 3500m (not 6500m) <= 4.
		if err := c.Validate(ctx, appAttrs(Update, mkApp("a", "n1", cpu("3500m")))); err != nil {
			t.Fatalf("want admitted, got %v", err)
		}
	})

	t.Run("node not reported is unconstrained", func(t *testing.T) {
		c := capacityCheck{lister: fakeLister{}}
		// Pinned to n1, which has not reported capacity -> admitted (stays pending).
		if err := c.Validate(ctx, appAttrs(Create, mkApp("b", "n1", cpu("1000")))); err != nil {
			t.Fatalf("want admitted with no node capacity, got %v", err)
		}
	})

	t.Run("no requests is ignored", func(t *testing.T) {
		c := capacityCheck{lister: fakeLister{nodes: []v1.Node{mkNode("n1", cap4)}}}
		if err := c.Validate(ctx, appAttrs(Create, mkApp("b", "n1", v1.ResourceAmounts{}))); err != nil {
			t.Fatalf("want admitted for zero-request app, got %v", err)
		}
	})
}
