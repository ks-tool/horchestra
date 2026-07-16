package admission

import (
	"context"
	"strings"
	"testing"

	v1 "ks-tool.dev/horchestra/api/v1"
)

func TestNodeExists(t *testing.T) {
	ctx := context.Background()
	nodes := []v1.Node{mkNode("n1", cpu("4"))}
	check := nodeExists{lister: fakeLister{nodes: nodes}}

	t.Run("existing node admitted", func(t *testing.T) {
		if err := check.Validate(ctx, appAttrs(Create, mkApp("a", "n1", cpu("1")))); err != nil {
			t.Fatalf("want admitted, got %v", err)
		}
	})

	t.Run("missing node rejected", func(t *testing.T) {
		err := check.Validate(ctx, appAttrs(Create, mkApp("a", "ghost", cpu("1"))))
		if err == nil || !strings.Contains(err.Error(), `node "ghost" does not exist`) {
			t.Fatalf("want does-not-exist error, got %v", err)
		}
	})

	t.Run("missing node rejected even with no requests", func(t *testing.T) {
		// Zero requests: capacityCheck would skip, but existence is still enforced.
		err := check.Validate(ctx, appAttrs(Create, mkApp("a", "ghost", v1.ResourceAmounts{})))
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("want does-not-exist error for request-less app, got %v", err)
		}
	})

	t.Run("missing node still deletable", func(t *testing.T) {
		if err := check.Validate(ctx, appAttrs(Delete, mkApp("a", "ghost", cpu("1")))); err != nil {
			t.Fatalf("delete of an app on a missing node must be allowed, got %v", err)
		}
	})

	t.Run("nil lister skips", func(t *testing.T) {
		if err := (nodeExists{}).Validate(ctx, appAttrs(Create, mkApp("a", "ghost", cpu("1")))); err != nil {
			t.Fatalf("nil lister should skip, got %v", err)
		}
	})
}
