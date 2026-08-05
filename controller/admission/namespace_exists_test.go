package admission

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

func mkNamespace(name string) corev1.Namespace {
	return corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
}

func inNamespace(name, ns string) corev1.Application {
	a := mkApp(name, "n1", cpu("1"))
	a.Namespace = ns
	return a
}

func nsAttrs(op Operation, app corev1.Application) *Attributes {
	return &Attributes{GVK: corev1.GroupVersion.WithKind("Application"), Operation: op, Object: &app}
}

func TestNamespaceExists(t *testing.T) {
	ctx := context.Background()

	t.Run("rejects an unknown namespace (422-style)", func(t *testing.T) {
		c := ruleCheck(fakeLister{namespaces: []corev1.Namespace{mkNamespace("team-a")}}, namespaceExistsRule)
		err := c.Validate(ctx, nsAttrs(Create, inNamespace("web", "ghost")))
		if err == nil || !strings.Contains(err.Error(), `namespace "ghost" does not exist`) {
			t.Fatalf("want unknown-namespace rejection, got %v", err)
		}
	})

	t.Run("accepts an existing namespace", func(t *testing.T) {
		c := ruleCheck(fakeLister{namespaces: []corev1.Namespace{mkNamespace("team-a")}}, namespaceExistsRule)
		if err := c.Validate(ctx, nsAttrs(Create, inNamespace("web", "team-a"))); err != nil {
			t.Fatalf("existing namespace must pass, got %v", err)
		}
	})

	t.Run("skips a cluster-scoped object (empty namespace)", func(t *testing.T) {
		c := ruleCheck(fakeLister{}, namespaceExistsRule)
		if err := c.Validate(ctx, nsAttrs(Create, inNamespace("web", ""))); err != nil {
			t.Fatalf("empty namespace must skip, got %v", err)
		}
	})

	t.Run("only guards Create/Update, not Delete", func(t *testing.T) {
		c := ruleCheck(fakeLister{}, namespaceExistsRule)
		if err := c.Validate(ctx, nsAttrs(Delete, inNamespace("web", "ghost"))); err != nil {
			t.Fatalf("delete must skip, got %v", err)
		}
	})

	t.Run("nil lister disables the check", func(t *testing.T) {
		if err := ruleCheck(nil, namespaceExistsRule).Validate(ctx, nsAttrs(Create, inNamespace("web", "ghost"))); err != nil {
			t.Fatalf("nil lister should skip, got %v", err)
		}
	})
}
