package admission

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/scheme"
)

func namespaceAttrs(op Operation, ns corev1.Namespace) *Attributes {
	return &Attributes{GVK: corev1.GroupVersion.WithKind("Namespace"), Operation: op, Object: &ns, OldObject: &ns}
}

// TestNamespaceProtection: deleting a Namespace removes one record and nothing else — no
// finalizer, no owner GC, no namespace controller — so a namespace that still holds objects must
// not be deletable. Otherwise the tenant's workloads keep running, their Secret payloads and
// volume data stay on disk, and whoever is given the recycled namespace name inherits all of it.
func TestNamespaceProtection(t *testing.T) {
	ctx := context.Background()
	check := ruleCheck(fakeLister{
		namespaces: []corev1.Namespace{mkNamespace("team-a"), mkNamespace("empty")},
		apps:       []corev1.Application{inNamespace("web", "team-a")},
		pvs:        []corev1.PersistentVolume{inNamespacePV("pg-data", "team-a")},
	}, namespaceProtectionRule)

	t.Run("a namespace holding objects is not deletable", func(t *testing.T) {
		err := check.Validate(ctx, namespaceAttrs(Delete, mkNamespace("team-a")))
		if err == nil {
			t.Fatal("deleted a namespace that still holds a workload and a volume")
		}
		if _, ok := err.(*ForbiddenError); !ok {
			t.Fatalf("err = %T (%v), want *ForbiddenError", err, err)
		}
		// The operator has to know what is in the way.
		for _, want := range []string{"application web", "persistentvolume pg-data"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not name %q", err, want)
			}
		}
	})

	t.Run("an empty namespace is deletable", func(t *testing.T) {
		if err := check.Validate(ctx, namespaceAttrs(Delete, mkNamespace("empty"))); err != nil {
			t.Fatalf("an empty namespace must be deletable: %v", err)
		}
	})

	t.Run("creating a namespace is untouched", func(t *testing.T) {
		if err := check.Validate(ctx, namespaceAttrs(Create, mkNamespace("team-a"))); err != nil {
			t.Fatalf("create must not run the deletion guard: %v", err)
		}
	})
}

// TestNamespacedKindsMatchTheScheme is the drift guard for the table the deletion check sweeps: a
// namespaced Kind missing from it is a Kind that survives its namespace's deletion, silently.
func TestNamespacedKindsMatchTheScheme(t *testing.T) {
	sch := scheme.New()
	corev1.AddToScheme(sch)
	rbacv1.AddToScheme(sch)
	certv1.AddToScheme(sch)

	swept := map[string]bool{}
	for _, m := range namespacedKinds {
		swept[m.ApiVersion+" "+m.Kind] = true
	}
	for gvk, r := range sch.Resources() {
		if !r.Namespaced {
			continue
		}
		if key := gvk.GroupVersion().String() + " " + gvk.Kind; !swept[key] {
			t.Fatalf("namespaced Kind %s is not in namespacedKinds: deleting a namespace would leave it behind", key)
		}
	}
}

func inNamespacePV(name, ns string) corev1.PersistentVolume {
	pv := mkPV(name)
	pv.ObjectMeta = metav1.ObjectMeta{Namespace: ns, Name: name}
	return pv
}
