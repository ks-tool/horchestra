package admission

import (
	"context"
	"reflect"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// sharedPV is a PersistentVolume its author opened to concurrent mounters.
func sharedPV(name string) corev1.PersistentVolume {
	pv := mkPV(name)
	pv.Spec.Shared = true
	return pv
}

// appMountingTwice mounts one volume at two paths — the root and a subPath — which is the
// ordinary way a single app lays out its own storage and must never read as two mounters.
func appMountingTwice(name, pv string) corev1.Application {
	a := appMounting(name, pv)
	a.Spec.Volumes = append(a.Spec.Volumes, corev1.VolumeMount{
		Volume:    corev1.VolumeSource{Type: corev1.VolumeTypePV, Name: pv},
		MountPath: "/inner",
		SubPath:   "inner",
	})
	return a
}

func TestPVExclusive(t *testing.T) {
	ctx := context.Background()

	t.Run("a second application is refused", func(t *testing.T) {
		c := ruleCheck(fakeLister{
			apps: []corev1.Application{appMounting("web", "pg-data")},
			pvs:  []corev1.PersistentVolume{mkPV("pg-data")},
		}, pvExclusiveRule)
		err := c.Validate(ctx, appAttrs(Create, appMounting("worker", "pg-data")))
		if err == nil || !strings.Contains(err.Error(), `"pg-data" is already mounted`) || !strings.Contains(err.Error(), "web") {
			t.Fatalf("want a refusal naming the holder, got %v", err)
		}
		if _, ok := err.(*ForbiddenError); !ok {
			t.Fatalf("want a ForbiddenError (403), got %T", err)
		}
	})

	// The scheduler creates a volume implicitly from an inline mount, and creates it
	// unshared — so "no PersistentVolume yet" must not be a hole in the rule, or two apps
	// would race for the same name and one would silently win.
	t.Run("a volume that does not exist yet is exclusive too", func(t *testing.T) {
		c := ruleCheck(fakeLister{apps: []corev1.Application{appMounting("web", "pg-data")}}, pvExclusiveRule)
		if err := c.Validate(ctx, appAttrs(Create, appMounting("worker", "pg-data"))); err == nil {
			t.Fatal("an implicitly-created volume must be exclusive before it exists")
		}
	})

	t.Run("spec.shared admits the second application", func(t *testing.T) {
		c := ruleCheck(fakeLister{
			apps: []corev1.Application{appMounting("web", "pg-data")},
			pvs:  []corev1.PersistentVolume{sharedPV("pg-data")},
		}, pvExclusiveRule)
		if err := c.Validate(ctx, appAttrs(Create, appMounting("worker", "pg-data"))); err != nil {
			t.Fatalf("a shared volume must admit a second mounter, got %v", err)
		}
	})

	// Re-applying an unchanged spec is an Update whose object is already in the list. Comparing
	// it against its own stored copy would make every app the second mounter of its own volume.
	t.Run("an application does not collide with itself", func(t *testing.T) {
		c := ruleCheck(fakeLister{
			apps: []corev1.Application{appMounting("web", "pg-data")},
			pvs:  []corev1.PersistentVolume{mkPV("pg-data")},
		}, pvExclusiveRule)
		if err := c.Validate(ctx, appAttrs(Update, appMounting("web", "pg-data"))); err != nil {
			t.Fatalf("an app updating itself must not collide with its own mount, got %v", err)
		}
	})

	t.Run("one application mounting the volume twice is one mounter", func(t *testing.T) {
		c := ruleCheck(fakeLister{pvs: []corev1.PersistentVolume{mkPV("pg-data")}}, pvExclusiveRule)
		if err := c.Validate(ctx, appAttrs(Create, appMountingTwice("web", "pg-data"))); err != nil {
			t.Fatalf("a root mount beside a subPath mount is one app, got %v", err)
		}
	})

	// Sharing is granted by the volume, so revoking it must not leave the invariant false
	// behind: the apps are already running on the data when the write lands.
	t.Run("shared cannot be cleared while several mount it", func(t *testing.T) {
		c := ruleCheck(fakeLister{
			apps: []corev1.Application{appMounting("web", "pg-data"), appMounting("worker", "pg-data")},
			pvs:  []corev1.PersistentVolume{sharedPV("pg-data")},
		}, pvExclusiveRule)
		err := c.Validate(ctx, pvAttrs(Update, mkPV("pg-data")))
		if err == nil || !strings.Contains(err.Error(), "cannot be cleared") {
			t.Fatalf("want the clear refused, got %v", err)
		}
		if _, ok := err.(*ForbiddenError); !ok {
			t.Fatalf("want a ForbiddenError (403), got %T", err)
		}
		// With one mounter left there is nothing to break, so it goes back to exclusive freely.
		c = ruleCheck(fakeLister{
			apps: []corev1.Application{appMounting("web", "pg-data")},
			pvs:  []corev1.PersistentVolume{sharedPV("pg-data")},
		}, pvExclusiveRule)
		if err := c.Validate(ctx, pvAttrs(Update, mkPV("pg-data"))); err != nil {
			t.Fatalf("clearing shared with a single mounter must be allowed, got %v", err)
		}
	})

	t.Run("another namespace's volume of the same name is untouched", func(t *testing.T) {
		other := appMounting("web", "pg-data")
		other.Namespace = "team-b"
		c := ruleCheck(fakeLister{
			apps: []corev1.Application{other},
			pvs:  []corev1.PersistentVolume{mkPV("pg-data")},
		}, pvExclusiveRule)
		if err := c.Validate(ctx, appAttrs(Create, appMounting("worker", "pg-data"))); err != nil {
			t.Fatalf("a volume is namespace-scoped; another tenant's must not collide, got %v", err)
		}
	})

	t.Run("a tmpfs mount claims nothing", func(t *testing.T) {
		app := mkApp("worker", "n1", cpu("1"))
		app.Spec.Volumes = []corev1.VolumeMount{{Volume: corev1.VolumeSource{Type: corev1.VolumeTypeTmpfs}, MountPath: "/run"}}
		c := ruleCheck(fakeLister{apps: []corev1.Application{appMounting("web", "pg-data")}}, pvExclusiveRule)
		if err := c.Validate(ctx, appAttrs(Create, app)); err != nil {
			t.Fatalf("a tmpfs mount references no volume, got %v", err)
		}
	})

	t.Run("nil lister skips", func(t *testing.T) {
		if err := ruleCheck(nil, pvExclusiveRule).Validate(ctx, appAttrs(Create, appMounting("worker", "pg-data"))); err != nil {
			t.Fatalf("nil lister should skip, got %v", err)
		}
	})
}

// TestPVExclusiveIsNotDeclarableByAnApplication: the whole point of putting the flag on the
// PersistentVolume is that a workload cannot grant itself access to another's storage. An
// Application's inline pv volume must therefore carry no sharing field at all — if one is ever
// added to VolumeSource, this test is where the decision gets re-examined rather than silently
// reversed.
func TestPVExclusiveIsNotDeclarableByAnApplication(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[corev1.VolumeSource](),
		reflect.TypeFor[corev1.VolumeMount](),
	} {
		for i := range typ.NumField() {
			f := typ.Field(i)
			if strings.Contains(strings.ToLower(f.Name+f.Tag.Get("json")), "shared") {
				t.Errorf("%s.%s lets an Application declare the sharing itself; it belongs on the PersistentVolume, whose author knows what the data is",
					typ.Name(), f.Name)
			}
		}
	}
	// And the PersistentVolume is where it does live — so the assertion above is about the
	// placement of a field that exists, not about one nobody has written yet.
	if _, ok := reflect.TypeFor[corev1.PersistentVolumeSpec]().FieldByName("Shared"); !ok {
		t.Error("PersistentVolumeSpec.Shared is gone: exclusivity would then have no documented escape hatch")
	}
}
