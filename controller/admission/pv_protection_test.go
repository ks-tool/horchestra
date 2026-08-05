package admission

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

func mkPV(name string) corev1.PersistentVolume {
	return corev1.PersistentVolume{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "PersistentVolume"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
}

func pvAttrs(op Operation, pv corev1.PersistentVolume) *Attributes {
	return &Attributes{GVK: corev1.GroupVersion.WithKind("PersistentVolume"), Operation: op, Object: &pv, OldObject: &pv}
}

func appMounting(name, pv string) corev1.Application {
	a := mkApp(name, "n1", cpu("1"))
	a.Spec.Volumes = []corev1.VolumeMount{{Volume: corev1.VolumeSource{Type: corev1.VolumeTypePV, Name: pv}, MountPath: "/data"}}
	return a
}

func TestPVProtection(t *testing.T) {
	ctx := context.Background()

	t.Run("in-use PV delete rejected (403, names the app)", func(t *testing.T) {
		c := ruleCheck(fakeLister{apps: []corev1.Application{appMounting("web", "pg-data")}}, pvProtectionRule)
		err := c.Validate(ctx, pvAttrs(Delete, mkPV("pg-data")))
		if err == nil || !strings.Contains(err.Error(), `"pg-data" is in use`) || !strings.Contains(err.Error(), "web") {
			t.Fatalf("want in-use rejection naming the app, got %v", err)
		}
		if _, ok := err.(*ForbiddenError); !ok {
			t.Fatalf("want a ForbiddenError (403), got %T", err)
		}
	})

	t.Run("lists every mounting app", func(t *testing.T) {
		c := ruleCheck(fakeLister{apps: []corev1.Application{
			appMounting("web", "pg-data"), appMounting("worker", "pg-data"), appMounting("other", "elsewhere"),
		}}, pvProtectionRule)
		err := c.Validate(ctx, pvAttrs(Delete, mkPV("pg-data")))
		if err == nil || !strings.Contains(err.Error(), "web") || !strings.Contains(err.Error(), "worker") {
			t.Fatalf("want both mounting apps named, got %v", err)
		}
		if strings.Contains(err.Error(), "other") {
			t.Fatalf("an app mounting a different PV must not be listed: %v", err)
		}
	})

	t.Run("unused PV deletable", func(t *testing.T) {
		c := ruleCheck(fakeLister{apps: []corev1.Application{appMounting("web", "other")}}, pvProtectionRule)
		if err := c.Validate(ctx, pvAttrs(Delete, mkPV("pg-data"))); err != nil {
			t.Fatalf("an unmounted PV must be deletable, got %v", err)
		}
	})

	t.Run("tmpfs mount protects no PV", func(t *testing.T) {
		app := mkApp("web", "n1", cpu("1"))
		app.Spec.Volumes = []corev1.VolumeMount{{Volume: corev1.VolumeSource{Type: corev1.VolumeTypeTmpfs}, MountPath: "/run"}}
		c := ruleCheck(fakeLister{apps: []corev1.Application{app}}, pvProtectionRule)
		if err := c.Validate(ctx, pvAttrs(Delete, mkPV("pg-data"))); err != nil {
			t.Fatalf("a tmpfs mount references no PV, got %v", err)
		}
	})

	t.Run("only guards Delete", func(t *testing.T) {
		c := ruleCheck(fakeLister{apps: []corev1.Application{appMounting("web", "pg-data")}}, pvProtectionRule)
		if err := c.Validate(ctx, pvAttrs(Create, mkPV("pg-data"))); err != nil {
			t.Fatalf("create/update of a PV must not be blocked, got %v", err)
		}
	})

	t.Run("nil lister skips", func(t *testing.T) {
		if err := ruleCheck(nil, pvProtectionRule).Validate(ctx, pvAttrs(Delete, mkPV("pg-data"))); err != nil {
			t.Fatalf("nil lister should skip, got %v", err)
		}
	})
}
