package service

import (
	"context"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/admission"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// rollbackFakeStore satisfies storage.Storage via the embedded (nil) interface; Rollback only
// calls GetRevision, Get and — on a valid target — Rollback, which are overridden here.
type rollbackFakeStore struct {
	storage.Storage
	target     types.Object
	cur        types.Object
	rolledBack bool
}

func (f *rollbackFakeStore) GetRevision(context.Context, types.ObjectMeta, string, int64) (types.Object, error) {
	return f.target, nil
}
func (f *rollbackFakeStore) Get(context.Context, types.ObjectMeta) (types.Object, error) {
	return f.cur, nil
}
func (f *rollbackFakeStore) Rollback(context.Context, types.ObjectMeta, string, int64) (types.Object, error) {
	f.rolledBack = true
	return f.target, nil
}

// TestServiceRollbackReAdmission checks that Rollback re-validates the historical target through
// admission BEFORE committing: a revision violating the no-root floor (uid 0) is Forbidden and
// never persisted, while a valid revision rolls back.
func TestServiceRollbackReAdmission(t *testing.T) {
	ctx := context.Background()
	sch := scheme.New()
	corev1.AddToScheme(sch)
	chain := admission.DefaultChain(nil, nil)
	m := types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Application", Namespace: "team", Name: "web"}
	mkApp := func(uid int64) *corev1.Application {
		u := uid
		return &corev1.Application{
			TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
			ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "web"},
			Spec: corev1.ApplicationSpec{
				Image:           "reg/app:v1",
				SecurityContext: &corev1.SecurityContext{RunAsUser: &u},
			},
		}
	}

	// A target that violates the no-root floor (uid 0) must be Forbidden and never persisted.
	bad := &rollbackFakeStore{target: mkApp(0), cur: mkApp(65532)}
	if _, err := New(bad, sch, chain).Rollback(ctx, m, "uid-1", 5); !apierrors.IsForbidden(err) {
		t.Fatalf("a rollback to a uid-0 revision must be Forbidden, got %v", err)
	}
	if bad.rolledBack {
		t.Error("a floor-violating rollback must not be persisted")
	}

	// A valid target rolls back.
	good := &rollbackFakeStore{target: mkApp(65532), cur: mkApp(65532)}
	if _, err := New(good, sch, chain).Rollback(ctx, m, "uid-1", 5); err != nil {
		t.Fatalf("a valid rollback must succeed, got %v", err)
	}
	if !good.rolledBack {
		t.Error("a valid rollback must be persisted")
	}
}
