// Package service is the business-logic layer between pkg/apiserver's HTTP
// handlers and api/storage. Every write decodes the request body into its typed
// object through the scheme, runs the admission chain on that typed value
// (defaulting + policy), and hands the result to storage — reads and deletes are
// addressed by types.ObjectMeta. Storage sentinel errors are mapped onto typed
// Kubernetes API errors so handlers can serialize them directly.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/apiserver/admission"

	jsonpatch "github.com/evanphx/json-patch/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type Service struct {
	store     storage.Storage
	scheme    *scheme.Scheme
	admission admission.Chain
}

func New(store storage.Storage, sch *scheme.Scheme, chain admission.Chain) *Service {
	return &Service{store: store, scheme: sch, admission: chain}
}

func (s *Service) Get(ctx context.Context, m types.ObjectMeta) (types.Object, error) {
	obj, err := s.store.Get(ctx, m)
	if err != nil {
		return nil, s.apiError(err, gvkOf(m), m.Name)
	}
	return obj, nil
}

func (s *Service) List(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error) {
	list, err := s.store.List(ctx, m, opts)
	if err != nil {
		return nil, s.apiError(err, gvkOf(m), "")
	}
	return list, nil
}

func (s *Service) Watch(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) (<-chan metav1.WatchEvent, error) {
	ch, err := s.store.Watch(ctx, m, opts)
	if err != nil {
		return nil, s.apiError(err, gvkOf(m), "")
	}
	return ch, nil
}

func (s *Service) Create(ctx context.Context, gvk schema.GroupVersionKind, data []byte) (types.Object, error) {
	obj, err := s.decode(gvk, data)
	if err != nil {
		return nil, err
	}
	if nameOf(obj) == "" {
		return nil, invalid(gvk, "", fmt.Errorf("metadata.name is required"))
	}
	if err := s.admit(ctx, gvk, obj, nil, admission.Create); err != nil {
		return nil, err
	}

	out, err := s.store.Create(ctx, obj)
	if err != nil {
		return nil, s.apiError(err, gvk, nameOf(obj))
	}
	return out, nil
}

func (s *Service) checkUpdate(ctx context.Context, gvk schema.GroupVersionKind, data []byte) (types.Object, error) {
	obj, err := s.decode(gvk, data)
	if err != nil {
		return nil, err
	}
	old, err := s.store.Get(ctx, metaOf(gvk, obj))
	if err != nil {
		return nil, s.apiError(err, gvk, nameOf(obj))
	}
	if err := s.admit(ctx, gvk, obj, old, admission.Update); err != nil {
		return nil, err
	}

	return obj, nil
}

func (s *Service) Update(ctx context.Context, gvk schema.GroupVersionKind, data []byte) (types.Object, error) {
	obj, err := s.checkUpdate(ctx, gvk, data)
	if err != nil {
		return nil, err
	}

	out, err := s.store.Update(ctx, obj)
	if err != nil {
		return nil, s.apiError(err, gvk, nameOf(obj))
	}
	return out, nil
}

// UpdateSubresource decodes the body and persists only the named subresource
// (e.g. "status") of the addressed object, leaving its spec untouched.
func (s *Service) UpdateSubresource(ctx context.Context, gvk schema.GroupVersionKind, subresource string, data []byte) (types.Object, error) {
	obj, err := s.checkUpdate(ctx, gvk, data)
	if err != nil {
		return nil, err
	}

	out, err := s.store.UpdateSubresource(ctx, subresource, obj)
	if err != nil {
		return nil, s.apiError(err, gvk, nameOf(obj))
	}
	return out, nil
}

// Patch applies a JSON Merge Patch (RFC 7386) or JSON Patch (RFC 6902) to the
// current object and persists the result through the Update path (admission +
// storage). Strategic merge patch is unsupported: it needs Go struct tags this
// schema-less path does not have — the same choice kube-apiserver makes for
// CustomResources.
func (s *Service) Patch(ctx context.Context, m types.ObjectMeta, pt apitypes.PatchType, data []byte) (types.Object, error) {
	gvk := gvkOf(m)
	cur, err := s.store.Get(ctx, m)
	if err != nil {
		return nil, s.apiError(err, gvk, m.Name)
	}
	curJSON, err := json.Marshal(cur)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}

	var patched []byte
	switch pt {
	case apitypes.MergePatchType:
		patched, err = jsonpatch.MergePatch(curJSON, data)
	case apitypes.JSONPatchType:
		p, e := jsonpatch.DecodePatch(data)
		if e != nil {
			return nil, apierrors.NewBadRequest(e.Error())
		}
		patched, err = p.Apply(curJSON)
	default:
		// 415, as kube-apiserver returns for an unsupported patch media type.
		return nil, apierrors.NewGenericServerResponse(
			http.StatusUnsupportedMediaType, "patch", s.scheme.GroupResource(gvk), m.Name,
			fmt.Sprintf("unsupported patch type %q", pt), 0, false)
	}
	if err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}

	obj, err := s.decode(gvk, patched)
	if err != nil {
		return nil, err
	}
	if err := s.admit(ctx, gvk, obj, cur, admission.Update); err != nil {
		return nil, err
	}

	out, err := s.store.Update(ctx, obj)
	if err != nil {
		return nil, s.apiError(err, gvk, m.Name)
	}
	return out, nil
}

func (s *Service) Delete(ctx context.Context, m types.ObjectMeta) error {
	gvk := gvkOf(m)
	cur, err := s.store.Get(ctx, m)
	if err != nil {
		return s.apiError(err, gvk, m.Name)
	}
	a := &admission.Attributes{GVK: gvk, Operation: admission.Delete, Object: cur, OldObject: cur}
	if err := s.admission.Validate(ctx, a); err != nil {
		return s.admissionError(gvk, m.Name, err)
	}
	if err := s.store.Delete(ctx, m); err != nil {
		return s.apiError(err, gvk, m.Name)
	}
	return nil
}

// Rollback restores the object to the historical revision targetRV. It is a
// privileged control-plane operation and passes straight to storage (no admission).
func (s *Service) Rollback(ctx context.Context, m types.ObjectMeta, uid string, targetRV int64) (types.Object, error) {
	out, err := s.store.Rollback(ctx, m, uid, targetRV)
	if err != nil {
		return nil, s.apiError(err, gvkOf(m), m.Name)
	}
	return out, nil
}

// decode builds the typed object for gvk and fills it from the request body.
// Per-Kind JSON-schema validation (required fields, unknown-field rejection) is
// not yet reintroduced; decode enforces only that the body is well-typed JSON.
func (s *Service) decode(gvk schema.GroupVersionKind, data []byte) (types.Object, error) {
	obj, err := s.scheme.New(gvk)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	if err := json.Unmarshal(data, obj); err != nil {
		return nil, invalid(gvk, "", err)
	}
	return obj, nil
}

// admit runs the admission chain over the typed object (mutating it in place —
// defaulting stamps apiVersion/kind), so storage sees the admitted object.
func (s *Service) admit(ctx context.Context, gvk schema.GroupVersionKind, obj, old types.Object, op admission.Operation) error {
	a := &admission.Attributes{GVK: gvk, Operation: op, Object: obj, OldObject: old}
	if err := s.admission.Run(ctx, a); err != nil {
		return s.admissionError(gvk, nameOf(obj), err)
	}
	return nil
}

func gvkOf(m types.ObjectMeta) schema.GroupVersionKind {
	gv, _ := schema.ParseGroupVersion(m.ApiVersion)
	return gv.WithKind(m.Kind)
}

func metaOf(gvk schema.GroupVersionKind, obj types.Object) types.ObjectMeta {
	acc, err := apimeta.Accessor(obj)
	if err != nil {
		return types.ObjectMeta{ApiVersion: gvk.GroupVersion().String(), Kind: gvk.Kind}
	}
	return types.ObjectMeta{
		ApiVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Name:       acc.GetName(),
	}
}

func nameOf(obj types.Object) string {
	acc, err := apimeta.Accessor(obj)
	if err != nil {
		return ""
	}
	return acc.GetName()
}

// apiError maps storage sentinel errors onto typed API errors.
func (s *Service) apiError(err error, gvk schema.GroupVersionKind, name string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, storage.ErrNotFound):
		return apierrors.NewNotFound(s.scheme.GroupResource(gvk), name)
	case errors.Is(err, storage.ErrAlreadyExists):
		return apierrors.NewAlreadyExists(s.scheme.GroupResource(gvk), name)
	case errors.Is(err, storage.ErrConflict):
		return apierrors.NewConflict(s.scheme.GroupResource(gvk), name, err)
	default:
		return apierrors.NewInternalError(err)
	}
}

func invalid(gvk schema.GroupVersionKind, name string, err error) error {
	return apierrors.NewInvalid(gvk.GroupKind(), name, field.ErrorList{
		field.Invalid(field.NewPath("metadata"), name, err.Error()),
	})
}

// admissionError maps an admission failure onto a typed API error: a plugin that
// denied on authorization grounds (ForbiddenError) becomes 403, everything else —
// schema and validation failures — becomes 422 Invalid.
func (s *Service) admissionError(gvk schema.GroupVersionKind, name string, err error) error {
	if _, ok := errors.AsType[*admission.ForbiddenError](err); ok {
		return apierrors.NewForbidden(s.scheme.GroupResource(gvk), name, err)
	}
	return invalid(gvk, name, err)
}
