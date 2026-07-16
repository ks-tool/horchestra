package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	jsonpatch "github.com/evanphx/json-patch/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"

	v1 "ks-tool.dev/horchestra/api/v1"
	"ks-tool.dev/horchestra/pkg/admission"
	"ks-tool.dev/horchestra/pkg/storage"
)

type Service struct {
	store     storage.Storage
	admission admission.Chain
}

func New(store storage.Storage, chain admission.Chain) *Service {
	return &Service{store: store, admission: chain}
}

func (s *Service) Get(ctx context.Context, gvk schema.GroupVersionKind, name string) (*unstructured.Unstructured, error) {
	obj, err := s.store.Get(ctx, gvk, name)
	if err != nil {
		return nil, apiError(err, gvk, name)
	}
	return obj, nil
}

func (s *Service) List(ctx context.Context, gvk schema.GroupVersionKind) (*unstructured.UnstructuredList, error) {
	list, err := s.store.List(ctx, gvk)
	if err != nil {
		return nil, apiError(err, gvk, "")
	}
	return list, nil
}

func (s *Service) Watch(ctx context.Context, gvk schema.GroupVersionKind) (<-chan metav1.WatchEvent, error) {
	return s.store.Watch(ctx, gvk)
}

func (s *Service) Create(ctx context.Context, gvk schema.GroupVersionKind, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	stored, err := s.admit(ctx, gvk, obj, admission.Create)
	if err != nil {
		return nil, err
	}
	out, err := s.store.Create(ctx, gvk, stored)
	if err != nil {
		return nil, apiError(err, gvk, obj.GetName())
	}
	return out, nil
}

func (s *Service) Update(ctx context.Context, gvk schema.GroupVersionKind, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	stored, err := s.admit(ctx, gvk, obj, admission.Update)
	if err != nil {
		return nil, err
	}
	out, err := s.store.Update(ctx, gvk, stored)
	if err != nil {
		return nil, apiError(err, gvk, obj.GetName())
	}
	return out, nil
}

// admit validates the request body against the Kind's input schema, decodes it
// into its typed api/v1 value, runs the admission chain on that typed object, and
// re-encodes the (possibly defaulted) result for storage — the shared create/update
// path so both go through schema validation and typed admission identically.
func (s *Service) admit(ctx context.Context, gvk schema.GroupVersionKind, obj *unstructured.Unstructured, op admission.Operation) (*unstructured.Unstructured, error) {
	if err := v1.Validate(gvk, obj); err != nil {
		return nil, invalid(gvk, obj.GetName(), err)
	}
	typed, err := v1.Decode(gvk, obj)
	if err != nil {
		return nil, invalid(gvk, obj.GetName(), err)
	}
	// Defaulting (Kubernetes-style typed Default()) runs after decode and before
	// admission, so admission and storage see the defaulted object. Kinds without a
	// Default() are left untouched.
	if d, ok := typed.(v1.Defaulter); ok {
		d.Default()
	}
	a := &admission.Attributes{GVK: gvk, Operation: op, Object: typed}
	if err := s.admission.Run(ctx, a); err != nil {
		return nil, admissionError(gvk, obj.GetName(), err)
	}
	stored, err := v1.Encode(a.Object)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	return stored, nil
}

// Patch applies a JSON Merge Patch (RFC 7386) or JSON Patch (RFC 6902) to the
// current object and persists the result through Update (admission + storage).
// Strategic merge patch is unsupported: it needs Go struct tags that do not
// exist for schema-less resources — the same choice kube-apiserver makes for
// CustomResources.
func (s *Service) Patch(ctx context.Context, gvk schema.GroupVersionKind, name string, pt types.PatchType, data []byte) (*unstructured.Unstructured, error) {
	cur, err := s.store.Get(ctx, gvk, name)
	if err != nil {
		return nil, apiError(err, gvk, name)
	}
	curJSON, err := cur.MarshalJSON()
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	var patched []byte
	switch pt {
	case types.MergePatchType:
		patched, err = jsonpatch.MergePatch(curJSON, data)
	case types.JSONPatchType:
		p, e := jsonpatch.DecodePatch(data)
		if e != nil {
			return nil, apierrors.NewBadRequest(e.Error())
		}
		patched, err = p.Apply(curJSON)
	default:
		// 415, as kube-apiserver returns for an unsupported patch media type.
		return nil, apierrors.NewGenericServerResponse(
			http.StatusUnsupportedMediaType, "patch", groupResource(gvk), name,
			fmt.Sprintf("unsupported patch type %q", pt), 0, false)
	}
	if err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}
	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(patched); err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}
	obj.SetName(name)
	return s.Update(ctx, gvk, obj)
}

func (s *Service) Delete(ctx context.Context, gvk schema.GroupVersionKind, name string) error {
	obj, err := s.store.Get(ctx, gvk, name)
	if err != nil {
		return apiError(err, gvk, name)
	}
	typed, err := v1.Decode(gvk, obj)
	if err != nil {
		return invalid(gvk, name, err)
	}
	a := &admission.Attributes{GVK: gvk, Operation: admission.Delete, Object: typed, OldObject: typed}
	if err := s.admission.Validate(ctx, a); err != nil {
		return admissionError(gvk, name, err)
	}
	if err := s.store.Delete(ctx, gvk, name); err != nil {
		return apiError(err, gvk, name)
	}
	return nil
}

// apiError maps storage sentinel errors onto typed API errors.
func apiError(err error, gvk schema.GroupVersionKind, name string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, storage.ErrNotFound):
		return apierrors.NewNotFound(groupResource(gvk), name)
	case errors.Is(err, storage.ErrAlreadyExists):
		return apierrors.NewAlreadyExists(groupResource(gvk), name)
	case errors.Is(err, storage.ErrConflict):
		return apierrors.NewConflict(groupResource(gvk), name, err)
	default:
		return apierrors.NewInternalError(err)
	}
}

func groupResource(gvk schema.GroupVersionKind) schema.GroupResource {
	plural, _ := apimeta.UnsafeGuessKindToResource(gvk)
	return plural.GroupResource()
}

func invalid(gvk schema.GroupVersionKind, name string, err error) error {
	return apierrors.NewInvalid(gvk.GroupKind(), name, field.ErrorList{
		field.Invalid(field.NewPath("metadata"), name, err.Error()),
	})
}

// admissionError maps an admission failure onto a typed API error: a plugin
// that denied on authorization grounds (ForbiddenError) becomes 403, everything
// else — schema and validation failures — becomes 422 Invalid.
func admissionError(gvk schema.GroupVersionKind, name string, err error) error {
	var forbidden *admission.ForbiddenError
	if errors.As(err, &forbidden) {
		return apierrors.NewForbidden(groupResource(gvk), name, err)
	}
	return invalid(gvk, name, err)
}
