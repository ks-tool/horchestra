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
	"slices"
	"strings"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/admission"

	jsonpatch "github.com/evanphx/json-patch/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
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

func (s *Service) Create(ctx context.Context, gvk schema.GroupVersionKind, data []byte, ns string) (types.Object, error) {
	obj, err := s.decode(gvk, data)
	if err != nil {
		return nil, err
	}
	if err := bindNamespace(obj, ns); err != nil {
		return nil, err
	}
	if nameOf(obj) == "" {
		return nil, invalid(gvk, "", fmt.Errorf("metadata.name is required"))
	}
	if err := validIdentity(obj); err != nil {
		return nil, invalid(gvk, nameOf(obj), err)
	}
	if err := s.admit(ctx, gvk, obj, nil, admission.Create, ""); err != nil {
		return nil, err
	}

	out, err := s.store.Create(ctx, obj)
	if err != nil {
		return nil, s.apiError(err, gvk, nameOf(obj))
	}
	return out, nil
}

func (s *Service) checkUpdate(ctx context.Context, gvk schema.GroupVersionKind, data []byte, subresource, ns, name string) (types.Object, error) {
	obj, err := s.decode(gvk, data)
	if err != nil {
		return nil, err
	}
	if err := bindNamespace(obj, ns); err != nil {
		return nil, err
	}
	// The URL addresses the object; a body naming a different one would update the wrong object
	// and be audited under the wrong name. Checked on the typed value for the same reason the
	// namespace is: a raw probe of metadata.name reads one exact key while the decoder folds
	// field names, so the two could disagree about which object this even is.
	if name != "" && nameOf(obj) != "" && nameOf(obj) != name {
		return nil, apierrors.NewBadRequest(fmt.Sprintf(
			"the name of the object (%s) does not match the name on the URL (%s)", nameOf(obj), name))
	}
	old, err := s.store.Get(ctx, metaOf(gvk, obj))
	if err != nil {
		return nil, s.apiError(err, gvk, nameOf(obj))
	}
	if err := s.admit(ctx, gvk, obj, old, admission.Update, subresource); err != nil {
		return nil, err
	}

	return obj, nil
}

func (s *Service) Update(ctx context.Context, gvk schema.GroupVersionKind, data []byte, ns, name string) (types.Object, error) {
	obj, err := s.checkUpdate(ctx, gvk, data, "", ns, name)
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
func (s *Service) UpdateSubresource(ctx context.Context, gvk schema.GroupVersionKind, subresource string, data []byte, ns string) (types.Object, error) {
	obj, err := s.checkUpdate(ctx, gvk, data, subresource, ns, "")
	if err != nil {
		return nil, err
	}

	out, err := s.store.UpdateSubresource(ctx, subresource, obj)
	if err != nil {
		return nil, s.apiError(err, gvk, nameOf(obj))
	}
	return out, nil
}

// maxJSONPatchOperations bounds an RFC 6902 patch, matching kube-apiserver. The 3 MiB body
// cap is not a bound on its own: a patch is only a few bytes per operation, so a legal body
// carries tens of thousands of them.
const maxJSONPatchOperations = 10000

// patchApplyOptions bounds what applying a patch may cost. "copy" is the dangerous operation:
// it deep-copies the value it names, so `copy /spec/args -> /spec/args/-` doubles the array
// each time and ~30 of them take a 1 KiB document past a terabyte — the controller is
// OOM-killed before admission, RBAC or storage ever run, from one request by the
// lowest-privilege authenticated tenant. AccumulatedCopySizeLimit caps the total growth
// "copy" may cause; the non-standard negative-index extension is switched off with it since
// nothing here relies on it.
var patchApplyOptions = func() *jsonpatch.ApplyOptions {
	o := jsonpatch.NewApplyOptions()
	o.AccumulatedCopySizeLimit = 3 << 20 // the API server body cap (apiserver.maxBodyBytes)
	o.SupportNegativeIndices = false
	o.EnsurePathExistsOnAdd = false
	o.AllowMissingPathOnRemove = false
	return o
}()

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
		if len(p) > maxJSONPatchOperations {
			return nil, apierrors.NewRequestEntityTooLargeError(
				fmt.Sprintf("the allowed maximum of %d json patch operations was exceeded", maxJSONPatchOperations))
		}
		patched, err = p.ApplyWithOptions(curJSON, patchApplyOptions)
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
	// A patch addresses exactly the object fetched above; it must not change that object's
	// identity or bypass optimistic concurrency. Re-bind namespace/name/uid and the
	// resourceVersion to the fetched object, so a crafted patch (e.g. rewriting
	// metadata.namespace, or nulling resourceVersion) can never land the write on another
	// object or overwrite it unconditionally — storage keys the update by the object's own
	// namespace/name.
	if err := rebindIdentity(obj, cur); err != nil {
		return nil, err
	}
	if err := s.admit(ctx, gvk, obj, cur, admission.Update, ""); err != nil {
		return nil, err
	}

	out, err := s.store.Update(ctx, obj)
	if err != nil {
		return nil, s.apiError(err, gvk, m.Name)
	}
	return out, nil
}

// rebindIdentity forces obj's immutable identity (namespace/name/uid) and resourceVersion to
// ref's — used after applying a patch so the write targets exactly the addressed object with
// its current version.
func rebindIdentity(obj, ref types.Object) error {
	o, err := apimeta.Accessor(obj)
	if err != nil {
		return apierrors.NewInternalError(err)
	}
	r, err := apimeta.Accessor(ref)
	if err != nil {
		return apierrors.NewInternalError(err)
	}
	o.SetNamespace(r.GetNamespace())
	o.SetName(r.GetName())
	o.SetUID(r.GetUID())
	o.SetResourceVersion(r.GetResourceVersion())
	return nil
}

// Delete removes an object, or turns the request into a two-phase deletion when something still
// has to happen first (see markDeleting).
//
// opts.PropagationPolicy is the caller's say over the object's DEPENDENTS, and `Orphan` is the
// only value that changes anything here: it is `kubectl delete --cascade=orphan`, and it means
// "remove this, leave what it created". The decision belongs on the delete request and not in a
// spec field, because it is a fact about THIS removal rather than about the object — and because
// a spec field would quietly turn `update` into authority over what a later `delete` destroys.
//
// Only a Kind that HAS dependents accepts it; anywhere else it is refused rather than ignored, so
// a caller is never told "orphaned" about an object that has nothing to orphan.
func (s *Service) Delete(ctx context.Context, m types.ObjectMeta, opts metav1.DeleteOptions) error {
	gvk := gvkOf(m)
	cur, err := s.store.Get(ctx, m)
	if err != nil {
		return s.apiError(err, gvk, m.Name)
	}
	orphan := opts.PropagationPolicy != nil && *opts.PropagationPolicy == metav1.DeletePropagationOrphan
	if orphan && !hasDependents(gvk) {
		return apierrors.NewBadRequest(fmt.Sprintf(
			"propagationPolicy %q: kind %s has no dependents to orphan", metav1.DeletePropagationOrphan, gvk.Kind))
	}
	a := &admission.Attributes{GVK: gvk, Operation: admission.Delete, Object: cur, OldObject: cur}
	if err := s.admission.Validate(ctx, a); err != nil {
		return s.admissionError(gvk, m.Name, err)
	}
	held, err := s.markDeleting(ctx, cur, orphan)
	if err != nil {
		return s.apiError(err, gvk, m.Name)
	}
	if held {
		return nil
	}
	if err := s.store.Delete(ctx, m); err != nil {
		return s.apiError(err, gvk, m.Name)
	}
	return nil
}

// markDeleting turns a DELETE into a request when something still has to happen before the object
// may go, and reports whether it did. An object with no finalizer is erased on the spot, which is
// every object today and the behaviour this preserves.
//
// The record of an intended deletion has to be the OBJECT, for the same reason a job's attempt
// count is: nothing else outlives the parties. Erasing first and letting the consequences follow
// meant a node learned that a workload was gone by its ABSENCE from the next desired state — so
// the object had to disappear before the workload did, there was no state to observe in between
// (a workload that will not stop is exactly the one an operator goes looking for), and the grace
// period the author wrote was gone with the spec by the time anything used it.
//
// Stamping is idempotent: a second DELETE on an object already being deleted is not an error and
// does not move the timestamp, so a client retrying a delete cannot restart the clock.
//
// It writes straight to the store rather than through the update path, deliberately. This is
// metadata the control plane stamps on an object that already passed admission, and running it
// back through would re-default and re-validate a stored object on its way out — and trip the very
// guard that keeps finalizers out of client hands. metadata.generation does not move either: the
// store's generation compares every core field EXCEPT metadata, so a deletion does not read as a
// spec change to the node that runs the workload.
func (s *Service) markDeleting(ctx context.Context, cur types.Object, orphan bool) (bool, error) {
	acc, err := apimeta.Accessor(cur)
	if err != nil || len(acc.GetFinalizers()) == 0 {
		return false, nil //nolint:nilerr // an object with no accessor has no finalizers either
	}
	// The orphan intent is recorded as a FINALIZER, which is Kubernetes' own mechanism and the
	// only one that works here: the request that carries the policy is long gone by the time the
	// controller acts on the deletion, and the object is the one thing that outlives both.
	stamped := orphan && !slices.Contains(acc.GetFinalizers(), metav1.FinalizerOrphanDependents)
	if stamped {
		acc.SetFinalizers(append(acc.GetFinalizers(), metav1.FinalizerOrphanDependents))
	}
	if acc.GetDeletionTimestamp() != nil {
		// Already going. A second delete does not move the clock, but it may still be the one
		// that says to orphan — a caller allowed to re-issue the delete is allowed to say it.
		if stamped {
			if _, err := s.store.Update(ctx, cur); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	now := metav1.NewTime(time.Now())
	acc.SetDeletionTimestamp(&now)
	if _, err := s.store.Update(ctx, cur); err != nil {
		return false, err
	}
	return true, nil
}

// hasDependents reports whether a Kind owns objects that could be orphaned. Only ApplicationSet
// does: it renders child Applications and its loop is what honours the orphan finalizer. An
// Application owns nothing, so `--cascade=orphan` on one names a relationship that does not
// exist.
func hasDependents(gvk schema.GroupVersionKind) bool {
	return gvk.Group == corev1.GroupName && gvk.Kind == "ApplicationSet"
}

// Rollback restores the object to the historical revision targetRV. It re-validates the target
// through the admission chain's Validate pass BEFORE committing it: a historical revision may
// predate a tightened floor, so rolling back must not reintroduce an object today's admission
// would reject (e.g. the no-root floor). Only Validate runs (no Admit), so the target is restored
// verbatim, not re-defaulted.
func (s *Service) Rollback(ctx context.Context, m types.ObjectMeta, uid string, targetRV int64) (types.Object, error) {
	gvk := gvkOf(m)
	target, err := s.store.GetRevision(ctx, m, uid, targetRV)
	if err != nil {
		return nil, s.apiError(err, gvk, m.Name)
	}
	cur, err := s.store.Get(ctx, m)
	if err != nil {
		return nil, s.apiError(err, gvk, m.Name)
	}
	a := &admission.Attributes{GVK: gvk, Operation: admission.Update, Object: target, OldObject: cur}
	if err := s.admission.Validate(ctx, a); err != nil {
		return nil, s.admissionError(gvk, m.Name, err)
	}

	out, err := s.store.Rollback(ctx, m, uid, targetRV)
	if err != nil {
		return nil, s.apiError(err, gvk, m.Name)
	}
	return out, nil
}

// decode checks the request body against its Kind's input schema and builds the typed object
// from it. The schema reads the RAW BYTES, and nothing downstream can substitute for that: once
// the body is a Go value a misspelled key is indistinguishable from an absent one, and an
// out-of-range number has already been truncated by the decoder. Every write reaches storage
// through here — create, update, status and the re-serialized result of a patch — so there is
// one place the shape is enforced.
func (s *Service) decode(gvk schema.GroupVersionKind, data []byte) (types.Object, error) {
	obj, err := s.scheme.New(gvk)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	// Defaulting comes first — custom defaulters, then the schema's declared ones — so what is
	// stored is what the server says an absent field means. Validation then runs over the
	// completed body, which is the order that matters: a value defaulting supplied is checked
	// exactly like an authored one, never trusted because the server wrote it.
	data, err = s.scheme.Default(gvk, data)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	// Decode first, but judge the schema's verdict first: the decoder's error names a Go struct
	// field and the schema's names the JSON path the author actually wrote, so where both would
	// fire (a string where a number belongs) the schema's is the one to return. What the decode
	// buys is the object's name for the error — the one thing the raw body cannot be asked for
	// safely, since a probe reads one exact key while the decoder folds field names.
	decodeErr := json.Unmarshal(data, obj)
	if errs := s.scheme.Validate(gvk, data); len(errs) > 0 {
		return nil, apierrors.NewInvalid(gvk.GroupKind(), nameOf(obj), errs)
	}
	if decodeErr != nil {
		return nil, invalid(gvk, nameOf(obj), decodeErr)
	}
	return obj, nil
}

// admit runs the admission chain over the typed object (mutating it in place —
// defaulting stamps apiVersion/kind), so storage sees the admitted object.
func (s *Service) admit(ctx context.Context, gvk schema.GroupVersionKind, obj, old types.Object, op admission.Operation, subresource string) error {
	a := &admission.Attributes{GVK: gvk, Operation: op, Object: obj, OldObject: old, Subresource: subresource}
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
		Namespace:  acc.GetNamespace(),
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

// validIdentity rejects a metadata.name or namespace that is not a DNS-1123 name. Both flow
// into node-side filesystem paths, systemd unit names and overlay mount-option strings, so a
// value carrying '/', ',', ':' or whitespace could traverse the node state dir or inject an
// overlay mount option; confining them to the Kubernetes DNS-1123 character set at the write
// boundary closes that at the source (mirroring the ApplicationSet child-name check for every
// directly-created object).
func validIdentity(obj types.Object) error {
	acc, err := apimeta.Accessor(obj)
	if err != nil {
		return err
	}
	if msgs := validation.IsDNS1123Subdomain(acc.GetName()); len(msgs) > 0 {
		return fmt.Errorf("metadata.name %q is invalid: %s", acc.GetName(), strings.Join(msgs, "; "))
	}
	if ns := acc.GetNamespace(); ns != "" {
		if msgs := validation.IsDNS1123Label(ns); len(msgs) > 0 {
			return fmt.Errorf("metadata.namespace %q is invalid: %s", ns, strings.Join(msgs, "; "))
		}
	}
	return nil
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

// bindNamespace binds a decoded object to ns — the namespace the CALLER is authoritative about
// (the URL's for an HTTP write, the object's own for an internal one, empty for a cluster-scoped
// Kind) — and refuses a body that names a different one.
//
// It runs on the typed value, and that is the whole point. It used to rewrite the raw JSON:
// probe metadata for the exact key "namespace", then set it and re-marshal. Both halves were
// wrong. A map key is an exact string while encoding/json folds FIELD names with a Unicode-aware
// comparison, so "nameſpace" (U+017F) was a different key to the probe and the same field to the
// decoder; and re-marshalling a map sorts its keys, which put that spelling last, where
// last-wins made it the one that took effect. A tenant holding rights in one namespace could
// write into any. On the typed object there is one field and nothing left to spell.
func bindNamespace(obj types.Object, ns string) error {
	meta, ok := obj.(metav1.Object)
	if !ok {
		return apierrors.NewBadRequest("object carries no metadata")
	}
	if got := meta.GetNamespace(); got != "" && got != ns {
		if ns == "" {
			return apierrors.NewBadRequest(
				"the object must not set metadata.namespace: this resource is cluster-scoped")
		}
		return apierrors.NewBadRequest(fmt.Sprintf(
			"the namespace of the object (%s) does not match the namespace of the request (%s)", got, ns))
	}
	meta.SetNamespace(ns)
	return nil
}
