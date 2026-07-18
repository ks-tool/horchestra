package apiserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ks-tool/horchestra/api/types"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"
)

// maxBodyBytes caps a request body, matching kube-apiserver's default.
const maxBodyBytes = 3 << 20

func (s *APIServer) get(w http.ResponseWriter, req bunrouter.Request) error {
	obj, err := s.svc.Get(req.Context(), reqMeta(req))
	if err != nil {
		return err
	}
	if tableRequested(req) {
		tbl, err := objectsTable(gvkFromContext(req.Context()), []types.Object{obj})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, tbl)
	}
	return writeJSON(w, http.StatusOK, obj)
}

// listOrWatch serves the collection endpoint: a streaming Watch when ?watch=true,
// otherwise a one-shot List.
func (s *APIServer) listOrWatch(w http.ResponseWriter, req bunrouter.Request) error {
	if req.URL.Query().Get("watch") == "true" {
		return s.watch(w, req)
	}

	items, err := s.svc.List(req.Context(), reqMeta(req), listOptions(req))
	if err != nil {
		return err
	}
	gvk := gvkFromContext(req.Context())
	if tableRequested(req) {
		tbl, err := objectsTable(gvk, items)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, tbl)
	}
	return writeJSON(w, http.StatusOK, listBody(gvk, items))
}

func (s *APIServer) watch(w http.ResponseWriter, req bunrouter.Request) error {
	ch, err := s.svc.Watch(req.Context(), reqMeta(req), listOptions(req))
	if err != nil {
		return err
	}
	streamWatch(w, ch)
	return nil
}

func (s *APIServer) create(w http.ResponseWriter, req bunrouter.Request) error {
	data, err := readBody(w, req)
	if err != nil {
		return apierrors.NewBadRequest(err.Error())
	}
	obj, err := s.svc.Create(req.Context(), gvkFromContext(req.Context()), data)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, obj)
}

func (s *APIServer) update(w http.ResponseWriter, req bunrouter.Request) error {
	data, err := readBody(w, req)
	if err != nil {
		return apierrors.NewBadRequest(err.Error())
	}
	// The body addresses the object; a name that disagrees with the URL would
	// update a different (or wrong) object, so reject it (as kube-apiserver does).
	if bodyName, urlName := nameFromBody(data), req.Param("name"); bodyName != "" && bodyName != urlName {
		return apierrors.NewBadRequest(fmt.Sprintf(
			"the name of the object (%s) does not match the name on the URL (%s)", bodyName, urlName))
	}
	obj, err := s.svc.Update(req.Context(), gvkFromContext(req.Context()), data)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, obj)
}

func (s *APIServer) patch(w http.ResponseWriter, req bunrouter.Request) error {
	data, err := readBody(w, req)
	if err != nil {
		return apierrors.NewBadRequest(err.Error())
	}
	obj, err := s.svc.Patch(req.Context(), reqMeta(req), patchType(req), data)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, obj)
}

func (s *APIServer) delete(w http.ResponseWriter, req bunrouter.Request) error {
	if err := s.svc.Delete(req.Context(), reqMeta(req)); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, successStatus())
}

// reqMeta builds the storage address from the route-bound GVK (see bind) and the
// :name path parameter. Resources are cluster-scoped, so namespace stays empty.
func reqMeta(req bunrouter.Request) types.ObjectMeta {
	gvk := gvkFromContext(req.Context())
	return types.ObjectMeta{
		ApiVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Name:       req.Param("name"),
	}
}

func listOptions(req bunrouter.Request) metav1.ListOptions {
	q := req.URL.Query()
	return metav1.ListOptions{
		LabelSelector:   q.Get("labelSelector"),
		FieldSelector:   q.Get("fieldSelector"),
		ResourceVersion: q.Get("resourceVersion"),
	}
}

// patchType reads the patch media type from Content-Type, dropping any
// parameters; service.Patch decides which types it supports.
func patchType(req bunrouter.Request) apitypes.PatchType {
	ct, _, _ := strings.Cut(req.Header.Get("Content-Type"), ";")
	return apitypes.PatchType(strings.TrimSpace(ct))
}

func readBody(w http.ResponseWriter, req bunrouter.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodyBytes))
}

// nameFromBody extracts metadata.name from a request body, to validate it against
// the name in the URL. Returns "" when absent or unparseable.
func nameFromBody(data []byte) string {
	var m struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(data, &m)
	return m.Metadata.Name
}

// objectList is the <Kind>List envelope kubectl expects around a collection.
type objectList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta `json:"metadata"`
	Items           []types.Object  `json:"items"`
}

func listBody(gvk schema.GroupVersionKind, items []types.Object) *objectList {
	if items == nil {
		items = []types.Object{}
	}
	return &objectList{
		TypeMeta: metav1.TypeMeta{APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind + "List"},
		Items:    items,
	}
}

// objectsTable renders typed objects as a server-side metav1.Table so kubectl
// prints the kind's real columns (Node Status/CPU/MEM, PV size/node, …) instead
// of falling back to its hardcoded types (NAME + AGE) for an unknown GVK.
func objectsTable(gvk schema.GroupVersionKind, items []types.Object) (*metav1.Table, error) {
	rows := make([]unstructured.Unstructured, 0, len(items))
	for _, obj := range items {
		u, err := toUnstructured(obj)
		if err != nil {
			return nil, err
		}
		rows = append(rows, u)
	}
	return newTable(gvk, rows, defaultNodeReadyTimeout)
}

// toUnstructured converts a typed API object to unstructured through a JSON round
// trip, so fields with custom JSON marshaling (resource.Quantity, metav1.Time)
// serialize to the strings the Table column extractors read.
func toUnstructured(obj types.Object) (unstructured.Unstructured, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return unstructured.Unstructured{}, err
	}
	var u unstructured.Unstructured
	if err := u.UnmarshalJSON(data); err != nil {
		return unstructured.Unstructured{}, err
	}
	return u, nil
}

// streamWatch writes each event as a newline-delimited JSON frame (the Kubernetes
// watch wire format), flushing after each, until the channel closes — which
// happens when the request context is cancelled on client disconnect.
func streamWatch(w http.ResponseWriter, ch <-chan metav1.WatchEvent) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush() // send headers now so the client knows the stream is open
	}
	enc := json.NewEncoder(w)
	for evt := range ch {
		if err := enc.Encode(evt); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(v)
}
