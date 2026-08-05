package apiserver

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/ks-tool/horchestra/api/types"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
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
	if err := rejectWatchList(req); err != nil {
		return err
	}
	ch, err := s.svc.Watch(req.Context(), reqMeta(req), listOptions(req))
	if err != nil {
		return err
	}
	// A watch has to answer in the same shape the list did. kubectl asks for a Table on both,
	// and when the stream comes back carrying plain API objects it does not error — it falls
	// back to the columns it hardcodes for an unknown kind, so `kubectl get app -w` printed the
	// real columns from the initial list and then a bare NAME/AGE table for every event after.
	var asTable schema.GroupVersionKind
	if tableRequested(req) {
		asTable = gvkFromContext(req.Context())
	}
	streamWatch(w, ch, asTable)
	return nil
}

func (s *APIServer) create(w http.ResponseWriter, req bunrouter.Request) error {
	data, err := readBody(w, req)
	if err != nil {
		return apierrors.NewBadRequest(err.Error())
	}
	obj, err := s.svc.Create(req.Context(), gvkFromContext(req.Context()), data, req.Param("namespace"))
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
	obj, err := s.svc.Update(req.Context(), gvkFromContext(req.Context()), data, req.Param("namespace"), req.Param("name"))
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
	opts, err := deleteOptions(w, req)
	if err != nil {
		return err
	}
	if err := s.svc.Delete(req.Context(), reqMeta(req), opts); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, successStatus())
}

// deleteOptions reads the DeleteOptions kubectl sends in the body of a DELETE — `--cascade=orphan`
// travels there and nowhere else. An empty body is the ordinary delete and not an error, which is
// what every client that has no options to state sends.
func deleteOptions(w http.ResponseWriter, req bunrouter.Request) (metav1.DeleteOptions, error) {
	var opts metav1.DeleteOptions
	body, err := readBody(w, req)
	if err != nil {
		return opts, err
	}
	if len(body) == 0 {
		return opts, nil
	}
	if err := json.Unmarshal(body, &opts); err != nil {
		return opts, apierrors.NewBadRequest("delete options: " + err.Error())
	}
	return opts, nil
}

// reqMeta builds the storage address from the route-bound GVK (see bind) and the
// :namespace/:name path parameters. A cluster-scoped resource's route has no
// :namespace, so its namespace stays empty.
func reqMeta(req bunrouter.Request) types.ObjectMeta {
	gvk := gvkFromContext(req.Context())
	return types.ObjectMeta{
		ApiVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Namespace:  req.Param("namespace"),
		Name:       req.Param("name"),
	}
}

// rejectWatchList refuses the watch-list protocol — `sendInitialEvents=true`, the streaming
// replacement for LIST that a modern client-go tries FIRST — instead of serving it an ordinary
// watch.
//
// Ignoring an unknown query parameter is usually harmless and here it hung the client. The
// protocol ends its initial batch with a BOOKMARK carrying `k8s.io/initial-events-end`, and the
// client waits for exactly that before it considers itself synced; an ordinary event stream never
// sends one, so the wait never ends. `kubectl delete` (which waits by default) sat there for
// minutes reporting "hasn't received required bookmark event marking the end of initial events
// stream" — on a delete that had already completed.
//
// Refusing is what makes the client whole: client-go treats a failed watch-list as "the server
// does not have it" and falls back to the ordinary LIST + WATCH, which this server serves
// correctly. It is the honest answer either way — the parameter asks for a guarantee about the
// stream's beginning that nothing here makes.
func rejectWatchList(req bunrouter.Request) error {
	if req.URL.Query().Get("sendInitialEvents") != "true" {
		return nil
	}
	return apierrors.NewBadRequest("sendInitialEvents is not supported: this server does not send " +
		"the initial-events-end bookmark the watch-list protocol requires — use a LIST followed by a WATCH")
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
func streamWatch(w http.ResponseWriter, ch <-chan metav1.WatchEvent, asTable schema.GroupVersionKind) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush() // send headers now so the client knows the stream is open
	}
	enc := json.NewEncoder(w)
	for evt := range ch {
		if !asTable.Empty() {
			evt = tableEvent(asTable, evt)
		}
		if err := enc.Encode(evt); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// tableEvent re-renders one watch event's object as a single-row metav1.Table, the form a
// Table-requesting client expects every frame of the stream to carry.
//
// The event arrives already serialized (the storage layer marshals it once and fans it out), so
// the row is built straight from that JSON rather than decoded back through the scheme. The
// column definitions ride on every frame: sending them once and omitting them afterwards is what
// the upstream apiserver does to save bytes, but it makes each frame depend on the client having
// kept the first one, which is not worth the handful of bytes here.
//
// An event that cannot be rendered is passed through untouched rather than dropped — a client
// seeing an object where it expected a Table degrades to the wrong columns, which is what it did
// before this existed; a swallowed event would instead leave it believing nothing changed.
func tableEvent(gvk schema.GroupVersionKind, evt metav1.WatchEvent) metav1.WatchEvent {
	var u unstructured.Unstructured
	if err := u.UnmarshalJSON(evt.Object.Raw); err != nil {
		return evt
	}
	tbl, err := newTable(gvk, []unstructured.Unstructured{u}, defaultNodeReadyTimeout)
	if err != nil {
		return evt
	}
	raw, err := json.Marshal(tbl)
	if err != nil {
		return evt
	}
	evt.Object = runtime.RawExtension{Raw: raw}
	return evt
}

func writeJSON(w http.ResponseWriter, code int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(v)
}
