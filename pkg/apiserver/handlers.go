package apiserver

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func (s *Server) get(w http.ResponseWriter, req bunrouter.Request) error {
	gvk := gvkFromContext(req.Context())
	obj, err := s.svc.Get(req.Context(), gvk, req.Param("name"))
	if err != nil {
		return err
	}
	if tableRequested(req) {
		tbl, err := newTable(gvk, []unstructured.Unstructured{*obj}, s.nodeReadyTimeout)
		if err != nil {
			return apierrors.NewInternalError(err)
		}
		return bunrouter.JSON(w, tbl)
	}
	return bunrouter.JSON(w, obj)
}

func (s *Server) listOrWatch(w http.ResponseWriter, req bunrouter.Request) error {
	gvk := gvkFromContext(req.Context())
	if req.URL.Query().Get("watch") == "true" {
		return s.watch(w, req, gvk)
	}
	list, err := s.svc.List(req.Context(), gvk)
	if err != nil {
		return err
	}
	if tableRequested(req) {
		tbl, err := newTable(gvk, list.Items, s.nodeReadyTimeout)
		if err != nil {
			return apierrors.NewInternalError(err)
		}
		return bunrouter.JSON(w, tbl)
	}
	return bunrouter.JSON(w, list)
}

func (s *Server) create(w http.ResponseWriter, req bunrouter.Request) error {
	gvk := gvkFromContext(req.Context())
	obj, err := decodeObject(req)
	if err != nil {
		return apierrors.NewBadRequest(err.Error())
	}
	out, err := s.svc.Create(req.Context(), gvk, obj)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(out)
}

func (s *Server) update(w http.ResponseWriter, req bunrouter.Request) error {
	gvk := gvkFromContext(req.Context())
	obj, err := decodeObject(req)
	if err != nil {
		return apierrors.NewBadRequest(err.Error())
	}
	obj.SetName(req.Param("name"))
	out, err := s.svc.Update(req.Context(), gvk, obj)
	if err != nil {
		return err
	}
	return bunrouter.JSON(w, out)
}

func (s *Server) patch(w http.ResponseWriter, req bunrouter.Request) error {
	gvk := gvkFromContext(req.Context())
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		return apierrors.NewBadRequest(err.Error())
	}
	// Compare only the media type; some clients append parameters (e.g.
	// "application/merge-patch+json; charset=utf-8").
	ct := req.Header.Get("Content-Type")
	if mt, _, e := mime.ParseMediaType(ct); e == nil {
		ct = mt
	}
	out, err := s.svc.Patch(req.Context(), gvk, req.Param("name"), types.PatchType(ct), body)
	if err != nil {
		return err
	}
	return bunrouter.JSON(w, out)
}

func (s *Server) delete(w http.ResponseWriter, req bunrouter.Request) error {
	gvk := gvkFromContext(req.Context())
	if err := s.svc.Delete(req.Context(), gvk, req.Param("name")); err != nil {
		return err
	}
	return bunrouter.JSON(w, successStatus())
}

func (s *Server) watch(w http.ResponseWriter, req bunrouter.Request, gvk schema.GroupVersionKind) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return apierrors.NewInternalError(fmt.Errorf("streaming unsupported"))
	}
	ch, err := s.svc.Watch(req.Context(), gvk)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	enc := json.NewEncoder(w)
	for evt := range ch {
		_ = enc.Encode(evt)
		flusher.Flush()
	}
	return nil
}

func decodeObject(req bunrouter.Request) (*unstructured.Unstructured, error) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(body); err != nil {
		return nil, err
	}
	return u, nil
}

func successStatus() *metav1.Status {
	return &metav1.Status{
		TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
		Status:   metav1.StatusSuccess,
	}
}
