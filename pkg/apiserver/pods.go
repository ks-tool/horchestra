package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "ks-tool.dev/horchestra/api/v1"
)

// Pod is the read-only projection of an Application into the legacy core group, so
// `kubectl logs <app>` (which is pod-centric) resolves it and streams its unit
// logs. One application is one process is one container, so the pod has exactly
// one container named after the app.
type Pod struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PodSpec   `json:"spec,omitempty"`
	Status            PodStatus `json:"status,omitempty"`
}

type PodSpec struct {
	NodeName   string      `json:"nodeName,omitempty"`
	Containers []Container `json:"containers,omitempty"`
}

type Container struct {
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
}

type PodStatus struct {
	Phase string `json:"phase,omitempty"`
}

type PodList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Pod `json:"items"`
}

// podsGR shapes not-found errors as pod errors (what kubectl expects).
var podsGR = schema.GroupResource{Resource: "pods"}

// coreResourceList advertises the legacy core group's only resource: the
// read-only `pods` alias (with its `log` subresource), so kubectl can discover it
// and drive `kubectl logs`.
func (s *Server) coreResourceList(w http.ResponseWriter, _ bunrouter.Request) error {
	return bunrouter.JSON(w, &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{Name: "pods", SingularName: "pod", Namespaced: false, Kind: "Pod", Verbs: metav1.Verbs{"get", "list"}},
			{Name: "pods/log", Namespaced: false, Kind: "Pod", Verbs: metav1.Verbs{"get"}},
		},
	})
}

// podGet returns the Pod projection of the Application of the same name, so
// `kubectl logs <app>` resolves it and then requests pods/<app>/log.
func (s *Server) podGet(w http.ResponseWriter, req bunrouter.Request) error {
	app, err := s.application(req.Context(), req.Param("name"))
	if err != nil {
		return asPodError(err, req.Param("name"))
	}
	return bunrouter.JSON(w, syntheticPod(app))
}

// podList projects every Application into a Pod (for `kubectl get pods`).
func (s *Server) podList(w http.ResponseWriter, req bunrouter.Request) error {
	list, err := s.svc.List(req.Context(), v1.ApplicationResource.GVK)
	if err != nil {
		return err
	}
	pods := PodList{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"},
		Items:    make([]Pod, 0, len(list.Items)),
	}
	for i := range list.Items {
		obj, err := v1.Decode(v1.ApplicationResource.GVK, &list.Items[i])
		if err != nil {
			continue
		}
		if app, ok := obj.(*v1.Application); ok {
			pods.Items = append(pods.Items, *syntheticPod(app))
		}
	}
	return bunrouter.JSON(w, &pods)
}

// podLog streams the application's logs from the node it runs on. It resolves the
// Application to its spec.node, opens a stream over the agent transport, and
// forwards the bytes to the response (flushing, so `--follow` is live).
func (s *Server) podLog(w http.ResponseWriter, req bunrouter.Request) error {
	if s.logs == nil {
		return apierrors.NewServiceUnavailable("log streaming is not available")
	}
	name := req.Param("name")
	app, err := s.application(req.Context(), name)
	if err != nil {
		return asPodError(err, name)
	}
	if len(app.Spec.NodeName) == 0 {
		return apierrors.NewBadRequest("application " + name + " has no spec.nodeName")
	}
	q := req.URL.Query()
	follow := q.Get("follow") == "true"
	var tail int64
	if t := q.Get("tailLines"); len(t) > 0 {
		tail, _ = strconv.ParseInt(t, 10, 64)
	}

	ch, cancel, err := s.logs.StreamLogs(req.Context(), app.Spec.NodeName, name, follow, tail)
	if err != nil {
		return apierrors.NewServiceUnavailable(err.Error())
	}
	defer func() { _ = cancel() }()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	for {
		select {
		case <-req.Context().Done():
			return nil
		case b, ok := <-ch:
			if !ok {
				return nil // end of logs
			}
			if _, err := w.Write(b); err != nil {
				return nil // client gone
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

// application fetches an Application by name and decodes it to its typed form
// through the scheme.
func (s *Server) application(ctx context.Context, name string) (*v1.Application, error) {
	obj, err := s.svc.Get(ctx, v1.ApplicationResource.GVK, name)
	if err != nil {
		return nil, err
	}
	decoded, err := v1.Decode(v1.ApplicationResource.GVK, obj)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	app, ok := decoded.(*v1.Application)
	if !ok {
		return nil, apierrors.NewInternalError(fmt.Errorf("object %q is not an Application", name))
	}
	return app, nil
}

// syntheticPod projects an Application into a Pod: a name, one container named
// after the app (its image the app's source), the node it is pinned to, and a
// Running phase.
func syntheticPod(app *v1.Application) *Pod {
	return &Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: app.Name},
		Spec: PodSpec{
			NodeName:   app.Spec.NodeName,
			Containers: []Container{{Name: app.Name, Image: app.Spec.Image}},
		},
		Status: PodStatus{Phase: "Running"},
	}
}

// asPodError re-shapes an application not-found as a pod not-found (what kubectl
// expects on the pods alias), passing other errors through.
func asPodError(err error, name string) error {
	if apierrors.IsNotFound(err) {
		return apierrors.NewNotFound(podsGR, name)
	}
	return err
}
