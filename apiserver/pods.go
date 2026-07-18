package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// pod is the read-only projection of an Application into the legacy core group, so
// `kubectl logs <app>` (which is pod-centric) resolves it and streams its unit
// logs. One application is one process is one container, so the pod has exactly
// one container named after the app.
type pod struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   podSpec   `json:"spec,omitempty"`
	Status podStatus `json:"status,omitempty"`
}

type podSpec struct {
	NodeName   string      `json:"nodeName,omitempty"`
	Containers []container `json:"containers,omitempty"`
}

type container struct {
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
}

type podStatus struct {
	Phase string `json:"phase,omitempty"`
}

type podList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []pod `json:"items"`
}

// podsGR shapes not-found errors as pod errors (what kubectl expects).
var podsGR = schema.GroupResource{Resource: "pods"}

// coreResourceList advertises the legacy core group's only resource: the
// read-only `pods` alias (with its `log` subresource), so kubectl can discover it
// and drive `kubectl logs`.
func (s *APIServer) coreResourceList(w http.ResponseWriter, _ bunrouter.Request) error {
	return bunrouter.JSON(w, &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{Name: "pods", SingularName: "pod", Namespaced: false, Kind: "Pod", Verbs: metav1.Verbs{"get", "list"}},
			{Name: "pods/log", Namespaced: false, Kind: "Pod", Verbs: metav1.Verbs{"get"}},
		},
	})
}

// podGet returns the pod projection of the Application of the same name, so
// `kubectl logs <app>` resolves it and then requests pods/<app>/log.
func (s *APIServer) podGet(w http.ResponseWriter, req bunrouter.Request) error {
	app, err := s.application(req.Context(), req.Param("name"))
	if err != nil {
		return asPodError(err, req.Param("name"))
	}
	return bunrouter.JSON(w, syntheticPod(app))
}

// podList projects every Application into a pod (for `kubectl get pods`).
func (s *APIServer) podList(w http.ResponseWriter, req bunrouter.Request) error {
	meta := types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Application"}
	list, err := s.svc.List(req.Context(), meta, metav1.ListOptions{})
	if err != nil {
		return err
	}

	pods := podList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}}
	for _, item := range list {
		if app, ok := item.(*corev1.Application); ok {
			pods.Items = append(pods.Items, *syntheticPod(app))
		}
	}
	return bunrouter.JSON(w, &pods)
}

// podLog streams the application's logs from the node it runs on. It resolves the
// Application to its spec.node, opens a stream over the agent transport, and
// forwards the bytes to the response (flushing, so `--follow` is live).
func (s *APIServer) podLog(w http.ResponseWriter, req bunrouter.Request) error {
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
func (s *APIServer) application(ctx context.Context, name string) (*corev1.Application, error) {
	meta := types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: "Application", Name: name}
	obj, err := s.svc.Get(ctx, meta)
	if err != nil {
		return nil, err
	}

	app, ok := obj.(*corev1.Application)
	if !ok {
		return nil, apierrors.NewInternalError(fmt.Errorf("object %q is not an Application", name))
	}
	return app, nil
}

// syntheticPod projects an Application into a pod: a name, one container named
// after the app (its image the app's source), the node it is pinned to, and a
// Running phase.
func syntheticPod(app *corev1.Application) *pod {
	return &pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: app.Name},
		Spec: podSpec{
			NodeName:   app.Spec.NodeName,
			Containers: []container{{Name: app.Name, Image: app.Spec.Image}},
		},
		Status: podStatus{Phase: "Running"},
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
