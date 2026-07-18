package apiserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/apiserver/admission"
	"github.com/ks-tool/horchestra/apiserver/internal/memory"
	"github.com/ks-tool/horchestra/apiserver/service"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const widgetAPIVersion = "test.horchestra.io/v1"

var apiWidgetGVK = schema.GroupVersionKind{Group: "test.horchestra.io", Version: "v1", Kind: "Widget"}

type widget struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              widgetSpec `json:"spec"`
}

type widgetSpec struct {
	Image string `json:"image,omitempty"`
}

func newHandlerServer(t *testing.T) *APIServer {
	t.Helper()
	sch := scheme.New()
	sch.AddResource(apiWidgetGVK, func() types.Object { return new(widget) }, scheme.Resource{Plural: "widgets"})
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	srv := New(sch, service.New(store, sch, admission.DefaultChain(nil)))
	srv.EmulatePodsAPI()
	return srv
}

func doReq(t *testing.T, s *APIServer, method, path, ctype, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func mustDecodeWidget(t *testing.T, b []byte) *widget {
	t.Helper()
	var wd widget
	if err := json.Unmarshal(b, &wd); err != nil {
		t.Fatalf("decode widget: %v (body=%s)", err, b)
	}
	return &wd
}

func TestHandlers_CRUD(t *testing.T) {
	s := newHandlerServer(t)
	const base = "/apis/test.horchestra.io/v1/widgets"

	// Create -> 201 with defaulted apiVersion/kind and a resourceVersion.
	w := doReq(t, s, http.MethodPost, base, "application/json", `{"metadata":{"name":"db"},"spec":{"image":"postgres:16"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%s", w.Code, w.Body)
	}
	created := mustDecodeWidget(t, w.Body.Bytes())
	if created.Name != "db" || created.APIVersion != widgetAPIVersion || created.Kind != "Widget" {
		t.Errorf("created identity = %s %s/%s", created.Name, created.APIVersion, created.Kind)
	}
	if created.ResourceVersion == "" {
		t.Error("created has no resourceVersion")
	}

	// Get -> 200.
	if w = doReq(t, s, http.MethodGet, base+"/db", "", ""); w.Code != http.StatusOK {
		t.Fatalf("get status = %d, body=%s", w.Code, w.Body)
	} else if got := mustDecodeWidget(t, w.Body.Bytes()); got.Spec.Image != "postgres:16" {
		t.Errorf("get image = %q, want postgres:16", got.Spec.Image)
	}
	// Get missing -> 404.
	if w = doReq(t, s, http.MethodGet, base+"/missing", "", ""); w.Code != http.StatusNotFound {
		t.Errorf("get(missing) status = %d, want 404", w.Code)
	}

	// List -> 200 with a WidgetList envelope.
	w = doReq(t, s, http.MethodGet, base, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", w.Code, w.Body)
	}
	var list struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		Items      []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Kind != "WidgetList" || list.APIVersion != widgetAPIVersion {
		t.Errorf("list envelope = %s/%s, want %s/WidgetList", list.APIVersion, list.Kind, widgetAPIVersion)
	}
	if len(list.Items) != 1 {
		t.Errorf("list items = %d, want 1", len(list.Items))
	}

	// Update at the current resourceVersion -> 200.
	upd := fmt.Sprintf(`{"metadata":{"name":"db","resourceVersion":%q},"spec":{"image":"postgres:17"}}`, created.ResourceVersion)
	if w = doReq(t, s, http.MethodPut, base+"/db", "application/json", upd); w.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", w.Code, w.Body)
	} else if got := mustDecodeWidget(t, w.Body.Bytes()); got.Spec.Image != "postgres:17" {
		t.Errorf("update image = %q, want postgres:17", got.Spec.Image)
	}

	// Merge patch -> 200.
	if w = doReq(t, s, http.MethodPatch, base+"/db", "application/merge-patch+json", `{"spec":{"image":"postgres:18"}}`); w.Code != http.StatusOK {
		t.Fatalf("patch status = %d, body=%s", w.Code, w.Body)
	} else if got := mustDecodeWidget(t, w.Body.Bytes()); got.Spec.Image != "postgres:18" {
		t.Errorf("patch image = %q, want postgres:18", got.Spec.Image)
	}

	// Delete -> 200 Status, then it's gone.
	if w = doReq(t, s, http.MethodDelete, base+"/db", "", ""); w.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body=%s", w.Code, w.Body)
	}
	if w = doReq(t, s, http.MethodGet, base+"/db", "", ""); w.Code != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", w.Code)
	}
}

func TestHandlers_CreateConflictAndInvalid(t *testing.T) {
	s := newHandlerServer(t)
	const base = "/apis/test.horchestra.io/v1/widgets"

	if w := doReq(t, s, http.MethodPost, base, "application/json", `{"metadata":{"name":"db"},"spec":{}}`); w.Code != http.StatusCreated {
		t.Fatalf("first create = %d", w.Code)
	}
	// Duplicate -> 409.
	if w := doReq(t, s, http.MethodPost, base, "application/json", `{"metadata":{"name":"db"},"spec":{}}`); w.Code != http.StatusConflict {
		t.Errorf("duplicate create = %d, want 409", w.Code)
	}
	// Missing name -> 422.
	if w := doReq(t, s, http.MethodPost, base, "application/json", `{"spec":{}}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("nameless create = %d, want 422", w.Code)
	}
}
