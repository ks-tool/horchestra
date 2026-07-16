package apiserver

import (
	"encoding/json"
	"net/http"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func writeError(w http.ResponseWriter, err error) {
	if status, ok := err.(apierrors.APIStatus); ok {
		s := status.Status()
		// Stamp the Status TypeMeta so clients can decode the body as a
		// meta.k8s.io/v1 Status; without it kubectl reports "Object 'Kind' is
		// missing" and renders a generic "unknown" error instead of the message.
		s.APIVersion, s.Kind = "v1", "Status"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(s.Code))
		_ = json.NewEncoder(w).Encode(s)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func notFound(_ http.ResponseWriter, req bunrouter.Request) error {
	return apierrors.NewNotFound(schema.GroupResource{}, req.URL.Path)
}
