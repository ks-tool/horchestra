package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// openAPICache holds the served OpenAPI v3 documents. The API surface is fixed once the scheme
// is populated at startup, so each document is rendered once and every later request is a map
// lookup — the same treatment discovery gets, and for the same reason: kubectl fetches these on
// every command that validates a manifest.
type openAPICache struct {
	once  sync.Once
	index []byte            // the /openapi/v3 discovery document
	docs  map[string][]byte // "<group>/<version>" -> rendered document
}

// openAPIRoot serves /openapi/v3 — the index naming one document per group-version. kubectl asks
// for this first and follows the serverRelativeURL it finds; the hash in that URL is what lets a
// client cache a document and skip re-downloading it.
func (s *APIServer) openAPIRoot(w http.ResponseWriter, _ bunrouter.Request) error {
	return writeOpenAPI(w, s.openAPI().index)
}

// openAPIGroupVersion serves /openapi/v3/apis/<group>/<version> — the schemas a client validates
// a manifest of that group-version against.
func (s *APIServer) openAPIGroupVersion(w http.ResponseWriter, req bunrouter.Request) error {
	key := req.Param("group") + "/" + req.Param("version")
	doc, ok := s.openAPI().docs[key]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "openapi"}, key)
	}
	return writeOpenAPI(w, doc)
}

func writeOpenAPI(w http.ResponseWriter, doc []byte) error {
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write(doc)
	return err
}

// openAPI renders the documents on first use and returns them.
func (s *APIServer) openAPI() *openAPICache {
	s.openapi.once.Do(func() {
		s.openapi.docs = map[string][]byte{}
		paths := map[string]any{}
		for _, gv := range s.scheme.OpenAPIGroupVersions() {
			doc, ok := s.scheme.OpenAPIV3(gv)
			if !ok {
				continue
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				continue // a Kind whose schema will not serialize is not worth failing every command over
			}
			key := gv.Group + "/" + gv.Version
			s.openapi.docs[key] = raw
			sum := sha256.Sum256(raw)
			paths["apis/"+key] = map[string]string{
				"serverRelativeURL": "/openapi/v3/apis/" + key + "?hash=" + hex.EncodeToString(sum[:]),
			}
		}
		s.openapi.index, _ = json.Marshal(map[string]any{"paths": paths})
	})
	return &s.openapi
}
