package apiserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/authn"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// NamespaceFilter reports the namespaces a caller may see in the self-service Namespace
// listing: accessible is the set of namespace names (used when seesAll is false), and
// seesAll is true for an admin (every namespace). It must not require any cluster-wide
// list permission — that is the whole point of self-service listing.
type NamespaceFilter func(ctx context.Context, id *authn.Identity) (accessible map[string]bool, seesAll bool, err error)

// SetNamespaceFilter wires the per-caller filter for the Namespace collection endpoint,
// so a user lists the namespaces they can access without cluster-wide rights. Left
// unset (a build with auth compiled out), the endpoint returns every namespace.
func (s *APIServer) SetNamespaceFilter(f NamespaceFilter) { s.nsFilter = f }

// namespaceList serves the Namespace collection with self-service filtering: it lists
// every Namespace, then (when a filter is wired and the caller is not an admin) keeps
// only the ones the caller can access.
func (s *APIServer) namespaceList(w http.ResponseWriter, req bunrouter.Request) error {
	if req.URL.Query().Get("watch") == "true" {
		// A watch streams events unfiltered, which would let a non-admin enumerate every
		// namespace — the exact leak the filtered LIST prevents. Only an admin (seesAll) may
		// watch the full namespace set; a non-admin uses the self-service LIST instead.
		if s.nsFilter != nil {
			_, seesAll, err := s.nsFilter(req.Context(), authn.FromContext(req.Context()))
			if err != nil {
				return err
			}
			if !seesAll {
				return apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "",
					fmt.Errorf("watching all namespaces requires cluster-wide access; use a (filtered) list"))
			}
		}
		return s.watch(w, req)
	}
	items, err := s.svc.List(req.Context(), reqMeta(req), listOptions(req))
	if err != nil {
		return err
	}
	if s.nsFilter != nil {
		accessible, seesAll, err := s.nsFilter(req.Context(), authn.FromContext(req.Context()))
		if err != nil {
			return err
		}
		if !seesAll {
			items = keepNamespaces(items, accessible)
		}
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

// keepNamespaces filters a Namespace list to those whose name is in accessible.
func keepNamespaces(items []types.Object, accessible map[string]bool) []types.Object {
	out := make([]types.Object, 0, len(accessible))
	for _, o := range items {
		if acc, err := apimeta.Accessor(o); err == nil && accessible[acc.GetName()] {
			out = append(out, o)
		}
	}
	return out
}
