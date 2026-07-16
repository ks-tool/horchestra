package apiserver

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"ks-tool.dev/horchestra/pkg/authn"
	"ks-tool.dev/horchestra/pkg/authz"
)

func AuditID(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
	return func(w http.ResponseWriter, req bunrouter.Request) error {
		id := req.Header.Get("Audit-Id")
		if len(id) == 0 {
			id = uuid.New().String()
		}
		w.Header().Set("Audit-Id", id)
		return next(w, req)
	}
}

func Auth(a authn.Authenticator) bunrouter.MiddlewareFunc {
	return func(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
		return func(w http.ResponseWriter, req bunrouter.Request) error {
			id, err := a.Authenticate(req.Request)
			if err != nil {
				return apierrors.NewUnauthorized(err.Error())
			}
			return next(w, req.WithContext(authn.WithIdentity(req.Context(), id)))
		}
	}
}

func Authz(az authz.Authorizer) bunrouter.MiddlewareFunc {
	return func(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
		return func(w http.ResponseWriter, req bunrouter.Request) error {
			at := authz.AttributesFromRequest(req.Request, authn.FromContext(req.Context()))
			ok, err := az.Authorize(req.Context(), at)
			if err != nil {
				return apierrors.NewInternalError(err)
			}
			if !ok {
				return apierrors.NewForbidden(schema.GroupResource{Group: at.Group, Resource: at.Resource}, at.Name, fmt.Errorf("access denied"))
			}
			return next(w, req)
		}
	}
}
