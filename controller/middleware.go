package apiserver

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
)

// Recover turns a panic in any handler or middleware below it into a 500 for that one request,
// logged with its stack. Without it net/http's per-connection recovery aborts the connection
// with no audit line and no stack, so a reachable panic degrades into an unattributable stream
// of dropped requests. Place it outermost, before AuditID, so a panic in the middleware chain
// itself is caught too.
func Recover(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
	return func(w http.ResponseWriter, req bunrouter.Request) (err error) {
		defer func() {
			if v := recover(); v != nil {
				log.Error().Interface("panic", v).Str("verb", req.Method).Str("path", req.URL.Path).
					Bytes("stack", debug.Stack()).Msg("recovered from a panic serving a request")
				err = apierrors.NewInternalError(fmt.Errorf("internal server error"))
			}
		}()
		return next(w, req)
	}
}

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

// RequestLog records every mutating request (create/update/patch/delete) with its
// verb, path, caller identity and audit id — so a write, and especially a DELETE,
// is always attributable — plus the sensitive `pods/<app>/log` read, so streaming
// another workload's logs leaves a trail. Other reads (plain GET/watch) are not
// logged, to keep the audit trail focused and low-noise. Place it after Auth (so
// the identity is set) and before Authz (so a denied request is logged too).
func RequestLog(next bunrouter.HandlerFunc) bunrouter.HandlerFunc {
	return func(w http.ResponseWriter, req bunrouter.Request) error {
		err := next(w, req)
		mutating := req.Method == http.MethodPost || req.Method == http.MethodPut ||
			req.Method == http.MethodPatch || req.Method == http.MethodDelete
		// A log stream is a sensitive read (it can carry another tenant's secrets), so audit it
		// like a mutation even though it is a GET.
		logRead := req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/log")
		if mutating || logRead {
			user := "-"
			if id := authn.FromContext(req.Context()); id != nil {
				user = id.Name
			}
			ev := log.Info().
				Str("verb", req.Method).
				Str("path", req.URL.Path).
				Str("user", user).
				Str("auditID", w.Header().Get("Audit-Id")).
				Str("remote", req.RemoteAddr)
			if err != nil {
				ev = ev.Err(err)
			}
			ev.Msg("api request")
		}
		return err
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
