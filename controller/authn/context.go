package authn

import "context"

type identityKey struct{}

// WithIdentity stores the authenticated identity in the context so downstream
// layers (authorization, admission) can read it back with FromContext.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// FromContext returns the identity stored by WithIdentity, or nil when the
// request is unauthenticated or predates the auth middleware.
func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey{}).(*Identity)
	return id
}
