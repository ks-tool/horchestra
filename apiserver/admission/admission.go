package admission

import (
	"context"
	"fmt"

	"github.com/ks-tool/horchestra/api/types"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ForbiddenError is returned by a plugin that denies an operation on authorization
// grounds (as opposed to a schema/validation failure). The service layer maps it
// to HTTP 403, matching how an authorizer denial is reported, rather than 422.
type ForbiddenError struct{ Reason string }

func (e *ForbiddenError) Error() string { return e.Reason }

// Forbidden builds a ForbiddenError with a formatted reason.
func Forbidden(format string, args ...any) error {
	return &ForbiddenError{Reason: fmt.Sprintf(format, args...)}
}

type Operation string

const (
	Create Operation = "CREATE"
	Update Operation = "UPDATE"
	Delete Operation = "DELETE"
)

// Attributes carries the request an admission plugin inspects. Object is the
// typed api/v1 value under review (the controller decodes it through the scheme
// before admission), so plugins work with real Go types rather than unstructured
// maps.
type Attributes struct {
	GVK       schema.GroupVersionKind
	Operation Operation
	Object    types.Object
	OldObject types.Object
}

type Plugin interface {
	Admit(ctx context.Context, a *Attributes) error
	Validate(ctx context.Context, a *Attributes) error
}

type Chain []Plugin

// Run applies every plugin's mutation pass, then every plugin's validation pass.
func (c Chain) Run(ctx context.Context, a *Attributes) error {
	for _, p := range c {
		if err := p.Admit(ctx, a); err != nil {
			return err
		}
	}
	return c.Validate(ctx, a)
}

// Validate runs only the validation pass, for operations like Delete that have
// nothing to mutate.
func (c Chain) Validate(ctx context.Context, a *Attributes) error {
	for _, p := range c {
		if err := p.Validate(ctx, a); err != nil {
			return err
		}
	}
	return nil
}
