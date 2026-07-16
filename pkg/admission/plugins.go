package admission

import (
	"context"
)

// defaulting stamps the canonical apiVersion/kind onto the typed object so a
// stored object always carries them, even when the request body omitted them.
type defaulting struct{}

func (defaulting) Admit(_ context.Context, a *Attributes) error {
	a.Object.GetObjectKind().SetGroupVersionKind(a.GVK)
	return nil
}

func (defaulting) Validate(context.Context, *Attributes) error { return nil }

// DefaultChain is the admission chain the controller runs. Input shape and
// required fields are validated earlier, against the per-Kind JSON schema (see
// api/v1.Validate); the chain here defaults and enforces the policy checks.
// lister lets the capacity check read the live Applications and Nodes
// (storage.Storage satisfies it); pass nil to disable that check (e.g. in unit
// tests that don't need it).
func DefaultChain(lister Lister) Chain {
	return Chain{defaulting{}, nodeRestriction{}, nodeExists{lister: lister}, capacityCheck{lister: lister}, appPolicy{}}
}
