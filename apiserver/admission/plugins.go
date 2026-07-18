package admission

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/types"
)

// Lister reads objects the admission chain needs beyond the one under review. The
// storage/service List satisfies it directly, so nodeExists and capacityCheck see
// the live Applications and Nodes without depending on the whole storage surface.
type Lister interface {
	List(ctx context.Context, m types.ObjectMeta, opts metav1.ListOptions) ([]types.Object, error)
}

// resourceMeta addresses a core-group resource by kind, for a List.
func resourceMeta(kind string) types.ObjectMeta {
	return types.ObjectMeta{ApiVersion: corev1.GroupVersion.String(), Kind: kind}
}

// defaulting stamps the canonical apiVersion/kind onto the typed object so a
// stored object always carries them, even when the request body omitted them.
type defaulting struct{}

func (defaulting) Admit(_ context.Context, a *Attributes) error {
	a.Object.GetObjectKind().SetGroupVersionKind(a.GVK)
	return nil
}

func (defaulting) Validate(context.Context, *Attributes) error { return nil }

// DefaultChain is the admission chain the controller runs. Input shape and
// required fields are validated earlier, against the per-Kind JSON schema; the
// chain here defaults the typed object and enforces the cross-field and policy
// checks. lister lets nodeExists and the capacity check read the live Applications
// and Nodes (storage.Storage satisfies it); pass nil to disable those two checks
// (e.g. in unit tests that don't need them).
func DefaultChain(lister Lister) Chain {
	return Chain{
		defaulting{},
		appPolicy{},
		nodeRestriction{},
		nodeExists{lister: lister},
		capacityCheck{lister: lister},
	}
}
