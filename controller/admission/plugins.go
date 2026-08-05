package admission

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/features"
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

// Option configures DefaultChain. It is for deployment settings a plugin needs and cannot derive —
// distinct from features.Gates, which is what a deployment turns ON, with no value to carry.
type Option func(*chainConfig)

type chainConfig struct {
	serviceCIDR   string
	routedNetwork bool
}

// WithServiceCIDR names the range a Service's address is allocated from when its author declares
// none. Unset means no allocation: a declared address is real because whoever wrote it knows what
// answers there, while an allocated one needs something that translates it — the eBPF datapath —
// and naming a range is how a deployment says it has that.
func WithServiceCIDR(cidr string) Option {
	return func(c *chainConfig) { c.serviceCIDR = cidr }
}

// WithRoutedNetwork tells the chain this cluster can give a workload a network of its own — the
// controller was started with a routed range, and the nodes have a helper that can wire one.
// Without it `spec.hostNetwork: false` is refused, because accepting it would promise an isolation
// nothing on any node provides.
func WithRoutedNetwork(on bool) Option {
	return func(c *chainConfig) { c.routedNetwork = on }
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
// checks. lister lets referenceCheck (namespace/node existence, PV protection) and
// the capacity check read the live Namespaces, Applications and Nodes
// (storage.Storage satisfies it); pass nil to disable those lister-backed checks
// (e.g. in unit tests that don't need them). gates is the feature set this deployment
// opted into — a nil map is every gate at its default, which is off.
//
// opts carry what a deployment configures rather than opts into; today that is the service range,
// and without one no cluster address is allocated.
func DefaultChain(lister Lister, gates features.Gates, opts ...Option) Chain {
	var cfg chainConfig
	for _, o := range opts {
		o(&cfg)
	}
	return Chain{
		defaulting{},
		secretPolicy{gates: gates},
		csrPolicy{},
		rbacRules{},
		applicationSet{lister: lister, routedNetwork: cfg.routedNetwork},
		childOwnership{},
		finalizerOwnership{},
		// Before the floor: the allocator assigns the workload's real id out of its namespace's
		// block, and the floor's sentinel only stands in where no block exists.
		uidAllocation{lister: lister},
		serviceVIP{lister: lister, cidr: cfg.serviceCIDR},
		policyEnforcement{},
		appPolicy{routedNetwork: cfg.routedNetwork},
		servicePolicy{lister: lister},
		serviceAddress{lister: lister},
		nodePolicy{},
		nodeRestriction{lister: lister},
		newReferenceCheck(lister),
		capacityCheck{lister: lister},
	}
}
