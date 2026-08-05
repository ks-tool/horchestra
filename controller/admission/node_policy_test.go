package admission

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

func nodeAttrs(op Operation, labels map[string]string) *Attributes {
	n := &corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: labels},
	}
	return &Attributes{GVK: corev1.GroupVersion.WithKind("Node"), Operation: op, Object: n}
}

// TestNodePolicyReservesTheDerivedLabelDomain: spec.labels is the operator's intent and
// status.labels is what the control plane measured. A spec key under the reserved domain
// would put two values behind one lookup — a way to label an amd64 machine arm64, or to move
// it into a topology domain it is not in — so it is refused at the write, naming the key.
func TestNodePolicyReservesTheDerivedLabelDomain(t *testing.T) {
	ctx := context.Background()
	p := nodePolicy{}

	err := p.Validate(ctx, nodeAttrs(Create, map[string]string{corev1.LabelArch: "arm64"}))
	if err == nil || !strings.Contains(err.Error(), corev1.LabelArch) {
		t.Fatalf("want the reserved key refused and named, got %v", err)
	}
	if _, ok := err.(*ForbiddenError); !ok {
		t.Fatalf("want a ForbiddenError (403), got %T", err)
	}

	// Every derived key, not just the one that happens to be checked first.
	for _, k := range []string{corev1.LabelHostname, corev1.LabelOS, corev1.LabelArch} {
		if err := p.Validate(ctx, nodeAttrs(Update, map[string]string{k: "x"})); err == nil {
			t.Errorf("%q was accepted in spec.labels", k)
		}
	}

	// The operator's own labels are the normal case and must stay untouched.
	if err := p.Validate(ctx, nodeAttrs(Create, map[string]string{"tier": "secure", "zone": "dc3"})); err != nil {
		t.Fatalf("an operator's own labels must be accepted, got %v", err)
	}
	if err := p.Validate(ctx, nodeAttrs(Create, nil)); err != nil {
		t.Fatalf("a node with no labels must be accepted, got %v", err)
	}

	// A message naming several keys must not depend on map iteration order.
	both := map[string]string{corev1.LabelArch: "arm64", corev1.LabelOS: "plan9"}
	first := p.Validate(ctx, nodeAttrs(Create, both))
	for range 8 {
		if got := p.Validate(ctx, nodeAttrs(Create, both)); got.Error() != first.Error() {
			t.Fatalf("the refusal is not deterministic:\n%v\n%v", first, got)
		}
	}

	// It guards the spec, so a status write and a delete are none of its business.
	statusWrite := nodeAttrs(Update, map[string]string{corev1.LabelArch: "arm64"})
	statusWrite.Subresource = "status"
	if err := p.Validate(ctx, statusWrite); err != nil {
		t.Fatalf("a status write must not be judged on the stored spec, got %v", err)
	}
	if err := p.Validate(ctx, nodeAttrs(Delete, map[string]string{corev1.LabelArch: "arm64"})); err != nil {
		t.Fatalf("deleting such a Node must stay possible, got %v", err)
	}
}

// TestNodePolicyInDefaultChain proves the rule is wired into the chain the controller runs,
// not merely present in the package.
func TestNodePolicyInDefaultChain(t *testing.T) {
	err := DefaultChain(nil, nil).Validate(context.Background(), nodeAttrs(Create, map[string]string{corev1.LabelOS: "plan9"}))
	if err == nil || !strings.Contains(err.Error(), corev1.LabelOS) {
		t.Fatalf("the default chain must refuse a reserved spec label, got %v", err)
	}
}
