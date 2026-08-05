package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// ruleCheck builds a referenceCheck exercising one rule in isolation, so each rule's test
// drives the real skeleton (nil-lister guard + operation filter) with only its own rule.
func ruleCheck(l Lister, r referenceRule) referenceCheck {
	return referenceCheck{lister: l, rules: []referenceRule{r}}
}

// TestReferenceCheckInDefaultChain proves the consolidated referenceCheck is wired into the
// chain the controller runs (not merely present in the package), enforcing both a
// create-time reference (nodeExists) and a deletion guard (pvProtection).
func TestReferenceCheckInDefaultChain(t *testing.T) {
	ctx := context.Background()
	lister := fakeLister{
		namespaces: []corev1.Namespace{mkNamespace("team-a")},
		nodes:      []corev1.Node{mkNode("n1", cpu("4"))},
		apps:       []corev1.Application{appMounting("web", "pg-data")},
	}
	chain := DefaultChain(lister, nil)

	if err := chain.Run(ctx, appAttrs(Create, mkApp("a", "ghost", cpu("1")))); err == nil ||
		!strings.Contains(err.Error(), `node "ghost" does not exist`) {
		t.Fatalf("chain must enforce nodeExists, got %v", err)
	}
	if err := chain.Validate(ctx, pvAttrs(Delete, mkPV("pg-data"))); err == nil {
		t.Fatal("chain must enforce pvProtection on an in-use PV delete")
	} else if _, ok := err.(*ForbiddenError); !ok {
		t.Fatalf("pvProtection must deny with a ForbiddenError (403), got %T %v", err, err)
	}
}
