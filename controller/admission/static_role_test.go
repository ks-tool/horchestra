package admission

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/features"
)

func vaultSecretAttrs(ann map[string]string) *Attributes {
	sec := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "db", Annotations: ann},
		Type:       corev1.SecretTypeVault,
	}
	return &Attributes{GVK: corev1.GroupVersion.WithKind("Secret"), Operation: Create, Object: sec}
}

func staticRoleAnn(role string) map[string]string {
	return map[string]string{
		corev1.AnnExternalSecretStore:      "corp",
		corev1.AnnExternalSecretStaticRole: role,
	}
}

var gateOn = features.Gates{features.VaultStaticRoles: true}

// TestStaticRoleNeedsItsGate: the capability is opt-in, so without the gate the annotation
// is refused at the write — naming the gate, because "unknown annotation, silently ignored"
// is how an operator ends up believing a credential rotates when nothing reads it.
func TestStaticRoleNeedsItsGate(t *testing.T) {
	ctx := context.Background()

	err := secretPolicy{}.Validate(ctx, vaultSecretAttrs(staticRoleAnn("database/app-rw")))
	if err == nil || !strings.Contains(err.Error(), string(features.VaultStaticRoles)) {
		t.Fatalf("want the gate named in the refusal, got %v", err)
	}
	if _, ok := err.(*ForbiddenError); !ok {
		t.Fatalf("want a ForbiddenError (403) — it is an authority decision, not a bad request; got %T", err)
	}

	if err := (secretPolicy{gates: gateOn}).Validate(ctx, vaultSecretAttrs(staticRoleAnn("database/app-rw"))); err != nil {
		t.Fatalf("with the gate on the secret must be admitted, got %v", err)
	}
	// An explicit false is the same as absent.
	off := secretPolicy{gates: features.Gates{features.VaultStaticRoles: false}}
	if err := off.Validate(ctx, vaultSecretAttrs(staticRoleAnn("database/app-rw"))); err == nil {
		t.Fatal("an explicitly disabled gate must still refuse")
	}
}

// TestVaultSecretNamesExactlyOneSource: a KV path is a value someone wrote, a static role is
// a credential Vault owns and rotates. A Secret carrying both would leave which one a
// workload gets to whichever branch the node's fetch tests first; carrying neither is a
// Secret that can never materialize.
func TestVaultSecretNamesExactlyOneSource(t *testing.T) {
	ctx := context.Background()
	p := secretPolicy{gates: gateOn}

	both := staticRoleAnn("database/app-rw")
	both[corev1.AnnExternalSecretPath] = "prod/db"
	if err := p.Validate(ctx, vaultSecretAttrs(both)); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want a mutual-exclusion refusal, got %v", err)
	}

	if err := p.Validate(ctx, vaultSecretAttrs(map[string]string{corev1.AnnExternalSecretStore: "corp"})); err == nil {
		t.Fatal("a vault secret naming no source must be refused")
	}

	// The KV path stays exactly as it was — the gate governs the new source, not the old one.
	kv := map[string]string{corev1.AnnExternalSecretStore: "corp", corev1.AnnExternalSecretPath: "prod/db"}
	if err := (secretPolicy{}).Validate(ctx, vaultSecretAttrs(kv)); err != nil {
		t.Fatalf("a KV-path secret must be admitted with no gate at all, got %v", err)
	}
}

// TestStaticRoleShapeIsCheckedWithTheNodesOwnParser: a shape this edge accepted but the node
// refused would hold every application mounting the secret — reachable by a principal with
// no rights over Applications at all. Both sides call corev1.ParseEngineRole.
func TestStaticRoleShapeIsCheckedWithTheNodesOwnParser(t *testing.T) {
	ctx := context.Background()
	p := secretPolicy{gates: gateOn}
	for _, bad := range []string{"app-rw", "database/", "database/../secret/x", "database/app rw"} {
		if err := p.Validate(ctx, vaultSecretAttrs(staticRoleAnn(bad))); err == nil {
			t.Errorf("static role %q was admitted", bad)
		}
	}
}

// TestStaticRoleGateReachesTheDefaultChain proves the gate is threaded from the chain the
// controller builds, not merely honoured by the plugin in isolation.
func TestStaticRoleGateReachesTheDefaultChain(t *testing.T) {
	ctx := context.Background()
	if err := DefaultChain(nil, nil).Validate(ctx, vaultSecretAttrs(staticRoleAnn("database/app-rw"))); err == nil {
		t.Fatal("the default chain with no gates must refuse a static-role secret")
	}
	if err := DefaultChain(nil, gateOn).Validate(ctx, vaultSecretAttrs(staticRoleAnn("database/app-rw"))); err != nil {
		t.Fatalf("the default chain with the gate on must admit it, got %v", err)
	}
}
