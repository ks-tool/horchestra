package admission

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/features"
)

// maxSecretBytes caps a Secret's total data size (Kubernetes' 1 MiB limit), so a secret
// cannot be used to push an unbounded blob through the control plane and down to a node's
// tmpfs.
const maxSecretBytes = 1 << 20

// secretPolicy is the Secret defaulting-and-validation plugin. Admit folds the write-only
// StringData into Data and clears it, and defaults an empty Type to Opaque, so a stored
// Secret only ever carries Data. Validate enforces the Secret invariants: a vault secret
// carries no inline data (its value lives in a SecretStore), an immutable Secret's data
// cannot change, the total stays under the size cap, and every key is a bare path basename
// (so it projects to a file without escaping the mount).
type secretPolicy struct{ gates features.Gates }

func (secretPolicy) Admit(_ context.Context, a *Attributes) error {
	sec, ok := a.Object.(*corev1.Secret)
	if !ok {
		return nil
	}
	if sec.Type == "" {
		sec.Type = corev1.SecretTypeOpaque
	}
	if len(sec.StringData) > 0 {
		if sec.Data == nil {
			sec.Data = make(map[string][]byte, len(sec.StringData))
		}
		for k, v := range sec.StringData {
			sec.Data[k] = []byte(v) // stringData wins over data on a key clash (k8s parity)
		}
		sec.StringData = nil
	}
	return nil
}

func (p secretPolicy) Validate(_ context.Context, a *Attributes) error {
	if a.Operation == Delete || a.IsSubresource() {
		return nil
	}
	sec, ok := a.Object.(*corev1.Secret)
	if !ok {
		return nil
	}
	if sec.Type == corev1.SecretTypeVault {
		if len(sec.Data) > 0 {
			// A vault secret's value lives in its SecretStore; inline data would be a second
			// copy the store never rotates. The store/path/keys travel as annotations.
			return fmt.Errorf("type %q carries no inline data: the value is fetched from the secret store", corev1.SecretTypeVault)
		}
		if err := p.validateVaultSource(sec); err != nil {
			return err
		}
	}
	total := 0
	for k, v := range sec.Data {
		// The SAME validator the node applies to the projected path. A key is turned into a
		// relative file path by every mount that declares no items remapping, so a key this
		// edge accepts but a node refuses stops the Apply of every application in the
		// namespace that mounts the secret — reachable by a principal holding no rights over
		// Applications at all.
		if err := corev1.ValidBaseName(k, "key"); err != nil {
			return fmt.Errorf("data: %w", err)
		}
		total += len(k) + len(v)
	}
	if total > maxSecretBytes {
		return fmt.Errorf("data: secret size %d exceeds the %d-byte limit", total, maxSecretBytes)
	}
	if a.Operation == Update {
		if old, ok := a.OldObject.(*corev1.Secret); ok && old.Immutable != nil && *old.Immutable {
			// The flag has to be immutable itself, or immutability is worth nothing: clearing it
			// in one write and changing the data in the next satisfied a data-only check while
			// defeating exactly the guarantee the flag exists to give. kube-apiserver refuses the
			// same way.
			if sec.Immutable == nil || !*sec.Immutable {
				return fmt.Errorf("immutable: the immutable flag may not be cleared")
			}
			if !secretDataEqual(old.Data, sec.Data) {
				return fmt.Errorf("data: secret is immutable and its data may not change")
			}
		}
	}
	return nil
}

// validateVaultSource settles which of the two sources a vault Secret names, and whether
// this deployment admits it at all.
//
// The two are mutually exclusive rather than one falling back to the other: a KV path is a
// value someone wrote and a static role is a credential Vault owns and rotates on its own
// schedule, so a Secret carrying both would leave which one a workload actually gets to
// whichever branch the node's fetch happens to test first.
//
// The gate is checked HERE, at the write, and not again on the node. That is deliberate and
// it is the Kubernetes semantic: turning a gate off stops new objects from naming the
// capability, it does not reach back and break the workloads already running on one. An
// operator who wants those gone deletes them, which the API can express; a control plane
// that silently stopped serving a stored Secret would hold every application mounting it
// with no write anywhere to explain why.
func (p secretPolicy) validateVaultSource(sec *corev1.Secret) error {
	sources := []struct {
		ann  string
		gate features.Feature
		val  string
	}{
		{corev1.AnnExternalSecretPath, "", strings.TrimSpace(sec.Annotations[corev1.AnnExternalSecretPath])},
		{corev1.AnnExternalSecretStaticRole, features.VaultStaticRoles, strings.TrimSpace(sec.Annotations[corev1.AnnExternalSecretStaticRole])},
		{corev1.AnnExternalSecretDynamicRole, features.VaultDynamicSecrets, strings.TrimSpace(sec.Annotations[corev1.AnnExternalSecretDynamicRole])},
	}
	var named []int
	for i, src := range sources {
		if src.val != "" {
			named = append(named, i)
		}
	}
	switch len(named) {
	case 0:
		return fmt.Errorf("annotations: a %s secret names its value with %s, %s or %s",
			corev1.SecretTypeVault, corev1.AnnExternalSecretPath,
			corev1.AnnExternalSecretStaticRole, corev1.AnnExternalSecretDynamicRole)
	case 1:
	default:
		return fmt.Errorf("annotations: %s and %s are mutually exclusive — a secret names ONE source",
			sources[named[0]].ann, sources[named[1]].ann)
	}
	src := sources[named[0]]
	if src.gate == "" {
		return nil // a KV path needs no gate: it is what a vault secret has always been
	}
	if !p.gates.Enabled(src.gate) {
		return Forbidden("annotation %s needs the %s feature gate, which this cluster does not have on (--feature-gates=%s=true)",
			src.ann, src.gate, src.gate)
	}
	// Parsed with the SAME function the node fetches through, so a shape this edge accepts
	// cannot be one the node then refuses — which would hold every application mounting the
	// secret, reachable by a principal holding no rights over Applications at all.
	if _, err := corev1.ParseEngineRole(src.val); err != nil {
		return fmt.Errorf("annotation %s: %w", src.ann, err)
	}
	return nil
}

// secretDataEqual reports whether two secret data maps hold the same keys and bytes.
func secretDataEqual(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		if bv, ok := b[k]; !ok || !bytes.Equal(av, bv) {
			return false
		}
	}
	return true
}
