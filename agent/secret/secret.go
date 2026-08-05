// Package secret is the agent's Secrets mechanism: it materializes an Application's
// type:secret volume mounts into in-memory VolumeSecret handles the runtime renders as
// read-only credentials. The controllerStore materializes from the Secrets the
// controller pushes inline in desired state; a type horchestra.io/vault secret is
// resolved by a Vault/OpenBao client behind the same port, node-direct — its value
// never passes through the controller.
package secret

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"
)

// Secrets resolves an Application's references to Secrets: its volume mounts into materialized
// VolumeSecret handles, and its spec.env secretRefs into "KEY=VALUE" strings. Both are
// fail-closed: a missing non-optional secret is an error, so the caller leaves the app pending
// rather than starting it without its credentials.
type Secrets interface {
	Materialize(ctx context.Context, app workload.App, pushed []corev1.Secret, stores []secretsv1.SecretStore) ([]workload.Volume, error)
	// MaterializeEnv resolves app.EnvRefs in declared order. A wildcard reference expands in
	// place, one variable per key in sorted key order, so the projection is deterministic.
	MaterializeEnv(ctx context.Context, app workload.App, pushed []corev1.Secret, stores []secretsv1.SecretStore) ([]string, error)
}

// Stale is an optional Secrets capability: which of the applications resolved in the last
// pass are running on a value the mechanism could not refresh, and for how long.
//
// It exists so a credential quietly aging is visible on the object an operator looks at
// rather than only in a node's journal. Keeping the workload running on its last good value
// is the decided answer — the failure is in the control path, not in the workload — but a
// silent one would be indistinguishable from everything being fine.
type Stale interface {
	StaleApps() map[string]time.Duration
}

// NodeBound is an optional Secrets capability: the agent binds the mechanism to its own node
// identity — the CN of the client certificate it authenticates the control-plane session with —
// so the mechanism can refuse to unseal anything for an Application that names a different
// spec.nodeName. The application cannot supply it: the CN is read from the certificate inside
// NewAgent, and the -node flag is only its fallback, so binding here is what makes the check use
// the identity the controller actually authorized rather than a value the host chose for itself.
type NodeBound interface {
	BindNode(cn string)
}

// controllerStore is the Secrets mechanism: an Opaque Secret materializes from the Data
// pushed inline in desired state, a horchestra.io/vault one is fetched from its
// SecretStore by the vault client — either way the value is held only for the duration
// of the call (never persisted).
//
// It unseals a Secret only for an Application whose spec.nodeName equals this agent's certificate
// CN. The controller already scopes the push — a node receives only the Secrets its own workloads
// reference — but that filter runs on the other side of the wire, and a node must not depend on it
// for the confidentiality of another node's credentials. Unbound, it refuses everything: a
// mechanism that does not know which node it serves cannot decide that anything is its own.
type controllerStore struct {
	// stale is the last pass's staleness, keyed by workload id. Written by Materialize and
	// read by the status builder, both on the agent's single reconcile goroutine.
	stale map[string]time.Duration

	cn    string
	ca    []byte // the control plane's CA, projected beside a workload's token
	vault *Vault
}

// NewControllerStore builds the Secrets mechanism. vault resolves horchestra.io/vault
// secrets and may be nil — the store then fails closed on them. It materializes nothing
// until the agent binds it to the node identity from its client certificate (see NodeBound).
func NewControllerStore(vault *Vault) Secrets {
	return &controllerStore{vault: vault, stale: map[string]time.Duration{}}
}

// CABound is implemented by a mechanism that projects the control plane's CA beside a workload's
// token. The agent hands it the bundle it verifies its own connection with — the same trust, not a
// second copy someone has to keep in step.
type CABound interface {
	BindCA(ca []byte)
}

// BindNode ties the mechanism to the agent's certificate CN.
func (s *controllerStore) BindNode(cn string) { s.cn = cn }

// BindCA hands the mechanism the CA a workload needs to verify the control plane it was given a
// token for. It travels with the token because the two are useless apart: a credential for a
// server you cannot verify is a credential you can only present to an impostor.
func (s *controllerStore) BindCA(ca []byte) { s.ca = ca }

// ownWorkload refuses an Application this agent is not the one deploying. The comparison is
// spec.nodeName against the certificate CN — the same pair the controller scopes the push by and
// the reconciler selects on, so all three agree on what "mine" means, and none of them relies on
// a node-supplied name.
func (s *controllerStore) ownWorkload(app workload.App) error {
	switch {
	case s.cn == "":
		return fmt.Errorf("refusing secrets for %s: this mechanism was never bound to a node identity", app.ID())
	case app.Node == "":
		return fmt.Errorf("refusing secrets for %s: it names no node, so agent %q is not the one deploying it",
			app.ID(), s.cn)
	case app.Node != s.cn:
		return fmt.Errorf("refusing secrets for %s: its nodeName is %q, not this agent's identity %q",
			app.ID(), app.Node, s.cn)
	}
	return nil
}

func (s *controllerStore) Materialize(ctx context.Context, app workload.App, pushed []corev1.Secret, stores []secretsv1.SecretStore) ([]workload.Volume, error) {
	if err := s.ownWorkload(app); err != nil {
		return nil, err
	}
	byID := index(pushed)
	var out []workload.Volume
	for _, m := range app.Volumes {
		if !m.IsSecret() {
			continue
		}
		optional := m.Volume.Optional != nil && *m.Volume.Optional
		sec, ok := byID[corev1.WorkloadID(app.Namespace, m.SecretName())]
		if !ok {
			if optional {
				continue // an optional secret may be absent
			}
			return nil, fmt.Errorf("secret %q not available", m.SecretName())
		}
		s.noteStaleness(app, sec, stores)
		data, err := s.resolveData(ctx, sec, stores, app.VaultToken())
		if err != nil {
			// Fail-closed (the app stays pending) rather than mount the secret empty; an
			// optional mount tolerates an unfetchable value the way it tolerates a missing one.
			if optional {
				continue
			}
			return nil, fmt.Errorf("secret %q: %w", m.SecretName(), err)
		}
		content, err := project(data, m.Volume.Items, optional)
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", m.SecretName(), err)
		}
		if len(content) == 0 {
			continue // nothing to mount (all keys optional-and-absent)
		}
		out = append(out, workload.Volume{Kind: workload.VolumeSecret, MountPath: m.MountPath, ReadOnly: true, Content: content})
	}
	return append(out, s.tokenVolumes(app)...), nil
}

// The three files a token volume projects, named as Kubernetes names them in a projected service
// account volume — a workload configured for one is configured for the other, and nobody has to
// learn a second convention: `<mountPath>/token`, `/ca.crt`, `/namespace`.
const (
	TokenFile     = "token"
	CAFile        = "ca.crt"
	NamespaceFile = "namespace"
)

// tokenVolumes materializes the workload's own identity tokens — one per token volume it declares,
// carrying the JWT the controller minted for that volume's audience.
//
// It is a VolumeSecret and not a kind of its own on purpose: the delivery a token needs is the
// delivery a secret already has. RAM only, replaced in place when the value changes, and reclaimed
// with the workload. That last property is what makes it a PROJECTED token in the Kubernetes sense
// — the controller re-mints inside the refresh margin and pushes, the agent writes the new bytes
// over the old, and a workload that re-reads the file has a live credential without restarting.
//
// A volume whose token the push did not carry is left out rather than mounted empty: an empty file
// where a credential belongs reads as an authentication failure at the far end, which is a much
// worse thing to debug than a missing mount.
func (s *controllerStore) tokenVolumes(app workload.App) []workload.Volume {
	var out []workload.Volume
	for _, m := range app.Volumes {
		if !m.IsToken() {
			continue
		}
		token := app.Token(m.TokenAudience())
		if token == "" {
			continue
		}
		content := map[string][]byte{
			TokenFile:     []byte(token),
			NamespaceFile: []byte(app.Namespace),
		}
		if len(s.ca) > 0 {
			content[CAFile] = s.ca
		}
		out = append(out, workload.Volume{
			Kind: workload.VolumeSecret, MountPath: m.MountPath, ReadOnly: true, Content: content,
		})
	}
	return out
}

// resolveData is the value of one pushed Secret: the inline Data for an Opaque secret, a
// node-direct fetch from its SecretStore for a horchestra.io/vault one. token is the
// workload's identity JWT (used by a jwt-method store; empty for cert auth). Fail-closed:
// no vault client, no matching store or an unreachable server is an error, never empty
// content.
func (s *controllerStore) resolveData(ctx context.Context, sec corev1.Secret, stores []secretsv1.SecretStore, token string) (map[string][]byte, error) {
	if sec.Type != corev1.SecretTypeVault {
		return sec.Data, nil
	}
	if s.vault == nil {
		return nil, fmt.Errorf("type %s needs a vault client this node does not have", sec.Type)
	}
	return s.vault.Fetch(ctx, sec, stores, token)
}

// project builds the file set a secret mount exposes: every data key at its own basename,
// or the explicit Items remapping (destination path → source key). A missing item key is an
// error unless the mount is optional.
func project(data map[string][]byte, items []corev1.KeyToPath, optional bool) (map[string][]byte, error) {
	content := map[string][]byte{}
	if len(items) == 0 {
		maps.Copy(content, data)
		return content, nil
	}
	for _, it := range items {
		v, ok := data[it.Key]
		if !ok {
			if optional {
				continue
			}
			return nil, fmt.Errorf("key %q not found", it.Key)
		}
		content[it.Path] = v
	}
	return content, nil
}

// index keys the pushed Secrets by their namespace-qualified id.
// noteStaleness records that this application is running on a value the mechanism could not
// refresh, so the reconcile pass can put it on the object's status. A credential quietly
// aging is otherwise indistinguishable from everything being fine: keeping the workload
// running on its last good value is the decided answer, but a silent one is not.
func (s *controllerStore) noteStaleness(app workload.App, sec corev1.Secret, stores []secretsv1.SecretStore) {
	if s.vault == nil || sec.Type != corev1.SecretTypeVault {
		return
	}
	if d, ok := s.vault.StaleFor(sec, stores); ok {
		if cur, seen := s.stale[app.ID()]; !seen || d > cur {
			s.stale[app.ID()] = d // the worst of an application's secrets is what it reports
		}
	} else {
		delete(s.stale, app.ID())
	}
}

// StaleApps is the staleness seen in the last pass, per workload id.
func (s *controllerStore) StaleApps() map[string]time.Duration { return s.stale }

func index(pushed []corev1.Secret) map[string]corev1.Secret {
	byID := make(map[string]corev1.Secret, len(pushed))
	for _, s := range pushed {
		byID[corev1.WorkloadID(s.Namespace, s.Name)] = s
	}
	return byID
}

// MaterializeEnv resolves the app's spec.env secretRefs into "KEY=VALUE" strings, in declared
// order, expanding a wildcard reference in sorted key order.
//
// Every failure is loud. A missing Secret or key is an error unless the reference is optional,
// in which case the variable is simply absent — optional means the value may be MISSING, never
// that an unusable one is silently dropped: a key that is not a valid environment-variable name
// (a Secret key may be any file basename, so "ca.pem" is legal there and impossible here) and a
// value carrying a newline or NUL both fail with the offending key named. A name produced twice,
// or one that collides with a literal spec.env entry, is refused rather than resolved to
// whichever happens to win.
func (s *controllerStore) MaterializeEnv(ctx context.Context, app workload.App, pushed []corev1.Secret, stores []secretsv1.SecretStore) ([]string, error) {
	if len(app.EnvRefs) == 0 {
		return nil, nil
	}
	if err := s.ownWorkload(app); err != nil {
		return nil, err
	}
	byID := index(pushed)
	claimed := map[string]struct{}{}
	for _, e := range app.Env {
		if name, _, ok := strings.Cut(e, "="); ok {
			claimed[name] = struct{}{}
		}
	}
	var out []string
	add := func(name, value string) error {
		if err := corev1.ValidEnvName(name, "env name"); err != nil {
			return err
		}
		if err := corev1.ValidEnvValue(name, value); err != nil {
			return err
		}
		if _, dup := claimed[name]; dup {
			return fmt.Errorf("env name %q is already set by another entry", name)
		}
		claimed[name] = struct{}{}
		out = append(out, name+"="+value)
		return nil
	}
	for _, v := range app.EnvRefs {
		ref := v.SecretRef
		sec, ok := byID[corev1.WorkloadID(app.Namespace, ref.Name)]
		if !ok {
			if ref.IsOptional() {
				continue
			}
			return nil, fmt.Errorf("secret %q not available", ref.Name)
		}
		data, err := s.resolveData(ctx, sec, stores, app.VaultToken())
		if err != nil {
			if ref.IsOptional() {
				continue
			}
			return nil, fmt.Errorf("secret %q: %w", ref.Name, err)
		}
		if !ref.IsWildcard() {
			value, ok := data[ref.Key]
			if !ok {
				if ref.IsOptional() {
					continue
				}
				return nil, fmt.Errorf("secret %q: key %q not found", ref.Name, ref.Key)
			}
			if err := add(v.Name, string(value)); err != nil {
				return nil, fmt.Errorf("secret %q key %q: %w", ref.Name, ref.Key, err)
			}
			continue
		}
		for _, key := range slices.Sorted(maps.Keys(data)) {
			if err := add(ref.Prefix+key, string(data[key])); err != nil {
				return nil, fmt.Errorf("secret %q key %q: %w", ref.Name, key, err)
			}
		}
	}
	return out, nil
}
