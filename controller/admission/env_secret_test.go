package admission

import (
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/internal/memory"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func envApp(env ...corev1.EnvVar) corev1.Application {
	a := mkApp("web", "n1", cpu("1"))
	a.Spec.Env = env
	return a
}

// TestEnvSecretRefValidation pins the invariants a spec.env entry must satisfy before it ever
// reaches a node. The names a wildcard derives from a Secret's keys cannot be decided here — the
// Secret may not exist yet, and its keys change independently — so this covers exactly what the
// Application alone can answer, and the node re-validates the rest.
func TestEnvSecretRefValidation(t *testing.T) {
	ref := func(name, key, prefix string) *corev1.EnvSecretRef {
		return &corev1.EnvSecretRef{Name: name, Key: key, Prefix: prefix}
	}
	cases := []struct {
		name string
		env  []corev1.EnvVar
		want string // substring of the expected rejection; empty = must be accepted
	}{
		{
			name: "literal",
			env:  []corev1.EnvVar{{Name: "PGDATA", Value: "/var/lib/postgresql/data"}},
		},
		{
			name: "single key",
			env:  []corev1.EnvVar{{Name: "PGPASSWORD", SecretRef: ref("creds", "password", "")}},
		},
		{
			name: "wildcard with a prefix",
			env:  []corev1.EnvVar{{SecretRef: ref("creds", corev1.EnvSecretAllKeys, "PG_")}},
		},
		{
			name: "both value and secretRef",
			env:  []corev1.EnvVar{{Name: "X", Value: "v", SecretRef: ref("creds", "password", "")}},
			want: "not both",
		},
		{
			name: "secretRef without a name",
			env:  []corev1.EnvVar{{Name: "X", SecretRef: ref("", "password", "")}},
			want: "requires name",
		},
		{
			name: "secretRef without a key",
			env:  []corev1.EnvVar{{Name: "X", SecretRef: ref("creds", "", "")}},
			want: "requires key",
		},
		{
			name: "wildcard carrying a name",
			env:  []corev1.EnvVar{{Name: "X", SecretRef: ref("creds", corev1.EnvSecretAllKeys, "")}},
			want: "must not set name",
		},
		{
			name: "prefix on a single key",
			env:  []corev1.EnvVar{{Name: "X", SecretRef: ref("creds", "password", "PG_")}},
			want: "only to a wildcard",
		},
		{
			name: "env name a shell cannot express",
			env:  []corev1.EnvVar{{Name: "pg.password", SecretRef: ref("creds", "password", "")}},
			want: "not a valid environment variable name",
		},
		{
			name: "env name starting with a digit",
			env:  []corev1.EnvVar{{Name: "1PASSWORD", Value: "v"}},
			want: "not a valid environment variable name",
		},
		{
			name: "prefix a shell cannot express",
			env:  []corev1.EnvVar{{SecretRef: ref("creds", corev1.EnvSecretAllKeys, "pg-")}},
			want: "env prefix",
		},
		{
			name: "secret key that is not a file basename",
			env:  []corev1.EnvVar{{Name: "X", SecretRef: ref("creds", "../etc/shadow", "")}},
			want: "secretRef.key",
		},
		{
			name: "literal value carrying a newline",
			env:  []corev1.EnvVar{{Name: "X", Value: "a\nB=forged"}},
			want: "newline",
		},
		{
			name: "the same name twice",
			env: []corev1.EnvVar{
				{Name: "X", Value: "a"},
				{Name: "X", SecretRef: ref("creds", "password", "")},
			},
			want: "declared twice",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := envApp(tc.env...)
			err := (appPolicy{}).Validate(t.Context(), appAttrs(Create, app))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("must be accepted, got %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("must be rejected (want %q), got nil", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestEnvSecretRefIsAReference: an env secretRef must carry the same weight as a volume mount in
// both directions — a missing non-optional Secret is refused at the API instead of holding the
// app pending forever, and a Secret an app reads through env cannot be deleted from under it.
// Two definitions of "consumes a secret" would drift apart, so both rules read SecretRefs().
func TestEnvSecretRefIsAReference(t *testing.T) {
	ctx := t.Context()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	chain := DefaultChain(store, nil)
	// envApp pins its workload to node "n1" in namespace "n1", so both must exist for the
	// reference rules under test to be the ones that decide.
	ns := mkNamespace("n1")
	if _, err := store.Create(ctx, &ns); err != nil {
		t.Fatalf("seed namespace: %v", err)
	}
	node := mkNode("n1", corev1.ResourceAmounts{CPU: resource.MustParse("8"), Memory: resource.MustParse("16Gi")})
	if _, err := store.Create(ctx, &node); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	app := envApp(corev1.EnvVar{Name: "PGPASSWORD", SecretRef: &corev1.EnvSecretRef{Name: "creds", Key: "password"}})
	app.Namespace = "n1"
	if err := chain.Run(ctx, appAttrs(Create, app)); err == nil || !strings.Contains(err.Error(), `secret "creds" does not exist`) {
		t.Fatalf("a missing non-optional env secret must be refused, got %v", err)
	}

	optional := envApp(corev1.EnvVar{Name: "PGPASSWORD", SecretRef: &corev1.EnvSecretRef{
		Name: "creds", Key: "password", Optional: new(true),
	}})
	optional.Namespace = "n1"
	if err := chain.Run(ctx, appAttrs(Create, optional)); err != nil {
		t.Fatalf("an optional env secret may be absent, got %v", err)
	}

	sec := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "n1"},
		Data:       map[string][]byte{"password": []byte("v")},
	}
	if _, err := store.Create(ctx, sec); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	if err := chain.Run(ctx, appAttrs(Create, app)); err != nil {
		t.Fatalf("the secret exists now, so the app must be accepted: %v", err)
	}

	stored := app
	stored.TypeMeta = metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"}
	if _, err := store.Create(ctx, &stored); err != nil {
		t.Fatalf("seed application: %v", err)
	}
	del := &Attributes{GVK: corev1.GroupVersion.WithKind("Secret"), Operation: Delete, Object: sec}
	if err := chain.Validate(ctx, del); err == nil || !strings.Contains(err.Error(), "in use by application(s) web") {
		t.Fatalf("deleting a secret an app reads through env must be refused, got %v", err)
	}
}
