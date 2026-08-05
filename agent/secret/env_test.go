package secret

import (
	"strings"
	"testing"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func pushedSecret(name string, data map[string][]byte) corev1.Secret {
	return corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a"},
		Data:       data,
	}
}

// testNode is the certificate CN the fixtures' store is bound to; every app is pinned to it,
// since the mechanism refuses to unseal anything for a workload this agent does not deploy.
const testNode = "node-1"

func envApp(literal []string, refs ...corev1.EnvVar) workload.App {
	return workload.App{Name: "web", Namespace: "team-a", Node: testNode, Env: literal, EnvRefs: refs}
}

// boundStore is the mechanism as the agent hands it over: bound to its certificate CN.
func boundStore() Secrets {
	s := NewControllerStore(nil)
	s.(NodeBound).BindNode(testNode)
	return s
}

func ref(name, key, prefix string, optional bool) *corev1.EnvSecretRef {
	r := &corev1.EnvSecretRef{Name: name, Key: key, Prefix: prefix}
	if optional {
		r.Optional = new(true)
	}
	return r
}

// TestMaterializeEnv pins the projection: declared order for the entries, sorted key order
// inside a wildcard, and a fail-closed answer to every way a reference can be unusable. What
// admission could not decide — the names a wildcard derives from a Secret's keys, and the values
// themselves — is decided here, which is why "silently skipped" is never an outcome.
func TestMaterializeEnv(t *testing.T) {
	creds := pushedSecret("creds", map[string][]byte{
		"password": []byte("s3cr3t"),
		"username": []byte("app"),
		"host":     []byte("db.internal"),
	})

	cases := []struct {
		name    string
		app     workload.App
		pushed  []corev1.Secret
		want    []string
		wantErr string
	}{
		{
			name:   "single key",
			app:    envApp(nil, corev1.EnvVar{Name: "PGPASSWORD", SecretRef: ref("creds", "password", "", false)}),
			pushed: []corev1.Secret{creds},
			want:   []string{"PGPASSWORD=s3cr3t"},
		},
		{
			name:   "wildcard imports every key in sorted order",
			app:    envApp(nil, corev1.EnvVar{SecretRef: ref("creds", corev1.EnvSecretAllKeys, "", false)}),
			pushed: []corev1.Secret{creds},
			want:   []string{"host=db.internal", "password=s3cr3t", "username=app"},
		},
		{
			name:   "wildcard with a prefix",
			app:    envApp(nil, corev1.EnvVar{SecretRef: ref("creds", corev1.EnvSecretAllKeys, "PG_", false)}),
			pushed: []corev1.Secret{creds},
			want:   []string{"PG_host=db.internal", "PG_password=s3cr3t", "PG_username=app"},
		},
		{
			name: "declared order is preserved across entries",
			app: envApp(nil,
				corev1.EnvVar{Name: "SECOND", SecretRef: ref("creds", "username", "", false)},
				corev1.EnvVar{Name: "FIRST", SecretRef: ref("creds", "password", "", false)},
			),
			pushed: []corev1.Secret{creds},
			want:   []string{"SECOND=app", "FIRST=s3cr3t"},
		},
		{
			name:   "an optional reference may be absent",
			app:    envApp(nil, corev1.EnvVar{Name: "X", SecretRef: ref("missing", "password", "", true)}),
			pushed: []corev1.Secret{creds},
			want:   nil,
		},
		{
			name:   "an optional key may be absent",
			app:    envApp(nil, corev1.EnvVar{Name: "X", SecretRef: ref("creds", "nope", "", true)}),
			pushed: []corev1.Secret{creds},
			want:   nil,
		},
		{
			name:    "a required secret must be present",
			app:     envApp(nil, corev1.EnvVar{Name: "X", SecretRef: ref("missing", "password", "", false)}),
			pushed:  []corev1.Secret{creds},
			wantErr: `secret "missing" not available`,
		},
		{
			name:    "a required key must be present",
			app:     envApp(nil, corev1.EnvVar{Name: "X", SecretRef: ref("creds", "nope", "", false)}),
			pushed:  []corev1.Secret{creds},
			wantErr: `key "nope" not found`,
		},
		{
			name: "a key that is not a valid env name fails even when optional",
			app:  envApp(nil, corev1.EnvVar{SecretRef: ref("files", corev1.EnvSecretAllKeys, "", true)}),
			pushed: []corev1.Secret{pushedSecret("files", map[string][]byte{
				"ca.pem": []byte("x"),
			})},
			wantErr: "not a valid environment variable name",
		},
		{
			name: "a multi-line value belongs in a mount",
			app:  envApp(nil, corev1.EnvVar{Name: "KEY", SecretRef: ref("files", "key", "", false)}),
			pushed: []corev1.Secret{pushedSecret("files", map[string][]byte{
				"key": []byte("-----BEGIN\nkey\n-----END\n"),
			})},
			wantErr: "mount it as a file instead",
		},
		{
			name:    "a literal entry already owns the name",
			app:     envApp([]string{"PGPASSWORD=plain"}, corev1.EnvVar{Name: "PGPASSWORD", SecretRef: ref("creds", "password", "", false)}),
			pushed:  []corev1.Secret{creds},
			wantErr: "already set by another entry",
		},
		{
			name: "two wildcards colliding",
			app: envApp(nil,
				corev1.EnvVar{SecretRef: ref("creds", corev1.EnvSecretAllKeys, "", false)},
				corev1.EnvVar{SecretRef: ref("creds", corev1.EnvSecretAllKeys, "", false)},
			),
			pushed:  []corev1.Secret{creds},
			wantErr: "already set by another entry",
		},
		{
			name:    "a secret from another namespace is not reachable",
			app:     envApp(nil, corev1.EnvVar{Name: "X", SecretRef: ref("creds", "password", "", false)}),
			pushed:  []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "team-b"}, Data: map[string][]byte{"password": []byte("theirs")}}},
			wantErr: `secret "creds" not available`,
		},
	}

	store := boundStore()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.MaterializeEnv(t.Context(), tc.app, tc.pushed, nil)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("a failed resolution must return nothing, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("env = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEnvRefsAreNotLiterals: a secretRef entry must not also be flattened as a literal — an
// empty "NAME=" would land in the unit's own Environment= and shadow the resolved value.
func TestEnvRefsAreNotLiterals(t *testing.T) {
	app := workload.FromApplication(corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a"},
		Spec: corev1.ApplicationSpec{
			Env: []corev1.EnvVar{
				{Name: "PGDATA", Value: "/data"},
				{Name: "PGPASSWORD", SecretRef: ref("creds", "password", "", false)},
			},
		},
	})
	if len(app.Env) != 1 || app.Env[0] != "PGDATA=/data" {
		t.Fatalf("literal env = %v, want only the literal entry", app.Env)
	}
	if len(app.EnvRefs) != 1 || app.EnvRefs[0].Name != "PGPASSWORD" {
		t.Fatalf("env refs = %v, want the secretRef entry", app.EnvRefs)
	}
	if len(app.SecretEnv) != 0 {
		t.Fatal("FromApplication must not resolve anything; the reconciler fills SecretEnv")
	}
}

// TestSecretsAreOnlyForThisAgentsWorkloads: a Secret may be unsealed only for an Application this
// agent is the one deploying — spec.nodeName equal to the CN of the certificate the controller
// authorized its session with. The push filter already scopes what a node receives, but that runs
// on the other side of the wire; a node must not depend on it for the confidentiality of another
// node's credentials.
func TestSecretsAreOnlyForThisAgentsWorkloads(t *testing.T) {
	creds := pushedSecret("creds", map[string][]byte{"password": []byte("s3cr3t")})
	envRef := corev1.EnvVar{Name: "PGPASSWORD", SecretRef: ref("creds", "password", "", false)}
	mount := corev1.VolumeMount{
		Volume:    corev1.VolumeSource{Type: corev1.VolumeTypeSecret, Name: "creds"},
		MountPath: "/etc/creds",
	}

	cases := []struct {
		name    string
		cn      string // what the agent binds, "" = never bound
		node    string // the Application's spec.nodeName
		wantErr string
	}{
		{name: "its own workload", cn: "node-1", node: "node-1"},
		{name: "another node's workload", cn: "node-1", node: "node-2", wantErr: `nodeName is "node-2"`},
		{name: "an unscheduled workload", cn: "node-1", node: "", wantErr: "names no node"},
		{name: "an unbound mechanism", cn: "", node: "node-1", wantErr: "never bound"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewControllerStore(nil)
			if tc.cn != "" {
				store.(NodeBound).BindNode(tc.cn)
			}
			app := workload.App{
				Name: "web", Namespace: "team-a", Node: tc.node,
				EnvRefs: []corev1.EnvVar{envRef},
				Volumes: []corev1.VolumeMount{mount},
			}
			pushed := []corev1.Secret{creds}

			env, envErr := store.MaterializeEnv(t.Context(), app, pushed, nil)
			vols, volErr := store.Materialize(t.Context(), app, pushed, nil)
			if tc.wantErr == "" {
				if envErr != nil || volErr != nil {
					t.Fatalf("own workload must be served: env %v, volumes %v", envErr, volErr)
				}
				if len(env) != 1 || len(vols) != 1 {
					t.Fatalf("env = %v, volumes = %v", env, vols)
				}
				return
			}
			for what, err := range map[string]error{"env": envErr, "volumes": volErr} {
				if err == nil {
					t.Fatalf("%s must be refused (want %q)", what, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("%s error %q does not mention %q", what, err, tc.wantErr)
				}
			}
			if env != nil || vols != nil {
				t.Fatalf("a refusal must return nothing: env %v, volumes %v", env, vols)
			}
		})
	}
}
