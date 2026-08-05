package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mkSecret(name string, data map[string][]byte) corev1.Secret {
	return corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Data:       data,
	}
}

func secretAttrs(op Operation, sec corev1.Secret) *Attributes {
	return &Attributes{GVK: corev1.GroupVersion.WithKind("Secret"), Operation: op, Object: &sec, OldObject: &sec}
}

func appMountingSecret(name, secret string, optional bool) corev1.Application {
	a := mkApp(name, "n1", cpu("1"))
	vs := corev1.VolumeSource{Type: corev1.VolumeTypeSecret, Name: secret}
	if optional {
		o := true
		vs.Optional = &o
	}
	a.Spec.Volumes = []corev1.VolumeMount{{Volume: vs, MountPath: "/creds"}}
	return a
}

func TestSecretPolicyAdmit(t *testing.T) {
	sec := corev1.Secret{StringData: map[string]string{"user": "admin"}, Data: map[string][]byte{"pw": []byte("x")}}
	if err := (secretPolicy{}).Admit(context.Background(), &Attributes{Operation: Create, Object: &sec}); err != nil {
		t.Fatal(err)
	}
	if sec.StringData != nil {
		t.Error("stringData must be cleared after the merge")
	}
	if string(sec.Data["user"]) != "admin" || string(sec.Data["pw"]) != "x" {
		t.Errorf("stringData must be folded into data, got %v", sec.Data)
	}
	if sec.Type != corev1.SecretTypeOpaque {
		t.Errorf("empty type must default to Opaque, got %q", sec.Type)
	}
}

func TestSecretPolicyValidate(t *testing.T) {
	ctx := context.Background()
	p := secretPolicy{}

	vaultInline := corev1.Secret{Type: corev1.SecretTypeVault, Data: map[string][]byte{"k": []byte("v")}}
	if err := p.Validate(ctx, &Attributes{Operation: Create, Object: &vaultInline}); err == nil || !strings.Contains(err.Error(), "no inline data") {
		t.Fatalf("want inline-data rejection on a vault secret, got %v", err)
	}
	// A vault secret carries no data — its value is fetched — but it must still say WHERE
	// from. One naming no source used to be stored happily and then hold every application
	// mounting it, with the only complaint on a node's journal.
	vault := corev1.Secret{
		Type: corev1.SecretTypeVault,
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			corev1.AnnExternalSecretStore: "corp",
			corev1.AnnExternalSecretPath:  "prod/db",
		}},
	}
	if err := p.Validate(ctx, &Attributes{Operation: Create, Object: &vault}); err != nil {
		t.Fatalf("an empty-data vault secret naming a path must validate, got %v", err)
	}
	sourceless := corev1.Secret{Type: corev1.SecretTypeVault}
	if err := p.Validate(ctx, &Attributes{Operation: Create, Object: &sourceless}); err == nil {
		t.Fatal("a vault secret naming neither a path nor a static role must be refused")
	}

	badKey := corev1.Secret{Data: map[string][]byte{"a/b": []byte("v")}}
	if err := p.Validate(ctx, &Attributes{Operation: Create, Object: &badKey}); err == nil || !strings.Contains(err.Error(), "single path component") {
		t.Fatalf("want bad-key rejection, got %v", err)
	}

	// A key the node will refuse to project must be refused HERE. Admission used to accept any
	// slash-free key while the agent validated the projected path with the stricter container-path
	// rules, so a "tls key" or "a:b" key was admitted centrally and rejected on every node —
	// stopping the Apply of every application in the namespace that mounts the secret, reachable
	// by a principal with no rights over Applications at all.
	for _, key := range []string{"tls key", "a:b", "a\\b", "a\tb", ".", "..", ""} {
		sec := corev1.Secret{Data: map[string][]byte{key: []byte("v")}}
		if err := p.Validate(ctx, &Attributes{Operation: Create, Object: &sec}); err == nil {
			t.Fatalf("key %q must be rejected at admission: the node cannot project it", key)
		}
	}
	for _, key := range []string{"tls.key", "ca_bundle.pem", "user-1"} {
		sec := corev1.Secret{Data: map[string][]byte{key: []byte("v")}}
		if err := p.Validate(ctx, &Attributes{Operation: Create, Object: &sec}); err != nil {
			t.Fatalf("key %q must be accepted, got %v", key, err)
		}
	}

	big := corev1.Secret{Data: map[string][]byte{"k": make([]byte, maxSecretBytes+1)}}
	if err := p.Validate(ctx, &Attributes{Operation: Create, Object: &big}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("want size-limit rejection, got %v", err)
	}

	imm := true
	old := corev1.Secret{Immutable: &imm, Data: map[string][]byte{"k": []byte("v1")}}
	updated := corev1.Secret{Immutable: &imm, Data: map[string][]byte{"k": []byte("v2")}}
	if err := p.Validate(ctx, &Attributes{Operation: Update, Object: &updated, OldObject: &old}); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("want immutable-change rejection, got %v", err)
	}
	same := corev1.Secret{Immutable: &imm, Data: map[string][]byte{"k": []byte("v1")}}
	if err := p.Validate(ctx, &Attributes{Operation: Update, Object: &same, OldObject: &old}); err != nil {
		t.Fatalf("unchanged immutable data must pass, got %v", err)
	}
}

func TestAppPolicySecretVolume(t *testing.T) {
	ctx := context.Background()

	noName := mkApp("web", "n1", cpu("1"))
	noName.Spec.Volumes = []corev1.VolumeMount{{Volume: corev1.VolumeSource{Type: corev1.VolumeTypeSecret}, MountPath: "/c"}}
	if err := (appPolicy{}).Validate(ctx, appAttrs(Create, noName)); err == nil || !strings.Contains(err.Error(), "requires volume.name") {
		t.Fatalf("want name-required rejection, got %v", err)
	}

	withSize := mkApp("web", "n1", cpu("1"))
	withSize.Spec.Volumes = []corev1.VolumeMount{{Volume: corev1.VolumeSource{Type: corev1.VolumeTypeSecret, Name: "db", Size: resource.MustParse("1Mi")}, MountPath: "/c"}}
	if err := (appPolicy{}).Validate(ctx, appAttrs(Create, withSize)); err == nil || !strings.Contains(err.Error(), "must not set size") {
		t.Fatalf("want size rejection, got %v", err)
	}
}

func TestSecretRef(t *testing.T) {
	ctx := context.Background()

	missing := ruleCheck(fakeLister{}, secretRefRule)
	if err := missing.Validate(ctx, appAttrs(Create, appMountingSecret("web", "db", false))); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("want missing-secret rejection, got %v", err)
	}
	if err := missing.Validate(ctx, appAttrs(Create, appMountingSecret("web", "db", true))); err != nil {
		t.Fatalf("an optional missing secret must pass, got %v", err)
	}

	present := ruleCheck(fakeLister{secrets: []corev1.Secret{mkSecret("db", nil)}}, secretRefRule)
	if err := present.Validate(ctx, appAttrs(Create, appMountingSecret("web", "db", false))); err != nil {
		t.Fatalf("an existing secret must pass, got %v", err)
	}
}

func TestSecretProtection(t *testing.T) {
	ctx := context.Background()
	c := ruleCheck(fakeLister{apps: []corev1.Application{appMountingSecret("web", "db", false)}}, secretProtectionRule)
	err := c.Validate(ctx, secretAttrs(Delete, mkSecret("db", nil)))
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("want in-use rejection, got %v", err)
	}
	if _, ok := err.(*ForbiddenError); !ok {
		t.Fatalf("want a ForbiddenError (403), got %T", err)
	}
}

// TestSecretImmutableFlagCannotBeCleared: guarding only the data made immutability a two-request
// formality — clear the flag in one write (data unchanged, so the check passed), change the data
// in the next. The flag has to be immutable itself, as kube-apiserver makes it.
func TestSecretImmutableFlagCannotBeCleared(t *testing.T) {
	yes := true
	old := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "db"},
		Immutable:  &yes,
		Data:       map[string][]byte{"password": []byte("original")},
	}

	clear := &corev1.Secret{
		ObjectMeta: old.ObjectMeta,
		Data:       map[string][]byte{"password": []byte("original")}, // data untouched
	}
	if err := (secretPolicy{}).Validate(t.Context(), &Attributes{
		Operation: Update, Object: clear, OldObject: old,
	}); err == nil {
		t.Fatal("the immutable flag was allowed to be cleared, which makes immutability bypassable in two writes")
	}

	no := false
	explicitFalse := &corev1.Secret{ObjectMeta: old.ObjectMeta, Immutable: &no, Data: old.Data}
	if err := (secretPolicy{}).Validate(t.Context(), &Attributes{
		Operation: Update, Object: explicitFalse, OldObject: old,
	}); err == nil {
		t.Fatal("immutable:false was allowed on an immutable secret")
	}

	// Keeping the flag and the data is still a legal no-op update (e.g. a label change).
	same := &corev1.Secret{ObjectMeta: old.ObjectMeta, Immutable: &yes, Data: old.Data}
	if err := (secretPolicy{}).Validate(t.Context(), &Attributes{
		Operation: Update, Object: same, OldObject: old,
	}); err != nil {
		t.Fatalf("an unchanged immutable secret must still validate: %v", err)
	}
}
