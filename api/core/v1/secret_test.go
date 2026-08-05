package v1

import (
	"encoding/json"
	"testing"

	"github.com/ks-tool/horchestra/api/scheme"
)

func TestSecretScheme(t *testing.T) {
	s := scheme.New()
	AddToScheme(s)

	// Registered as a namespaced resource with the expected plural + short name.
	r, ok := s.Resource(GroupVersion.WithKind("Secret"))
	if !ok {
		t.Fatal("Secret is not registered")
	}
	if r.Plural != "secrets" || !r.Namespaced {
		t.Fatalf("Secret resource meta = %+v, want plural=secrets namespaced=true", r)
	}

	// Decode a Secret the way the service does: scheme resolves the GVK to a typed empty
	// object, then the body is unmarshalled into it. data is base64 on the wire (k8s
	// parity); stringData is carried through here (the secretPolicy plugin folds it into
	// Data later).
	body := `{"apiVersion":"horchestra.io/v1","kind":"Secret","metadata":{"name":"db","namespace":"team-a"},` +
		`"data":{"password":"czNjcjN0"},"stringData":{"user":"admin"}}`
	obj, err := s.Decode([]byte(body))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	sec, ok := obj.(*Secret)
	if !ok {
		t.Fatalf("decoded type = %T, want *Secret", obj)
	}
	if err := json.Unmarshal([]byte(body), sec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := string(sec.Data["password"]); got != "s3cr3t" {
		t.Fatalf("data.password = %q, want s3cr3t (base64-decoded)", got)
	}
	if sec.StringData["user"] != "admin" {
		t.Fatalf("stringData.user = %q, want admin", sec.StringData["user"])
	}
	if sec.ID() != "team-a_db" {
		t.Fatalf("ID = %q, want team-a_db", sec.ID())
	}
}

// TestVolumeSecretHelpers checks the secret volume discriminator and name accessor.
func TestVolumeSecretHelpers(t *testing.T) {
	m := VolumeMount{Volume: VolumeSource{Type: VolumeTypeSecret, Name: "db"}, MountPath: "/creds"}
	if !m.IsSecret() || m.IsPV() || m.IsTmpfs() {
		t.Fatalf("IsSecret/IsPV/IsTmpfs = %v/%v/%v, want true/false/false", m.IsSecret(), m.IsPV(), m.IsTmpfs())
	}
	if m.SecretName() != "db" {
		t.Fatalf("SecretName = %q, want db", m.SecretName())
	}
}
