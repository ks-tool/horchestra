package secret

import (
	"context"
	"testing"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

func tokenApp(audience string) workload.App {
	app := workload.App{
		Name: "gateway", Namespace: "edge", UID: "u1", Node: "node-1",
		Volumes: []corev1.VolumeMount{{
			Volume:    corev1.VolumeSource{Type: corev1.VolumeTypeToken, Audience: audience},
			MountPath: "/var/run/horchestra",
		}},
		Tokens: map[string]string{corev1.TokenAudienceAPI: "jwt-api", corev1.TokenAudienceVault: "jwt-vault"},
	}
	return app
}

// TestATokenVolumeCarriesTheWorkloadsOwnIdentity: a port, a placement and this mount are all an
// edge needs — no shared secret in a config file, and the credential is the workload's own.
func TestATokenVolumeCarriesTheWorkloadsOwnIdentity(t *testing.T) {
	s := &controllerStore{cn: "node-1", ca: []byte("-----BEGIN CERTIFICATE-----")}
	vols, err := s.Materialize(context.Background(), tokenApp(""), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 1 || vols[0].MountPath != "/var/run/horchestra" {
		t.Fatalf("volumes = %+v, want the token mount", vols)
	}
	v := vols[0]
	if v.Kind != workload.VolumeSecret || !v.ReadOnly {
		t.Errorf("kind/readonly = %v/%v, want a read-only RAM mount", v.Kind, v.ReadOnly)
	}
	// An unnamed audience is this control plane's: a workload asking for "a token" wants to talk
	// to the API that gave it one.
	if got := string(v.Content[TokenFile]); got != "jwt-api" {
		t.Errorf("token = %q, want the API-audience one", got)
	}
	if got := string(v.Content[NamespaceFile]); got != "edge" {
		t.Errorf("namespace file = %q, want the workload's own", got)
	}
	if len(v.Content[CAFile]) == 0 {
		t.Error("no ca.crt: a credential for a server you cannot verify is one you can only present to an impostor")
	}
}

// TestTheAudienceSelectsTheToken: the workload holds one credential per door, and the mount asks
// for the door by name.
func TestTheAudienceSelectsTheToken(t *testing.T) {
	s := &controllerStore{cn: "node-1"}
	vols, err := s.Materialize(context.Background(), tokenApp(corev1.TokenAudienceVault), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(vols[0].Content[TokenFile]); got != "jwt-vault" {
		t.Errorf("token = %q, want the audience the mount named", got)
	}
}

// TestAMissingTokenIsNotAnEmptyFile: an empty credential where one belongs reads as an
// authentication failure at the far end, which is far worse to debug than a missing mount.
func TestAMissingTokenIsNotAnEmptyFile(t *testing.T) {
	app := tokenApp("elsewhere")
	s := &controllerStore{cn: "node-1"}
	vols, err := s.Materialize(context.Background(), app, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 0 {
		t.Errorf("volumes = %+v, want none: the push carried no token for that audience", vols)
	}
}
