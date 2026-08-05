package secret

import (
	"context"
	"testing"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func app(ns, name string, mounts ...corev1.VolumeMount) workload.App {
	// Pinned to testNode: the mechanism unseals nothing for a workload this agent does not deploy.
	return workload.App{Namespace: ns, Name: name, Node: testNode, Volumes: mounts}
}

func secretMount(name string, optional bool, items ...corev1.KeyToPath) corev1.VolumeMount {
	vs := corev1.VolumeSource{Type: corev1.VolumeTypeSecret, Name: name, Items: items}
	if optional {
		o := true
		vs.Optional = &o
	}
	return corev1.VolumeMount{Volume: vs, MountPath: "/creds"}
}

func sec(ns, name string, data map[string][]byte) corev1.Secret {
	return corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Data: data}
}

func TestMaterialize(t *testing.T) {
	pushed := []corev1.Secret{sec("team", "db", map[string][]byte{"password": []byte("s3cr3t"), "user": []byte("admin")})}
	vols, err := boundStore().Materialize(context.Background(), app("team", "web", secretMount("db", false)), pushed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 1 || vols[0].Kind != workload.VolumeSecret || vols[0].MountPath != "/creds" || !vols[0].ReadOnly {
		t.Fatalf("unexpected volume: %+v", vols)
	}
	if string(vols[0].Content["password"]) != "s3cr3t" || string(vols[0].Content["user"]) != "admin" {
		t.Fatalf("content = %v", vols[0].Content)
	}
}

func TestMaterializeFailClosed(t *testing.T) {
	s := boundStore()
	if _, err := s.Materialize(context.Background(), app("team", "web", secretMount("db", false)), nil, nil); err == nil {
		t.Fatal("want a fail-closed error for a missing non-optional secret")
	}
	vols, err := s.Materialize(context.Background(), app("team", "web", secretMount("db", true)), nil, nil)
	if err != nil || len(vols) != 0 {
		t.Fatalf("an optional missing secret must skip, got vols=%v err=%v", vols, err)
	}
}

// TestMaterializeVaultFailClosed: a horchestra.io/vault secret carries no inline data, so until
// a vault client lands the store must fail closed on it, never mount empty credentials.
func TestMaterializeVaultFailClosed(t *testing.T) {
	pushed := []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "db"}, Type: corev1.SecretTypeVault}}
	if _, err := boundStore().Materialize(context.Background(), app("team", "web", secretMount("db", false)), pushed, nil); err == nil {
		t.Fatal("a non-optional vault secret must fail closed without a vault client")
	}
	vols, err := boundStore().Materialize(context.Background(), app("team", "web", secretMount("db", true)), pushed, nil)
	if err != nil || len(vols) != 0 {
		t.Fatalf("an optional vault secret must skip, got vols=%v err=%v", vols, err)
	}
}

func TestMaterializeItems(t *testing.T) {
	pushed := []corev1.Secret{sec("team", "db", map[string][]byte{"password": []byte("s3cr3t"), "user": []byte("admin")})}
	vols, err := boundStore().Materialize(context.Background(),
		app("team", "web", secretMount("db", false, corev1.KeyToPath{Key: "password", Path: "pw.txt"})), pushed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols[0].Content) != 1 || string(vols[0].Content["pw.txt"]) != "s3cr3t" {
		t.Fatalf("items projection = %v, want only pw.txt=s3cr3t", vols[0].Content)
	}
}

// TestMaterializeCrossNamespaceIsolation checks a secret in another namespace is not visible.
func TestMaterializeCrossNamespaceIsolation(t *testing.T) {
	pushed := []corev1.Secret{sec("other", "db", map[string][]byte{"k": []byte("v")})}
	if _, err := boundStore().Materialize(context.Background(), app("team", "web", secretMount("db", false)), pushed, nil); err == nil {
		t.Fatal("a secret in another namespace must not satisfy the mount (fail-closed)")
	}
}
