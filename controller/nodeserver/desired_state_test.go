package nodeserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	apischeme "github.com/ks-tool/horchestra/api/scheme"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"
	apitypes "github.com/ks-tool/horchestra/api/types"
	"github.com/ks-tool/horchestra/controller/internal/memory"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestDesiredState_NodeScopesAppsButPushesAllPVs locks in the down-push builder's two
// deliberate rules: Applications are node-scoped (least exposure — only the node's own apps
// reach it), but every PersistentVolume NAME is present so the agent can tell a deleted volume
// from one reassigned to another node. Do not drop a foreign volume from the list without first
// adding explicit delete events — this test guards that. What a foreign
// volume may carry is a separate rule, covered by TestDesiredStateRedactsForeignVolumes.
func TestDesiredState_NodeScopesAppsButPushesAllPVs(t *testing.T) {
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	ctl := &fakeController{store: store, sch: sch}
	ctx := context.Background()

	mustCreateApp(t, ctl, "web", nodeName)   // pinned to this node
	mustCreateApp(t, ctl, "other", "node-2") // pinned elsewhere

	pv := &corev1.PersistentVolume{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "PersistentVolume"},
		ObjectMeta: metav1.ObjectMeta{Name: "pg-data"},
		Spec:       corev1.PersistentVolumeSpec{Node: "node-2"}, // bound to the OTHER node
	}
	data, err := json.Marshal(pv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.Create(ctx, corev1.GroupVersion.WithKind("PersistentVolume"), data, ""); err != nil {
		t.Fatalf("create pv: %v", err)
	}

	ds, _, err := New(ctl).desiredState(ctx, nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if len(ds.Applications) != 1 {
		t.Fatalf("apps: node-scope must push only this node's app, got %d", len(ds.Applications))
	}
	if len(ds.PersistentVolumes) != 1 {
		t.Fatalf("pvs: the full PV set must reach every node (delete-vs-reassign), got %d", len(ds.PersistentVolumes))
	}
}

// TestDesiredState_NodeScopesSecrets locks in the secret least-exposure filter: a node
// receives only the Secrets its own pinned apps mount, never an unreferenced one.
func TestDesiredState_NodeScopesSecrets(t *testing.T) {
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	ctl := &fakeController{store: store, sch: sch}
	ctx := context.Background()

	appJSON := `{"metadata":{"name":"web"},"spec":{"image":"reg/web:v1","placement":{"nodeName":"` + nodeName + `"}` +
		`,"volumes":[{"volume":{"type":"secret","name":"db"},"mountPath":"/creds"}]}}`
	if _, err := ctl.Create(ctx, corev1.GroupVersion.WithKind("Application"), []byte(appJSON), ""); err != nil {
		t.Fatalf("create app: %v", err)
	}
	for _, name := range []string{"db", "unused"} { // "db" is referenced, "unused" is not
		body := `{"metadata":{"name":"` + name + `"},"data":{"k":"dg=="}}`
		if _, err := ctl.Create(ctx, corev1.GroupVersion.WithKind("Secret"), []byte(body), ""); err != nil {
			t.Fatalf("create secret %s: %v", name, err)
		}
	}

	ds, _, err := New(ctl).desiredState(ctx, nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if len(ds.Secrets) != 1 {
		t.Fatalf("node-scope must push only the referenced secret, got %d", len(ds.Secrets))
	}
	var got corev1.Secret
	if err := json.Unmarshal(ds.Secrets[0], &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "db" {
		t.Fatalf("pushed secret = %q, want db (the referenced one)", got.Name)
	}
}

// TestDesiredState_PushesReferencedSecretStores locks in the store least-exposure rule one
// level down: a node receives only the SecretStores named by its pushed vault secrets — an
// unreferenced store never leaves the controller, and an Opaque secret pulls no store at all.
func TestDesiredState_PushesReferencedSecretStores(t *testing.T) {
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	secretsv1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	ctl := &fakeController{store: store, sch: sch}
	ctx := context.Background()

	appJSON := `{"metadata":{"name":"web"},"spec":{"image":"reg/web:v1","placement":{"nodeName":"` + nodeName + `"}` +
		`,"volumes":[{"volume":{"type":"secret","name":"db"},"mountPath":"/creds"}]}}`
	if _, err := ctl.Create(ctx, corev1.GroupVersion.WithKind("Application"), []byte(appJSON), ""); err != nil {
		t.Fatalf("create app: %v", err)
	}
	secJSON := `{"metadata":{"name":"db","annotations":{"` + corev1.AnnExternalSecretStore + `":"corp-vault","` +
		corev1.AnnExternalSecretPath + `":"prod/db"}},"type":"` + corev1.SecretTypeVault + `"}`
	if _, err := ctl.Create(ctx, corev1.GroupVersion.WithKind("Secret"), []byte(secJSON), ""); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	for _, name := range []string{"corp-vault", "other-vault"} { // only corp-vault is named by the secret
		body := `{"metadata":{"name":"` + name + `"},"spec":{"server":"https://vault.example:8200"}}`
		if _, err := ctl.Create(ctx, secretsv1.GroupVersion.WithKind("SecretStore"), []byte(body), ""); err != nil {
			t.Fatalf("create secretstore %s: %v", name, err)
		}
	}

	ds, _, err := New(ctl).desiredState(ctx, nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if len(ds.SecretStores) != 1 {
		t.Fatalf("want only the referenced store pushed, got %d", len(ds.SecretStores))
	}
	var st secretsv1.SecretStore
	if err := json.Unmarshal(ds.SecretStores[0], &st); err != nil {
		t.Fatal(err)
	}
	if st.Name != "corp-vault" {
		t.Fatalf("pushed store = %q, want corp-vault", st.Name)
	}
	if len(ds.WorkloadTokens) != 0 {
		t.Fatalf("a cert-method store must not mint workload tokens, got %d", len(ds.WorkloadTokens))
	}
}

type fakeMinter struct{ minted []string }

func (m *fakeMinter) MintWorkloadToken(workload, _, audience string) (string, time.Time, error) {
	m.minted = append(m.minted, workload+"@"+audience)
	return "jwt-for-" + workload + "@" + audience, time.Now().Add(15 * time.Minute), nil
}

// TestDesiredState_MintsTokensForTokenStoreApps locks in the per-workload token rule: a
// token is minted and pushed for exactly the apps whose vault secrets ride a
// kubernetes-method store — an app on inline secrets gets none, so the credential set a
// node holds mirrors what is scheduled on it.
func TestDesiredState_MintsTokensForTokenStoreApps(t *testing.T) {
	sch := apischeme.New()
	corev1.AddToScheme(sch)
	secretsv1.AddToScheme(sch)
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	ctl := &fakeController{store: store, sch: sch}
	ctx := context.Background()

	vaultApp := `{"metadata":{"name":"web"},"spec":{"image":"reg/web:v1","placement":{"nodeName":"` + nodeName + `"}` +
		`,"volumes":[{"volume":{"type":"secret","name":"db"},"mountPath":"/creds"}]}}`
	plainApp := `{"metadata":{"name":"plain"},"spec":{"image":"reg/p:v1","placement":{"nodeName":"` + nodeName + `"}` +
		`,"volumes":[{"volume":{"type":"secret","name":"inline"},"mountPath":"/creds"}]}}`
	for _, a := range []string{vaultApp, plainApp} {
		if _, err := ctl.Create(ctx, corev1.GroupVersion.WithKind("Application"), []byte(a), ""); err != nil {
			t.Fatalf("create app: %v", err)
		}
	}
	vaultSec := `{"metadata":{"name":"db","annotations":{"` + corev1.AnnExternalSecretStore + `":"corp-vault","` +
		corev1.AnnExternalSecretPath + `":"prod/db"}},"type":"` + corev1.SecretTypeVault + `"}`
	if _, err := ctl.Create(ctx, corev1.GroupVersion.WithKind("Secret"), []byte(vaultSec), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.Create(ctx, corev1.GroupVersion.WithKind("Secret"), []byte(`{"metadata":{"name":"inline"},"data":{"k":"dg=="}}`), ""); err != nil {
		t.Fatal(err)
	}
	storeJSON := `{"metadata":{"name":"corp-vault"},"spec":{"server":"https://vault.example:8200","auth":{"method":"kubernetes","role":"workloads"}}}`
	if _, err := ctl.Create(ctx, secretsv1.GroupVersion.WithKind("SecretStore"), []byte(storeJSON), ""); err != nil {
		t.Fatal(err)
	}

	m := &fakeMinter{}
	srv := New(ctl, WithTokenMinter(m))
	ds, sig1, err := srv.desiredState(ctx, nodeName)
	if err != nil {
		t.Fatalf("desiredState: %v", err)
	}
	if len(ds.WorkloadTokens) != 1 {
		t.Fatalf("want exactly the jwt-store app's token, got %d", len(ds.WorkloadTokens))
	}
	wt := ds.WorkloadTokens[0]
	// Addressed by the object's UID, which is the node's key for a workload; the token itself is
	// still minted for the namespace/name subject a Vault policy is written against.
	gvk := corev1.GroupVersion.WithKind("Application")
	app, err := ctl.Get(ctx, apitypes.ObjectMeta{ApiVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	wantID := string(app.(*corev1.Application).UID)
	if wantID == "" {
		t.Fatal("the application has no uid, so the node has no key to address its token by")
	}
	if wt.GetWorkload() != wantID || wt.GetToken() != "jwt-for-"+corev1.WorkloadID("", "web")+"@"+corev1.TokenAudienceVault {
		t.Fatalf("token = %+v, want workload %q at the vault audience", wt, wantID)
	}
	if wt.GetAudience() != corev1.TokenAudienceVault {
		t.Errorf("audience = %q, want the Vault one — a token for one door names it", wt.GetAudience())
	}

	// A second build inside the refresh margin serves the cache — same token, same
	// signature, so token delivery does not defeat the push dedup.
	ds2, sig2, err := srv.desiredState(ctx, nodeName)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.minted) != 1 {
		t.Fatalf("want one mint across two builds (cache), got %d", len(m.minted))
	}
	if sig1 != sig2 || ds2.WorkloadTokens[0].GetToken() != wt.GetToken() {
		t.Fatal("a cached token must keep the push signature stable")
	}
}
