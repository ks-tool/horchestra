package e2e

import (
	"net/http"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestApplication_Lifecycle(t *testing.T) {
	s := startServer(t)

	// Create — the body omits apiVersion/kind; admission must stamp them.
	code, body := s.create(appPath(""), newApp("db", "node-1", "postgres:16"))
	if code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", code, body)
	}
	var created corev1.Application
	decode(t, body, &created)
	if created.APIVersion != "horchestra.io/v1" || created.Kind != "Application" {
		t.Errorf("created TypeMeta = %s/%s", created.APIVersion, created.Kind)
	}
	if created.UID == "" || created.ResourceVersion == "" || created.CreationTimestamp.IsZero() {
		t.Errorf("created metadata incomplete: uid=%q rv=%q ts=%v", created.UID, created.ResourceVersion, created.CreationTimestamp)
	}
	if created.Spec.Image != "postgres:16" || created.Spec.NodeName != "node-1" {
		t.Errorf("created spec = %+v", created.Spec)
	}

	// Get returns the same object.
	var got corev1.Application
	if code := s.getInto(appPath("db"), &got); code != http.StatusOK {
		t.Fatalf("get = %d", code)
	}
	if got.UID != created.UID {
		t.Errorf("get uid = %q, want %q", got.UID, created.UID)
	}

	// List returns an ApplicationList envelope holding it.
	var list corev1.ApplicationList
	if code := s.getInto(appPath(""), &list); code != http.StatusOK {
		t.Fatalf("list = %d", code)
	}
	if list.Kind != "ApplicationList" {
		t.Errorf("list kind = %q, want ApplicationList", list.Kind)
	}
	if len(list.Items) != 1 || list.Items[0].Name != "db" {
		t.Fatalf("list items = %d, want 1×db", len(list.Items))
	}

	// Update at the current resourceVersion.
	got.Spec.Image = "postgres:17"
	code, body = s.put(appPath("db"), &got)
	if code != http.StatusOK {
		t.Fatalf("update = %d, body=%s", code, body)
	}
	var updated corev1.Application
	decode(t, body, &updated)
	if updated.Spec.Image != "postgres:17" {
		t.Errorf("updated image = %q, want postgres:17", updated.Spec.Image)
	}
	if updated.UID != created.UID {
		t.Error("update changed uid")
	}
	if updated.ResourceVersion == created.ResourceVersion {
		t.Error("update did not bump resourceVersion")
	}

	// Merge patch changes only the patched field.
	code, body = s.merge(appPath("db"), `{"spec":{"image":"postgres:18"}}`)
	if code != http.StatusOK {
		t.Fatalf("patch = %d, body=%s", code, body)
	}
	var patched corev1.Application
	decode(t, body, &patched)
	if patched.Spec.Image != "postgres:18" {
		t.Errorf("patched image = %q, want postgres:18", patched.Spec.Image)
	}
	if patched.Spec.NodeName != "node-1" {
		t.Errorf("merge patch dropped nodeName = %q", patched.Spec.NodeName)
	}

	// Delete returns a success Status, then the object is gone.
	code, body = s.del(appPath("db"))
	if code != http.StatusOK {
		t.Fatalf("delete = %d, body=%s", code, body)
	}
	var status metav1.Status
	decode(t, body, &status)
	if status.Status != metav1.StatusSuccess {
		t.Errorf("delete status = %q, want Success", status.Status)
	}
	if code, _ := s.get(appPath("db")); code != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", code)
	}
}

func TestApplication_Errors(t *testing.T) {
	s := startServer(t)

	if code, _ := s.get(appPath("ghost")); code != http.StatusNotFound {
		t.Errorf("get missing = %d, want 404", code)
	}

	code, body := s.create(appPath(""), newApp("db", "n1", "img"))
	if code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", code, body)
	}
	var created corev1.Application
	decode(t, body, &created)

	if code, _ := s.create(appPath(""), newApp("db", "n1", "img")); code != http.StatusConflict {
		t.Errorf("duplicate create = %d, want 409", code)
	}
	if code, _ := s.create(appPath(""), newApp("", "n1", "img")); code != http.StatusUnprocessableEntity {
		t.Errorf("nameless create = %d, want 422", code)
	}

	// Optimistic concurrency: one successful update, then a stale one conflicts.
	created.Spec.Image = "img-a"
	if code, _ := s.put(appPath("db"), &created); code != http.StatusOK {
		t.Fatalf("first update failed")
	}
	created.Spec.Image = "img-b" // `created` still carries the pre-update resourceVersion
	if code, _ := s.put(appPath("db"), &created); code != http.StatusConflict {
		t.Errorf("stale update = %d, want 409", code)
	}

	if code, _ := s.put(appPath("ghost"), newApp("ghost", "n1", "img")); code != http.StatusNotFound {
		t.Errorf("update missing = %d, want 404", code)
	}
	if code, _ := s.do(http.MethodPatch, appPath("db"), "application/strategic-merge-patch+json", []byte(`{}`)); code != http.StatusUnsupportedMediaType {
		t.Errorf("strategic patch = %d, want 415", code)
	}
	if code, _ := s.del(appPath("ghost")); code != http.StatusNotFound {
		t.Errorf("delete missing = %d, want 404", code)
	}
}

// TestUpdate_NameMismatch: a PUT whose body names a different (existing) object
// must be rejected, so the URL name can't be used to update another object.
func TestUpdate_NameMismatch(t *testing.T) {
	s := startServer(t)
	mustCreate(t, s, appPath(""), newApp("db", "n1", "db-img"))
	_, otherBody := s.create(appPath(""), newApp("other", "n1", "other-img"))
	var other corev1.Application
	decode(t, otherBody, &other)

	// PUT /applications/db carrying `other` (with its real resourceVersion, so the
	// only thing stopping it is the name check) must be a 400, not an update of `other`.
	other.Spec.Image = "hijacked"
	if code, resp := s.put(appPath("db"), &other); code != http.StatusBadRequest {
		t.Fatalf("name-mismatch PUT = %d, want 400; body=%s", code, resp)
	}
	var got corev1.Application
	s.getInto(appPath("other"), &got)
	if got.Spec.Image != "other-img" {
		t.Errorf("other image = %q, want other-img (mismatched PUT must not modify it)", got.Spec.Image)
	}
}

// TestGroups_Isolation checks that Kinds in different groups are stored and
// listed independently, and that each Kind's resourceVersion counter is its own.
func TestGroups_Isolation(t *testing.T) {
	s := startServer(t)

	_, appBody := s.create(appPath(""), newApp("db", "n1", "img"))
	var app corev1.Application
	decode(t, appBody, &app)
	if app.ResourceVersion != "1" {
		t.Errorf("first application resourceVersion = %q, want 1", app.ResourceVersion)
	}

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "reader"},
		Spec: rbacv1.RoleSpec{Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"horchestra.io"},
			Resources: []string{"applications"},
			Verbs:     []string{"get", "list"},
		}}},
	}
	code, roleBody := s.create(rolePath(""), role)
	if code != http.StatusCreated {
		t.Fatalf("create role = %d, body=%s", code, roleBody)
	}
	var createdRole rbacv1.Role
	decode(t, roleBody, &createdRole)
	if createdRole.APIVersion != "rbac.horchestra.io/v1" || createdRole.Kind != "Role" {
		t.Errorf("role TypeMeta = %s/%s", createdRole.APIVersion, createdRole.Kind)
	}
	// Independent per-GVK counter: the first Role also starts at 1.
	if createdRole.ResourceVersion != "1" {
		t.Errorf("first role resourceVersion = %q, want 1 (per-GVK counter)", createdRole.ResourceVersion)
	}

	var apps corev1.ApplicationList
	s.getInto(appPath(""), &apps)
	if len(apps.Items) != 1 {
		t.Errorf("applications list = %d, want 1 (roles must not leak in)", len(apps.Items))
	}
	var roles rbacv1.RoleList
	s.getInto(rolePath(""), &roles)
	if len(roles.Items) != 1 {
		t.Errorf("roles list = %d, want 1", len(roles.Items))
	}
	// A node has never been created, so its collection is empty (not 404).
	var nodes corev1.NodeList
	if code := s.getInto(nodePath(""), &nodes); code != http.StatusOK || len(nodes.Items) != 0 {
		t.Errorf("empty nodes list = %d / %d items, want 200 / 0", code, len(nodes.Items))
	}
}
