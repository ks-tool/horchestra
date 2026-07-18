package e2e

import (
	"net/http"
	"slices"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestApplication_JSONPatch exercises the RFC 6902 patch branch (distinct from
// the merge-patch path) and its malformed-input error.
func TestApplication_JSONPatch(t *testing.T) {
	s := startServer(t)
	if code, _ := s.create(appPath(""), newApp("db", "node-1", "postgres:16")); code != http.StatusCreated {
		t.Fatalf("create failed")
	}

	code, body := s.do(http.MethodPatch, appPath("db"), "application/json-patch+json",
		[]byte(`[{"op":"replace","path":"/spec/image","value":"postgres:19"}]`))
	if code != http.StatusOK {
		t.Fatalf("json patch = %d, body=%s", code, body)
	}
	var patched corev1.Application
	decode(t, body, &patched)
	if patched.Spec.Image != "postgres:19" {
		t.Errorf("json-patched image = %q, want postgres:19", patched.Spec.Image)
	}
	if patched.Spec.NodeName != "node-1" {
		t.Errorf("json patch dropped nodeName = %q", patched.Spec.NodeName)
	}

	// A patch body that is not a valid RFC 6902 operation array -> 400.
	if code, _ := s.do(http.MethodPatch, appPath("db"), "application/json-patch+json", []byte(`{"not":"an-array"}`)); code != http.StatusBadRequest {
		t.Errorf("malformed json patch = %d, want 400", code)
	}
}

// TestCreate_MalformedBody: a body that is not well-typed JSON is rejected as 422.
func TestCreate_MalformedBody(t *testing.T) {
	s := startServer(t)
	if code, _ := s.do(http.MethodPost, appPath(""), "application/json", []byte(`{`)); code != http.StatusUnprocessableEntity {
		t.Errorf("malformed create body = %d, want 422", code)
	}
}

// TestList_LabelSelector verifies List returns all items and honors a label
// selector filter.
func TestList_LabelSelector(t *testing.T) {
	s := startServer(t)
	mustCreate(t, s, appPath(""), labeledApp("a", "img", map[string]string{"env": "prod"}))
	mustCreate(t, s, appPath(""), labeledApp("b", "img", map[string]string{"env": "dev"}))
	mustCreate(t, s, appPath(""), labeledApp("c", "img", map[string]string{"env": "prod"}))

	var all corev1.ApplicationList
	s.getInto(appPath(""), &all)
	if got := appNames(all); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("list all = %v, want [a b c]", got)
	}

	var prod corev1.ApplicationList
	if code := s.getInto(appPath("")+"?labelSelector=env%3Dprod", &prod); code != http.StatusOK {
		t.Fatalf("filtered list = %d", code)
	}
	if got := appNames(prod); !slices.Equal(got, []string{"a", "c"}) {
		t.Errorf("list env=prod = %v, want [a c]", got)
	}
}

// TestPersistentVolume_Lifecycle confirms the generic verb wiring works for a
// second, distinct Kind end to end.
func TestPersistentVolume_Lifecycle(t *testing.T) {
	s := startServer(t)
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "data"},
		Spec:       corev1.PersistentVolumeSpec{Node: "node-1", Size: resource.MustParse("10Gi")},
	}
	code, body := s.create(pvPath(""), pv)
	if code != http.StatusCreated {
		t.Fatalf("create pv = %d, body=%s", code, body)
	}
	var created corev1.PersistentVolume
	decode(t, body, &created)
	if created.APIVersion != "horchestra.io/v1" || created.Kind != "PersistentVolume" {
		t.Errorf("pv TypeMeta = %s/%s", created.APIVersion, created.Kind)
	}

	var list corev1.PersistentVolumeList
	s.getInto(pvPath(""), &list)
	if list.Kind != "PersistentVolumeList" || len(list.Items) != 1 {
		t.Errorf("pv list = kind %q, %d items", list.Kind, len(list.Items))
	}

	created.Spec.Mode = "0700"
	if code, b := s.put(pvPath("data"), &created); code != http.StatusOK {
		t.Fatalf("update pv = %d, %s", code, b)
	}
	if code, _ := s.del(pvPath("data")); code != http.StatusOK {
		t.Fatalf("delete pv failed")
	}
	if code, _ := s.get(pvPath("data")); code != http.StatusNotFound {
		t.Errorf("get pv after delete = %d, want 404", code)
	}
}

// TestRoleBinding_CRUD exercises the rbac group's second Kind over the write path.
func TestRoleBinding_CRUD(t *testing.T) {
	s := startServer(t)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "bind"},
		Spec: rbacv1.RoleBindingSpec{
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}},
			RoleRef:  rbacv1.RoleRef{Kind: "Role", Name: "reader"},
		},
	}
	code, body := s.create(rbPath(""), rb)
	if code != http.StatusCreated {
		t.Fatalf("create rolebinding = %d, body=%s", code, body)
	}
	var created rbacv1.RoleBinding
	decode(t, body, &created)
	if created.APIVersion != "rbac.horchestra.io/v1" || created.Kind != "RoleBinding" {
		t.Errorf("rolebinding TypeMeta = %s/%s", created.APIVersion, created.Kind)
	}
	if len(created.Spec.Subjects) != 1 || created.Spec.RoleRef.Name != "reader" {
		t.Errorf("rolebinding spec = %+v", created.Spec)
	}

	var got rbacv1.RoleBinding
	if code := s.getInto(rbPath("bind"), &got); code != http.StatusOK {
		t.Fatalf("get rolebinding = %d", code)
	}
	if code, _ := s.del(rbPath("bind")); code != http.StatusOK {
		t.Fatalf("delete rolebinding failed")
	}
}

func mustCreate(t *testing.T, s *testServer, path string, obj any) {
	t.Helper()
	if code, body := s.create(path, obj); code != http.StatusCreated {
		t.Fatalf("create %s = %d, body=%s", path, code, body)
	}
}

func appNames(list corev1.ApplicationList) []string {
	names := make([]string, 0, len(list.Items))
	for _, a := range list.Items {
		names = append(names, a.Name)
	}
	slices.Sort(names)
	return names
}
