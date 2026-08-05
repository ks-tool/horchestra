package e2e

import (
	"net/http"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDiscovery_Groups(t *testing.T) {
	s := startServer(t)

	var groups metav1.APIGroupList
	if code := s.getInto("/apis", &groups); code != http.StatusOK {
		t.Fatalf("GET /apis = %d", code)
	}
	byName := map[string]metav1.APIGroup{}
	for _, g := range groups.Groups {
		byName[g.Name] = g
	}
	for _, want := range []string{"horchestra.io", "rbac.horchestra.io"} {
		g, ok := byName[want]
		if !ok {
			t.Fatalf("group %q missing from /apis (got %v)", want, byName)
		}
		if g.PreferredVersion.Version != "v1" {
			t.Errorf("group %q preferredVersion = %q, want v1", want, g.PreferredVersion.Version)
		}
	}

	var group metav1.APIGroup
	if code := s.getInto("/apis/horchestra.io", &group); code != http.StatusOK {
		t.Fatalf("GET /apis/horchestra.io = %d", code)
	}
	if len(group.Versions) != 1 || group.Versions[0].Version != "v1" {
		t.Errorf("horchestra.io versions = %+v, want [v1]", group.Versions)
	}

	if code, _ := s.get("/apis/nope.group"); code != http.StatusNotFound {
		t.Errorf("GET unknown group = %d, want 404", code)
	}
}

func TestDiscovery_Resources(t *testing.T) {
	s := startServer(t)

	var rl metav1.APIResourceList
	if code := s.getInto("/apis/horchestra.io/v1", &rl); code != http.StatusOK {
		t.Fatalf("GET /apis/horchestra.io/v1 = %d", code)
	}
	byName := map[string]metav1.APIResource{}
	for _, r := range rl.APIResources {
		byName[r.Name] = r
	}

	app, ok := byName["applications"]
	if !ok {
		t.Fatalf("applications not in resource list (got %v)", keys(byName))
	}
	if app.Kind != "Application" || app.SingularName != "application" {
		t.Errorf("applications = kind %q singular %q", app.Kind, app.SingularName)
	}
	if !slices.Equal([]string(app.ShortNames), []string{"app", "apps"}) {
		t.Errorf("applications shortNames = %v, want [app apps]", app.ShortNames)
	}
	if !slices.Contains([]string(app.Verbs), "create") || !slices.Contains([]string(app.Verbs), "watch") {
		t.Errorf("applications verbs = %v, want to include create+watch", app.Verbs)
	}
	for _, plural := range []string{"nodes", "persistentvolumes"} {
		if _, ok := byName[plural]; !ok {
			t.Errorf("%s missing from resource list", plural)
		}
	}
	// List kinds must NOT be advertised as addressable resources.
	if _, ok := byName["applicationlists"]; ok {
		t.Error("applicationlists must not appear as an addressable resource")
	}

	var rbac metav1.APIResourceList
	if code := s.getInto("/apis/rbac.horchestra.io/v1", &rbac); code != http.StatusOK {
		t.Fatalf("GET rbac resources = %d", code)
	}
	rbacNames := map[string]bool{}
	for _, r := range rbac.APIResources {
		rbacNames[r.Name] = true
	}
	if !rbacNames["roles"] || !rbacNames["rolebindings"] {
		t.Errorf("rbac resources = %v, want roles+rolebindings", rbacNames)
	}

	if code, _ := s.get("/apis/horchestra.io/v2"); code != http.StatusNotFound {
		t.Errorf("GET unknown version = %d, want 404", code)
	}
}

func TestDiscovery_Legacy(t *testing.T) {
	s := startServer(t)

	var versions metav1.APIVersions
	if code := s.getInto("/api", &versions); code != http.StatusOK {
		t.Fatalf("GET /api = %d", code)
	}
	if !slices.Contains(versions.Versions, "v1") {
		t.Errorf("/api versions = %v, want to include v1", versions.Versions)
	}

	var rl metav1.APIResourceList
	if code := s.getInto("/api/v1", &rl); code != http.StatusOK {
		t.Fatalf("GET /api/v1 = %d", code)
	}
	names := map[string]bool{}
	for _, r := range rl.APIResources {
		names[r.Name] = true
	}
	if !names["pods"] {
		t.Errorf("/api/v1 resources = %v, want to include pods", keys(names))
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
