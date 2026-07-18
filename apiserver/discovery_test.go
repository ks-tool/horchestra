package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"

	"github.com/uptrace/bunrouter"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// discoveryObj is a minimal pointer-backed types.Object; discovery only reads
// the GVK a type is registered under, not the value, so an empty struct is enough.
type discoveryObj struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

const discGroup = "orch.horchestra.io"

func gvkOf(group, version, kind string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
}

// serverWith returns an APIServer whose scheme has each gvk registered.
func serverWith(t *testing.T, gvks ...schema.GroupVersionKind) *APIServer {
	t.Helper()
	sch := scheme.New()
	for _, k := range gvks {
		sch.AddKnownTypes(k, func() types.Object { return &discoveryObj{} })
	}
	return &APIServer{scheme: sch}
}

// TestGroupVersions_MultipleVersionsPerGroup: a group carrying several versions
// is reported with all of them, de-duplicated and ordered by descending
// kube-aware priority (GA before beta before alpha); a second group stays
// independent and an unknown group has no versions.
func TestGroupVersions_MultipleVersionsPerGroup(t *testing.T) {
	s := serverWith(t,
		gvkOf(discGroup, "v1", "Application"),
		gvkOf(discGroup, "v1", "Node"), // same version, different kind -> one entry
		gvkOf(discGroup, "v2", "Application"),
		gvkOf(discGroup, "v2beta1", "Application"),
		gvkOf(discGroup, "v1alpha1", "Application"),
		gvkOf("rbac.horchestra.io", "v1", "Role"),
	)

	if got, want := s.groupVersions()[discGroup], []string{"v2", "v1", "v2beta1", "v1alpha1"}; !slices.Equal(got, want) {
		t.Fatalf("groupVersions()[%q] = %v, want %v", discGroup, got, want)
	}
	if got, want := s.groupVersions()["rbac.horchestra.io"], []string{"v1"}; !slices.Equal(got, want) {
		t.Fatalf("second group = %v, want %v (versions must not leak across groups)", got, want)
	}
	if got := s.groupVersions()["missing.group"]; len(got) != 0 {
		t.Fatalf("unknown group should have no versions, got %v", got)
	}
}

// TestAPIGroupList_MultiVersionGroup drives the cached /apis handler: the group
// advertises every version in priority order, PreferredVersion is the
// highest-priority one, and each entry's GroupVersion is fully qualified.
func TestAPIGroupList_MultiVersionGroup(t *testing.T) {
	s := serverWith(t,
		gvkOf(discGroup, "v1", "Application"),
		gvkOf(discGroup, "v2", "Application"),
		gvkOf(discGroup, "v2beta1", "Application"),
	)

	var list metav1.APIGroupList
	decodeDiscovery(t, s.apiGroupList, &list)

	if len(list.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(list.Groups))
	}
	g := list.Groups[0]
	if g.Name != discGroup {
		t.Fatalf("group name = %q, want %q", g.Name, discGroup)
	}

	var versions []string
	for _, v := range g.Versions {
		versions = append(versions, v.Version)
		if want := discGroup + "/" + v.Version; v.GroupVersion != want {
			t.Errorf("GroupVersion = %q, want %q", v.GroupVersion, want)
		}
	}
	if want := []string{"v2", "v1", "v2beta1"}; !slices.Equal(versions, want) {
		t.Fatalf("versions = %v, want %v", versions, want)
	}
	if g.PreferredVersion.Version != "v2" {
		t.Fatalf("PreferredVersion = %q, want v2", g.PreferredVersion.Version)
	}
}

// TestDiscovery_Cached: the documents are built once and reused, so repeated
// calls hand back the same cached instance.
func TestDiscovery_Cached(t *testing.T) {
	s := serverWith(t, gvkOf(discGroup, "v1", "Application"), gvkOf(discGroup, "v2", "Application"))
	if s.discovery().groupList != s.discovery().groupList {
		t.Fatal("groupList is not cached (different instance across calls)")
	}
}

// decodeDiscovery invokes a request-agnostic discovery handler and JSON-decodes
// its response body into out.
func decodeDiscovery(t *testing.T, h func(http.ResponseWriter, bunrouter.Request) error, out any) {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := h(rec, bunrouter.Request{}); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}
