package apiserver

import (
	"net/http"
	"strings"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "ks-tool.dev/horchestra/api/v1"
)

// apiVersions answers kubectl's probe of the legacy core group. This API serves
// no core group, so the version list is empty.
func (s *Server) apiVersions(w http.ResponseWriter, _ bunrouter.Request) error {
	// Advertise core v1 so kubectl discovers the pods alias (backing `kubectl
	// logs`); /api/v1 then lists it.
	return bunrouter.JSON(w, &metav1.APIVersions{
		TypeMeta: metav1.TypeMeta{Kind: "APIVersions", APIVersion: "v1"},
		Versions: []string{"v1"},
	})
}

func (s *Server) apiGroupList(w http.ResponseWriter, _ bunrouter.Request) error {
	var groups []metav1.APIGroup
	seen := map[string]bool{}
	for _, res := range s.resources {
		if seen[res.GVK.Group] {
			continue
		}
		seen[res.GVK.Group] = true
		groups = append(groups, apiGroupFor(res.GVK.Group))
	}
	return bunrouter.JSON(w, &metav1.APIGroupList{
		TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"},
		Groups:   groups,
	})
}

func (s *Server) apiGroup(w http.ResponseWriter, req bunrouter.Request) error {
	group := req.Param("group")
	if !s.hasGroup(group) {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "apigroups"}, group)
	}
	return bunrouter.JSON(w, new(apiGroupFor(group)))
}

func (s *Server) apiResourceList(w http.ResponseWriter, req bunrouter.Request) error {
	group, version := req.Param("group"), req.Param("version")
	var list []metav1.APIResource
	for _, res := range s.resources {
		if res.GVK.Group != group || res.GVK.Version != version {
			continue
		}
		list = append(list, metav1.APIResource{
			Name:         res.Plural,
			SingularName: strings.ToLower(res.GVK.Kind),
			Namespaced:   false,
			Kind:         res.GVK.Kind,
			Group:        res.GVK.Group,
			Version:      res.GVK.Version,
			Verbs:        metav1.Verbs{"get", "list", "watch", "create", "update", "patch", "delete"},
			ShortNames:   res.ShortNames,
		})
	}
	if len(list) == 0 {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "apiresources"}, group+"/"+version)
	}
	return bunrouter.JSON(w, &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
		GroupVersion: group + "/" + version,
		APIResources: list,
	})
}

func (s *Server) hasGroup(group string) bool {
	for _, r := range s.resources {
		if r.GVK.Group == group {
			return true
		}
	}
	return false
}

func apiGroupFor(group string) metav1.APIGroup {
	gvd := metav1.GroupVersionForDiscovery{GroupVersion: group + "/" + v1.Version, Version: v1.Version}
	return metav1.APIGroup{
		TypeMeta:         metav1.TypeMeta{Kind: "APIGroup", APIVersion: "v1"},
		Name:             group,
		Versions:         []metav1.GroupVersionForDiscovery{gvd},
		PreferredVersion: gvd,
	}
}
