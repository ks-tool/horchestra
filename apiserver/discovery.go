package apiserver

import (
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/uptrace/bunrouter"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiversion "k8s.io/apimachinery/pkg/version"
)

// discoveryCache holds the precomputed discovery documents. The served API
// surface is fixed once the scheme is populated at startup, so each document is
// derived from the scheme once — on the first discovery request — and every later
// request is a map lookup instead of a fresh reflect-and-sort pass.
type discoveryCache struct {
	once      sync.Once
	groupList *metav1.APIGroupList
	groups    map[string]*metav1.APIGroup
	resources map[string]*metav1.APIResourceList
}

// apiVersions answers kubectl's probe of the legacy core group. This API serves
// no core group, so the version list is empty.
func (s *APIServer) apiVersions(w http.ResponseWriter, _ bunrouter.Request) error {
	// Advertise core v1 so kubectl discovers the pods alias (backing `kubectl
	// logs`); /api/v1 then lists it.
	return bunrouter.JSON(w, &metav1.APIVersions{
		TypeMeta: metav1.TypeMeta{Kind: "APIVersions", APIVersion: "v1"},
		Versions: []string{"v1"},
	})
}

func (s *APIServer) apiGroupList(w http.ResponseWriter, _ bunrouter.Request) error {
	return bunrouter.JSON(w, s.discovery().groupList)
}

func (s *APIServer) apiGroup(w http.ResponseWriter, req bunrouter.Request) error {
	group := req.Param("group")
	g, ok := s.discovery().groups[group]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "apigroups"}, group)
	}
	return bunrouter.JSON(w, g)
}

func (s *APIServer) apiResourceList(w http.ResponseWriter, req bunrouter.Request) error {
	group, version := req.Param("group"), req.Param("version")
	list, ok := s.discovery().resources[group+"/"+version]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "apiresources"}, group+"/"+version)
	}
	return bunrouter.JSON(w, list)
}

// discovery builds the cached documents on first use and returns them. It is
// safe for concurrent callers: sync.Once serializes the build and publishes its
// writes to every reader.
func (s *APIServer) discovery() *discoveryCache {
	s.disc.once.Do(func() {
		gvs := s.groupVersions()
		names := make([]string, 0, len(gvs))
		for group := range gvs {
			names = append(names, group)
		}
		slices.Sort(names)

		groupList := &metav1.APIGroupList{
			TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"},
			Groups:   make([]metav1.APIGroup, 0, len(names)),
		}
		for _, group := range names {
			groupList.Groups = append(groupList.Groups, apiGroupFor(group, gvs[group]))
		}
		groups := make(map[string]*metav1.APIGroup, len(groupList.Groups))
		for i := range groupList.Groups {
			g := &groupList.Groups[i]
			groups[g.Name] = g
		}

		resources := map[string]*metav1.APIResourceList{}
		for gvk, r := range s.scheme.Resources() {
			gv := gvk.Group + "/" + gvk.Version
			rl := resources[gv]
			if rl == nil {
				rl = &metav1.APIResourceList{
					TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
					GroupVersion: gv,
				}
				resources[gv] = rl
			}
			rl.APIResources = append(rl.APIResources, metav1.APIResource{
				Name:         r.Plural,
				SingularName: r.Singular,
				Namespaced:   false,
				Kind:         gvk.Kind,
				Group:        gvk.Group,
				Version:      gvk.Version,
				Verbs:        metav1.Verbs{"get", "list", "watch", "create", "update", "patch", "delete"},
				ShortNames:   r.ShortNames,
			})
		}
		for _, rl := range resources {
			slices.SortFunc(rl.APIResources, func(a, b metav1.APIResource) int {
				return strings.Compare(a.Name, b.Name)
			})
		}

		s.disc.groupList = groupList
		s.disc.groups = groups
		s.disc.resources = resources
	})
	return &s.disc
}

// groupVersions maps every API group the scheme serves to its versions, ordered
// by descending kube-aware priority (GA before beta before alpha, higher numbers
// first — e.g. v2, v1, v1beta1). A group has at least one version whenever it
// appears in the map, so an empty slice means the group is unknown.
func (s *APIServer) groupVersions() map[string][]string {
	groups := map[string][]string{}
	for _, gvk := range s.scheme.AllKnownTypes() {
		if !slices.Contains(groups[gvk.Group], gvk.Version) {
			groups[gvk.Group] = append(groups[gvk.Group], gvk.Version)
		}
	}
	for _, versions := range groups {
		slices.SortFunc(versions, func(a, b string) int {
			return apiversion.CompareKubeAwareVersionStrings(b, a)
		})
	}
	return groups
}

// apiGroupFor builds the discovery record for one API group. versions must be
// ordered by descending kube-aware priority (highest first); the leading entry
// becomes the PreferredVersion — the version kubectl defaults to for the group.
func apiGroupFor(group string, versions []string) metav1.APIGroup {
	gvds := make([]metav1.GroupVersionForDiscovery, 0, len(versions))
	for _, v := range versions {
		gvds = append(gvds, metav1.GroupVersionForDiscovery{
			GroupVersion: group + "/" + v,
			Version:      v,
		})
	}
	g := metav1.APIGroup{
		TypeMeta: metav1.TypeMeta{Kind: "APIGroup", APIVersion: "v1"},
		Name:     group,
		Versions: gvds,
	}
	if len(gvds) > 0 {
		g.PreferredVersion = gvds[0]
	}
	return g
}
