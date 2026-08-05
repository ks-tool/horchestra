package apiserver

import (
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/version"
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

// serverVersion answers GET /version, which is the first thing a Kubernetes client asks and
// the only place it can learn what it is talking to. Without it `kubectl version` reports its
// own half and calls the server's unknown, which is a poor answer for the one question an
// operator asks before filing anything.
//
// It is served unauthenticated-adjacent — the same discovery allowlist as /api and /apis —
// because a build identifier is not a secret and a client needs it before it has decided
// whether to authenticate at all.
func (s *APIServer) serverVersion(w http.ResponseWriter, _ bunrouter.Request) error {
	return bunrouter.JSON(w, version.Info())
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
		// The metrics group is DERIVED, not stored, so it is not in the scheme and has to be
		// advertised by hand. Without it kubectl never looks for the API at all and `top`
		// reports it as unavailable — discovery is how a client learns the group exists.
		mgv := metav1.GroupVersionForDiscovery{GroupVersion: metricsGV, Version: metricsVersion}
		groupList.Groups = append(groupList.Groups, metav1.APIGroup{
			TypeMeta:         metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroup"},
			Name:             metricsGroup,
			Versions:         []metav1.GroupVersionForDiscovery{mgv},
			PreferredVersion: mgv,
		})

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
				Namespaced:   r.Namespaced,
				Kind:         gvk.Kind,
				Group:        gvk.Group,
				Version:      gvk.Version,
				Verbs:        metav1.Verbs{"get", "list", "watch", "create", "update", "patch", "delete"},
				ShortNames:   r.ShortNames,
			})
		}
		// Subresources are not in the scheme — nothing stores them — so the ones this server
		// serves are listed by hand, the way pods/log is in the core list. RBAC never consults
		// discovery, so the permission works without this; what it buys is that an operator can
		// SEE the subresource exists instead of having to read the source to find out.
		if rl := resources[corev1.GroupVersion.String()]; rl != nil {
			rl.APIResources = append(rl.APIResources, metav1.APIResource{
				Name: "applications/metrics", Namespaced: true, Kind: "ApplicationMetrics",
				Group: corev1.GroupName, Version: corev1.GroupVersion.Version,
				Verbs: metav1.Verbs{"get"},
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
