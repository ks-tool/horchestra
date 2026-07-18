package v1

import (
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName = "horchestra.io"
	Version   = "v1"
)

var (
	GroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}
)

func AddToScheme(s *scheme.Scheme) {
	s.AddResource(
		GroupVersion.WithKind("Application"),
		func() types.Object { return new(Application) },
		scheme.Resource{Plural: "applications", ShortNames: []string{"app", "apps"}},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("ApplicationList"),
		func() types.Object { return new(ApplicationList) },
	)

	s.AddResource(
		GroupVersion.WithKind("Node"),
		func() types.Object { return new(Node) },
		scheme.Resource{Plural: "nodes", ShortNames: []string{"no"}},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("NodeList"),
		func() types.Object { return new(NodeList) },
	)

	s.AddResource(
		GroupVersion.WithKind("PersistentVolume"),
		func() types.Object { return new(PersistentVolume) },
		scheme.Resource{Plural: "persistentvolumes", ShortNames: []string{"pv"}},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("PersistentVolumeList"),
		func() types.Object { return new(PersistentVolumeList) },
	)
}
