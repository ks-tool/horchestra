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
		GroupVersion.WithKind("Namespace"),
		func() types.Object { return new(Namespace) },
		scheme.Resource{Plural: "namespaces", ShortNames: []string{"ns"}},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("NamespaceList"),
		func() types.Object { return new(NamespaceList) },
	)

	s.AddResource(
		GroupVersion.WithKind("Service"),
		func() types.Object { return new(Service) },
		scheme.Resource{Plural: "services", ShortNames: []string{"svc"}, Namespaced: true},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("ServiceList"),
		func() types.Object { return new(ServiceList) },
	)

	s.AddResource(
		GroupVersion.WithKind("Application"),
		func() types.Object { return new(Application) },
		scheme.Resource{Plural: "applications", ShortNames: []string{"app", "apps"}, Namespaced: true},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("ApplicationList"),
		func() types.Object { return new(ApplicationList) },
	)
	s.RegisterDefaults(GroupVersion.WithKind("Application"), defaultApplication)

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
		scheme.Resource{Plural: "persistentvolumes", ShortNames: []string{"pv"}, Namespaced: true},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("PersistentVolumeList"),
		func() types.Object { return new(PersistentVolumeList) },
	)

	s.AddResource(
		GroupVersion.WithKind("Secret"),
		func() types.Object { return new(Secret) },
		scheme.Resource{Plural: "secrets", ShortNames: []string{"sec"}, Namespaced: true, NoHistory: true},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("SecretList"),
		func() types.Object { return new(SecretList) },
	)

	s.AddResource(
		GroupVersion.WithKind("ApplicationSet"),
		func() types.Object { return new(ApplicationSet) },
		scheme.Resource{Plural: "applicationsets", ShortNames: []string{"appset", "appsets"}, Namespaced: true},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("ApplicationSetList"),
		func() types.Object { return new(ApplicationSetList) },
	)
	s.RegisterDefaults(GroupVersion.WithKind("ApplicationSet"), defaultApplicationSet)
}
