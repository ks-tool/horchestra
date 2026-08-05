package v1

import (
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName = "secrets.horchestra.io"
	Version   = "v1"
)

var (
	GroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}
)

func AddToScheme(s *scheme.Scheme) {
	s.AddResource(
		GroupVersion.WithKind("SecretStore"),
		func() types.Object { return new(SecretStore) },
		scheme.Resource{Plural: "secretstores", ShortNames: []string{"ss"}, Namespaced: true},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("SecretStoreList"),
		func() types.Object { return new(SecretStoreList) },
	)
}
