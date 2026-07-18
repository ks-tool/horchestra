package v1

import (
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName = "rbac.horchestra.io"
	Version   = "v1"
)

var (
	GroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}
)

func AddToScheme(s *scheme.Scheme) {
	s.AddResource(
		GroupVersion.WithKind("Role"),
		func() types.Object { return new(Role) },
		scheme.Resource{Plural: "roles"},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("RoleList"),
		func() types.Object { return new(RoleList) },
	)

	s.AddResource(
		GroupVersion.WithKind("RoleBinding"),
		func() types.Object { return new(RoleBinding) },
		scheme.Resource{Plural: "rolebindings"},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("RoleBindingList"),
		func() types.Object { return new(RoleBindingList) },
	)
}
