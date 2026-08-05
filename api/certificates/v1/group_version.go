package v1

import (
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/types"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName = "certificates.horchestra.io"
	Version   = "v1"
)

var GroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}

// AddToScheme registers the node certificate Kind: CertificateSigningRequest, cluster-scoped (a
// node's identity is not namespaced).
func AddToScheme(s *scheme.Scheme) {
	s.AddResource(
		GroupVersion.WithKind("CertificateSigningRequest"),
		func() types.Object { return new(CertificateSigningRequest) },
		scheme.Resource{Plural: "certificatesigningrequests", ShortNames: []string{"csr"}},
	)
	s.AddKnownTypes(
		GroupVersion.WithKind("CertificateSigningRequestList"),
		func() types.Object { return new(CertificateSigningRequestList) },
	)
}
