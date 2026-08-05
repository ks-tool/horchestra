package authz

import (
	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/scheme"
)

// testScheme is the registry the namespace-scope decision reads: seesAll turns on a read over a
// NAMESPACED resource, so the tests need the same resource metadata the server registers.
func testScheme() *scheme.Scheme {
	sch := scheme.New()
	corev1.AddToScheme(sch)
	rbacv1.AddToScheme(sch)
	certv1.AddToScheme(sch)
	return sch
}
