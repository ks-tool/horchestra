package types

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Object is a built-in resource: it exposes its metadata (name, labels, …) and
// its apiVersion/kind. Every Kind in this package satisfies it by embedding
// metav1.TypeMeta and metav1.ObjectMeta — so admission and the service work with
// typed api/v1 values instead of poking at unstructured maps.
type Object interface {
	GetObjectKind() schema.ObjectKind
}

type ObjectMeta struct {
	ApiVersion string
	Kind       string
	Namespace  string
	Name       string
}

func (meta ObjectMeta) String() string {
	if meta.Namespace != "" {
		return fmt.Sprintf("%s, kind=%s %s/%s", meta.ApiVersion, meta.Kind, meta.Namespace, meta.Name)
	}
	return fmt.Sprintf("%s, kind=%s %s", meta.ApiVersion, meta.Kind, meta.Name)
}
