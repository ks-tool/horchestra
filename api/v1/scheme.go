package v1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Object is a built-in resource: it exposes its metadata (name, labels, …) and
// its apiVersion/kind. Every Kind in this package satisfies it by embedding
// metav1.TypeMeta and metav1.ObjectMeta — so admission and the service work with
// typed api/v1 values instead of poking at unstructured maps.
type Object interface {
	metav1.Object
	GetObjectKind() schema.ObjectKind
}

// scheme maps a GroupVersionKind to a constructor for its Go type — the typed
// registry the controller uses to turn a request into an api/v1 struct, the same
// role runtime.Scheme plays in Kubernetes.
var scheme = map[schema.GroupVersionKind]func() Object{
	ApplicationResource.GVK:      func() Object { return &Application{} },
	NodeResource.GVK:             func() Object { return &Node{} },
	PersistentVolumeResource.GVK: func() Object { return &PersistentVolume{} },
	RoleResource.GVK:             func() Object { return &Role{} },
	RoleBindingResource.GVK:      func() Object { return &RoleBinding{} },
}

// New returns a fresh typed object for gvk, or false if the kind is not built in.
func New(gvk schema.GroupVersionKind) (Object, bool) {
	f, ok := scheme[gvk]
	if !ok {
		return nil, false
	}
	return f(), true
}

// Decode converts an unstructured object into the typed api/v1 struct registered
// for gvk.
func Decode(gvk schema.GroupVersionKind, u *unstructured.Unstructured) (Object, error) {
	obj, ok := New(gvk)
	if !ok {
		return nil, fmt.Errorf("no type registered for %s", gvk)
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// Encode converts a typed api/v1 object back to unstructured for storage. It drops
// a null metadata.creationTimestamp — the artefact the converter emits for the
// zero Time — so a stored object stays as clean as the request that created it.
func Encode(obj Object) (*unstructured.Unstructured, error) {
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	if meta, ok := m["metadata"].(map[string]any); ok {
		if ct, present := meta["creationTimestamp"]; present && ct == nil {
			delete(meta, "creationTimestamp")
		}
	}
	return &unstructured.Unstructured{Object: m}, nil
}
