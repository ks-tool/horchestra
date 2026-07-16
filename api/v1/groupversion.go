package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName = "orch.ks-tool.dev"
	RBACGroup = "rbac.ks-tool.dev"
	Version   = "v1"
)

var (
	GroupVersion     = schema.GroupVersion{Group: GroupName, Version: Version}
	RBACGroupVersion = schema.GroupVersion{Group: RBACGroup, Version: Version}
)

type Resource struct {
	GVK        schema.GroupVersionKind
	Plural     string
	ShortNames []string
}

// APIPath returns the REST path of the resource; when name is non-empty it
// addresses that object: /apis/{group}/{version}/{plural}[/{name}].
func (r Resource) APIPath(name string) string {
	path := "/apis/" + r.GVK.Group + "/" + r.GVK.Version + "/" + r.Plural
	if len(name) > 0 {
		path += "/" + name
	}
	return path
}

// TypeMeta returns the apiVersion/kind stamped on objects of this resource.
func (r Resource) TypeMeta() metav1.TypeMeta {
	return metav1.TypeMeta{APIVersion: r.GVK.GroupVersion().String(), Kind: r.GVK.Kind}
}

var (
	ApplicationResource      = Resource{GVK: GroupVersion.WithKind("Application"), Plural: "applications", ShortNames: []string{"app", "apps"}}
	NodeResource             = Resource{GVK: GroupVersion.WithKind("Node"), Plural: "nodes", ShortNames: []string{"no"}}
	PersistentVolumeResource = Resource{GVK: GroupVersion.WithKind("PersistentVolume"), Plural: "persistentvolumes", ShortNames: []string{"pv"}}
	RoleResource             = Resource{GVK: RBACGroupVersion.WithKind("Role"), Plural: "roles"}
	RoleBindingResource      = Resource{GVK: RBACGroupVersion.WithKind("RoleBinding"), Plural: "rolebindings"}

	BaseResources = []Resource{ApplicationResource, NodeResource, PersistentVolumeResource, RoleResource, RoleBindingResource}
)
