package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type Role struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec RoleSpec `json:"spec,omitempty"`
}

type RoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Role `json:"items"`
}

type RoleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec RoleBindingSpec `json:"spec"`
}

type RoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []RoleBinding `json:"items"`
}

type PolicyRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

type RoleSpec struct {
	Rules []PolicyRule `json:"rules"`
}

type Subject struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type RoleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type RoleBindingSpec struct {
	Subjects []Subject `json:"subjects"`
	RoleRef  RoleRef   `json:"roleRef"`
}
