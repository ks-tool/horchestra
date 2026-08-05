package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Role is a set of permissions inside one namespace. It grants nothing on its own — a RoleBinding
// is what gives it to someone. For permissions that span namespaces or reach cluster-scoped
// Kinds, see ClusterRole.
type Role struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec RoleSpec `json:"spec"`
}

type RoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Role `json:"items"`
}

// RoleBinding grants a Role's permissions to subjects within the binding's own namespace. Its
// RoleRef may name a Role or a ClusterRole; naming a ClusterRole grants that cluster-wide rule
// set here only, which is how one definition is reused per namespace without widening it.
type RoleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec RoleBindingSpec `json:"spec"`
}

type RoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []RoleBinding `json:"items"`
}

// ClusterRole is a cluster-scoped set of PolicyRules, referenced by a ClusterRoleBinding
// (granting cluster-wide) or by a namespaced RoleBinding (granting the rules within that
// binding's namespace). It shares RoleSpec with the namespaced Role.
type ClusterRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec RoleSpec `json:"spec"`
}

type ClusterRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterRole `json:"items"`
}

// ClusterRoleBinding binds subjects to a ClusterRole cluster-wide — every namespace and
// cluster-scoped resources. Its RoleRef.Kind is "ClusterRole".
type ClusterRoleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec RoleBindingSpec `json:"spec"`
}

type ClusterRoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterRoleBinding `json:"items"`
}

// PolicyRule is one permission: verbs over resources, or verbs over request paths that address
// no resource. A rule names one or the other, never both — the two are decided by different
// things (an apiGroup/resource/namespace tuple against a path), and a rule carrying both would
// read as an intersection while granting the union.
type PolicyRule struct {
	APIGroups []string `json:"apiGroups,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Verbs     []string `json:"verbs"`
	// NonResourceURLs grants request paths that address no object: /metrics, /openapi/v3,
	// discovery. Such a path has no namespace to be scoped to, so only a ClusterRole granted
	// through a ClusterRoleBinding confers them — naming a ClusterRole from a namespaced
	// RoleBinding grants its resource rules in that namespace and none of its paths.
	//
	// The verb is the HTTP method, lowercased ("get"), because a path has no operation of its
	// own to name. A trailing "*" matches by prefix ("/openapi/*" covers /openapi/v3 but not
	// /openapi), and a bare "*" is every path; nothing else is a pattern.
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
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
