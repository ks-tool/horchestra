// Package appset expands an ApplicationSet bundle into its child Applications and reconciles
// them. Expand is pure — each component becomes one child (or, for a nodeSpread component, one
// child per matching Node with spec.nodeName injected), its typed spec deep-copied, the set's
// common config projected in, and the child stamped with the set's namespace, owner labels and
// a controller ownerReference. There is no templating.
package appset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"strings"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Expand renders an ApplicationSet into its desired child Applications: one child per
// component, or — for a nodeSpread component — one child per Node whose labels match the
// selector, with spec.nodeName pinned to it. Pure: no storage, no cluster reads beyond the
// passed node list (empty yields no nodeSpread children). A duplicate child name is an error.
// MaxChildren caps how many Applications one ApplicationSet may render. Expansion is driven by
// the set's component list crossed with the matching nodes, both of which a tenant controls, and
// each child is a real object that passes through the lister-backed admission chain — so an
// uncapped set is a cheap way to turn one request into tens of thousands of writes.
const MaxChildren = 500

func Expand(set *corev1.ApplicationSet, nodes []corev1.Node) ([]corev1.Application, error) {
	if len(set.Spec.Applications) == 0 {
		return nil, fmt.Errorf("applicationset %q has no applications", set.Name)
	}
	var children []corev1.Application
	seen := map[string]bool{}
	add := func(child corev1.Application) error {
		if seen[child.Name] {
			return fmt.Errorf("applicationset %q renders a duplicate child name %q", set.Name, child.Name)
		}
		if len(children) >= MaxChildren {
			return fmt.Errorf("applicationset %q renders more than %d children", set.Name, MaxChildren)
		}
		seen[child.Name] = true
		children = append(children, child)
		return nil
	}
	for i := range set.Spec.Applications {
		comp := set.Spec.Applications[i]
		if comp.Scale.NodeSpread == nil {
			for _, replica := range replicaIndexes(comp) {
				child, err := buildChild(set, comp, "", replica)
				if err != nil {
					return nil, err
				}
				if err := add(child); err != nil {
					return nil, err
				}
			}
			continue
		}
		for j := range nodes {
			n := nodes[j]
			if !selectorMatches(comp.Scale.NodeSpread.NodeSelector, n.SchedulingLabels()) {
				continue
			}
			child, err := buildChild(set, comp, n.Name, nil)
			if err != nil {
				return nil, err
			}
			if err := add(child); err != nil {
				return nil, err
			}
		}
	}
	return children, nil
}

// ExpandServices renders the Services an ApplicationSet owns: one per component that declares
// ports and does not name a service of its own.
//
// A component's replicas are its instances, and instances of one component are one thing to call —
// which is exactly what a Service is for and what a per-node registration cannot be, since the
// replicas are on different nodes by design. So the set renders the name rather than leaving every
// author to write the same object by hand beside every bundle.
//
// A component that NAMES a service is joining one, not asking for one: the name may belong to
// somebody else's object, and rendering it would mean this loop creating, rewriting and pruning an
// object it does not own. The reference is validated like any other (a name that exists), and the
// child joins it — so `serviceName: checkout` still puts a component called `api` behind `checkout`,
// with the Service authored where it is owned.
//
// Init steps get none. A run-to-completion component is finished, not reachable, and a name in the
// catalog that resolves to nothing running is worse than no name.
func ExpandServices(set *corev1.ApplicationSet) []corev1.Service {
	var out []corev1.Service
	for i := range set.Spec.Applications {
		comp := set.Spec.Applications[i]
		name := renderedServiceName(set, comp)
		if name == "" {
			continue
		}
		controller := true
		ports := make([]corev1.ServicePort, 0, len(comp.Spec.Ports))
		for _, p := range comp.Spec.Ports {
			// The service's port IS the workload's here: the set renders both sides, so there is
			// nothing for a targetPort to bridge, and stating one would only be a second place for
			// the same number.
			ports = append(ports, corev1.ServicePort{Name: p.Name, Port: int32(p.Port)})
		}
		out = append(out, corev1.Service{
			TypeMeta: metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Service"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: set.Namespace,
				Labels: map[string]string{
					corev1.LabelApplicationSet: set.Name,
					corev1.LabelComponent:      comp.Name,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet",
					Name: set.Name, UID: set.UID, Controller: &controller,
				}},
			},
			Spec: corev1.ServiceSpec{Ports: ports},
		})
	}
	return out
}

// renderedServiceName is the name of the Service this set renders for a component, or empty when
// it renders none: a component with no ports has nothing to register, one that names a service is
// joining somebody else's, and an init step is not reachable.
func renderedServiceName(set *corev1.ApplicationSet, comp corev1.NamedApplicationSpec) string {
	if len(comp.Spec.Ports) == 0 || comp.Spec.ServiceName != "" ||
		comp.Spec.Lifecycle.RestartPolicy == corev1.RestartNever {
		return ""
	}
	return sanitizeName(set.Name + "-" + comp.Name)
}

// serviceFor is the service a component's children declare: its own if it named one, otherwise the
// one the set renders. Empty when the component registers nowhere.
func serviceFor(set *corev1.ApplicationSet, comp corev1.NamedApplicationSpec) string {
	if comp.Spec.ServiceName != "" {
		return comp.Spec.ServiceName
	}
	return renderedServiceName(set, comp)
}

// replicaIndexes is the child index set of a component: a single unindexed child when
// replicas is unset, otherwise 0..N-1. A non-positive count yields nothing — admission
// rejects it, and expanding it into a negative-length loop must not panic here.
func replicaIndexes(comp corev1.NamedApplicationSpec) []*int {
	if comp.Scale.Replicas == nil {
		return []*int{nil}
	}
	out := make([]*int, 0, max(int(*comp.Scale.Replicas), 0))
	for i := range int(*comp.Scale.Replicas) {
		out = append(out, &i)
	}
	return out
}

// buildChild materializes one child Application from a component. node is empty for a bundle
// child (the scheduler places it — spec.nodeName stays empty) and the target node name for a
// nodeSpread child (the set pins spec.nodeName to it and owns the placement). replica is the
// fan-out index for a component with spec.replicas, nil for a single child; it only ever
// suffixes the name — every replica's spec is identical (no templating).
func buildChild(set *corev1.ApplicationSet, comp corev1.NamedApplicationSpec, node string, replica *int) (corev1.Application, error) {
	spec, err := deepCopySpec(comp.Spec)
	if err != nil {
		return corev1.Application{}, fmt.Errorf("applicationset %q component %q: copy spec: %w", set.Name, comp.Name, err)
	}
	projectCommon(&spec, set.Spec.Common)
	// A component that declares ports and names no service joins the one the set renders for it.
	// Stamped before the hash, so "already converged" is computed over what the child actually
	// carries.
	if svc := serviceFor(set, comp); svc != "" {
		spec.ServiceName = svc
	}
	name := set.Name + "-" + comp.Name
	if replica != nil {
		name += "-" + strconv.Itoa(*replica)
	}
	if node != "" {
		spec.Placement.NodeName = node
		name += "-" + node
	}
	controller := true
	// Stamp the digest of the rendered spec so the controller can tell "already converged" from
	// "changed" without comparing against a stored spec that admission has since mutated.
	annotations := mergeStrings(set.Spec.Common.Annotations, comp.Metadata.Annotations)
	hash, err := specHash(spec)
	if err != nil {
		return corev1.Application{}, fmt.Errorf("applicationset %q component %q: %w", set.Name, comp.Name, err)
	}
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[corev1.AnnAppsetSpecHash] = hash // stamped last, so a tenant cannot preset it
	return corev1.Application{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        sanitizeName(name),
			Namespace:   set.Namespace, // children always inherit the set's namespace (no cross-namespace fan-out)
			Labels:      childLabels(set, comp),
			Annotations: annotations,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: corev1.GroupVersion.String(), Kind: "ApplicationSet",
				Name: set.Name, UID: set.UID, Controller: &controller,
			}},
		},
		Spec: spec,
	}, nil
}

// specHash digests a rendered child spec. It is the convergence signal, so it must be stable
// across reconciles: ApplicationSpec is plain data and encoding/json emits struct fields in
// declaration order and map keys sorted, so the digest does not flap.
func specHash(spec corev1.ApplicationSpec) (string, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// deepCopySpec isolates a component's spec from the set before projectCommon mutates its
// env/volumes (a JSON round-trip — there is no generated DeepCopy). ApplicationSpec is plain
// data so the round-trip is faithful; a marshal error is surfaced, not dropped.
func deepCopySpec(spec corev1.ApplicationSpec) (corev1.ApplicationSpec, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return corev1.ApplicationSpec{}, err
	}
	var out corev1.ApplicationSpec
	if err := json.Unmarshal(b, &out); err != nil {
		return corev1.ApplicationSpec{}, err
	}
	return out, nil
}

// childLabels merges the common and per-child labels (child wins), then stamps the reserved
// GC labels last so they are never overridable.
func childLabels(set *corev1.ApplicationSet, comp corev1.NamedApplicationSpec) map[string]string {
	out := mergeStrings(set.Spec.Common.Labels, comp.Metadata.Labels)
	if out == nil {
		out = map[string]string{}
	}
	out[corev1.LabelApplicationSet] = set.Name
	out[corev1.LabelComponent] = comp.Name
	return out
}

// projectCommon layers the set's shared config into a child spec: common env merged UNDER the
// child's own (the child key wins), and common volumes appended deduplicated by mountPath (a
// child mount at the same path wins). Labels/annotations are projected separately at the
// metadata level.
func projectCommon(spec *corev1.ApplicationSpec, common corev1.CommonMeta) {
	haveEnv := map[string]bool{}
	for _, e := range spec.Env {
		haveEnv[e.Name] = true
	}
	for _, e := range common.Env {
		if !haveEnv[e.Name] {
			spec.Env = append(spec.Env, e) // child's own env (emitted first) wins on Name
			haveEnv[e.Name] = true         // and the first common var wins over a later same-Name dup
		}
	}
	have := map[string]bool{}
	for _, m := range spec.Volumes {
		have[m.MountPath] = true
	}
	for _, m := range common.Volumes {
		if !have[m.MountPath] {
			spec.Volumes = append(spec.Volumes, m)
		}
	}
}

// selectorMatches reports whether every selector label is present with the same value in have.
func selectorMatches(selector, have map[string]string) bool {
	for k, v := range selector {
		if have[k] != v {
			return false
		}
	}
	return true
}

// mergeStrings merges base and over into a new map (over wins on a key clash); nil if both empty.
func mergeStrings(base, over map[string]string) map[string]string {
	if len(base) == 0 && len(over) == 0 {
		return nil
	}
	out := map[string]string{}
	maps.Copy(out, base)
	maps.Copy(out, over)
	return out
}

// sanitizeName lowercases name and maps invalid characters to '-' so it is a valid DNS-1123
// object name, trimming and (on overflow) truncating to 253 with a hash suffix.
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-.")
	if len(s) > 253 {
		sum := sha256.Sum256([]byte(s))
		s = s[:244] + "-" + fmt.Sprintf("%x", sum[:4])
	}
	return s
}
