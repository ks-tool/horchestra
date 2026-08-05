package appset

import (
	"fmt"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func comp(name, image string) corev1.NamedApplicationSpec {
	return corev1.NamedApplicationSpec{Name: name, Spec: corev1.ApplicationSpec{Image: image}}
}

func spreadComp(name, image string, selector map[string]string) corev1.NamedApplicationSpec {
	c := comp(name, image)
	c.Scale.NodeSpread = &corev1.NodeSpread{NodeSelector: selector}
	return c
}

func bundleSet(name, ns string, apps ...corev1.NamedApplicationSpec) *corev1.ApplicationSet {
	return &corev1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.ApplicationSetSpec{Applications: apps},
	}
}

func labeledNode(name string, labels map[string]string) corev1.Node {
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func childByName(children []corev1.Application, name string) *corev1.Application {
	for i := range children {
		if children[i].Name == name {
			return &children[i]
		}
	}
	return nil
}

func mustExpand(t *testing.T, set *corev1.ApplicationSet) []corev1.Application {
	t.Helper()
	children, err := Expand(set, nil)
	if err != nil {
		t.Fatal(err)
	}
	return children
}

func TestExpandBundle(t *testing.T) {
	set := bundleSet("checkout", "shop", comp("db", "postgres:16"), comp("api", "reg/api:v1"))
	children := mustExpand(t, set)
	if len(children) != 2 {
		t.Fatalf("want 2 children, got %d", len(children))
	}
	db := childByName(children, "checkout-db")
	if db == nil {
		t.Fatal("checkout-db not rendered")
	}
	if db.Namespace != "shop" {
		t.Errorf("child namespace = %q, want shop", db.Namespace)
	}
	if db.Spec.Image != "postgres:16" {
		t.Errorf("child image = %q", db.Spec.Image)
	}
	if db.Spec.Placement.NodeName != "" {
		t.Errorf("a bundle child must leave nodeName empty for the scheduler, got %q", db.Spec.Placement.NodeName)
	}
	if db.Labels[corev1.LabelApplicationSet] != "checkout" || db.Labels[corev1.LabelComponent] != "db" {
		t.Errorf("reserved labels missing: %v", db.Labels)
	}
	if r := db.OwnerReferences; len(r) != 1 || r[0].Kind != "ApplicationSet" || r[0].Name != "checkout" || r[0].Controller == nil || !*r[0].Controller {
		t.Errorf("child must carry a controller ownerReference to the set, got %v", r)
	}
}

func TestExpandNodeSpread(t *testing.T) {
	set := bundleSet("mon", "obs", spreadComp("exp", "prom:v1", map[string]string{"role": "edge"}))
	nodes := []corev1.Node{
		labeledNode("n1", map[string]string{"role": "edge"}),
		labeledNode("n2", map[string]string{"role": "core"}),
		labeledNode("n3", map[string]string{"role": "edge"}),
	}
	children, err := Expand(set, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 2 {
		t.Fatalf("want one child per matching edge node (2), got %d", len(children))
	}
	c1 := childByName(children, "mon-exp-n1")
	if c1 == nil || c1.Spec.Placement.NodeName != "n1" {
		t.Fatalf("a nodeSpread child must be pinned to its node, got %+v", c1)
	}
	if childByName(children, "mon-exp-n2") != nil {
		t.Error("must not spread onto a non-matching node")
	}
}

func TestExpandNodeSpreadNoNodes(t *testing.T) {
	children, err := Expand(bundleSet("mon", "obs", spreadComp("exp", "prom:v1", nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 0 {
		t.Fatalf("no nodes → no nodeSpread children, got %d", len(children))
	}
}

func TestExpandProjectsCommon(t *testing.T) {
	set := bundleSet("web", "team", corev1.NamedApplicationSpec{
		Name: "a", Spec: corev1.ApplicationSpec{Image: "a:v1", Env: []corev1.EnvVar{{Name: "OWN", Value: "1"}}},
	})
	set.Spec.Common = corev1.CommonMeta{
		Labels:  map[string]string{"stack": "web"},
		Env:     []corev1.EnvVar{{Name: "OWN", Value: "override"}, {Name: "SHARED", Value: "yes"}},
		Volumes: []corev1.VolumeMount{{Volume: corev1.VolumeSource{Type: corev1.VolumeTypeTmpfs}, MountPath: "/scratch"}},
	}
	a := childByName(mustExpand(t, set), "web-a")
	if envVal(a.Spec.Env, "OWN") != "1" {
		t.Error("child env must win over common")
	}
	if envVal(a.Spec.Env, "SHARED") != "yes" {
		t.Error("common env must be projected under the child's")
	}
	if a.Labels["stack"] != "web" {
		t.Error("common label must be projected onto the child")
	}
	if len(a.Spec.Volumes) != 1 || a.Spec.Volumes[0].MountPath != "/scratch" {
		t.Errorf("common volume must be appended, got %v", a.Spec.Volumes)
	}
}

// envVal returns the value of the named env var in an ordered env list, or "" if absent.
func envVal(env []corev1.EnvVar, name string) string {
	for _, e := range env {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}

func TestExpandEmptyIsError(t *testing.T) {
	if _, err := Expand(bundleSet("x", "y"), nil); err == nil {
		t.Error("a set with no applications must be an error")
	}
}

func TestExpandDuplicateNameIsError(t *testing.T) {
	if _, err := Expand(bundleSet("web", "team", comp("a", "a:v1"), comp("a", "b:v1")), nil); err == nil {
		t.Error("duplicate component names must be an error")
	}
}

func TestSanitizeName(t *testing.T) {
	if got := sanitizeName("Web_App/1"); got != "web-app-1" {
		t.Errorf("sanitizeName = %q, want web-app-1", got)
	}
}

// TestExpandCapsFanout: expansion is the component list crossed with matching nodes, both
// tenant-controlled, and each child is a real object driven through the lister-backed admission
// chain. Uncapped, one request becomes tens of thousands of writes.
func TestExpandCapsFanout(t *testing.T) {
	set := &corev1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{Name: "big", Namespace: "team-a"},
	}
	for i := range MaxChildren + 5 {
		set.Spec.Applications = append(set.Spec.Applications, corev1.NamedApplicationSpec{
			Name: fmt.Sprintf("c%d", i),
			Spec: corev1.ApplicationSpec{Image: "example.com/app:v1"},
		})
	}
	if _, err := Expand(set, nil); err == nil {
		t.Fatalf("expanding %d components must be refused by the %d-child cap", len(set.Spec.Applications), MaxChildren)
	}

	set.Spec.Applications = set.Spec.Applications[:3]
	children, err := Expand(set, nil)
	if err != nil {
		t.Fatalf("an ordinary set must still expand: %v", err)
	}
	if len(children) != 3 {
		t.Fatalf("got %d children, want 3", len(children))
	}
}

// TestExpandStampsSpecHash: the digest is what the controller compares to decide whether a child
// needs rewriting, so it must be present, differ with the spec, and not be presettable by the
// tenant through the set's own annotations.
func TestExpandStampsSpecHash(t *testing.T) {
	build := func(image, ann string) corev1.Application {
		set := &corev1.ApplicationSet{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a"},
			Spec: corev1.ApplicationSetSpec{
				Common: corev1.CommonMeta{
					Annotations: map[string]string{corev1.AnnAppsetSpecHash: ann},
				},
				Applications: []corev1.NamedApplicationSpec{{
					Name: "api",
					Spec: corev1.ApplicationSpec{Image: image},
				}},
			},
		}
		out, err := Expand(set, nil)
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		return out[0]
	}

	a := build("example.com/app:v1", "forged-by-the-tenant")
	if got := a.Annotations[corev1.AnnAppsetSpecHash]; got == "" || got == "forged-by-the-tenant" {
		t.Fatalf("spec hash = %q: it must be stamped by the controller, not taken from the set", got)
	}
	b := build("example.com/app:v1", "")
	if a.Annotations[corev1.AnnAppsetSpecHash] != b.Annotations[corev1.AnnAppsetSpecHash] {
		t.Fatal("the same spec must hash the same, or the controller never converges")
	}
	c := build("example.com/app:v2", "")
	if a.Annotations[corev1.AnnAppsetSpecHash] == c.Annotations[corev1.AnnAppsetSpecHash] {
		t.Fatal("a changed spec must change the hash, or an update is never applied")
	}
}

// TestExpandReplicas: the second typed fan-out — N identical children named
// <set>-<component>-<i>, spec byte-identical (there is no templating), placement left to
// the scheduler for each independently.
func TestExpandReplicas(t *testing.T) {
	three := int32(3)
	comp := corev1.NamedApplicationSpec{
		Name:  "redis",
		Scale: corev1.Scale{Replicas: &three},
		Spec:  corev1.ApplicationSpec{Image: "redis:7"},
	}
	children := mustExpand(t, bundleSet("data", "team", comp))
	if len(children) != 3 {
		t.Fatalf("want 3 children, got %d", len(children))
	}
	for i, want := range []string{"data-redis-0", "data-redis-1", "data-redis-2"} {
		c := childByName(children, want)
		if c == nil {
			t.Fatalf("missing child %q (got %v)", want, names(children))
		}
		if c.Spec.Placement.NodeName != "" {
			t.Fatalf("child %q must be left to the scheduler, got nodeName %q", want, c.Spec.Placement.NodeName)
		}
		if c.Labels[corev1.LabelComponent] != "redis" {
			t.Fatalf("child %q: component label = %q", want, c.Labels[corev1.LabelComponent])
		}
		if i > 0 { // every replica carries the same rendered spec
			if c.Annotations[corev1.AnnAppsetSpecHash] != children[0].Annotations[corev1.AnnAppsetSpecHash] {
				t.Fatalf("replica %d has a different spec hash than replica 0", i)
			}
		}
	}
}

// TestExpandReplicasOneIsIndexed: setting replicas at all switches the component to indexed
// names — the discontinuity is deliberate and documented (toggling it renames children).
func TestExpandReplicasOneIsIndexed(t *testing.T) {
	one := int32(1)
	children := mustExpand(t, bundleSet("data", "team", corev1.NamedApplicationSpec{
		Name: "redis", Scale: corev1.Scale{Replicas: &one}, Spec: corev1.ApplicationSpec{Image: "redis:7"},
	}))
	if len(children) != 1 || children[0].Name != "data-redis-0" {
		t.Fatalf("want one child data-redis-0, got %v", names(children))
	}
}

// TestExpandReplicasCapsFanout: the fan-out cap counts replicas too — a component may not
// turn one request into an unbounded write storm.
func TestExpandReplicasCapsFanout(t *testing.T) {
	huge := int32(MaxChildren + 1)
	if _, err := Expand(bundleSet("data", "team", corev1.NamedApplicationSpec{
		Name: "redis", Scale: corev1.Scale{Replicas: &huge}, Spec: corev1.ApplicationSpec{Image: "redis:7"},
	}), nil); err == nil {
		t.Fatal("a replica count past MaxChildren must be refused")
	}
}

func names(children []corev1.Application) []string {
	out := make([]string, 0, len(children))
	for i := range children {
		out = append(out, children[i].Name)
	}
	return out
}
