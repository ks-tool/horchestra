package v1

import (
	"maps"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testNode(name string, platform Platform, spec map[string]string) *Node {
	return &Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: spec},
		Status:     NodeStatus{Platform: platform},
	}
}

// TestDerivedNodeLabels: the set is computed from the node's own report, and a fact the node
// did not report yields NO key — an empty-valued label would answer an Exists term with a lie
// and make DoesNotExist unusable.
func TestDerivedNodeLabels(t *testing.T) {
	full := DerivedNodeLabels(testNode("n1", Platform{OS: "linux", Arch: "amd64"}, nil))
	want := map[string]string{LabelHostname: "n1", LabelOS: "linux", LabelArch: "amd64"}
	if !maps.Equal(full, want) {
		t.Errorf("derived = %v, want %v", full, want)
	}
	// Every derived key lives under the reserved domain — that is what makes admission's
	// spec.labels refusal sufficient to keep one key from having two sources.
	for k := range full {
		if !strings.HasPrefix(k, LabelDomain) {
			t.Errorf("derived label %q is outside the reserved %q domain and can be shadowed from spec.labels", k, LabelDomain)
		}
	}

	bare := DerivedNodeLabels(testNode("n1", Platform{}, nil))
	if _, ok := bare[LabelOS]; ok {
		t.Error("a node that reported no platform must carry no os label, not an empty one")
	}
	if bare[LabelHostname] != "n1" {
		t.Error("the hostname label comes from the node's name, which registration already proved")
	}
}

// TestSchedulingLabelsMergeAndPrecedence: a placement rule sees one namespace of keys, and a
// spec entry cannot shadow a derived one. Admission refuses that entry at the write, but a
// Node stored before the refusal existed must still not be able to claim another architecture.
func TestSchedulingLabelsMergeAndPrecedence(t *testing.T) {
	n := testNode("n1", Platform{OS: "linux", Arch: "amd64"}, map[string]string{
		"tier":    "secure",
		LabelArch: "arm64", // a stored lie
	})
	n.Status.Labels = DerivedNodeLabels(n)

	got := n.SchedulingLabels()
	if got["tier"] != "secure" {
		t.Error("the operator's own labels must survive the merge")
	}
	if got[LabelArch] != "amd64" {
		t.Errorf("derived arch = %q, want amd64 — spec.labels must not shadow a measured fact", got[LabelArch])
	}
	if v, ok := n.SchedulingLabel(LabelArch); !ok || v != "amd64" {
		t.Errorf("SchedulingLabel disagrees with SchedulingLabels: %q, %v", v, ok)
	}
	if v, ok := n.SchedulingLabel("tier"); !ok || v != "secure" {
		t.Errorf("SchedulingLabel lost a spec-only key: %q, %v", v, ok)
	}
	if _, ok := n.SchedulingLabel("absent"); ok {
		t.Error("an absent key must report absent")
	}

	// The merged map is a copy: the snapshot the scheduler holds is shared across a whole
	// pass, so a rule writing into the result would leak into the next node's evaluation.
	got["tier"] = "public"
	if n.Labels["tier"] != "secure" {
		t.Error("the merged map aliases spec.labels")
	}
}
