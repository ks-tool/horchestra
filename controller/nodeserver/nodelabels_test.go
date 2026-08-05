package nodeserver

import (
	"context"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// reportedNode reads back the stored Node after a status report.
func reportedNode(t *testing.T, ctl *fakeController, name string) *corev1.Node {
	t.Helper()
	obj, err := ctl.Get(context.Background(), nodeMeta(name))
	if err != nil {
		t.Fatal(err)
	}
	n, ok := obj.(*corev1.Node)
	if !ok {
		t.Fatalf("stored object is %T, not a Node", obj)
	}
	return n
}

// TestDerivedLabelsAreStampedNotAccepted: the placement labels are computed here from what the
// node reported, exactly like the heartbeat is stamped here rather than taken. A node that
// sends its own set would be choosing which workloads it attracts — self-labelling into a
// placement pool is the same self-grant nodeRestriction refuses on spec, and status is the one
// field a node CAN write.
func TestDerivedLabelsAreStampedNotAccepted(t *testing.T) {
	ctl := newFake(t)
	srv := New(ctl)
	ctx := peerContext(t, "10.0.0.7")

	// The node reports a platform, and also claims a label pool it was never granted.
	reported := `{"metadata":{"name":"` + nodeName + `"},"status":{"ready":true,` +
		`"platform":{"os":"linux","arch":"amd64"},` +
		`"labels":{"horchestra.io/arch":"gpu","tier":"secure"}}}`
	if err := srv.applyStatus(ctx, nodeName, []byte(reported)); err != nil {
		t.Fatalf("first registration: %v", err)
	}

	n := reportedNode(t, ctl, nodeName)
	want := map[string]string{
		corev1.LabelHostname: nodeName,
		corev1.LabelOS:       "linux",
		corev1.LabelArch:     "amd64",
	}
	for k, v := range want {
		if n.Status.Labels[k] != v {
			t.Errorf("status.labels[%q] = %q, want %q", k, n.Status.Labels[k], v)
		}
	}
	if len(n.Status.Labels) != len(want) {
		t.Errorf("the node's own claimed labels survived: %v", n.Status.Labels)
	}
	// And they are what a placement rule sees, without the operator having typed anything.
	if v, ok := n.SchedulingLabel(corev1.LabelHostname); !ok || v != nodeName {
		t.Errorf("per-host topology is still unanswerable after registration: %q, %v", v, ok)
	}

	// Recomputed on every report, not frozen at registration: a machine re-imaged onto another
	// architecture must stop matching the rules that named the old one.
	reimaged := `{"metadata":{"name":"` + nodeName + `"},"status":{"ready":true,` +
		`"platform":{"os":"linux","arch":"arm64"}}}`
	if err := srv.applyStatus(ctx, nodeName, []byte(reimaged)); err != nil {
		t.Fatalf("second report: %v", err)
	}
	if got := reportedNode(t, ctl, nodeName).Status.Labels[corev1.LabelArch]; got != "arm64" {
		t.Errorf("arch label = %q after re-imaging, want arm64 — the set is stale", got)
	}
}
