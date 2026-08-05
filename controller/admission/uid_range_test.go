package admission

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

func appWithIDs(uid *int64, gid *int64) *corev1.Application {
	return &corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Name: "web"},
		Spec:       corev1.ApplicationSpec{SecurityContext: &corev1.SecurityContext{RunAsUser: uid, RunAsGroup: gid}},
	}
}

// TestNoRootFloorRejectsTruncatingIDs: the floor forbids uid 0, and an id outside the kernel's
// uid_t is uid 0 — setresuid(2) takes the value in a 64-bit register but the kernel reads
// uid_t, so runAsUser 4294967296 execs the workload as root inside its user namespace. Testing
// only the literal 0 would leave the floor bypassable by arithmetic.
func TestNoRootFloorRejectsTruncatingIDs(t *testing.T) {
	cases := []struct {
		name      string
		uid, gid  int64
		forbidden bool
	}{
		{name: "the nonroot sentinel", uid: 65532, gid: 65532},
		{name: "ordinary ids", uid: 1000, gid: 1000},
		{name: "highest usable id", uid: 1<<32 - 2, gid: 1<<32 - 2},
		{name: "uid 0", uid: 0, gid: 65532, forbidden: true},
		{name: "gid 0", uid: 65532, gid: 0, forbidden: true},
		{name: "uid 2^32 truncates to root", uid: 1 << 32, gid: 65532, forbidden: true},
		{name: "gid 2^32 truncates to root", uid: 65532, gid: 1 << 32, forbidden: true},
		{name: "uid 2^32 + sentinel", uid: 1<<32 + 65532, gid: 65532, forbidden: true},
		{name: "negative uid", uid: -1, gid: 65532, forbidden: true},
		{name: "the (uid_t)-1 sentinel", uid: 1<<32 - 1, gid: 65532, forbidden: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := appWithIDs(&tc.uid, &tc.gid)
			a := &Attributes{GVK: corev1.GroupVersion.WithKind("Application"), Operation: Create, Object: app}
			// Through the whole chain, so this covers the shipped write path and not just the plugin.
			err := DefaultChain(nil, nil).Run(t.Context(), a)
			if tc.forbidden {
				if err == nil {
					t.Fatalf("runAsUser=%d runAsGroup=%d was admitted", tc.uid, tc.gid)
				}
				return
			}
			if err != nil {
				t.Fatalf("runAsUser=%d runAsGroup=%d rejected: %v", tc.uid, tc.gid, err)
			}
		})
	}
}

// TestNoRootFloorRejectsTruncatingIDsMessage: the rejection has to explain itself, or an
// operator reads "out of range" as a typo rather than as an attempted floor bypass.
func TestNoRootFloorRejectsTruncatingIDsMessage(t *testing.T) {
	uid := int64(1 << 32)
	app := appWithIDs(&uid, nil)
	err := (policyEnforcement{}).Validate(t.Context(), &Attributes{Operation: Create, Object: app})
	if err == nil {
		t.Fatal("runAsUser 2^32 was admitted")
	}
	if !strings.Contains(err.Error(), "out of range") || !strings.Contains(err.Error(), "runAsUser") {
		t.Fatalf("error = %q, want it to name runAsUser and the range", err)
	}
}
