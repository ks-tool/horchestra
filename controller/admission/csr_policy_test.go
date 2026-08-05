package admission

import (
	"bytes"
	"context"
	"maps"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
)

// TestCSRPolicyRequesterImmutableOnUpdate locks the fix for the forgeable-requester finding: the
// requester identity is stamped at Create and must survive an Update verbatim, so a caller cannot
// rewrite the annotations the approval loop's selfnodeclient predicate trusts to sign a cert.
func TestCSRPolicyRequesterImmutableOnUpdate(t *testing.T) {
	ctx := context.Background()
	gvk := certv1.GroupVersion.WithKind("CertificateSigningRequest")

	old := &certv1.CertificateSigningRequest{
		TypeMeta: metav1.TypeMeta{APIVersion: certv1.GroupVersion.String(), Kind: "CertificateSigningRequest"},
		ObjectMeta: metav1.ObjectMeta{Name: "csr1", Annotations: map[string]string{
			certv1.AnnRequester:       "node-a",
			certv1.AnnRequesterGroups: "system:nodes",
		}},
	}
	// An update that tries to forge the requester (impersonate another node / escalate groups).
	forged := &certv1.CertificateSigningRequest{
		TypeMeta: old.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{Name: "csr1", Annotations: map[string]string{
			certv1.AnnRequester:       "attacker",
			certv1.AnnRequesterGroups: "system:masters",
		}},
	}
	attrs := &Attributes{GVK: gvk, Operation: Update, Object: forged, OldObject: old}
	if err := (csrPolicy{}).Admit(ctx, attrs); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if got := forged.Annotations[certv1.AnnRequester]; got != "node-a" {
		t.Fatalf("requester forged on update: got %q, want node-a", got)
	}
	if got := forged.Annotations[certv1.AnnRequesterGroups]; got != "system:nodes" {
		t.Fatalf("requester groups forged on update: got %q, want system:nodes", got)
	}
}

// copyCSR detaches the fields these cases mutate from the stored object.
func copyCSR(c *certv1.CertificateSigningRequest) *certv1.CertificateSigningRequest {
	out := *c
	out.Annotations = maps.Clone(c.Annotations)
	out.Spec.Request = bytes.Clone(c.Spec.Request)
	return &out
}

// TestCSRSigningInputsImmutable: the approval loop signs whatever public key spec.request holds
// at the moment it decides. Preserving the requester annotations is therefore not enough on its
// own — a requester who can update spec.request after creation (or after approval) has the
// controller sign a key of their choosing under an identity vetted for a different one. Status is
// preserved too, so a plain update cannot self-approve; the loop writes it through the status
// subresource, which does not run this path.
func TestCSRSigningInputsImmutable(t *testing.T) {
	stored := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "node-a",
			Annotations: map[string]string{certv1.AnnRequester: "node-a", certv1.AnnRequesterGroups: "system:nodes"},
		},
		Spec:   certv1.CertificateSigningRequestSpec{Request: []byte("ORIGINAL-CSR-PEM"), NodeName: "node-a"},
		Status: certv1.CertificateSigningRequestStatus{Phase: certv1.CSRApproved},
	}

	t.Run("spec.request may not change", func(t *testing.T) {
		incoming := copyCSR(stored)
		incoming.Spec.Request = []byte("ATTACKER-CSR-PEM")
		if err := (csrPolicy{}).Admit(t.Context(), &Attributes{
			Operation: Update, Object: incoming, OldObject: stored,
		}); err == nil {
			t.Fatal("spec.request was allowed to change after creation")
		}
	})

	t.Run("spec.nodeName may not change", func(t *testing.T) {
		incoming := copyCSR(stored)
		incoming.Spec.NodeName = "node-b"
		if err := (csrPolicy{}).Admit(t.Context(), &Attributes{
			Operation: Update, Object: incoming, OldObject: stored,
		}); err == nil {
			t.Fatal("spec.nodeName was allowed to change after creation")
		}
	})

	t.Run("status cannot be rewritten through a plain update", func(t *testing.T) {
		incoming := copyCSR(stored)
		incoming.Status = certv1.CertificateSigningRequestStatus{Phase: certv1.CSRPending}
		if err := (csrPolicy{}).Admit(t.Context(), &Attributes{
			Operation: Update, Object: incoming, OldObject: stored,
		}); err != nil {
			t.Fatalf("an otherwise-unchanged update must be allowed: %v", err)
		}
		if incoming.Status.Phase != certv1.CSRApproved {
			t.Fatalf("status.phase = %q, want the stored value preserved", incoming.Status.Phase)
		}
	})
}
