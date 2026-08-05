// Package v1 defines the node certificate Kind: a CertificateSigningRequest (a PEM request the
// controller's approval loop signs into a short-lived system:nodes client certificate). A node's
// private key never leaves the box — only its CSR is signed. Initial node identity is provisioned
// out-of-band by node-tool (which owns the PKI); this Kind carries certificate rotation, where a
// node re-issues a cert for its own name over its current mTLS credential (the selfnodeclient path).
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Groups and phase constants.
const (
	GroupNodes = "system:nodes"

	CSRPending  = "Pending"
	CSRApproved = "Approved"
	CSRDenied   = "Denied"

	// AnnRequester is stamped by admission from the authenticated identity that created the CSR
	// (never a client claim), so the approval loop can recognize a node rotating its own
	// certificate — the selfnodeclient path, where the requester equals the CSR's CN.
	AnnRequester = "certificates.horchestra.io/requester"
	// AnnRequesterGroups is the comma-joined groups of the authenticated creator, stamped by
	// admission — so the loop can confirm the requester carries system:nodes before self-approving
	// its rotation, without trusting a client claim.
	AnnRequesterGroups = "certificates.horchestra.io/requester-groups"
)

// CertificateSigningRequest is a PEM certificate request the controller approves and signs. The
// approval loop auto-signs it only on the selfnodeclient rotation path: the authenticated
// requester is a system:nodes identity whose name equals the CSR's CN. Any other CSR is left
// Pending for manual (or offline-CA, node-tool) approval.
type CertificateSigningRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   CertificateSigningRequestSpec   `json:"spec"`
	Status CertificateSigningRequestStatus `json:"status"`
}

// CertificateSigningRequestSpec is the PEM request and the groups the requester asks for.
type CertificateSigningRequestSpec struct {
	// Request is the PEM-encoded PKCS#10 certificate request.
	Request []byte `json:"request"`
	// Groups the requester asks the issued cert to carry (the approval loop enforces that these
	// are exactly system:nodes for auto-approval).
	Groups []string `json:"groups,omitempty"`
	// NodeName is the node CN the request is for (informational; the loop derives the CN from the
	// PEM request itself).
	NodeName string `json:"nodeName,omitempty"`
}

// CertificateSigningRequestStatus carries the approval decision and the issued certificate.
type CertificateSigningRequestStatus struct {
	// Phase is Pending, Approved or Denied.
	Phase string `json:"phase,omitempty"`
	// Certificate is the issued PEM client certificate, set when the CSR is Approved and signed.
	Certificate []byte `json:"certificate,omitempty"`
	// Reason explains a Denied request, or why a Pending one is still waiting.
	Reason string `json:"reason,omitempty"`
}

// CertificateSigningRequestList is a list of CSRs.
type CertificateSigningRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CertificateSigningRequest `json:"items"`
}
