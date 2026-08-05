package admission

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	"github.com/ks-tool/horchestra/controller/authn"
)

// csrPolicy governs CertificateSigningRequest writes. Admit stamps the authenticated requester
// (CN and groups) onto a freshly created CSR — from the verified identity, never a client claim —
// so the approval loop's selfnodeclient predicate can confine a node to a certificate for its own
// CN, and forces the status to Pending: a requester cannot self-approve by presetting status;
// only the approval loop moves it forward. Validate rejects a malformed or unsigned request.
type csrPolicy struct{}

func (csrPolicy) Admit(ctx context.Context, a *Attributes) error {
	csr, ok := a.Object.(*certv1.CertificateSigningRequest)
	if !ok {
		return nil
	}
	if a.IsSubresource() {
		// The approval loop moves the CSR through its STATUS subresource. Reverting status here
		// on that very write is what made a node certificate impossible to rotate — the loop
		// approved, admission put the old status back, the loop saw pending again, and one
		// authenticated CSR became an unbounded sign-and-fsync loop holding the storage write
		// mutex. Nothing this plugin guards (the requester annotations, the signing inputs) can
		// change on a subresource write, so there is nothing to do.
		return nil
	}
	if a.Operation == Update {
		// The requester identity is stamped once, at Create, and is immutable thereafter:
		// carry it over verbatim from the stored object so an update can never forge the
		// annotations the approval loop's selfnodeclient predicate trusts to sign a cert.
		old, ok := a.OldObject.(*certv1.CertificateSigningRequest)
		if !ok {
			return nil
		}
		preserveRequester(csr, old)
		// The signing INPUTS are immutable too. Preserving the requester is not enough on its
		// own: the loop signs whatever public key spec.request carries at the moment it decides,
		// so a requester who could update spec.request after creation (or after approval) would
		// have the controller sign a key of their choosing under an identity that was vetted for
		// a different one.
		if !bytes.Equal(csr.Spec.Request, old.Spec.Request) || csr.Spec.NodeName != old.Spec.NodeName {
			return Forbidden("spec.request and spec.nodeName are immutable after creation")
		}
		// Status moves only through the status subresource, which returns above — so a requester
		// cannot self-approve with a plain update of the object.
		csr.Status = old.Status
		return nil
	}
	if a.Operation != Create {
		return nil
	}
	if id := authn.FromContext(ctx); id != nil {
		if csr.Annotations == nil {
			csr.Annotations = map[string]string{}
		}
		csr.Annotations[certv1.AnnRequester] = id.Name
		csr.Annotations[certv1.AnnRequesterGroups] = strings.Join(id.Groups, ",")
	}
	csr.Status = certv1.CertificateSigningRequestStatus{Phase: certv1.CSRPending}
	return nil
}

// preserveRequester restores the stamped requester annotations onto csr from the stored object,
// dropping any caller-supplied override, so the requester recorded at Create is authoritative.
func preserveRequester(csr, old *certv1.CertificateSigningRequest) {
	for _, key := range []string{certv1.AnnRequester, certv1.AnnRequesterGroups} {
		if v, ok := old.Annotations[key]; ok {
			if csr.Annotations == nil {
				csr.Annotations = map[string]string{}
			}
			csr.Annotations[key] = v
		} else {
			delete(csr.Annotations, key)
		}
	}
}

func (csrPolicy) Validate(_ context.Context, a *Attributes) error {
	if a.Operation == Delete {
		return nil
	}
	csr, ok := a.Object.(*certv1.CertificateSigningRequest)
	if !ok {
		return nil
	}
	block, _ := pem.Decode(csr.Spec.Request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("spec.request: not a PEM CERTIFICATE REQUEST")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("spec.request: %w", err)
	}
	if err := req.CheckSignature(); err != nil {
		return fmt.Errorf("spec.request: bad signature: %w", err)
	}
	if req.Subject.CommonName == "" {
		return fmt.Errorf("spec.request: the CSR must carry a common name (the node name)")
	}
	return nil
}
