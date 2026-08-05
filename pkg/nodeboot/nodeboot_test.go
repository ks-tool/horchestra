package nodeboot

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
)

// csrServer mocks the controller's CSR REST: POST records the submitted CSR (Pending); GET
// returns it, flipping to Approved after approveAfter polls (or Denied when deny is set) —
// with a certificate, or without one when offline mimics an offline-CA controller.
func csrServer(t *testing.T, approveAfter int, deny, offline bool) (*httptest.Server, *certv1.CertificateSigningRequest, *int) {
	t.Helper()
	var submitted certv1.CertificateSigningRequest
	polls := 0
	base := "/apis/certificates.horchestra.io/v1/certificatesigningrequests"
	mux := http.NewServeMux()
	mux.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&submitted)
		submitted.Status.Phase = certv1.CSRPending
		_ = json.NewEncoder(w).Encode(submitted)
	})
	mux.HandleFunc(base+"/", func(w http.ResponseWriter, r *http.Request) {
		polls++
		out := submitted
		switch {
		case deny:
			out.Status = certv1.CertificateSigningRequestStatus{Phase: certv1.CSRDenied, Reason: "squatting guard"}
		case polls >= approveAfter:
			out.Status = certv1.CertificateSigningRequestStatus{Phase: certv1.CSRApproved, Certificate: []byte("SIGNED-CERT-PEM")}
			if offline {
				out.Status.Certificate = nil
			}
		default:
			out.Status.Phase = certv1.CSRPending
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &submitted, &polls
}

func TestEnroll(t *testing.T) {
	srv, submitted, _ := csrServer(t, 2, false, false)
	res, err := Enroll(context.Background(), Options{
		ControllerURL: srv.URL, NodeName: "node1",
		HTTPClient: srv.Client(), PollInterval: time.Millisecond, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.CertPEM) != "SIGNED-CERT-PEM" {
		t.Errorf("cert = %q, want the signed cert", res.CertPEM)
	}
	if len(res.KeyPEM) == 0 {
		t.Error("the generated private key must be returned")
	}
	// The submitted CSR must carry the node name and a valid PEM request.
	if submitted.Spec.NodeName != "node1" {
		t.Errorf("submitted nodeName = %q, want node1", submitted.Spec.NodeName)
	}
	if block, _ := pem.Decode(submitted.Spec.Request); block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Error("the submitted request must be a PEM CERTIFICATE REQUEST")
	}
}

func TestEnrollDenied(t *testing.T) {
	srv, _, _ := csrServer(t, 1, true, false)
	_, err := Enroll(context.Background(), Options{
		ControllerURL: srv.URL, NodeName: "node1",
		HTTPClient: srv.Client(), PollInterval: time.Millisecond, Timeout: 2 * time.Second,
	})
	if err == nil {
		t.Fatal("a denied CSR must return an error")
	}
}

func TestEnrollTimeout(t *testing.T) {
	srv, _, _ := csrServer(t, 999, false, false) // never approves
	_, err := Enroll(context.Background(), Options{
		ControllerURL: srv.URL, NodeName: "node1",
		HTTPClient: srv.Client(), PollInterval: 5 * time.Millisecond, Timeout: 30 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("enrollment must time out when the CSR is never signed")
	}
}

func TestEnrollOfflineCAFailsFastAndLoud(t *testing.T) {
	srv, _, polls := csrServer(t, 1, false, true) // Approved, but no certificate: offline-CA
	_, err := Enroll(context.Background(), Options{
		ControllerURL: srv.URL, NodeName: "node1",
		HTTPClient: srv.Client(), PollInterval: time.Millisecond, Timeout: time.Minute,
	})
	if err == nil {
		t.Fatal("an approved CSR with no certificate must fail, not poll to the timeout")
	}
	for _, want := range []string{"offline-CA", "--cluster-ca"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must name the missing signer configuration (%q)", err, want)
		}
	}
	if *polls != 1 {
		t.Errorf("polls = %d, want 1 (the failure is definitive on the first Approved status)", *polls)
	}
}
