// Package nodeboot is the node side of certificate rotation: it generates a keypair and CSR,
// submits the CSR to the controller authenticated by the node's current certificate (mTLS), polls
// until the controller's selfnodeclient path signs it, and returns the issued credentials. The
// private key never leaves this process — only the CSR is sent for signing. Initial node identity
// is provisioned out-of-band by node-tool (which owns the PKI), so there is no token-join path.
package nodeboot

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	"github.com/ks-tool/horchestra/api/pki"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Options configures a rotation.
type Options struct {
	ControllerURL string        // https://host:8443
	NodeName      string        // the CN the node requests (its own name)
	CA            []byte        // trusted CA PEM (trustBundle); REQUIRED — there is no unverified path
	ClientCert    []byte        // current node cert (mTLS) — authenticates the rotation CSR
	ClientKey     []byte        // current node key
	PollInterval  time.Duration // default 2s
	Timeout       time.Duration // default 2m
	HTTPClient    *http.Client  // override (tests); else built from CA/ClientCert
}

// Result is the issued node credentials, ready to write into a node.conf.
type Result struct {
	CertPEM []byte
	KeyPEM  []byte
	CAPEM   []byte
}

const csrPath = "/apis/" + certv1.GroupName + "/" + certv1.Version + "/certificatesigningrequests"

// Enroll runs the CSR flow and returns the issued node credentials.
func Enroll(ctx context.Context, o Options) (*Result, error) {
	if o.PollInterval <= 0 {
		o.PollInterval = 2 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Minute
	}
	csrPEM, keyPEM, err := pki.GenerateCSR(o.NodeName)
	if err != nil {
		return nil, err
	}
	client := o.HTTPClient
	if client == nil {
		if client, err = o.httpClient(); err != nil {
			return nil, err
		}
	}
	name, err := submitCSR(ctx, client, o, csrPEM)
	if err != nil {
		return nil, fmt.Errorf("submit CSR: %w", err)
	}
	certPEM, err := pollCSR(ctx, client, o, name)
	if err != nil {
		return nil, err
	}
	return &Result{CertPEM: certPEM, KeyPEM: keyPEM, CAPEM: o.CA}, nil
}

func submitCSR(ctx context.Context, client *http.Client, o Options, csrPEM []byte) (string, error) {
	obj := certv1.CertificateSigningRequest{
		TypeMeta:   metav1.TypeMeta{APIVersion: certv1.GroupVersion.String(), Kind: "CertificateSigningRequest"},
		ObjectMeta: metav1.ObjectMeta{Name: o.NodeName + "-" + randHex(4)},
		Spec:       certv1.CertificateSigningRequestSpec{Request: csrPEM, NodeName: o.NodeName, Groups: []string{certv1.GroupNodes}},
	}
	body, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	var created certv1.CertificateSigningRequest
	if err := o.do(ctx, client, http.MethodPost, o.ControllerURL+csrPath, body, &created); err != nil {
		return "", err
	}
	return obj.Name, nil // the server may echo the object; the name we chose is authoritative
}

func pollCSR(ctx context.Context, client *http.Client, o Options, name string) ([]byte, error) {
	deadline := time.Now().Add(o.Timeout)
	for {
		var csr certv1.CertificateSigningRequest
		if err := o.do(ctx, client, http.MethodGet, o.ControllerURL+csrPath+"/"+name, nil, &csr); err == nil {
			switch csr.Status.Phase {
			case certv1.CSRApproved:
				if len(csr.Status.Certificate) > 0 {
					return csr.Status.Certificate, nil
				}
				// The online signer writes Approved and the certificate in one status update, so
				// Approved-without-certificate can only be the offline-CA controller — no amount of
				// polling will produce one. Fail now, naming the missing signer, instead of timing
				// out silently on every enrolment attempt.
				return nil, fmt.Errorf("CSR %s was approved but no certificate was issued: the controller runs in offline-CA mode (started without --cluster-ca/--cluster-ca-key) and can never sign a rotation — redeploy it with `node-tool deploy-controller --cluster-ca-key`, or rotate this node's credentials out-of-band", name)
			case certv1.CSRDenied:
				return nil, fmt.Errorf("CSR denied: %s", csr.Status.Reason)
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for the CSR to be signed")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(o.PollInterval):
		}
	}
}

// do issues one authenticated JSON request and decodes the response into out (when non-nil).
func (o Options) do(ctx context.Context, client *http.Client, method, url string, body []byte, out any) error {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, bytes.TrimSpace(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// httpClient builds the TLS client: it trusts o.CA (trustBundle) and presents o.ClientCert for a
// rotation's mutual TLS. There is no unverified mode and no flag to ask for one — enrolment and
// rotation are exactly where a node hands over or renews its identity, so a connection nobody
// verified there is a man in the middle issuing itself a valid node certificate, and the result
// is written back into node.conf, taking the node's trust anchor with it.
func (o Options) httpClient() (*http.Client, error) {
	tlsConf := &tls.Config{}
	if len(o.CA) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(o.CA) {
			return nil, fmt.Errorf("invalid CA PEM")
		}
		tlsConf.RootCAs = pool
	} else {
		return nil, fmt.Errorf("nodeboot: no CA supplied — refusing to enrol or rotate over an unverified connection")
	}
	if len(o.ClientCert) > 0 && len(o.ClientKey) > 0 {
		cert, err := tls.X509KeyPair(o.ClientCert, o.ClientKey)
		if err != nil {
			return nil, err
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
