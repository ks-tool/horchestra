package nodeserver

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"google.golang.org/grpc/peer"
)

// fakePTR answers reverse lookups from a fixed table; an address absent from it has no PTR.
type fakePTR map[string][]string

func (f fakePTR) LookupAddr(_ context.Context, addr string) ([]string, error) {
	names, ok := f[addr]
	if !ok {
		return nil, errors.New("no such host")
	}
	return names, nil
}

// TestNameCoversPTR pins the matching rule at every depth: a certificate name covers a PTR when it
// is a label-aligned prefix of it — the whole name or any number of its leading labels — and the
// number of labels is not part of the rule, so a five-label FQDN behaves exactly like a two-label
// one. Everything that is not label-aligned is refused.
func TestNameCoversPTR(t *testing.T) {
	for _, ptr := range []string{
		"n1.rack2.dc3.example.org.", // five labels
		"hostname.example.org.",     // three
		"node-1.internal.",          // two
		"single.",                   // one
	} {
		labels := strings.Split(strings.TrimSuffix(ptr, "."), ".")
		// Every leading run of labels must cover it, up to and including the full name.
		for i := range labels {
			cn := strings.Join(labels[:i+1], ".")
			if !nameCoversPTR(cn, ptr) {
				t.Errorf("nameCoversPTR(%q, %q) = false, want true", cn, ptr)
			}
			if !nameCoversPTR(strings.ToUpper(cn), ptr) {
				t.Errorf("nameCoversPTR(%q, %q) = false, want true (case-insensitive)", strings.ToUpper(cn), ptr)
			}
		}
		// A prefix that stops inside a label, a longer name, and a suffix are not covers.
		first := labels[0]
		rejects := []string{
			"",
			first[:len(first)-1],                    // stops inside the first label
			ptr + "extra",                           // longer than the PTR
			"other." + strings.TrimSuffix(ptr, "."), // the PTR is the suffix, not the prefix
		}
		if len(labels) > 1 {
			rejects = append(rejects,
				strings.Join(labels[1:], "."),      // a parent zone, not this host
				"x."+strings.Join(labels[1:], "."), // a sibling host in the same zone
			)
		}
		for _, cn := range rejects {
			if nameCoversPTR(cn, ptr) {
				t.Errorf("nameCoversPTR(%q, %q) = true, want false", cn, ptr)
			}
		}
	}
}

// TestStrictRegistrationChecksThePeer: with strict registration a name may only be claimed by the
// host DNS gives it to. Without it the certificate is the whole claim — the displayed name is the CN
// and it need not resolve anywhere.
func TestStrictRegistrationChecksThePeer(t *testing.T) {
	ptr := fakePTR{"10.0.0.7": {"node-1.example.org."}}

	cases := []struct {
		name    string
		cn      string
		peer    string
		strict  bool
		wantErr string
	}{
		{name: "the short name of the host it connects from", cn: "node-1", peer: "10.0.0.7", strict: true},
		{name: "the full name", cn: "node-1.example.org", peer: "10.0.0.7", strict: true},
		{name: "another host's name", cn: "node-2", peer: "10.0.0.7", strict: true, wantErr: "does not cover"},
		{name: "an address with no reverse name", cn: "node-1", peer: "10.0.0.9", strict: true, wantErr: "no reverse name"},
		{name: "not strict: any name registers", cn: "whatever", peer: "10.0.0.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := New(newFake(t))
			if tc.strict {
				WithStrictRegistration(ptr)(srv)
			}
			err := srv.checkRegistration(peerContext(t, tc.peer), tc.cn)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("must be allowed to register, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("must be refused (want %q)", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestStrictRegistrationGatesTheNodeObject drives the real status path: a node that fails the check
// is not registered at all — no Node object, so nothing is ever pushed to it — while an
// ALREADY-REGISTERED node keeps reporting, because the check belongs to registration and a later
// DNS outage must not evict a running fleet.
func TestStrictRegistrationGatesTheNodeObject(t *testing.T) {
	ctl := newFake(t)
	srv := New(ctl)
	WithStrictRegistration(fakePTR{})(srv) // nothing has a reverse name
	ctx := peerContext(t, "10.0.0.7")
	reported := `{"metadata":{"name":"` + nodeName + `"},"status":{"ready":true}}`

	if err := srv.applyStatus(ctx, nodeName, []byte(reported)); err == nil {
		t.Fatal("a node that cannot prove its name must not register")
	}
	if _, err := ctl.Get(ctx, nodeMeta(nodeName)); err == nil {
		t.Fatal("no Node object may exist for a refused registration")
	}

	// Once it is registered — by an operator, or by a working DNS — reporting continues regardless.
	mustCreateNode(t, ctl, nodeName)
	if err := srv.applyStatus(ctx, nodeName, []byte(reported)); err != nil {
		t.Fatalf("an already-registered node must keep reporting: %v", err)
	}
	obj, err := ctl.Get(ctx, nodeMeta(nodeName))
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := obj.(*corev1.Node); !ok || !n.Status.Ready {
		t.Fatalf("the reported status must have been persisted, got %+v", obj)
	}
}

// peerContext is a context carrying a gRPC peer address, as the transport sets for a live session.
func peerContext(t *testing.T, ip string) context.Context {
	t.Helper()
	return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 45678}})
}
