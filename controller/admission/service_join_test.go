package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// svcAuthorizer allows `get services` only on the names it lists.
type svcAuthorizer struct{ allow map[string]bool }

func (s svcAuthorizer) Authorize(_ context.Context, at authz.Attributes) (bool, error) {
	if at.Resource != "services" || at.Verb != "get" {
		return false, nil
	}
	return s.allow[at.Name], nil
}

// TestJoiningAServiceNeedsToReadIt: membership is self-declared, which is what keeps the model free
// of a selector that could drift or be squatted — and the price of that is this check. Without it,
// anyone who can create an Application in a namespace can put themselves behind any service in it
// and take a share of its name and its traffic.
func TestJoiningAServiceNeedsToReadIt(t *testing.T) {
	j := serviceJoin{authorizer: svcAuthorizer{allow: map[string]bool{"mine": true}}}
	alice := authn.WithIdentity(context.Background(), &authn.Identity{Name: "alice"})
	app := func(service string) *Attributes {
		return &Attributes{Operation: Create, Object: &corev1.Application{
			ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web"},
			Spec:       corev1.ApplicationSpec{Image: "reg/x:v1", ServiceName: service},
		}}
	}

	if err := j.Validate(alice, app("mine")); err != nil {
		t.Errorf("joining a service she can read must be allowed: %v", err)
	}
	err := j.Validate(alice, app("someone-elses"))
	if err == nil || !strings.Contains(err.Error(), "may not join service") {
		t.Errorf("err = %v, want a refusal to join a service she cannot read", err)
	}
	// Joining nothing needs no permission — an edge is reached, not reaching.
	if err := j.Validate(alice, app("")); err != nil {
		t.Errorf("an application in no service must be allowed: %v", err)
	}
	// An internal writer (no identity) is trusted: a set's own write was checked with the
	// author's identity, which is what stops the check being bypassed by wrapping the workload
	// in a set.
	if err := j.Validate(context.Background(), app("someone-elses")); err != nil {
		t.Errorf("an internal writer must be trusted: %v", err)
	}
}

// TestASetIsAskedForEveryComponent: a set renders its children through an identity-less internal
// writer, so if the set's own write were not checked for all of them the rule would be bypassed by
// wrapping the workload in a bundle.
func TestASetIsAskedForEveryComponent(t *testing.T) {
	j := serviceJoin{authorizer: svcAuthorizer{allow: map[string]bool{"mine": true}}}
	alice := authn.WithIdentity(context.Background(), &authn.Identity{Name: "alice"})
	set := &Attributes{Operation: Create, Object: &corev1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "bundle"},
		Spec: corev1.ApplicationSetSpec{Applications: []corev1.NamedApplicationSpec{
			{Name: "a", Spec: corev1.ApplicationSpec{Image: "reg/x:v1", ServiceName: "mine"}},
			{Name: "b", Spec: corev1.ApplicationSpec{Image: "reg/x:v1", ServiceName: "someone-elses"}},
		}},
	}}

	if err := j.Validate(alice, set); err == nil {
		t.Error("a set joined a service its author cannot read")
	}
}
