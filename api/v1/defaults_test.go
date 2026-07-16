package v1

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

func TestApplicationDefault(t *testing.T) {
	// Static default: an empty restartPolicy becomes Always.
	a := &Application{}
	a.Default()
	if a.Spec.RestartPolicy != RestartAlways {
		t.Fatalf("restartPolicy default = %q, want %q", a.Spec.RestartPolicy, RestartAlways)
	}

	// An explicit restartPolicy is preserved.
	b := &Application{Spec: ApplicationSpec{RestartPolicy: RestartNever}}
	b.Default()
	if b.Spec.RestartPolicy != RestartNever {
		t.Fatalf("restartPolicy overwritten: got %q", b.Spec.RestartPolicy)
	}

	// Computed default (not a static tag): an unset request falls back to the limit.
	c := &Application{Spec: ApplicationSpec{Resources: ResourceRequirements{
		Limits: ResourceAmounts{CPU: resource.MustParse("2"), Memory: resource.MustParse("1Gi")},
	}}}
	c.Default()
	if c.Spec.Resources.Requests.CPU.Cmp(resource.MustParse("2")) != 0 {
		t.Fatalf("cpu request not defaulted from limit: %v", c.Spec.Resources.Requests.CPU)
	}
	if c.Spec.Resources.Requests.Memory.Cmp(resource.MustParse("1Gi")) != 0 {
		t.Fatalf("memory request not defaulted from limit: %v", c.Spec.Resources.Requests.Memory)
	}

	// An explicit request is not overwritten by the limit.
	d := &Application{Spec: ApplicationSpec{Resources: ResourceRequirements{
		Requests: ResourceAmounts{CPU: resource.MustParse("500m")},
		Limits:   ResourceAmounts{CPU: resource.MustParse("2")},
	}}}
	d.Default()
	if d.Spec.Resources.Requests.CPU.Cmp(resource.MustParse("500m")) != 0 {
		t.Fatalf("explicit cpu request overwritten: %v", d.Spec.Resources.Requests.CPU)
	}
}
