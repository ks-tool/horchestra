package admission

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "ks-tool.dev/horchestra/api/v1"
)

func policyApp(spec v1.ApplicationSpec) *v1.Application {
	return &v1.Application{
		TypeMeta:   v1.ApplicationResource.TypeMeta(),
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
		Spec:       spec,
	}
}

func TestAppPolicy(t *testing.T) {
	tru := true
	zero, nonZero := int64(0), int64(70)
	reqLim := func(reqCPU, limCPU, reqMem, limMem string) v1.ApplicationSpec {
		amt := func(s string) resource.Quantity {
			if s == "" {
				return resource.Quantity{}
			}
			return resource.MustParse(s)
		}
		return v1.ApplicationSpec{Resources: v1.ResourceRequirements{
			Requests: v1.ResourceAmounts{CPU: amt(reqCPU), Memory: amt(reqMem)},
			Limits:   v1.ResourceAmounts{CPU: amt(limCPU), Memory: amt(limMem)},
		}}
	}

	cases := []struct {
		name   string
		spec   v1.ApplicationSpec
		reject string
	}{
		{"requests within limits", reqLim("500m", "1", "256Mi", "512Mi"), ""},
		{"requests equal limits", reqLim("1", "1", "512Mi", "512Mi"), ""},
		{"cpu request exceeds limit", reqLim("2", "1", "", ""), "cpu request"},
		{"memory request exceeds limit", reqLim("", "", "2Gi", "1Gi"), "memory request"},
		{"runAsNonRoot without uid", v1.ApplicationSpec{SecurityContext: &v1.SecurityContext{RunAsNonRoot: &tru}}, "runAsNonRoot"},
		{"runAsNonRoot with zero uid", v1.ApplicationSpec{SecurityContext: &v1.SecurityContext{RunAsNonRoot: &tru, RunAsUser: &zero}}, "runAsNonRoot"},
		{"runAsNonRoot with non-zero uid", v1.ApplicationSpec{SecurityContext: &v1.SecurityContext{RunAsNonRoot: &tru, RunAsUser: &nonZero}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := appPolicy{}.Validate(context.Background(), &Attributes{Operation: Create, Object: policyApp(tc.spec)})
			if tc.reject == "" {
				if err != nil {
					t.Fatalf("want accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.reject) {
				t.Fatalf("want rejection mentioning %q, got %v", tc.reject, err)
			}
		})
	}
}
