package admission

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

func policyApp(spec corev1.ApplicationSpec) *corev1.Application {
	return &corev1.Application{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.GroupVersion.String(), Kind: "Application"},
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
		Spec:       spec,
	}
}

func TestAppPolicy(t *testing.T) {
	reqLim := func(reqCPU, limCPU, reqMem, limMem string) corev1.ApplicationSpec {
		amt := func(s string) resource.Quantity {
			if s == "" {
				return resource.Quantity{}
			}
			return resource.MustParse(s)
		}
		return corev1.ApplicationSpec{Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceAmounts{CPU: amt(reqCPU), Memory: amt(reqMem)},
			Limits:   corev1.ResourceAmounts{CPU: amt(limCPU), Memory: amt(limMem)},
		}}
	}

	cases := []struct {
		name   string
		spec   corev1.ApplicationSpec
		reject string
	}{
		{"requests within limits", reqLim("500m", "1", "256Mi", "512Mi"), ""},
		{"requests equal limits", reqLim("1", "1", "512Mi", "512Mi"), ""},
		{"cpu request exceeds limit", reqLim("2", "1", "", ""), "cpu request"},
		{"memory request exceeds limit", reqLim("", "", "2Gi", "1Gi"), "memory request"},
		{"negative cpu request", reqLim("-1", "", "", ""), "negative"},
		{"negative memory limit", reqLim("", "", "", "-1Gi"), "negative"},
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

// TestAppPolicyVolumePaths locks the path-injection/traversal guard: a mountPath or secret
// items[].path carrying whitespace, ':' or '..' must be rejected (it would inject a systemd
// bind directive or escape the per-workload mount root on the node), while a clean path passes.
func TestAppPolicyVolumePaths(t *testing.T) {
	vol := func(mountPath string, items ...corev1.KeyToPath) corev1.ApplicationSpec {
		return corev1.ApplicationSpec{Volumes: []corev1.VolumeMount{{
			Volume:    corev1.VolumeSource{Type: corev1.VolumeTypeSecret, Name: "s", Items: items},
			MountPath: mountPath,
		}}}
	}
	item := func(p string) corev1.KeyToPath { return corev1.KeyToPath{Key: "k", Path: p} }
	cases := []struct {
		name   string
		spec   corev1.ApplicationSpec
		reject string
	}{
		{"clean absolute mountPath", vol("/creds"), ""},
		{"mountPath with space injects a bind", vol("/data /etc:/x"), "whitespace"},
		{"mountPath with colon", vol("/data:/x"), "whitespace"},
		{"mountPath with .. traverses", vol("/data/../../etc"), "clean path"},
		{"relative mountPath", vol("data"), "absolute"},
		{"empty mountPath", vol(""), "required"},
		{"secret item path traversal", vol("/creds", item("../../etc/shadow")), "'..'"},
		{"secret item absolute path", vol("/creds", item("/etc/shadow")), "relative"},
		{"secret item clean path ok", vol("/creds", item("sub/key")), ""},
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

// TestIsolationIsAdmittedOnlyWhereItExists: `hostNetwork: false` is a request for something a node
// has to be able to deliver. Where the fleet has no routed range it is refused, naming the flag —
// admitting it would promise an isolation nothing on any node provides, and the workload would run
// flat with nobody the wiser.
func TestIsolationIsAdmittedOnlyWhereItExists(t *testing.T) {
	isolated := false
	app := &corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "team-a"},
		Spec:       corev1.ApplicationSpec{Image: "reg/api:v1", HostNetwork: &isolated},
	}
	attrs := &Attributes{GVK: corev1.GroupVersion.WithKind("Application"), Operation: Create, Object: app}

	err := (appPolicy{}).Validate(context.Background(), attrs)
	if err == nil {
		t.Fatal("isolation was admitted on a fleet that cannot provide it")
	}
	if !strings.Contains(err.Error(), "routed-cidr") {
		t.Errorf("the refusal must name what to do about it: %v", err)
	}
	if err := (appPolicy{routedNetwork: true}).Validate(context.Background(), attrs); err != nil {
		t.Errorf("isolation was refused on a fleet configured for it: %v", err)
	}
}
