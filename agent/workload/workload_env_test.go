package workload

import (
	"reflect"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEnvStrings(t *testing.T) {
	tests := []struct {
		name string
		in   []corev1.EnvVar
		want []string
	}{
		{
			name: "nil returns empty non-nil slice",
			in:   nil,
			want: []string{},
		},
		{
			name: "empty returns empty non-nil slice",
			in:   []corev1.EnvVar{},
			want: []string{},
		},
		{
			name: "joins name and value with =",
			in:   []corev1.EnvVar{{Name: "KEY", Value: "VALUE"}},
			want: []string{"KEY=VALUE"},
		},
		{
			name: "empty value keeps trailing =",
			in:   []corev1.EnvVar{{Name: "KEY", Value: ""}},
			want: []string{"KEY="},
		},
		{
			name: "preserves declared order (not sorted)",
			in: []corev1.EnvVar{
				{Name: "Z", Value: "1"},
				{Name: "A", Value: "2"},
				{Name: "M", Value: "3"},
			},
			want: []string{"Z=1", "A=2", "M=3"},
		},
		{
			name: "duplicate names kept as separate entries in order",
			in: []corev1.EnvVar{
				{Name: "DUP", Value: "first"},
				{Name: "OTHER", Value: "x"},
				{Name: "DUP", Value: "second"},
			},
			want: []string{"DUP=first", "OTHER=x", "DUP=second"},
		},
		{
			name: "value containing = is preserved (only joined once)",
			in:   []corev1.EnvVar{{Name: "URL", Value: "a=b=c"}},
			want: []string{"URL=a=b=c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := envStrings(tt.in)
			if got == nil {
				t.Fatalf("envStrings(%#v) = nil, want non-nil slice", tt.in)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("envStrings(%#v) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

// envStrings must not alias the caller's EnvVar backing array — it produces a
// fresh []string of its own, and the input order is what lands in the output.
func TestEnvStringsIsFreshSlice(t *testing.T) {
	in := []corev1.EnvVar{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}}
	got := envStrings(in)
	if len(got) != len(in) {
		t.Fatalf("envStrings len = %d, want %d", len(got), len(in))
	}
	// Mutating the source after projection must not change the projection.
	in[0].Value = "mutated"
	if got[0] != "A=1" {
		t.Fatalf("envStrings result changed after mutating source: got[0] = %q, want %q", got[0], "A=1")
	}
}

func TestFromApplicationEnv(t *testing.T) {
	t.Run("projects env in declared order", func(t *testing.T) {
		app := corev1.Application{
			Spec: corev1.ApplicationSpec{
				Env: []corev1.EnvVar{
					{Name: "FIRST", Value: "1"},
					{Name: "SECOND", Value: "2"},
					{Name: "FIRST", Value: "dup"},
				},
			},
		}
		want := []string{"FIRST=1", "SECOND=2", "FIRST=dup"}
		if got := FromApplication(app).Env; !reflect.DeepEqual(got, want) {
			t.Fatalf("FromApplication Env = %#v, want %#v", got, want)
		}
	})

	t.Run("nil env projects to empty non-nil slice", func(t *testing.T) {
		got := FromApplication(corev1.Application{}).Env
		if got == nil {
			t.Fatalf("FromApplication Env = nil, want empty non-nil slice")
		}
		if len(got) != 0 {
			t.Fatalf("FromApplication Env = %#v, want empty slice", got)
		}
	})
}

func TestFromApplicationFields(t *testing.T) {
	sc := &corev1.SecurityContext{RunAsUser: new(int64(65532))}
	vols := []corev1.VolumeMount{
		{Volume: corev1.VolumeSource{Type: corev1.VolumeTypeTmpfs}, MountPath: "/scratch"},
	}
	app := corev1.Application{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a"},
		Spec: corev1.ApplicationSpec{
			Image:     "reg.io/ns/web:v1",
			Placement: corev1.Placement{NodeName: "node-1"},
			Command:   []string{"/bin/app"},
			Args:      []string{"--flag", "value"},
			Env:       []corev1.EnvVar{{Name: "K", Value: "V"}},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceAmounts{CPU: resource.MustParse("500m"), Memory: resource.MustParse("256Mi")},
				Limits:   corev1.ResourceAmounts{CPU: resource.MustParse("1"), Memory: resource.MustParse("512Mi")},
			},
			Lifecycle:       corev1.Lifecycle{RestartPolicy: corev1.RestartOnFailure},
			SecurityContext: sc,
			Volumes:         vols,
		},
	}

	got := FromApplication(app)

	if got.Name != "web" {
		t.Errorf("Name = %q, want web", got.Name)
	}
	if got.Namespace != "team-a" {
		t.Errorf("Namespace = %q, want team-a", got.Namespace)
	}
	if got.Node != "node-1" {
		t.Errorf("Node = %q, want node-1 (from spec.nodeName)", got.Node)
	}
	if got.Image != "reg.io/ns/web:v1" {
		t.Errorf("Image = %q, want reg.io/ns/web:v1", got.Image)
	}
	if !reflect.DeepEqual(got.Command, []string{"/bin/app"}) {
		t.Errorf("Command = %#v, want [/bin/app]", got.Command)
	}
	if !reflect.DeepEqual(got.Args, []string{"--flag", "value"}) {
		t.Errorf("Args = %#v, want [--flag value]", got.Args)
	}
	if !reflect.DeepEqual(got.Env, []string{"K=V"}) {
		t.Errorf("Env = %#v, want [K=V]", got.Env)
	}
	if got.Requests.CPU.Cmp(resource.MustParse("500m")) != 0 || got.Requests.Memory.Cmp(resource.MustParse("256Mi")) != 0 {
		t.Errorf("Requests = %+v, want cpu=500m memory=256Mi", got.Requests)
	}
	if got.Limits.CPU.Cmp(resource.MustParse("1")) != 0 || got.Limits.Memory.Cmp(resource.MustParse("512Mi")) != 0 {
		t.Errorf("Limits = %+v, want cpu=1 memory=512Mi", got.Limits)
	}
	if got.Lifecycle.RestartPolicy != corev1.RestartOnFailure {
		t.Errorf("RestartPolicy = %q, want %q", got.Lifecycle.RestartPolicy, corev1.RestartOnFailure)
	}
	if got.SecurityContext != sc {
		t.Errorf("SecurityContext = %p, want the spec pointer %p (no copy)", got.SecurityContext, sc)
	}
	if !reflect.DeepEqual(got.Volumes, vols) {
		t.Errorf("Volumes = %#v, want %#v", got.Volumes, vols)
	}
}
