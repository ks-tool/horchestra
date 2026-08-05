package plugins

import (
	"context"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/controller/loops/scheduler/framework"
)

func nodeWithRuntimes(runtimes ...string) *framework.NodeInfo {
	return &framework.NodeInfo{Node: corev1.Node{Status: corev1.NodeStatus{Runtimes: runtimes}}}
}

func appWithClass(class string) *corev1.Application {
	return &corev1.Application{Spec: corev1.ApplicationSpec{RuntimeClassName: class}}
}

func TestRuntimeClassFilter(t *testing.T) {
	p := NewRuntimeClass()
	ctx := context.Background()
	st := framework.NewCycleState()

	cases := []struct {
		name     string
		class    string
		runtimes []string
		fits     bool
	}{
		{"empty class fits any node", "", nil, true},
		{"empty class fits a node advertising runtimes", "", []string{"systemd"}, true},
		{"named class fits a node advertising it", "firecracker", []string{"systemd", "firecracker"}, true},
		{"named class rejects a node lacking it", "firecracker", []string{"systemd"}, false},
		{"named class rejects a node advertising nothing", "systemd", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Filter(ctx, st, appWithClass(tc.class), nodeWithRuntimes(tc.runtimes...))
			if got.IsSuccess() != tc.fits {
				t.Fatalf("fits=%v, want %v (status %v)", got.IsSuccess(), tc.fits, got)
			}
		})
	}
}
