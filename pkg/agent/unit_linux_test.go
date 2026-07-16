//go:build linux

package agent

import (
	"testing"

	v1 "ks-tool.dev/horchestra/api/v1"
)

func launchSpecFixture() *LaunchSpec {
	return &LaunchSpec{Rootfs: "/tmp/rootfs", Entrypoint: []string{"/img-entry"}, Cmd: []string{"/img-cmd"}, User: "app"}
}

func argvEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestUnitCommandArgs pins the Kubernetes command/args override semantics onto the
// exec'd argv — the verify-before-exec surface, so a regression here changes what
// actually runs.
func TestUnitCommandArgs(t *testing.T) {
	cases := []struct {
		name    string
		command []string
		args    []string
		want    []string
	}{
		{"image entrypoint+cmd", nil, nil, []string{"/img-entry", "/img-cmd"}},
		{"command overrides entrypoint and drops cmd", []string{"/c"}, nil, []string{"/c"}},
		{"args overrides cmd, keeps entrypoint", nil, []string{"a"}, []string{"/img-entry", "a"}},
		{"command+args", []string{"/c"}, []string{"a", "b"}, []string{"/c", "a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := Unit(App{Name: "x", Command: tc.command, Args: tc.args}, launchSpecFixture(), nil, nil)
			if !argvEqual(u.ExecStart, tc.want) {
				t.Fatalf("ExecStart = %v, want %v", u.ExecStart, tc.want)
			}
		})
	}
}

// TestUnitRestartPolicy pins the restartPolicy -> systemd mapping, including the
// oneshot RemainAfterExit that keeps a completed job from being re-run.
func TestUnitRestartPolicy(t *testing.T) {
	cases := []struct {
		policy, restart, svcType string
		remain                   bool
	}{
		{v1.RestartAlways, "always", "simple", false},
		{v1.RestartOnFailure, "on-failure", "simple", false},
		{v1.RestartNever, "no", "oneshot", true},
		{"", "always", "simple", false}, // empty maps to Always
	}
	for _, tc := range cases {
		u := Unit(App{Name: "x", RestartPolicy: tc.policy}, launchSpecFixture(), nil, nil)
		if u.Restart != tc.restart || u.Type != tc.svcType || u.RemainAfterExit != tc.remain {
			t.Errorf("%q -> Restart=%q Type=%q Remain=%v, want %q/%q/%v",
				tc.policy, u.Restart, u.Type, u.RemainAfterExit, tc.restart, tc.svcType, tc.remain)
		}
	}
}

// TestUnitSecurityContext checks identity and capability rendering, and that the
// hardened floor is never disabled by a securityContext.
func TestUnitSecurityContext(t *testing.T) {
	uid, gid := int64(70), int64(70)
	u := Unit(App{Name: "x", SecurityContext: &v1.SecurityContext{
		RunAsUser: &uid, RunAsGroup: &gid,
		Capabilities: &v1.Capabilities{Drop: []string{"ALL"}},
	}}, launchSpecFixture(), nil, nil)
	if u.User != "70" || u.Group != "70" {
		t.Fatalf("User/Group = %q/%q, want 70/70", u.User, u.Group)
	}
	if u.CapabilityBoundingSet == nil || *u.CapabilityBoundingSet != "" {
		t.Fatalf("drop ALL -> CapabilityBoundingSet = %v, want empty (drop all)", u.CapabilityBoundingSet)
	}
	if !u.Hardened {
		t.Fatal("hardened floor must stay on with a securityContext set")
	}

	// Specific capabilities are removed with the "~" prefix and CAP_ normalization.
	u2 := Unit(App{Name: "x", SecurityContext: &v1.SecurityContext{
		Capabilities: &v1.Capabilities{Drop: []string{"net_admin", "SYS_TIME"}},
	}}, launchSpecFixture(), nil, nil)
	if u2.CapabilityBoundingSet == nil || *u2.CapabilityBoundingSet != "~CAP_NET_ADMIN CAP_SYS_TIME" {
		t.Fatalf("CapabilityBoundingSet = %v, want ~CAP_NET_ADMIN CAP_SYS_TIME", u2.CapabilityBoundingSet)
	}

	// No securityContext: the image User is kept, no capability set, floor on.
	u3 := Unit(App{Name: "x"}, launchSpecFixture(), nil, nil)
	if u3.User != "app" || u3.CapabilityBoundingSet != nil || !u3.Hardened {
		t.Fatalf("no-sc unit: User=%q cap=%v hardened=%v", u3.User, u3.CapabilityBoundingSet, u3.Hardened)
	}
}
