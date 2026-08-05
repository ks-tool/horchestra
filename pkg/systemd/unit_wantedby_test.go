//go:build linux

package systemd

import (
	"strings"
	"testing"
)

// TestUnitRenderWantedBy checks the [Install] WantedBy target: unset falls back to the
// system default "multi-user.target", an explicit value (a per-user unit's
// "default.target") passes through, and in every case exactly one WantedBy line renders.
func TestUnitRenderWantedBy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wantedBy string
		want     string
	}{
		{name: "unset defaults to multi-user.target", wantedBy: "", want: "WantedBy=multi-user.target"},
		{name: "explicit default.target for a user unit", wantedBy: "default.target", want: "WantedBy=default.target"},
		{name: "explicit multi-user.target passes through", wantedBy: "multi-user.target", want: "WantedBy=multi-user.target"},
		{name: "arbitrary target passes through", wantedBy: "graphical.target", want: "WantedBy=graphical.target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Unit{ExecStart: []string{"/bin/true"}, WantedBy: tc.wantedBy}.Render()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("WantedBy=%q: rendered unit missing %q\n%s", tc.wantedBy, tc.want, out)
			}
			// The target must appear once and only once — no duplicate or leftover default line.
			if n := strings.Count(out, "WantedBy="); n != 1 {
				t.Errorf("WantedBy=%q: expected exactly one WantedBy line, got %d\n%s", tc.wantedBy, n, out)
			}
		})
	}
}

// TestUnitRenderWantedByUnsetIsNotDefaultTarget guards the fallback direction: an unset
// WantedBy must render the system target, never the per-user "default.target".
func TestUnitRenderWantedByUnsetIsNotDefaultTarget(t *testing.T) {
	out, err := Unit{ExecStart: []string{"/bin/true"}}.Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "WantedBy=default.target") {
		t.Errorf("unset WantedBy must default to multi-user.target, not default.target\n%s", out)
	}
	if !strings.Contains(out, "WantedBy=multi-user.target") {
		t.Errorf("unset WantedBy must render WantedBy=multi-user.target\n%s", out)
	}
}
