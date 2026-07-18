//go:build linux

package systemd

import (
	"strings"
	"testing"
)

// TestUnitRenderTypeAndCaps checks the run-to-completion and capability directives
// added for restartPolicy/securityContext support.
func TestUnitRenderTypeAndCaps(t *testing.T) {
	empty := ""
	out, err := Unit{
		Description:           "x",
		ExecStart:             []string{"/bin/true"},
		Type:                  "oneshot",
		RemainAfterExit:       true,
		Group:                 "70",
		CapabilityBoundingSet: &empty,
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Type=oneshot", "RemainAfterExit=yes", "Group=70", "CapabilityBoundingSet="} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered unit missing %q\n%s", want, out)
		}
	}
}

// TestUnitRenderDefaults checks an empty Type falls back to simple and that unset
// optional directives are not emitted.
func TestUnitRenderDefaults(t *testing.T) {
	out, err := Unit{ExecStart: []string{"/bin/true"}}.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Type=simple") {
		t.Errorf("empty Type should render Type=simple\n%s", out)
	}
	if strings.Contains(out, "RemainAfterExit") || strings.Contains(out, "CapabilityBoundingSet") || strings.Contains(out, "Group=") {
		t.Errorf("unset optional directives must not render\n%s", out)
	}
}
