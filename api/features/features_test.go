package features

import (
	"strings"
	"testing"
)

// TestParseRejectsWhatWouldSilentlyDoNothing: a mistyped gate is the failure mode worth
// designing against — an operator who believes a capability is on, and a cluster where it
// never was. Parse names what this build knows so the typo is answerable, not just refused.
func TestParseRejectsWhatWouldSilentlyDoNothing(t *testing.T) {
	for _, bad := range []string{"Nope=true", "VaultStaticRoles", "VaultStaticRoles=yes-please", "=true"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) was accepted", bad)
		}
	}
	if _, err := Parse("Nope=true"); err == nil || !strings.Contains(err.Error(), string(VaultStaticRoles)) {
		t.Errorf("an unknown gate must name what is known, got %v", err)
	}
	// The forms an operator actually types.
	for _, ok := range []string{"", "  ", "VaultStaticRoles=true", " VaultStaticRoles = false ", "VaultStaticRoles=1"} {
		if _, err := Parse(ok); err != nil {
			t.Errorf("Parse(%q): %v", ok, err)
		}
	}
}

// TestDefaultsAreOff: a gate exists because the capability is not yet something every
// cluster should carry, so an unset gate — and the nil map a caller with no opinion passes —
// must be off. A gate that defaulted on would be a capability with a switch, not a gate.
func TestDefaultsAreOff(t *testing.T) {
	var none Gates
	for _, name := range Names() {
		f := Feature(name)
		if none.Enabled(f) {
			t.Errorf("gate %s is on by default; a gate is opt-IN", f)
		}
		if registry[f].Doc == "" || registry[f].Stage == "" {
			t.Errorf("gate %s has no doc or stage, so --help cannot explain it", f)
		}
	}
	if none.Enabled(Feature("Removed")) {
		t.Error("an unknown gate must read as off")
	}
}

func TestEnabledFollowsTheExplicitEntry(t *testing.T) {
	g, err := Parse("VaultStaticRoles=true")
	if err != nil {
		t.Fatal(err)
	}
	if !g.Enabled(VaultStaticRoles) {
		t.Error("an explicit true must win over the default")
	}
	off, _ := Parse("VaultStaticRoles=false")
	if off.Enabled(VaultStaticRoles) {
		t.Error("an explicit false must be honoured")
	}
	// Round-trips through the flag's own form, stably — it is logged at startup.
	if got := g.String(); got != "VaultStaticRoles=true" {
		t.Errorf("String() = %q", got)
	}
	if Gates(nil).String() != "" {
		t.Error("an empty set must render empty, not as a literal map")
	}
}
