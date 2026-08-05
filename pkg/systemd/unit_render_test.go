//go:build linux

package systemd

import (
	"strings"
	"testing"
)

// TestUnitRenderTypeAndCaps checks the run-to-completion and capability directives
// added for restartPolicy/securityContext support.
func TestUnitRenderTypeAndCaps(t *testing.T) {
	out, err := Unit{
		Description:     "x",
		ExecStart:       []string{"/bin/true"},
		Type:            "oneshot",
		RemainAfterExit: true,
		Group:           "70",
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Type=oneshot", "RemainAfterExit=yes", "Group=70"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered unit missing %q\n%s", want, out)
		}
	}
}

// TestUnitRenderStateDirectory checks the StateDirectory= directive renders, giving a
// hardened non-root unit its writable data root under ProtectSystem=strict.
func TestUnitRenderStateDirectory(t *testing.T) {
	out, err := Unit{
		ExecStart:      []string{"/bin/true"},
		User:           "horchestra",
		Group:          "horchestra",
		StateDirectory: "horchestra",
		Hardened:       true,
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User=horchestra", "Group=horchestra", "StateDirectory=horchestra", "NoNewPrivileges=yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered unit missing %q\n%s", want, out)
		}
	}
}

// TestUnitRenderBindReadOnly checks a read-only bind renders BindReadOnlyPaths and does not
// add its destination to ReadWritePaths, while a writable bind renders BindPaths + ReadWritePaths.
func TestUnitRenderBindReadOnly(t *testing.T) {
	out, err := Unit{
		ExecStart:         []string{"/bin/true"},
		BindPaths:         []string{"/host/rw:/data"},
		ReadWritePaths:    []string{"/data"},
		BindReadOnlyPaths: []string{"/host/ro:/config"},
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"BindPaths=/host/rw:/data", "ReadWritePaths=/data", "BindReadOnlyPaths=/host/ro:/config"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered unit missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "ReadWritePaths=/config") {
		t.Errorf("a read-only bind's destination must not be in ReadWritePaths\n%s", out)
	}
}

// TestUnitRenderHardenedFloor checks the always-on confinement directives render under
// Hardened, that the two validation-pending ones are absent, and that a non-hardened unit
// renders none of them.
func TestUnitRenderHardenedFloor(t *testing.T) {
	out, err := Unit{ExecStart: []string{"/bin/true"}, Hardened: true}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateDevices=yes",
		"ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictNamespaces=yes",
		"RestrictSUIDSGID=yes", "SystemCallArchitectures=native", "CapabilityBoundingSet=",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("hardened unit missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "SystemCallFilter") {
		t.Error("SystemCallFilter must stay out of the floor until validated")
	}
	if plain, _ := (Unit{ExecStart: []string{"/bin/true"}}).Render(); strings.Contains(plain, "ProtectSystem") {
		t.Error("hardening must be gated on Hardened=true")
	}
	// NoNewPrivileges is part of the workload floor: exactly once for a hardened unit, and NOT on a
	// plain/daemon unit (which may need setuid helpers like newuidmap/fusermount3).
	if n := strings.Count(out, "NoNewPrivileges=yes"); n != 1 {
		t.Errorf("hardened unit must render NoNewPrivileges exactly once, got %d\n%s", n, out)
	}
	if plain, _ := (Unit{ExecStart: []string{"/bin/true"}}).Render(); strings.Contains(plain, "NoNewPrivileges") {
		t.Error("NoNewPrivileges is workload-only (Hardened); a plain/daemon unit must not get it")
	}
}

// TestUnitRenderSetCredential checks a service credential renders and that an unset one is
// not emitted.
func TestUnitRenderSetCredential(t *testing.T) {
	out, err := Unit{ExecStart: []string{"/bin/true"}, SetCredentials: []string{"creds_pw-abcd1234:s3cr3t"}}.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "SetCredential=creds_pw-abcd1234:s3cr3t") {
		t.Errorf("rendered unit missing SetCredential\n%s", out)
	}
	if plain, _ := (Unit{ExecStart: []string{"/bin/true"}}).Render(); strings.Contains(plain, "SetCredential") {
		t.Error("unset SetCredential must not render")
	}
}

// TestUnitRenderStartLimit checks the flapping backstop renders in the [Unit] section and
// that unset limits are omitted.
func TestUnitRenderStartLimit(t *testing.T) {
	out, err := Unit{
		ExecStart:             []string{"/bin/true"},
		StartLimitIntervalSec: "30s",
		StartLimitBurst:       "5",
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"StartLimitIntervalSec=30s", "StartLimitBurst=5"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered unit missing %q\n%s", want, out)
		}
	}
	if plain, _ := (Unit{ExecStart: []string{"/bin/true"}}).Render(); strings.Contains(plain, "StartLimit") {
		t.Error("unset StartLimit directives must not render")
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

// TestUnitRenderRejectsNewlineInjection checks that a value carrying a newline — e.g. an image
// env "X=y\nUser=0", or a WorkingDirectory carrying one — is refused at render, closing the
// directive-injection escape (go-systemd serializes Name=Value verbatim, so the newline would
// emit a spurious "User=0" that runs the service as root).
func TestUnitRenderRejectsNewlineInjection(t *testing.T) {
	for _, u := range []Unit{
		{ExecStart: []string{"/bin/true"}, User: "65532", Environment: []string{"X=y\nUser=0"}},
		{ExecStart: []string{"/bin/true"}, Environment: []string{"X=has space\nUser=0"}},
		{ExecStart: []string{"/bin/true"}, WorkingDirectory: "/w\nUser=0"},
		{ExecStart: []string{"/bin/true"}, BindPaths: []string{"/h:/d\nUser=0"}},
	} {
		if _, err := u.Render(); err == nil {
			t.Errorf("render must reject a value containing a newline: %+v", u)
		}
	}
	if _, err := (Unit{ExecStart: []string{"/bin/true"}, Environment: []string{"X=y"}}).Render(); err != nil {
		t.Fatalf("a clean unit must still render: %v", err)
	}
}
