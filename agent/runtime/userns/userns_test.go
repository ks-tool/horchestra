//go:build linux

package userns

import (
	"os"
	"strings"
	"testing"
)

// TestEnterUsernsRefusesRoot: the guard exists because running as root FAILS OPEN in the worst
// way — a user namespace created by root maps 0→0, so the process keeps real host capabilities
// while every outward sign (namespaces entered, workloads running, clean log) matches the
// unprivileged case. Before the guard, the only thing that stopped it was root usually lacking
// an /etc/subuid range, and the resulting error advised adding one.
func TestEnterUsernsRefusesRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("this asserts what happens AS root; the unprivileged path is covered elsewhere")
	}
	t.Setenv(usernsMarker, "") // not already inside, so the guard is reached
	err := EnterUserns(os.Stderr, UsernsOptions{Flags: AgentUsernsFlags})
	if err == nil {
		t.Fatal("running as root must be refused, not silently accepted")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Fatalf("the refusal must say why: %v", err)
	}
}
