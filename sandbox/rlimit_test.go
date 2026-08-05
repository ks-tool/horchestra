//go:build linux

package sandbox

import (
	"encoding/json"
	"testing"

	"golang.org/x/sys/unix"
)

// "infinity" exists so the config can say what 2^64-1 means. It has to survive a round trip, or
// a config that reads back differently from what was written is worse than one without the word.
func TestRlimitValueJSON(t *testing.T) {
	for _, tc := range []struct {
		json string
		want uint64
	}{
		{`1024`, 1024},
		{`0`, 0},
		{`"infinity"`, unix.RLIM_INFINITY},
	} {
		var v RlimitValue
		if err := json.Unmarshal([]byte(tc.json), &v); err != nil {
			t.Fatalf("%s: %v", tc.json, err)
		}
		if uint64(v) != tc.want {
			t.Errorf("%s decoded to %d, want %d", tc.json, v, tc.want)
		}
		back, err := json.Marshal(v)
		if err != nil || string(back) != tc.json {
			t.Errorf("%s round-tripped to %s (%v)", tc.json, back, err)
		}
	}
	var v RlimitValue
	if err := json.Unmarshal([]byte(`"lots"`), &v); err == nil {
		t.Error("a value that is neither a number nor infinity must be refused")
	}
}

// Only lowering works — raising a hard limit takes CAP_SYS_RESOURCE in the initial user
// namespace — so a config asking for more than it inherited must be refused where the reason can
// still be explained, not with an EPERM from inside the sandbox.
func TestValidateRlimits(t *testing.T) {
	var nofile unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &nofile); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		limits map[string]Rlimit
		ok     bool
	}{
		{"lowering", map[string]Rlimit{"NOFILE": {Soft: 64, Hard: 128}}, true},
		{"zero core", map[string]Rlimit{"CORE": {Soft: 0, Hard: 0}}, true},
		{"at the inherited hard limit",
			map[string]Rlimit{"NOFILE": {Soft: 1, Hard: RlimitValue(nofile.Max)}}, true},
		{"none at all", nil, true},
		{"unknown resource", map[string]Rlimit{"BANANAS": {Soft: 1, Hard: 1}}, false},
		{"soft above hard", map[string]Rlimit{"NOFILE": {Soft: 128, Hard: 64}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRlimits(tc.limits)
			if tc.ok && err != nil {
				t.Fatalf("valid limits refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected the limits to be refused")
			}
		})
	}

	// Raising above the inherited hard limit is refusable only when there is room above it.
	if nofile.Max != unix.RLIM_INFINITY {
		limits := map[string]Rlimit{"NOFILE": {Soft: 1, Hard: RlimitValue(nofile.Max + 1)}}
		if err := validateRlimits(limits); err == nil {
			t.Error("a hard limit above the inherited one must be refused")
		}
	}
}

// Every name the config accepts must map to a real resource, and the set must line up with what
// systemd calls the same thing — the whole point of the naming.
func TestRlimitResourceTable(t *testing.T) {
	for name, res := range rlimitResources {
		var rl unix.Rlimit
		if err := unix.Getrlimit(res, &rl); err != nil {
			t.Errorf("rlimit %s (%d): %v", name, res, err)
		}
	}
	for _, name := range []string{"NOFILE", "NPROC", "CORE", "AS", "FSIZE", "MEMLOCK", "STACK"} {
		if _, ok := rlimitResources[name]; !ok {
			t.Errorf("systemd has Limit%s= but the config does not accept %s", name, name)
		}
	}
}
