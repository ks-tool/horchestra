package v1

import "testing"

// TestValidRunAsID: the no-root floor is "not zero", but the kernel reads a uid in 32-bit
// uid_t — so an id that is non-zero in int64 and zero mod 2^32 is a floor bypass, not a typo.
// The range guard is what makes "not zero" mean it.
func TestValidRunAsID(t *testing.T) {
	cases := []struct {
		name string
		id   int64
		ok   bool
	}{
		{"the nonroot sentinel", 65532, true},
		{"lowest usable id", 1, true},
		{"highest usable id", 1<<32 - 2, true},
		{"root", 0, false},
		{"negative", -1, false},
		{"negative truncating to a valid id", -4294901760, false}, // 0xFFFF0000 as uid_t
		{"2^32 truncates to root", 1 << 32, false},
		{"2^32 + the nonroot sentinel", 1<<32 + 65532, false},
		{"2^64-scale value truncating to root", 1 << 40, false},
		{"the (uid_t)-1 sentinel", 1<<32 - 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidRunAsID("runAsUser", tc.id)
			if (err == nil) != tc.ok {
				t.Fatalf("ValidRunAsID(%d) = %v, want ok=%v", tc.id, err, tc.ok)
			}
		})
	}
}

// TestValidRunAsIDCoversTruncation is the property the individual cases stand for: no accepted
// id may be congruent to 0 modulo 2^32, because that is the value setresuid(2) actually applies.
func TestValidRunAsIDCoversTruncation(t *testing.T) {
	for _, id := range []int64{0, 1 << 32, 1 << 33, 1 << 40, -1 << 32} {
		if ValidRunAsID("runAsUser", id) == nil {
			t.Fatalf("id %d truncates to uid 0 but was accepted", id)
		}
	}
}
