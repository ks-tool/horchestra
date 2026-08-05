package systemd

import "testing"

// TestValidateOptionValueRejectsLineContinuation: a value ending in an odd run of backslashes
// makes systemd join the directive with the line that follows, so it does not add a directive
// (the newline case) but DELETES one. WorkingDirectory= is rendered immediately before User=
// and its value comes from the image config, so an image whose config.WorkingDir is `-/app\`
// swallows its own User= line — and a service with no User= runs as root.
func TestValidateOptionValueRejectsLineContinuation(t *testing.T) {
	reject := []struct{ name, value string }{
		{"WorkingDirectory", `-/app\`},
		{"WorkingDirectory", `/app\`},
		{"Environment", `X=y\`},
		{"SetCredential", `creds_pw:secret\`},
		{"BindPaths", `/h:/d\`},
		{"ExecStart", `/bin/sh -c foo\\\`}, // three: still odd
	}
	for _, tc := range reject {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			if err := validateOptionValue(tc.name, tc.value); err == nil {
				t.Fatalf("value %q must be rejected: it continues onto the next line", tc.value)
			}
		})
	}

	// An even run is an escaped literal backslash and must still render.
	accept := []struct{ name, value string }{
		{"WorkingDirectory", `/app`},
		{"Environment", `X=C:\\`},
		{"Environment", `X=a\b`}, // interior backslash, not trailing
		{"Description", ""},
	}
	for _, tc := range accept {
		t.Run("ok/"+tc.name+"="+tc.value, func(t *testing.T) {
			if err := validateOptionValue(tc.name, tc.value); err != nil {
				t.Fatalf("value %q must be accepted: %v", tc.value, err)
			}
		})
	}
}

// TestValidateOptionValueRejectsCommandSeparator: systemd concatenates several command lines in
// ONE ExecStart= when a bare ";" word separates them, and re-parses the '@-:+!' privilege
// modifiers for each — so a following line prefixed '+' runs fully privileged, ignoring User=
// and the whole hardened floor. quoteExecArg quotes ';' so no argv element can render one; this
// is the output-side assertion that a rendered ExecStart is still exactly one command line.
func TestValidateOptionValueRejectsCommandSeparator(t *testing.T) {
	for _, v := range []string{
		`/bin/true ; +/bin/sh -c id`,
		`/bin/true ;`,                      // separator at end of value
		`/bin/true ;	+/bin/sh`,             // separated by a tab
		`/bin/true "a b" ; +/bin/sh -c id`, // a quoted argument before the separator
	} {
		if err := validateOptionValue("ExecStart", v); err == nil {
			t.Fatalf("ExecStart %q must be rejected: the %q starts a second command line", v, ";")
		}
	}
}

// TestValidateOptionValueAcceptsQuotedSemicolon is the other half: a semicolon that is quoted,
// or merely part of a word, is a literal argument — `find … -exec … ;` and nginx's
// `-g "daemon off;"` both need it — and must still render.
func TestValidateOptionValueAcceptsQuotedSemicolon(t *testing.T) {
	for _, v := range []string{
		`/usr/bin/find /data -exec /bin/rm {} ";"`, // what quoteExecArg emits for a bare ";"
		`/docker-entrypoint.sh nginx -g "daemon off;"`,
		`/bin/sh -c "a;b"`,
		`/bin/true a;b`, // interior semicolon: not its own word, so not a separator
	} {
		if err := validateOptionValue("ExecStart", v); err != nil {
			t.Fatalf("ExecStart %q must be accepted: %v", v, err)
		}
	}
	// The check is ExecStart-specific: a semicolon is ordinary text in any other directive.
	if err := validateOptionValue("Environment", "X=a ; b"); err != nil {
		t.Fatalf("Environment must be accepted: %v", err)
	}
}

// TestValidateOptionValueRejectsControlChars keeps the original injection closed: a newline
// ADDS a directive where a trailing backslash removes one.
func TestValidateOptionValueRejectsControlChars(t *testing.T) {
	for _, v := range []string{"X=y\nUser=0", "a\rb", "a\x00b", "/w\nUser=0"} {
		if err := validateOptionValue("Environment", v); err == nil {
			t.Fatalf("value %q must be rejected", v)
		}
	}
}

func TestTrailingBackslashes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{``, 0},
		{`abc`, 0},
		{`abc\`, 1},
		{`abc\\`, 2},
		{`abc\\\`, 3},
		{`\`, 1},
		{`a\b`, 0},
	} {
		if got := trailingBackslashes(tc.in); got != tc.want {
			t.Errorf("trailingBackslashes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
