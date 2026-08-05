package systemd

import (
	"fmt"
	"strings"
)

// validateOptionValue rejects a rendered unit-option value that would change the STRUCTURE of
// the unit file rather than just its own directive. go-systemd serializes each option as
// "Name=Value" verbatim, so the value is the one place a caller-supplied string meets the
// unit-file grammar, and both of its escapes matter:
//
//   - a newline/CR ADDS a directive — an image env "X=y\nUser=0" emits a spurious User=0;
//   - a trailing odd run of backslashes REMOVES one — systemd joins a continued line with the
//     next, and WorkingDirectory= is rendered immediately before User=, so an image whose
//     config.WorkingDir ends in a backslash swallows its own User= line. A service with no
//     User= runs as root, which defeats the no-root backstop from the other direction.
//
// It lives outside the linux-only renderer so the grammar rules can be exercised anywhere.
func validateOptionValue(name, value string) error {
	if strings.ContainsAny(value, "\n\r\x00") {
		return fmt.Errorf("unit option %q value %q contains a newline, carriage return or NUL (would inject a directive)", name, value)
	}
	if trailingBackslashes(value)%2 == 1 {
		return fmt.Errorf("unit option %q value %q ends in a line continuation (would swallow the next directive)", name, value)
	}
	if name == "ExecStart" && hasCommandSeparator(value) {
		return fmt.Errorf("unit option %q value %q carries a bare %q command separator (would start a second, possibly privileged, command line)", name, value, ";")
	}
	return nil
}

// hasCommandSeparator reports whether a rendered ExecStart= value holds a bare ";" word.
// systemd concatenates several command lines in ONE ExecStart= when they are separated by an
// unquoted semicolon word, re-parsing the '@-:+!' privilege modifiers for each — so a following
// line prefixed '+' runs fully privileged, outside User= and the hardened floor. quoteExecArg
// quotes ';' so no argv element can reach this; this is the output-side assertion that the
// rendered directive is still exactly ONE command line, whatever produced it.
//
// The scan mirrors systemd's own test (config_parse_exec): a separator is a ';' that starts a
// word and is followed by end-of-value or whitespace, considered only outside double quotes.
func hasCommandSeparator(value string) bool {
	var inQuotes, escaped bool
	atWordStart := true
	for i := range len(value) {
		c := value[i]
		switch {
		case escaped:
			escaped, atWordStart = false, false
		case c == '\\' && inQuotes:
			escaped = true
		case c == '"':
			inQuotes, atWordStart = !inQuotes, false
		case inQuotes:
			atWordStart = false
		case c == ' ' || c == '\t':
			atWordStart = true
		case c == ';' && atWordStart && (i+1 == len(value) || value[i+1] == ' ' || value[i+1] == '\t'):
			return true
		default:
			atWordStart = false
		}
	}
	return false
}

// trailingBackslashes counts the backslashes a value ends with. An odd count is what systemd's
// parser reads as a line continuation; an even count is escaped literal backslashes and is safe.
func trailingBackslashes(s string) int {
	return len(s) - len(strings.TrimRight(s, `\`))
}
