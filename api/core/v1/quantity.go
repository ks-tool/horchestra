package v1

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// A resource quantity is short and its decimal exponent is small: "18446744073709551615Ki" is
// 22 characters, and 1e30 bytes is already a billion exabytes. Both are bounded here because
// resource.ParseQuantity is superlinear in the exponent — it rounds through an inf.Dec, which
// materializes 10^|exponent| as a big.Int — so "1e-100000000" costs tens of seconds of
// uninterruptible CPU and hundreds of MB for 13 bytes of input. The bound belongs at the decode
// because the typed decode runs BEFORE admission: no policy layer ever sees the value, and the
// request body cap bounds bytes, not exponent magnitude.
const (
	maxQuantityLen      = 32
	maxQuantityExponent = 30
)

// UnmarshalJSON bounds the volume's quantity literals, then decodes normally.
func (v *VolumeSource) UnmarshalJSON(raw []byte) error {
	if err := checkQuantityLiterals(raw); err != nil {
		return err
	}
	type plain VolumeSource
	return json.Unmarshal(raw, (*plain)(v))
}

// UnmarshalJSON bounds the volume's quantity literals, then decodes normally.
func (s *PersistentVolumeSpec) UnmarshalJSON(raw []byte) error {
	if err := checkQuantityLiterals(raw); err != nil {
		return err
	}
	type plain PersistentVolumeSpec
	return json.Unmarshal(raw, (*plain)(s))
}

// UnmarshalJSON bounds the cpu/memory literals, then decodes normally.
func (a *ResourceAmounts) UnmarshalJSON(raw []byte) error {
	if err := checkQuantityLiterals(raw); err != nil {
		return err
	}
	type plain ResourceAmounts
	return json.Unmarshal(raw, (*plain)(a))
}

// checkQuantityLiterals rejects an out-of-range numeric literal in the raw JSON of a
// quantity-bearing object, before resource.Quantity's UnmarshalJSON parses it. Every scalar
// field is checked, not the quantity-named keys alone: encoding/json matches field names
// case-insensitively and folds 's' to U+017F, so a key-directed probe can be spelled around
// ("ſize") while the typed decode still binds the value.
func checkQuantityLiterals(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil // not an object: the typed decode reports the shape error
	}
	for name, value := range fields {
		if err := checkNumericLiteral(value); err != nil {
			return fmt.Errorf("%s: %w", clip(name), err)
		}
	}
	return nil
}

// checkNumericLiteral bounds one JSON scalar that resource.ParseQuantity could be handed: a
// number, or a string that starts like one. Anything else — a path, a name, a base64 blob — is
// not a quantity literal and is left alone.
func checkNumericLiteral(value json.RawMessage) error {
	s := string(value)
	if len(s) == 0 {
		return nil
	}
	if s[0] == '"' {
		var unquoted string
		if json.Unmarshal(value, &unquoted) != nil {
			return nil // malformed string: the typed decode reports it
		}
		s = unquoted // decoded, so an escaped exponent ("1e-99999") reads as written
	}
	if !startsNumeric(s) {
		return nil
	}
	if len(s) > maxQuantityLen {
		return fmt.Errorf("quantity %q is longer than %d characters", clip(s), maxQuantityLen)
	}
	exp, ok := decimalExponent(s)
	if !ok {
		return nil
	}
	if exp > maxQuantityExponent || exp < -maxQuantityExponent {
		return fmt.Errorf("quantity %q: decimal exponent outside ±%d", s, maxQuantityExponent)
	}
	return nil
}

// startsNumeric reports whether s begins the way a quantity does, so ParseQuantity would try to
// read a number out of it.
func startsNumeric(s string) bool {
	c := s[0]
	if c == '+' || c == '-' {
		if len(s) == 1 {
			return false
		}
		c = s[1]
	}
	return c == '.' || (c >= '0' && c <= '9')
}

// decimalExponent returns the value of s's trailing decimal exponent ("1e-9" → -9). A quantity's
// SI suffix is not one ("1E" is exa, "1Ki" is binary), so an 'e'/'E' that is not followed by a
// signed integer reports false. An exponent of more than two digits is reported as just past the
// bound rather than converted, so a 30-digit one cannot overflow the conversion.
func decimalExponent(s string) (int, bool) {
	i := strings.IndexAny(s, "eE")
	if i < 0 {
		return 0, false
	}
	digits := s[i+1:]
	negative := false
	if len(digits) > 0 && (digits[0] == '+' || digits[0] == '-') {
		negative = digits[0] == '-'
		digits = digits[1:]
	}
	if digits == "" || strings.TrimLeft(digits, "0123456789") != "" {
		return 0, false // not an exponent (a suffix, or trailing junk the decode will reject)
	}
	exp := 0
	switch trimmed := strings.TrimLeft(digits, "0"); {
	case trimmed == "": // "1e000"
	case len(trimmed) > 2:
		exp = maxQuantityExponent + 1
	default:
		exp, _ = strconv.Atoi(trimmed)
	}
	if negative {
		exp = -exp
	}
	return exp, true
}

// clip bounds a caller-supplied string quoted back in an error message.
func clip(s string) string {
	if len(s) <= maxQuantityLen {
		return s
	}
	return s[:maxQuantityLen] + "…"
}
