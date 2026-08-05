package v1

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ks-tool/horchestra/api/scheme"
)

// TestEnvVarMarshal pins the wire shape. Every field is omitempty because a wildcard secretRef
// legitimately carries NO name — its names come from the Secret's keys — so a serialized
// `"name":""` would state something the entry does not mean.
func TestEnvVarMarshal(t *testing.T) {
	cases := []struct {
		name string
		in   EnvVar
		want string
	}{
		{"name and value", EnvVar{Name: "X", Value: "y"}, `{"name":"X","value":"y"}`},
		{"empty value omitted", EnvVar{Name: "X"}, `{"name":"X"}`},
		{"an empty entry says nothing", EnvVar{}, `{}`},
		{
			"single-key secretRef",
			EnvVar{Name: "PGPASSWORD", SecretRef: &EnvSecretRef{Name: "creds", Key: "password"}},
			`{"name":"PGPASSWORD","secretRef":{"name":"creds","key":"password"}}`,
		},
		{
			"wildcard secretRef carries no name",
			EnvVar{SecretRef: &EnvSecretRef{Name: "creds", Key: EnvSecretAllKeys, Prefix: "PG_"}},
			`{"secretRef":{"name":"creds","key":"*","prefix":"PG_"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal %+v: %v", tc.in, err)
			}
			if string(b) != tc.want {
				t.Fatalf("marshal %+v = %s, want %s", tc.in, b, tc.want)
			}
		})
	}
}

// TestEnvVarRoundTrip decodes the canonical {"name","value"} object back to the same struct.
func TestEnvVarRoundTrip(t *testing.T) {
	orig := EnvVar{Name: "X", Value: "y"}

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got EnvVar
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	if got != orig {
		t.Fatalf("round-trip = %+v, want %+v", got, orig)
	}

	// The documented wire form unmarshals field-for-field.
	var direct EnvVar
	if err := json.Unmarshal([]byte(`{"name":"X","value":"y"}`), &direct); err != nil {
		t.Fatalf("unmarshal literal: %v", err)
	}
	if direct != orig {
		t.Fatalf("decoded literal = %+v, want %+v", direct, orig)
	}
}

// TestEnvVarListOrderPreserved checks the ordered-list contract: marshal→unmarshal keeps the
// declared order (a map would not), and order is significant — a reversed list is not equal.
func TestEnvVarListOrderPreserved(t *testing.T) {
	list := []EnvVar{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}, {Name: "C", Value: "3"}}

	b, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `[{"name":"A","value":"1"},{"name":"B","value":"2"},{"name":"C","value":"3"}]`
	if string(b) != want {
		t.Fatalf("marshal list = %s, want %s", b, want)
	}

	var got []EnvVar
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	if !slices.Equal(got, list) {
		t.Fatalf("round-trip list = %+v, want %+v (order preserved)", got, list)
	}

	// Field-sensitivity: the same entries in a different order must not compare equal.
	reversed := slices.Clone(got)
	slices.Reverse(reversed)
	if slices.Equal(got, reversed) {
		t.Fatalf("reversed list compared equal to %+v — order is not being compared", got)
	}
}

// TestApplicationEnvArrayDecodes decodes an Application whose spec.env is a JSON array of
// {name,value} objects and asserts it yields an ordered []EnvVar. Duplicate Names survive the
// decode intact (deduplication is admission's job, not the decoder's), which the ordered list
// makes representable at all.
func TestApplicationEnvArrayDecodes(t *testing.T) {
	s := scheme.New()
	AddToScheme(s)

	const body = `{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"web"},` +
		`"spec":{"image":"reg.io/app:v1","placement":{"nodeName":"n1"},"env":[` +
		`{"name":"A","value":"1"},{"name":"B","value":"2"},{"name":"A","value":"3"}]}}`

	obj, err := s.Decode([]byte(body))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	app, ok := obj.(*Application)
	if !ok {
		t.Fatalf("decoded type = %T, want *Application", obj)
	}
	if err := json.Unmarshal([]byte(body), app); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := []EnvVar{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}, {Name: "A", Value: "3"}}
	if !slices.Equal(app.Spec.Env, want) {
		t.Fatalf("spec.env = %+v, want %+v (ordered, duplicates preserved)", app.Spec.Env, want)
	}
}

// TestApplicationEnvAbsentIsNil checks the empty/edge case: an Application with no spec.env
// decodes to a nil slice (omitempty on the field), not an empty non-nil one.
func TestApplicationEnvAbsentIsNil(t *testing.T) {
	const body = `{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"web"},` +
		`"spec":{"image":"reg.io/app:v1","placement":{"nodeName":"n1"}}}`

	var app Application
	if err := json.Unmarshal([]byte(body), &app); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if app.Spec.Env != nil {
		t.Fatalf("spec.env = %+v, want nil when absent", app.Spec.Env)
	}
}

// TestApplicationEnvMapDecodeFails asserts the intended breaking change: the OLD map shape
// (spec.env as a JSON object) no longer decodes now that Env is []EnvVar. The kind still
// resolves (Decode only reads apiVersion/kind), but unmarshalling the object into the slice
// field fails with a json.UnmarshalTypeError.
func TestApplicationEnvMapDecodeFails(t *testing.T) {
	s := scheme.New()
	AddToScheme(s)

	const body = `{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"web"},` +
		`"spec":{"image":"reg.io/app:v1","placement":{"nodeName":"n1"},"env":{"A":"1","B":"2"}}}`

	obj, err := s.Decode([]byte(body))
	if err != nil {
		t.Fatalf("Decode (kind resolution) should still succeed for the old shape: %v", err)
	}
	app, ok := obj.(*Application)
	if !ok {
		t.Fatalf("decoded type = %T, want *Application", obj)
	}

	err = json.Unmarshal([]byte(body), app)
	if err == nil {
		t.Fatal("unmarshal of old map-shaped spec.env must fail, got nil error")
	}

	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("error = %T (%v), want *json.UnmarshalTypeError", err, err)
	}
	if typeErr.Value != "object" {
		t.Fatalf("UnmarshalTypeError.Value = %q, want %q", typeErr.Value, "object")
	}
	if msg := err.Error(); !strings.Contains(msg, "cannot unmarshal object into") || !strings.Contains(msg, "EnvVar") {
		t.Fatalf("error = %q, want it to report unmarshalling an object into []EnvVar", msg)
	}
}
