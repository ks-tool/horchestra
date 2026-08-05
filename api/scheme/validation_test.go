package scheme_test

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/scheme"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

var appGVK = corev1.GroupVersion.WithKind("Application")

func newScheme(t *testing.T) *scheme.Scheme {
	t.Helper()
	s := scheme.New()
	corev1.AddToScheme(s)
	return s
}

// app builds a minimal valid Application body with spec merged in verbatim, so a case states
// only the field it is about.
func app(spec string) string {
	return `{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"a"},` +
		`"spec":{"image":"docker.io/library/alpine:3.20"` + spec + `}}`
}

// TestInputSchemaEnforcesFieldRules: the per-field rules live on the Go type as jsonschema tags
// and are enforced from there — an enum, a bound, a minimum length — with no Go validator
// restating any of them.
func TestInputSchemaEnforcesFieldRules(t *testing.T) {
	s := newScheme(t)
	for _, tc := range []struct {
		name, body, want string
	}{
		{"restartPolicy off the enum", app(`,"lifecycle":{"restartPolicy":"never"}`), "restartPolicy"},
		{"negative grace period", app(`,"lifecycle":{"terminationGracePeriodSeconds":-1}`), "terminationGracePeriodSeconds"},
		{"empty image", `{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"a"},"spec":{"image":""}}`, "image"},
		{"port out of range", app(`,"ports":[{"port":70000}]`), "port"},
		{"empty name", `{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":""},"spec":{"image":"x"}}`, "metadata.name"},
		{"no spec", `{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"a"}}`, "spec"},
		{"no image", `{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"a"},"spec":{}}`, "image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := s.Validate(appGVK, []byte(tc.body))
			if len(errs) == 0 {
				t.Fatalf("must be refused, got no errors")
			}
			if got := errs.ToAggregate().Error(); !strings.Contains(got, tc.want) {
				t.Fatalf("the error must name %q, got %s", tc.want, got)
			}
		})
	}

	// The three known policies pass, and so does an absent one — it is filled in by Default
	// before it is stored, never left empty for a consumer to interpret.
	for _, ok := range []string{corev1.RestartAlways, corev1.RestartOnFailure, corev1.RestartNever} {
		if errs := s.Validate(appGVK, []byte(app(`,"lifecycle":{"restartPolicy":"`+ok+`"}`))); len(errs) > 0 {
			t.Errorf("restartPolicy %q must pass: %v", ok, errs.ToAggregate())
		}
	}
	if errs := s.Validate(appGVK, []byte(app(``))); len(errs) > 0 {
		t.Errorf("a spec with nothing but an image must pass: %v", errs.ToAggregate())
	}
	// 0 is not "unset": it means kill immediately, and the bound is >= 0, not > 0.
	if errs := s.Validate(appGVK, []byte(app(`,"lifecycle":{"terminationGracePeriodSeconds":0}`))); len(errs) > 0 {
		t.Errorf("a zero grace period must pass: %v", errs.ToAggregate())
	}
}

// TestInputSchemaRefusesUnknownFields is the rule that needs a schema rather than a Go check: a
// misspelled key decodes to nothing at all, so without this the request succeeds and the field
// the author wrote silently does not exist.
func TestInputSchemaRefusesUnknownFields(t *testing.T) {
	s := newScheme(t)
	errs := s.Validate(appGVK, []byte(app(`,"termnationGracePeriodSeconds":5`)))
	if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "termnationGracePeriodSeconds") {
		t.Fatalf("a misspelled spec field must be refused by name, got %v", errs.ToAggregate())
	}
	if got := errs[0].Field; got != "spec.termnationGracePeriodSeconds" {
		t.Errorf("the error must be pinned to the field, got %q", got)
	}
}

// TestInputSchemaLeavesMetadataOpen: metadata is the one place the author is not the only
// writer. kubectl stamps its last-applied annotation there and the server stamps uid,
// resourceVersion and generation — a closed metadata would reject the server's own object on
// the update and patch paths, which re-validate what storage returned.
func TestInputSchemaLeavesMetadataOpen(t *testing.T) {
	s := newScheme(t)
	body := `{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"a",` +
		`"namespace":"default","uid":"3f1a","resourceVersion":"7","generation":2,` +
		`"creationTimestamp":null,"labels":{"app":"x"},"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}"}},` +
		`"spec":{"image":"x"},"status":{"phase":"Running","observedGeneration":2}}`
	if errs := s.Validate(appGVK, []byte(body)); len(errs) > 0 {
		t.Fatalf("a full server-shaped object must validate: %v", errs.ToAggregate())
	}
}

// TestInputSchemaStatusIsNotRequired: status is written through its own subresource by the node
// that observed it. The Go field carries no omitempty because the server always serializes it,
// but requiring it of an author would make every create carry an empty one.
func TestInputSchemaStatusIsNotRequired(t *testing.T) {
	s := newScheme(t)
	for _, kind := range []string{"Application", "Node", "ApplicationSet"} {
		gvk := corev1.GroupVersion.WithKind(kind)
		body := `{"apiVersion":"horchestra.io/v1","kind":"` + kind + `","metadata":{"name":"a"},"spec":` + minimalSpec(kind) + `}`
		if errs := s.Validate(gvk, []byte(body)); len(errs) > 0 {
			t.Errorf("%s without a status must validate: %v", kind, errs.ToAggregate())
		}
	}
}

func minimalSpec(kind string) string {
	switch kind {
	case "Application":
		return `{"image":"x"}`
	case "ApplicationSet":
		return `{"applications":[{"name":"c","spec":{"image":"x"}}]}`
	default:
		return `{}`
	}
}

// TestValidateSkipsUnregisteredKinds: only addressable resources carry a schema. A List kind or
// an unknown GVK is not silently rejected here — it is not this layer's to refuse.
func TestValidateSkipsUnregisteredKinds(t *testing.T) {
	s := newScheme(t)
	for _, gvk := range []schema.GroupVersionKind{
		corev1.GroupVersion.WithKind("ApplicationList"),
		{Group: "example.com", Version: "v1", Kind: "Widget"},
	} {
		if errs := s.Validate(gvk, []byte(`{"anything":true}`)); len(errs) > 0 {
			t.Errorf("%s must not be validated here, got %v", gvk, errs.ToAggregate())
		}
	}
}

// TestDefaultsComeFromTheSchema: an absent field is filled with what its own tag declares, and
// the value the server stores is therefore the value the schema documents — there is no second
// copy of it in a Go defaulter to drift.
//
// It doubles as the lockstep check for the one default a consumer still restates in Go: the node
// runtime falls back to corev1.DefaultTerminationGracePeriodSeconds for an object that never
// passed through here, and that constant and this tag must not disagree.
func TestDefaultsComeFromTheSchema(t *testing.T) {
	s := newScheme(t)
	out, err := s.Default(appGVK, []byte(app(``)))
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	var got struct {
		Spec struct {
			Lifecycle struct {
				RestartPolicy string `json:"restartPolicy"`
				Grace         *int64 `json:"terminationGracePeriodSeconds"`
			} `json:"lifecycle"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Spec.Lifecycle.RestartPolicy != corev1.RestartAlways {
		t.Errorf("restartPolicy = %q, want the declared default %q",
			got.Spec.Lifecycle.RestartPolicy, corev1.RestartAlways)
	}
	if g := got.Spec.Lifecycle.Grace; g == nil || *g != corev1.DefaultTerminationGracePeriodSeconds {
		t.Errorf("terminationGracePeriodSeconds = %v, want the declared default %d",
			g, corev1.DefaultTerminationGracePeriodSeconds)
	}
	// A defaulted body must still satisfy the schema that produced it.
	if errs := s.Validate(appGVK, out); len(errs) > 0 {
		t.Errorf("the defaulted body fails its own schema: %v", errs.ToAggregate())
	}
}

// TestAnOmittedTraitSectionStillDefaults: the traits live in sections now, and a declared default
// fills a field, never the object that would hold it — so an author who writes no `lifecycle` at
// all would have got an Application with NO restartPolicy, which is neither a service nor a job.
// That is the whole reason the Kind registers a defaulter of its own, and it is worth a test that
// names the omission rather than only the one covering the values: drop the registration and
// every field-level default assertion still passes, because they all write the section.
func TestAnOmittedTraitSectionStillDefaults(t *testing.T) {
	s := newScheme(t)
	// A component of a set reaches a node exactly like a directly-authored Application, so the
	// nested spec has to default identically. Both shapes, one assertion each.
	for _, tc := range []struct{ name, body string }{
		{"application", app(``)},
		{"applicationset component", `{"apiVersion":"horchestra.io/v1","kind":"ApplicationSet",` +
			`"metadata":{"name":"s"},"spec":{"applications":[{"name":"c",` +
			`"spec":{"image":"docker.io/library/alpine:3.20"}}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gvk := appGVK
			if tc.name != "application" {
				gvk = corev1.GroupVersion.WithKind("ApplicationSet")
			}
			out, err := s.Default(gvk, []byte(tc.body))
			if err != nil {
				t.Fatalf("Default: %v", err)
			}
			if !strings.Contains(string(out), `"restartPolicy":"`+corev1.RestartAlways+`"`) {
				t.Errorf("a spec with no lifecycle section was stored without one: %s", out)
			}
			if errs := s.Validate(gvk, out); len(errs) > 0 {
				t.Errorf("the defaulted body fails its own schema: %v", errs.ToAggregate())
			}
		})
	}
}

// TestCustomDefaulterRunsBeforeTheDeclaredOnes locks the order the whole seam depends on. A
// custom defaulter decides a value from what the AUTHOR wrote, so it has to see the object
// before anything has been filled in — run it second and every field it inspects is already set,
// and "the author asked for this" is indistinguishable from "the schema supplied it".
func TestCustomDefaulterRunsBeforeTheDeclaredOnes(t *testing.T) {
	s := newScheme(t)
	// A one-shot job wants to be left alone when it finishes; anything else follows the
	// declared default. The rule is only expressible by reading two fields together, which is
	// why it cannot be a field tag.
	// The lifecycle section it writes into is there because the Kind's OWN defaulter conjured
	// it, and defaulters run in registration order — so this also pins that a later defaulter
	// can count on the sections an earlier one supplied.
	s.RegisterDefaults(appGVK, func(obj map[string]any) {
		spec, _ := obj["spec"].(map[string]any)
		if spec == nil {
			return
		}
		lifecycle, _ := spec["lifecycle"].(map[string]any)
		if lifecycle == nil {
			return
		}
		if _, wrote := lifecycle["restartPolicy"]; wrote {
			return
		}
		if cmd, ok := spec["command"].([]any); ok && len(cmd) > 0 {
			lifecycle["restartPolicy"] = corev1.RestartNever
		}
	})

	// The custom defaulter fired, and the declared default did NOT overwrite it.
	out, err := s.Default(appGVK, []byte(app(`,"command":["/bin/true"]`)))
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if got := policyOf(t, out); got != corev1.RestartNever {
		t.Errorf("restartPolicy = %q, want %q — the declared default overwrote the custom one",
			got, corev1.RestartNever)
	}
	// With nothing for it to decide from, the declared default still lands.
	out, err = s.Default(appGVK, []byte(app(``)))
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if got := policyOf(t, out); got != corev1.RestartAlways {
		t.Errorf("restartPolicy = %q, want the declared default %q", got, corev1.RestartAlways)
	}
	// And what the custom defaulter supplies is validated like anything else, not trusted
	// because the server wrote it.
	if errs := s.Validate(appGVK, out); len(errs) > 0 {
		t.Errorf("the defaulted body fails its own schema: %v", errs.ToAggregate())
	}
}

// TestCustomDefaulterSeesTheAuthoredBody: an author who wrote the field keeps it, because the
// custom defaulter runs on the body as it arrived.
func TestCustomDefaulterSeesTheAuthoredBody(t *testing.T) {
	s := newScheme(t)
	var seen map[string]any
	s.RegisterDefaults(appGVK, func(obj map[string]any) {
		// A COPY: the defaulter is handed the live document so it can fill it, which means a
		// reference kept here would go on changing under the assertions below.
		spec, _ := obj["spec"].(map[string]any)
		lifecycle, _ := spec["lifecycle"].(map[string]any)
		seen = maps.Clone(lifecycle)
	})
	if _, err := s.Default(appGVK, []byte(app(`,"lifecycle":{"restartPolicy":"OnFailure"}`))); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if seen == nil {
		t.Fatal("the custom defaulter never ran")
	}
	if got := seen["restartPolicy"]; got != corev1.RestartOnFailure {
		t.Errorf("the defaulter saw restartPolicy %v, want the authored %q", got, corev1.RestartOnFailure)
	}
	if _, filled := seen["terminationGracePeriodSeconds"]; filled {
		t.Error("the defaulter saw a field the schema had already filled — it ran too late")
	}
}

func policyOf(t *testing.T, body []byte) string {
	t.Helper()
	var got struct {
		Spec struct {
			Lifecycle struct {
				RestartPolicy string `json:"restartPolicy"`
			} `json:"lifecycle"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return got.Spec.Lifecycle.RestartPolicy
}

// TestDefaultDoesNotOverwriteWhatWasWritten: defaults fill what is ABSENT. The case that needs
// the raw body is an authored zero — 0 means kill immediately, and to a decoded object it is
// indistinguishable from a field nobody wrote.
func TestDefaultDoesNotOverwriteWhatWasWritten(t *testing.T) {
	s := newScheme(t)
	out, err := s.Default(appGVK, []byte(app(`,"lifecycle":{"restartPolicy":"Never","terminationGracePeriodSeconds":0}`)))
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if !strings.Contains(string(out), `"terminationGracePeriodSeconds":0`) {
		t.Errorf("an authored 0 was overwritten: %s", out)
	}
	if !strings.Contains(string(out), `"restartPolicy":"Never"`) {
		t.Errorf("an authored restartPolicy was overwritten: %s", out)
	}
}

// TestDefaultDoesNotConjureAbsentObjects: a default fills a field, never the object that would
// hold it. A body with no spec must stay a body with no spec, so the schema still reports it
// missing instead of accepting an object built entirely out of defaults.
func TestDefaultDoesNotConjureAbsentObjects(t *testing.T) {
	s := newScheme(t)
	body := []byte(`{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"a"}}`)
	out, err := s.Default(appGVK, body)
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if strings.Contains(string(out), "spec") {
		t.Errorf("Default invented a spec: %s", out)
	}
	if errs := s.Validate(appGVK, out); len(errs) == 0 {
		t.Error("a body with no spec must still be refused")
	}
}

// TestDefaultLeavesUndeclaredKindsAlone: a Kind whose schema declares no default, or one with no
// schema at all, gets its body back untouched rather than re-serialized.
func TestDefaultLeavesUndeclaredKindsAlone(t *testing.T) {
	s := newScheme(t)
	for _, gvk := range []schema.GroupVersionKind{
		corev1.GroupVersion.WithKind("Namespace"),
		corev1.GroupVersion.WithKind("ApplicationList"),
	} {
		body := []byte(`{"apiVersion":"horchestra.io/v1","kind":"Namespace","metadata":{"name":"a"}}`)
		out, err := s.Default(gvk, body)
		if err != nil {
			t.Fatalf("Default(%s): %v", gvk, err)
		}
		if string(out) != string(body) {
			t.Errorf("Default(%s) rewrote a body with no defaults to apply: %s", gvk, out)
		}
	}
}

// TestSchemaErrorNamesEveryFailedField: the message is the whole point of validating the raw
// body — it must say which field and why, for every violation at once, not just the first.
func TestSchemaErrorNamesEveryFailedField(t *testing.T) {
	s := newScheme(t)
	errs := s.Validate(appGVK, []byte(app(`,"lifecycle":{"restartPolicy":"nope","terminationGracePeriodSeconds":-5}`)))
	if len(errs) != 2 {
		t.Fatalf("both violations must be reported, got %v", errs.ToAggregate())
	}
	got := errs.ToAggregate().Error()
	for _, want := range []string{
		`spec.lifecycle.restartPolicy: Unsupported value: "nope": supported values: "Always", "OnFailure", "Never"`,
		"spec.lifecycle.terminationGracePeriodSeconds: Invalid value: null: minimum: got -5, want 0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the error must contain %q, got %s", want, got)
		}
	}
}
