package e2e

import (
	"net/http"
	"testing"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// appWithEnv builds an Application pinned to node n1 carrying the given ordered env list.
func appWithEnv(name string, env []corev1.EnvVar) *corev1.Application {
	a := newApp(name, "n1", "postgres:16")
	a.Spec.Env = env
	return a
}

// TestEnv_RoundTripsOrdered posts an Application whose spec.env is an ordered list and
// asserts it comes back on GET as the same list — same names, same values, same order.
func TestEnv_RoundTripsOrdered(t *testing.T) {
	s := startServer(t)

	want := []corev1.EnvVar{
		{Name: "POSTGRES_PASSWORD", Value: "demo"},
		{Name: "PGDATA", Value: "/x"},
	}

	code, body := s.create(appPath(""), appWithEnv("db", want))
	if code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", code, body)
	}
	var created corev1.Application
	decode(t, body, &created)
	assertEnvEqual(t, "create response", created.Spec.Env, want)

	// GET the object back and re-check the persisted env list.
	var got corev1.Application
	if code := s.getInto(appPath("db"), &got); code != http.StatusOK {
		t.Fatalf("get = %d", code)
	}
	assertEnvEqual(t, "get response", got.Spec.Env, want)
}

// TestEnv_OrderIsSensitive posts the same two env vars in the reverse order and asserts
// the stored order tracks the declared order (env is an ordered list, not a set/map).
func TestEnv_OrderIsSensitive(t *testing.T) {
	s := startServer(t)

	want := []corev1.EnvVar{
		{Name: "PGDATA", Value: "/x"},
		{Name: "POSTGRES_PASSWORD", Value: "demo"},
	}

	code, body := s.create(appPath(""), appWithEnv("db", want))
	if code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", code, body)
	}

	var got corev1.Application
	if code := s.getInto(appPath("db"), &got); code != http.StatusOK {
		t.Fatalf("get = %d", code)
	}
	assertEnvEqual(t, "reversed order", got.Spec.Env, want)
}

// TestEnv_EmptyValueRoundTrips: an env var with an empty value (Value omitempty) still
// round-trips as a present entry with its name and an empty value.
func TestEnv_EmptyValueRoundTrips(t *testing.T) {
	s := startServer(t)

	want := []corev1.EnvVar{
		{Name: "PGDATA", Value: "/x"},
		{Name: "DEBUG", Value: ""},
	}

	code, body := s.create(appPath(""), appWithEnv("db", want))
	if code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", code, body)
	}

	var got corev1.Application
	if code := s.getInto(appPath("db"), &got); code != http.StatusOK {
		t.Fatalf("get = %d", code)
	}
	assertEnvEqual(t, "empty value", got.Spec.Env, want)
}

// TestEnv_NoEnvRoundTripsEmpty: an Application with no env has no env on GET (nil/empty),
// confirming the ordered list is genuinely optional.
func TestEnv_NoEnvRoundTripsEmpty(t *testing.T) {
	s := startServer(t)

	code, body := s.create(appPath(""), newApp("db", "n1", "postgres:16"))
	if code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", code, body)
	}

	var got corev1.Application
	if code := s.getInto(appPath("db"), &got); code != http.StatusOK {
		t.Fatalf("get = %d", code)
	}
	if len(got.Spec.Env) != 0 {
		t.Errorf("env for app with no env = %+v, want none", got.Spec.Env)
	}
}

// TestEnv_DuplicateNameRejected: admission must reject an Application whose env repeats a
// Name (a duplicate resolves inconsistently across runtimes) with a 403 Forbidden.
func TestEnv_DuplicateNameRejected(t *testing.T) {
	s := startServer(t)

	dup := []corev1.EnvVar{
		{Name: "PGDATA", Value: "/x"},
		{Name: "PGDATA", Value: "/y"},
	}

	code, body := s.create(appPath(""), appWithEnv("db", dup))
	if code != http.StatusForbidden {
		t.Fatalf("duplicate-env create = %d, want 403 Forbidden; body=%s", code, body)
	}

	// The rejected object must not have been persisted.
	if code, _ := s.get(appPath("db")); code != http.StatusNotFound {
		t.Errorf("get after rejected create = %d, want 404 (nothing persisted)", code)
	}

	// A distinct-name env with the same two values is accepted, proving it is the
	// duplicate Name — not the values — that is rejected.
	ok := []corev1.EnvVar{
		{Name: "PGDATA", Value: "/x"},
		{Name: "PGDATA2", Value: "/y"},
	}
	if code, body := s.create(appPath(""), appWithEnv("db", ok)); code != http.StatusCreated {
		t.Fatalf("distinct-name create = %d, want 201; body=%s", code, body)
	}
}

// TestEnv_DuplicateNameRejected_Status confirms the rejection carries a Forbidden Status
// envelope (not merely a 4xx by accident).
func TestEnv_DuplicateNameRejectedStatus(t *testing.T) {
	s := startServer(t)

	dup := []corev1.EnvVar{
		{Name: "K", Value: "1"},
		{Name: "K", Value: "2"},
	}
	code, body := s.create(appPath(""), appWithEnv("db", dup))
	if code != http.StatusForbidden {
		t.Fatalf("duplicate-env create = %d, want 403; body=%s", code, body)
	}
	var status metav1.Status
	decode(t, body, &status)
	if status.Status != metav1.StatusFailure || status.Code != http.StatusForbidden {
		t.Errorf("reject status = %q/%d, want Failure/403", status.Status, status.Code)
	}
}

// assertEnvEqual fails unless got matches want element-for-element in order.
func assertEnvEqual(t *testing.T, where string, got, want []corev1.EnvVar) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: env len = %d (%+v), want %d (%+v)", where, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Value != want[i].Value {
			t.Errorf("%s: env[%d] = %+v, want %+v (order must be preserved)", where, i, got[i], want[i])
		}
	}
}
