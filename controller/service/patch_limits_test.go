package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	apitypes "k8s.io/apimachinery/pkg/types"
)

// TestPatchRejectsCopyAmplification: RFC 6902 "copy" deep-copies the value it names, so copying
// an array onto its own tail doubles it every operation. Thirty of them take a 1 KiB document
// past a terabyte, and the allocation happens inside the patch library — before admission, RBAC
// or storage ever run — so the controller is OOM-killed by one small request from the
// lowest-privilege authenticated tenant. The 3 MiB body cap is no defence: a patch costs a few
// bytes per operation.
func TestPatchRejectsCopyAmplification(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"db"},"spec":{"image":"safe"}}`), ""); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Seed an array, then copy it onto its own tail: each op appends a snapshot of the whole
	// array, so the document doubles every time — 1 KiB to ~1 TiB in 30 ops.
	ops := []string{fmt.Sprintf(`{"op":"add","path":"/spec/args","value":[%q]}`, strings.Repeat("A", 1024))}
	for range 30 {
		ops = append(ops, `{"op":"copy","from":"/spec/args","path":"/spec/args/-"}`)
	}
	patch := "[" + strings.Join(ops, ",") + "]"
	if len(patch) > 4096 {
		t.Fatalf("the bomb should be tiny, got %d bytes", len(patch))
	}

	if _, err := svc.Patch(ctx, metaFor("db"), apitypes.JSONPatchType, []byte(patch)); err == nil {
		t.Fatal("an unbounded copy-amplification patch was accepted")
	}

	// The stored object must be untouched.
	got, err := svc.Get(ctx, metaFor("db"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if img := got.(*widget).Spec.Image; img != "safe" {
		t.Fatalf("spec.image = %q, want the original value", img)
	}
}

// TestPatchRejectsTooManyOperations: the operation count is bounded independently of the
// accumulated size, because a patch of cheap ops is still O(n) work per request.
func TestPatchRejectsTooManyOperations(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"db"},"spec":{"image":"safe"}}`), ""); err != nil {
		t.Fatalf("create: %v", err)
	}

	ops := make([]string, 0, maxJSONPatchOperations+1)
	for range maxJSONPatchOperations + 1 {
		ops = append(ops, `{"op":"add","path":"/spec/image","value":"x"}`)
	}
	patch := "[" + strings.Join(ops, ",") + "]"
	_, err := svc.Patch(ctx, metaFor("db"), apitypes.JSONPatchType, []byte(patch))
	if err == nil {
		t.Fatal("a patch exceeding the operation cap was accepted")
	}
	if !strings.Contains(err.Error(), "json patch operations") {
		t.Fatalf("error = %v, want it to name the operation limit", err)
	}
}

// TestPatchStillAppliesOrdinaryOperations: the limits must not break a normal patch, including
// a modest legitimate "copy".
func TestPatchStillAppliesOrdinaryOperations(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, widgetGVK, []byte(`{"metadata":{"name":"db"},"spec":{"image":"safe"}}`), ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	patch, err := json.Marshal([]map[string]any{
		{"op": "replace", "path": "/spec/image", "value": "nginx:1.27"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := svc.Patch(ctx, metaFor("db"), apitypes.JSONPatchType, patch)
	if err != nil {
		t.Fatalf("an ordinary patch must still apply: %v", err)
	}
	if img := out.(*widget).Spec.Image; img != "nginx:1.27" {
		t.Fatalf("spec.image = %q, want nginx:1.27", img)
	}
}
