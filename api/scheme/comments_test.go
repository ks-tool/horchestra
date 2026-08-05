package scheme

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGoCommentsAreCurrent catches the one way a build-time extraction can go wrong: an edited
// doc comment reaches the published schema only when someone regenerates, so without this a
// comment and the documentation clients are served drift apart silently — and invisibly in
// review, because the generated file is untouched.
//
// It re-runs the generator rather than reimplementing it: a check that restates the rules is a
// second copy of them, and the copy is what goes stale.
func TestGoCommentsAreCurrent(t *testing.T) {
	t.Chdir("..") // the api module root, where the generator runs
	if _, err := os.Stat(filepath.Join("core", "v1", "types.go")); err != nil {
		t.Skip("api source is not present: nothing to regenerate from")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain: cannot run the generator")
	}

	fresh := filepath.Join(t.TempDir(), "comments_gen.go")
	cmd := exec.Command("go", "run", "./internal/gencomments", "-o", fresh)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run generator: %v\n%s", err, out)
	}
	want, err := os.ReadFile(fresh)
	if err != nil {
		t.Fatalf("read regenerated map: %v", err)
	}
	got, err := os.ReadFile(filepath.Join("scheme", "comments_gen.go"))
	if err != nil {
		t.Fatalf("read committed map: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("scheme/comments_gen.go is stale — a doc comment changed since it was generated; run `make comments`")
	}
}
