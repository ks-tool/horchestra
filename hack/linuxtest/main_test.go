package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file covers exactly one thing: what linuxtest decides BEFORE it starts a container — which
// checkout to mount, which toolchain that checkout pins, and which gates the checkout can even run.
//
// It exists because that decision has now been wrong three times, each time for a different reason,
// and each time the symptom appeared far from the cause: a workspace requirement that outlived the
// workspace, a go.mod walk that mounted hack/ itself and failed seven directories later with `lstat
// api: no such file`, and a toolchain pin that refused a published checkout for having no root
// module. None of them are subtle once seen; all of them are invisible until a container has been
// pulled, started and handed the wrong directory.

// fakeRepo writes a checkout of the given shape and returns its root. A key ending in "/" is a
// directory, anything else a file with that content.
func fakeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, content := range files {
		full := filepath.Join(root, p)
		dir := full
		if !strings.HasSuffix(p, "/") {
			dir = filepath.Dir(full)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if dir == full {
			continue
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The temporary directory is reached through a symlink on darwin, and repoRoot walks up from
	// the RESOLVED working directory, so the comparison has to be made in resolved terms.
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// modFiles is the five library modules, each pinning the same Go version.
func modFiles(version string) map[string]string {
	files := map[string]string{}
	for _, m := range modules {
		files[m+"/go.mod"] = "module github.com/ks-tool/horchestra/" + m + "\n\ngo " + version + "\n"
	}
	return files
}

// TestTheRepositoryIsFoundByItsVCSRoot: linuxtest mounts a repository, and .git is what says where
// one begins. The walk must reach past every go.mod on the way — hack/ has one of its own, and it
// is where this tool is always run from.
func TestTheRepositoryIsFoundByItsVCSRoot(t *testing.T) {
	root := fakeRepo(t, map[string]string{
		".git/":       "",
		"go.mod":      "module github.com/ks-tool/horchestra\n\ngo 1.26.5\n",
		"hack/go.mod": "module github.com/ks-tool/horchestra/hack\n\ngo 1.26.5\n",
	})
	t.Chdir(filepath.Join(root, "hack"))

	got, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Errorf("repoRoot() = %q, want %q: mounting hack/ gives every gate a tree with no modules in it", got, root)
	}
}

// TestATarballIsFoundByItsOutermostGoMod: an unpacked release has no .git, and the fallback must
// still climb — taking the NEAREST go.mod is what mounted hack/ before.
func TestATarballIsFoundByItsOutermostGoMod(t *testing.T) {
	root := fakeRepo(t, map[string]string{
		"go.mod":      "module github.com/ks-tool/horchestra\n\ngo 1.26.5\n",
		"hack/go.mod": "module github.com/ks-tool/horchestra/hack\n\ngo 1.26.5\n",
	})
	t.Chdir(filepath.Join(root, "hack"))

	got, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Errorf("repoRoot() = %q, want %q", got, root)
	}
}

// TestALoneToolDirectoryIsRefusedByName: hack/ copied somewhere on its own is a plausible thing to
// do and an impossible thing to test, so it has to be refused where it happens, naming what is
// missing. The failure it replaces was seven `lstat api: no such file` lines about a directory
// nobody had been told was mounted.
func TestALoneToolDirectoryIsRefusedByName(t *testing.T) {
	root := fakeRepo(t, map[string]string{
		"go.mod": "module github.com/ks-tool/horchestra/hack\n\ngo 1.26.5\n",
	})

	err := checkRepo(root)
	if err == nil {
		t.Fatal("checkRepo accepted a directory holding none of the modules")
	}
	for _, m := range modules {
		if !strings.Contains(err.Error(), m) {
			t.Errorf("checkRepo error does not name the missing %s: %v", m, err)
		}
	}
}

// TestThePublishedCheckoutPinsFromItsModules: the published repository is the library modules
// alone — no workspace (go.work is not published) and, at the moment, no root module either. A
// toolchain check that can only read those two files refuses such a checkout outright, which is
// how `neither go.work nor go.mod is readable` came to be the answer to `make test-linux`.
func TestThePublishedCheckoutPinsFromItsModules(t *testing.T) {
	root := fakeRepo(t, modFiles("1.26.5"))

	got, from, err := goVersionPin(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.26.5" {
		t.Errorf("pin = %q, want 1.26.5", got)
	}
	if !strings.Contains(from, "module") {
		t.Errorf("pinned by %q, want the modules named: the message has to say which file decided", from)
	}
}

// TestTheWorkspaceOutranksTheModules: with a workspace in the tree it is the workspace that builds,
// so it is the workspace the image has to match.
func TestTheWorkspaceOutranksTheModules(t *testing.T) {
	files := modFiles("1.25.0")
	files["go.work"] = "go 1.26.5\n\nuse (\n\t./api\n)\n"
	root := fakeRepo(t, files)

	got, from, err := goVersionPin(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.26.5" || from != "go.work" {
		t.Errorf("pin = %q from %q, want 1.26.5 from go.work", got, from)
	}
}

// TestDisagreeingModulesLeaveNothingToMatch: two toolchains in one tree means half of it would be
// tested on a compiler it is not built with. Silently picking either is worse than not running.
func TestDisagreeingModulesLeaveNothingToMatch(t *testing.T) {
	files := modFiles("1.26.5")
	files["sandbox/go.mod"] = "module github.com/ks-tool/horchestra/sandbox\n\ngo 1.25.0\n"
	root := fakeRepo(t, files)

	_, _, err := goVersionPin(root)
	if err == nil {
		t.Fatal("a tree pinning two Go versions was accepted; one half of it would be tested on the wrong compiler")
	}
	for _, want := range []string{"1.26.5", "1.25.0", "sandbox"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the disagreement does not mention %q: %v", want, err)
		}
	}
}

// TestTheRootGatesNeedARootModule: every gate names the module it needs, so a checkout without one
// skips those gates instead of failing them. `go vet ./...` in a directory that is not a module is
// an error about GOPATH, which says nothing about this repository at all.
func TestTheRootGatesNeedARootModule(t *testing.T) {
	published := fakeRepo(t, modFiles("1.26.5"))
	full := fakeRepo(t, func() map[string]string {
		files := modFiles("1.26.5")
		files["go.mod"] = "module github.com/ks-tool/horchestra\n\ngo 1.26.5\n"
		return files
	}())

	for _, s := range steps(published, false) {
		if s.module == "" {
			continue
		}
		runnable := hasModule(published, s.module)
		if s.module == "." && runnable {
			t.Errorf("%s would run in a checkout with no root module", s.name)
		}
		if s.module != "." && !runnable {
			t.Errorf("%s was skipped although %s is in the checkout", s.name, s.module)
		}
	}
	if !hasModule(full, ".") {
		t.Error("the root gates would be skipped in a checkout that does have a root module")
	}
}

// TestGofmtTakesOnlyTheDirectoriesThatAreHere: gofmt reports a missing directory as an error, so
// naming cmd/ and pkg/ unconditionally fails the first gate of a published checkout — over
// formatting, which was never the problem.
func TestGofmtTakesOnlyTheDirectoriesThatAreHere(t *testing.T) {
	root := fakeRepo(t, modFiles("1.26.5"))

	var gofmt string
	for _, s := range steps(root, false) {
		if s.name == "gofmt" {
			gofmt = s.script
		}
	}
	if gofmt == "" {
		t.Fatal("there is no gofmt gate")
	}
	for _, absent := range []string{"cmd", "pkg"} {
		if strings.Contains(gofmt, " "+absent) {
			t.Errorf("gofmt is asked to format %s, which is not in this checkout: %s", absent, gofmt)
		}
	}
	for _, m := range modules {
		if !strings.Contains(gofmt, m) {
			t.Errorf("gofmt does not cover %s", m)
		}
	}
}
