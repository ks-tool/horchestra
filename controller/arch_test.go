package apiserver

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const modulePrefix = "github.com/ks-tool/horchestra/"

// These architecture tests replace compile-time walls the workspace layout used to give for
// free (a standalone ./scheduler module could not import controller at all; one shared
// api/node package makes a second transport copy impossible). They parse imports off the
// source tree, so a refactor that reaches across a boundary fails a test instead of silently
// widening the blast radius.

// repoRoot walks up from the test's working directory to the workspace root (the directory
// holding go.work), so the filesystem-walking arch tests are robust to whatever CWD go test
// runs them from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.work not found walking up from the test working directory")
		}
		dir = parent
	}
}

// goFiles calls fn for every non-test .go file under root, skipping VCS and build dirs.
func goFiles(t *testing.T, root string, fn func(path string)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			fn(path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// horchestraImportsUnder returns, per package directory under dir, the intra-repo
// (github.com/ks-tool/horchestra/…) import paths its non-test files use.
func horchestraImportsUnder(t *testing.T, dir string) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string][]string{}
	goFiles(t, dir, func(path string) {
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		pkg := filepath.Dir(path)
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(p, modulePrefix) {
				out[pkg] = append(out[pkg], p)
			}
		}
	})
	return out
}

func relTo(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil {
		return r
	}
	return p
}

// TestLoopsImportBoundary enforces the wall the standalone ./scheduler module used to give at
// compile time: a controller/loops/* loop may reach the rest of the tree only through api
// types, the loop framework and the service — never into another controller subsystem
// (admission, nodeserver, authn/authz, the HTTP layer) or the root module.
func TestLoopsImportBoundary(t *testing.T) {
	root := repoRoot(t)
	allowed := func(p string) bool {
		switch {
		case p == modulePrefix+"controller/loop",
			p == modulePrefix+"controller/service",
			strings.HasPrefix(p, modulePrefix+"controller/loops/"): // self + sibling loops
			return true
		case strings.HasPrefix(p, modulePrefix+"api/") && p != modulePrefix+"api/storage":
			return true // api kinds/types/scheme — but not the raw Storage interface (see the funnel test)
		}
		return false
	}
	for pkg, imps := range horchestraImportsUnder(t, filepath.Join(root, "controller", "loops")) {
		for _, p := range imps {
			if !allowed(p) {
				t.Errorf("%s imports %s\n  controller/loops/* may import only api/* (except api/storage), controller/loop, controller/service, and sibling loops",
					relTo(root, pkg), p)
			}
		}
	}
}

// TestStorageFunnel keeps mutating callers off raw storage: neither a controller/loops/* loop
// nor the node transport may import api/storage directly — both reach the store only through
// controller/service (the loops via their injected Cluster port, the nodeserver via its
// Controller port), so every write still runs the admission chain. authz is exempt: it only
// reads storage to answer authorization and never mutates.
func TestStorageFunnel(t *testing.T) {
	root := repoRoot(t)
	for _, sub := range []string{"controller/loops", "controller/nodeserver"} {
		for pkg, imps := range horchestraImportsUnder(t, filepath.Join(root, sub)) {
			for _, p := range imps {
				if p == modulePrefix+"api/storage" {
					t.Errorf("%s imports api/storage directly; mutate through controller/service instead", relTo(root, pkg))
				}
			}
		}
	}
}

// TestSingleTransportPackage guards the one-copy-of-the-transport invariant: two packages
// generating node.proto would register the same file/service/message names twice in
// protobuf's global registry and panic at init in the monolith that links both roles. The
// generated server registration must therefore be defined in exactly one package, api/node,
// and nothing may import the retired api/pb path.
func TestSingleTransportPackage(t *testing.T) {
	root := repoRoot(t)
	var defs []string
	goFiles(t, root, func(path string) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := string(b)
		if strings.Contains(src, "func RegisterNodeServiceServer(") {
			defs = append(defs, relTo(root, path))
		}
		if strings.Contains(src, modulePrefix+`api/pb"`) {
			t.Errorf("%s imports the retired api/pb transport path; use api/node", relTo(root, path))
		}
	})
	if len(defs) != 1 || !strings.HasPrefix(defs[0], filepath.Join("api", "node")) {
		t.Errorf("RegisterNodeServiceServer must be defined exactly once under api/node, found: %v", defs)
	}
}
