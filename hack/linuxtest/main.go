// Command linuxtest runs the repository's own gates — gofmt, go vet and every module's
// tests — inside a linux container.
//
// It exists because a large part of the tree is invisible to a darwin `make test`: the
// systemd unit renderer and both installers, the OCI image store and node-tool's file and
// SSH trust rules all sit behind `//go:build linux`, so their tests are silently skipped
// (measurably: 23 test functions run in pkg/systemd/units + cmd/node-tool on darwin
// against 69 here). The container runs as the CALLING uid rather than root, because the
// deploy-time ownership and symlink refusals those tests assert are vacuous for root — it
// passes every permission check by definition.
//
// The host's module cache is mounted, so no dependency is fetched over the network, and
// the build cache lives on the host, so a re-run is incremental.
//
// Usage: `make test-linux`, or directly from this directory:
//
//	GOWORK=off go run ./linuxtest [-image golang:1.26.5] [-race=false] [-only test] [-keep]
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Container-side paths. The repository is mounted rather than copied so a failing run can
// be re-run against an edit immediately; nothing in the gates writes into the tree.
const (
	srcDir      = "/src"
	modCacheDir = "/gomod"
	buildCache  = "/gocache"
)

// step is one gate: a shell script run in the container, reported pass/fail with its
// duration. Every step runs even after an earlier one fails — a vet error should not hide
// which tests would also have failed — and the exit code is the OR of all of them.
//
// module is the module directory the gate needs ("." for the root module, "" for a gate that
// needs none). A gate whose module is not in the checkout is skipped and named, because the
// tree's shape varies: the published repository carries the library modules and, at the moment,
// no root module at all.
type step struct {
	name   string
	module string
	script string
}

func main() {
	image := flag.String("image", "golang:1.26.5", "container image; its Go toolchain must match the tree's")
	race := flag.Bool("race", true, "run the controller module's tests under the race detector")
	only := flag.String("only", "", "run only steps whose name matches this regexp (e.g. 'test|vet')")
	keep := flag.Bool("keep", false, "leave the container running afterwards for inspection")
	timeout := flag.Duration("timeout", 30*time.Minute, "overall deadline")
	skipToolchain := flag.Bool("skip-toolchain-check", false, "allow an image whose Go version differs from the tree's")
	flag.Parse()

	if err := run(*image, *only, *race, *keep, *skipToolchain, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "linuxtest: %v\n", err)
		os.Exit(1)
	}
}

func run(image, only string, race, keep, skipToolchain bool, timeout time.Duration) error {
	filter := regexp.MustCompile(".")
	if only != "" {
		var err error
		if filter, err = regexp.Compile(only); err != nil {
			return fmt.Errorf("-only: %w", err)
		}
	}
	repo, err := repoRoot()
	if err != nil {
		return err
	}
	if err := checkRepo(repo); err != nil {
		return err
	}
	modCache, err := goEnv("GOMODCACHE")
	if err != nil {
		return err
	}
	hostBuildCache, err := hostCacheDir()
	if err != nil {
		return err
	}

	// Ctrl-C must still tear the container down, so the signal cancels the context the
	// deferred termination does NOT use.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The reaper is one more image to pull for a container this process terminates itself.
	// Only defaulted, never overridden: a CI setup that wants Ryuk can still ask for it.
	if _, set := os.LookupEnv("TESTCONTAINERS_RYUK_DISABLED"); !set {
		_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	}

	fmt.Printf("linuxtest: %s, repo %s, uid %d:%d\n", image, repo, os.Getuid(), os.Getgid())
	c, err := testcontainers.Run(ctx, image,
		testcontainers.WithEntrypoint("sleep", "infinity"),
		testcontainers.WithEnv(map[string]string{
			"GOMODCACHE": modCacheDir,
			"GOCACHE":    buildCache,
			// GOPATH and HOME are inside the container: the mounted module cache is the
			// only piece of the host's Go state this shares.
			"GOPATH": "/tmp/go",
			"HOME":   "/tmp",
		}),
		testcontainers.WithConfigModifier(func(cfg *container.Config) {
			// Not root: the tests that refuse a group-writable PKI directory or a
			// symlinked target only mean something for an unprivileged uid.
			cfg.User = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
			cfg.WorkingDir = srcDir
		}),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.Binds = []string{
				repo + ":" + srcDir,
				modCache + ":" + modCacheDir,
				hostBuildCache + ":" + buildCache,
			}
		}),
		testcontainers.WithWaitStrategyAndDeadline(2*time.Minute, wait.ForExec([]string{"true"})),
	)
	if err != nil {
		return fmt.Errorf("start %s: %w", image, err)
	}
	defer func() {
		if keep {
			id := c.GetContainerID()
			fmt.Printf("\nlinuxtest: container %s left running (docker exec -it %s bash); remove it with docker rm -f %s\n", id[:12], id[:12], id[:12])
			return
		}
		// A fresh context: the one above may already be cancelled, which is exactly when
		// the container most needs removing.
		tctx, tcancel := context.WithTimeout(context.Background(), time.Minute)
		defer tcancel()
		if err := testcontainers.TerminateContainer(c, testcontainers.StopContext(tctx)); err != nil {
			fmt.Fprintf(os.Stderr, "linuxtest: terminate container: %v\n", err)
		}
	}()

	if !skipToolchain {
		if err := checkToolchain(ctx, c, repo, image); err != nil {
			return err
		}
	}

	all := steps(repo, race)
	var failed, ran, skipped []string
	for _, s := range all {
		if !filter.MatchString(s.name) {
			continue
		}
		if s.module != "" && !hasModule(repo, s.module) {
			skipped = append(skipped, s.name)
			continue
		}
		ran = append(ran, s.name)
		ok, err := execStep(ctx, c, s)
		if err != nil {
			return err // the container or docker itself is broken; the gates are undecided
		}
		if !ok {
			failed = append(failed, s.name)
		}
	}
	// A -only that matches nothing must not read as success: a mistyped filter would
	// otherwise report a green run that tested nothing at all. Neither must a checkout
	// that holds no module — "all gates passed" over nothing is the worst answer here.
	if len(ran) == 0 {
		if len(skipped) > 0 {
			return fmt.Errorf("every gate was skipped: %s holds none of the modules they need", repo)
		}
		names := make([]string, 0, len(all))
		for _, s := range all {
			names = append(names, s.name)
		}
		return fmt.Errorf("-only %q matched no step; steps are: %s", only, strings.Join(names, ", "))
	}
	if len(skipped) > 0 {
		fmt.Printf("\nlinuxtest: skipped, module not in this checkout: %s\n", strings.Join(skipped, ", "))
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed: %s", strings.Join(failed, ", "))
	}
	fmt.Println("\nlinuxtest: all gates passed on linux")
	return nil
}

// steps is the gate list, in the order a developer wants them: formatting and vet first
// (they fail in seconds), then the modules' tests. It mirrors `make lint` + `make test`,
// which is the point — the same gates, on the platform half the code is written for.
func steps(repo string, race bool) []step {
	controllerTest := "cd controller && go test ./..."
	if race {
		controllerTest += " -race"
	}
	// gofmt takes the directories that are here. It is one gate over the whole tree rather than
	// one per module, so an absent module must drop out of its argument list instead of failing
	// the gate — gofmt reports a missing directory as an error, not as nothing to format.
	fmtDirs := present(repo, "api", "controller", "agent", "netd", "sandbox", "cmd", "pkg")
	return []step{
		{"gofmt", "", `out="$(gofmt -l ` + strings.Join(fmtDirs, " ") + `)"; ` +
			`if [ -n "$out" ]; then echo "needs formatting:"; echo "$out"; exit 1; fi; echo clean`},
		{"vet root", ".", "go vet ./..."},
		{"vet api", "api", "cd api && go vet ./..."},
		{"vet controller", "controller", "cd controller && go vet ./..."},
		{"vet agent", "agent", "cd agent && go vet ./..."},
		{"vet netd", "netd", "cd netd && go vet ./..."},
		{"vet sandbox", "sandbox", "cd sandbox && go vet ./..."},
		{"test api", "api", "cd api && go test ./..."},
		{"test controller", "controller", controllerTest},
		{"test agent", "agent", "cd agent && go test ./..."},
		{"test netd", "netd", "cd netd && go test ./..."},
		// The sandbox module is linux-only and cannot run anywhere else at all, so this is the
		// only gate that ever executes its tests — including the FIFO handshake ones, which check
		// an ordering no type-check can see.
		{"test sandbox", "sandbox", "cd sandbox && go test ./..."},
		{"test root", ".", "go test ./..."},
	}
}

// hasModule reports whether a module directory is in this checkout. "." is the root module.
func hasModule(repo, dir string) bool {
	_, err := os.Stat(filepath.Join(repo, dir, "go.mod"))
	return err == nil
}

// present filters directory names down to the ones that exist.
func present(repo string, dirs ...string) []string {
	var here []string
	for _, d := range dirs {
		if fi, err := os.Stat(filepath.Join(repo, d)); err == nil && fi.IsDir() {
			here = append(here, d)
		}
	}
	return here
}

// execStep runs one gate, streaming its output as it arrives, and reports whether it
// passed. A non-zero exit is the gate's answer, not an error of this program.
func execStep(ctx context.Context, c testcontainers.Container, s step) (bool, error) {
	fmt.Printf("\n=== %s\n", s.name)
	start := time.Now()
	code, out, err := c.Exec(ctx, []string{"sh", "-c", s.script}, tcexec.Multiplexed())
	if err != nil {
		return false, fmt.Errorf("exec %q: %w", s.name, err)
	}
	if err := stream(out); err != nil {
		return false, fmt.Errorf("read %q output: %w", s.name, err)
	}
	took := time.Since(start).Round(time.Millisecond)
	if code != 0 {
		fmt.Printf("--- FAIL %s (%s, exit %d)\n", s.name, took, code)
		return false, nil
	}
	fmt.Printf("--- PASS %s (%s)\n", s.name, took)
	return true, nil
}

func stream(r io.Reader) error {
	if r == nil {
		return nil
	}
	// Line-buffered rather than io.Copy so a long `go test` run prints as it goes; the
	// buffer is generous because a test failure's diff can be one very long line.
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			fmt.Print(line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if !strings.HasSuffix(line, "\n") && line != "" {
					fmt.Println()
				}
				return nil
			}
			return err
		}
	}
}

// checkToolchain refuses an image whose Go toolchain is not the one this tree pins. Silently
// testing a different compiler than the project builds with is worse than not testing:
// the gates would pass while saying nothing about the shipped toolchain.
func checkToolchain(ctx context.Context, c testcontainers.Container, repo, image string) error {
	want, pinnedBy, err := goVersionPin(repo)
	if err != nil {
		return err
	}
	code, out, err := c.Exec(ctx, []string{"go", "env", "GOVERSION"}, tcexec.Multiplexed())
	if err != nil {
		return fmt.Errorf("read the image's Go version: %w", err)
	}
	b, err := io.ReadAll(out)
	if err != nil {
		return fmt.Errorf("read the image's Go version: %w", err)
	}
	got := strings.TrimPrefix(strings.TrimSpace(string(b)), "go")
	if code != 0 || got == "" {
		return fmt.Errorf("%s does not report a Go version (exit %d)", image, code)
	}
	if got != want {
		return fmt.Errorf("%s carries Go %s but %s pins %s: use -image golang:%s (or pass -skip-toolchain-check)",
			image, got, pinnedBy, want, want)
	}
	fmt.Printf("linuxtest: Go %s matches %s\n", got, pinnedBy)
	return nil
}

var goDirective = regexp.MustCompile(`(?m)^go\s+(\S+)`)

// goVersionPin is the Go version this tree pins, and the file that pins it.
//
// Three sources, in the order of how much of the tree they speak for: go.work when there is a
// workspace, the root go.mod when there is a root module, and otherwise the modules' own go.mod
// files. All three are read because both of the first two are optional now — the modules resolve
// one another from the proxy, so a workspace only redirects them at the working tree, and a
// checkout of the published repository is the library modules alone, root module and all.
//
// Falling back to the modules requires them to AGREE. A tree pinning two toolchains has no single
// version for the container to match, and picking one silently would test half the code on a
// compiler it is not built with — which is the thing this check exists to prevent.
func goVersionPin(repo string) (version, from string, err error) {
	for _, name := range []string{"go.work", "go.mod"} {
		b, err := os.ReadFile(filepath.Join(repo, name))
		if err != nil {
			continue
		}
		if m := goDirective.FindSubmatch(b); m != nil {
			return string(m[1]), name, nil
		}
		return "", "", fmt.Errorf("%s has no go directive", name)
	}

	byVersion := map[string][]string{}
	for _, m := range modules {
		b, err := os.ReadFile(filepath.Join(repo, m, "go.mod"))
		if err != nil {
			continue
		}
		if d := goDirective.FindSubmatch(b); d != nil {
			byVersion[string(d[1])] = append(byVersion[string(d[1])], m)
		}
	}
	switch len(byVersion) {
	case 0:
		return "", "", errors.New("no go directive anywhere: neither go.work, nor a root go.mod, nor any module's")
	case 1:
		for v := range byVersion {
			return v, "every module's go.mod", nil
		}
	}
	var disagree []string
	for v, mods := range byVersion {
		disagree = append(disagree, fmt.Sprintf("%s: %s", v, strings.Join(mods, " ")))
	}
	sort.Strings(disagree)
	return "", "", fmt.Errorf("the modules pin different Go versions (%s), so there is none for the image to match",
		strings.Join(disagree, "; "))
}

// repoRoot is the checkout to mount, found by walking up to the outermost `.git`.
//
// By VCS and not by go.mod, because "the repository" is what this tool mounts and .git is what says
// where one begins. Two earlier attempts got this wrong in opposite ways: looking for go.work broke
// when the workspace went away, and looking for a go.mod picked the NEAREST one whenever no ancestor
// had another — mounting hack/ itself, which then failed seven directories later with `lstat api: no
// such file` and never mentioned the mount.
//
// A checkout without .git falls back to the outermost go.mod, which is right for a tarball; either
// way the caller checks what it found before using it.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	git, mod := "", ""
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			git = dir
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			mod = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if git != "" {
		return git, nil
	}
	if mod != "" {
		return mod, nil
	}
	return "", errors.New("no .git or go.mod above the working directory: run this from inside the repository")
}

// modules are the library modules, which a checkout of this repository has all of. The root
// module is not among them: it is the binaries, and the published repository does not carry it.
var modules = []string{"api", "controller", "agent", "netd", "sandbox"}

// checkRepo refuses a root that is not this repository, naming what is missing.
//
// Without it a wrong mount is discovered by the gates themselves, one confusing message per module —
// `lstat api: no such file or directory`, seven times, about a directory nobody mentioned mounting.
// A tool that mounts the wrong thing should say so rather than let the first gate guess.
func checkRepo(repo string) error {
	var missing []string
	for _, d := range modules {
		if fi, err := os.Stat(filepath.Join(repo, d)); err != nil || !fi.IsDir() {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s does not look like the horchestra repository: %s missing. "+
			"linuxtest mounts the checkout it finds by walking up from the working directory",
			repo, strings.Join(missing, ", "))
	}
	return nil
}

// goEnv asks the HOST toolchain for a setting (the module cache to mount).
func goEnv(name string) (string, error) {
	out, err := exec.Command("go", "env", name).Output()
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", name, err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", fmt.Errorf("go env %s is empty", name)
	}
	return v, nil
}

// hostCacheDir is the build cache the container writes through, kept on the host so a
// re-run compiles only what changed. Created with the caller's ownership, which is why the
// container must not run as root — a root-owned cache would be unusable next time.
func hostCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "horchestra-linuxtest-gocache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}
