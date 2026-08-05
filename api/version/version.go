// Package version is what this build says about itself, in the shape a Kubernetes client
// reads it: kubectl asks GET /version before it does anything clever, and an answer in any
// other shape is one it silently ignores.
//
// The numbers come from the build, not from a constant somebody remembers to bump: the
// revision and its timestamp are what the toolchain stamped into the binary, so a build from
// a dirty tree says so instead of claiming the commit it was nearly at. Release is the one
// value a human sets, and -ldflags is where a release build sets it.
package version

import (
	"runtime"
	"runtime/debug"
	"strings"

	"k8s.io/apimachinery/pkg/version"
)

// Release is the version this build claims. A development build carries the pre-release
// zero; a release sets it with
// -ldflags "-X github.com/ks-tool/horchestra/api/version.Release=v1.2.3".
var Release = "v0.0.1"

// Major and Minor are the fields a client uses for skew arithmetic. They track Release and
// are set beside it for the same reason.
var (
	Major = "0"
	Minor = "0"
)

// Info is what this build reports. Fields the toolchain did not stamp read "unknown" rather
// than empty, because an empty commit renders as a version that was never built by anyone.
func Info() version.Info {
	info := version.Info{
		Major:        Major,
		Minor:        Minor,
		GitVersion:   Release,
		GitCommit:    "unknown",
		GitTreeState: "unknown",
		BuildDate:    "unknown",
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			info.GitCommit = s.Value
		case "vcs.time":
			info.BuildDate = s.Value
		case "vcs.modified":
			// A build from a modified tree is not the commit it names, and saying so here is
			// the difference between a version an operator can go and look up and one that
			// merely looks like one.
			if s.Value == "true" {
				info.GitTreeState = "dirty"
			} else {
				info.GitTreeState = "clean"
			}
		}
	}
	if info.GitTreeState == "dirty" && !strings.HasSuffix(info.GitVersion, "-dirty") {
		info.GitVersion += "-dirty"
	}
	return info
}
