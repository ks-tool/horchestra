//go:build linux

// Package sandbox runs one workload inside a read-only overlayfs root assembled from prepared
// layer directories, in fresh rootless namespaces, and hands it over with an emptied capability
// bounding set, a non-root id and a seccomp filter.
//
// It is the ExecStart= stage of a systemd unit: the caller prepares a Config and everything
// around it (layer directories via oci-layouts, unit properties, state dir, secrets); sandbox
// only enforces the config and ends in execve of the workload. Nothing is ever cleaned up here —
// every mount lives in a private mount namespace that dies with the unit's cgroup.
//
// The binaries in cmd/ are Main, with and without Strict; a caller embedding the sandbox in a
// larger program uses LoadConfig and Run instead.
package sandbox

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// Main is the whole command line: it parses --config, loads it under opts, runs the workload and
// exits with its status. Both binaries in cmd/ are one call to it, so they cannot drift from each
// other in flag handling or exit codes.
func Main(opts ...Option) {
	log.SetFlags(0)
	log.SetPrefix(filepath.Base(os.Args[0]) + ": ")

	cfgPath := flag.String("config", "", "path to the sandbox config (JSON)")
	// Required, not optional: the config sits where the caller's own user can rewrite it between
	// two starts of the same unit, so one accepted without its digest is a workload somebody else
	// defined running under the application's name.
	cfgSum := flag.String("config-sha256", "", "sha256 of that config, as the caller rendered it")
	flag.Parse()
	if len(*cfgPath) == 0 || len(*cfgSum) == 0 || flag.NArg() != 0 {
		_, _ = fmt.Fprintf(os.Stderr, "usage: %s --config <file.json> --config-sha256 <hex>\n", filepath.Base(os.Args[0]))
		os.Exit(2)
	}

	cfg, err := LoadConfig(*cfgPath, append(opts, WithDigest(*cfgSum))...)
	if err != nil {
		log.Fatal(err)
	}
	if err = Run(cfg); err != nil {
		// The workload's exit code is the unit's result; pass it up unchanged so systemd and
		// callers agree on it.
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() > 0 {
			os.Exit(ee.ExitCode())
		}
		log.Fatal(err)
	}
}

// Run executes cfg, picking the stage this process is: the first call re-execs the binary into
// fresh namespaces and shepherds it; that second process assembles the rootfs and becomes the
// workload, so Run there never returns on success.
//
// Exported because this package is reached two ways — as its own binary through Main, and as a
// subcommand of the node binary, which parses its own flags and has no use for Main's.
func Run(cfg *Config) error {
	if inSandbox() {
		return enter(cfg)
	}
	return reexec(cfg)
}
