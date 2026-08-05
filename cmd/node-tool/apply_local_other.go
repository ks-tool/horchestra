//go:build !linux

package main

import "errors"

// applyLocal is linux-only: it writes systemd units and drives systemd over D-Bus. The flag still
// EXISTS off linux so the refusal names the reason — an unknown-flag error would read as a version
// mismatch, which is the wrong thing to go looking for.
//
// The operator's half of apply is cross-platform on purpose: a fleet is deployed FROM a workstation
// and TO linux hosts, and this is the half that runs on the host.
func applyLocal(_ *Fleet, addr string) {
	fatal(errors.New("--local installs systemd units and can only run on the host itself (linux); from a workstation, run apply without it and let it reach "+addr+" over SSH"),
		"apply --local")
}
