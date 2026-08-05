//go:build linux

// Command sandbox-strict is the sandbox command that refuses a config which relaxes a
// protection or leaves a bound unset: Seccomp.Allow, which takes syscalls back out of the
// built-in denylist, and a TmpfsMount that leaves out either of its bounds — Size, or the
// Inodes that size= does not imply — which the kernel would then default to a share of the
// host's RAM.
//
// Install it where no workload may do either, whatever its config says. The distinction is the
// binary rather than a flag or a config field on purpose: a switch that travels with the config
// would be set by the same party the strict build exists to bound.
package main

import "github.com/ks-tool/horchestra/sandbox"

func main() { sandbox.Main(sandbox.Strict()) }
