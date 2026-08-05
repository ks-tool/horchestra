//go:build linux

// Command sandbox runs one workload in a read-only rootless sandbox described by a JSON config:
//
//	sandbox --config /etc/sandbox/myapp.json
//
// See the sandbox package for what the config describes and what the sandbox enforces. The
// sandbox-strict binary next to this one is the same command, minus the ability to relax the
// syscall filter.
package main

import "github.com/ks-tool/horchestra/sandbox"

func main() { sandbox.Main() }
