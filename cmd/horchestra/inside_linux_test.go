//go:build linux

package main

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// insideNetns runs fn in the namespace at path, on a thread of its own that is never unlocked on
// the failure path — the same rule the agent and the helper both follow, and for the same reason:
// a thread left in the wrong namespace must be discarded by the runtime rather than reused.
func insideNetns(path string, fn func() error) error {
	ns, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = ns.Close() }()

	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		origin, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = origin.Close() }()
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		callErr := fn()
		if err := unix.Setns(int(origin.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- callErr
			return
		}
		runtime.UnlockOSThread()
		done <- callErr
	}()
	return <-done
}
