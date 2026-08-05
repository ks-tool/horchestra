//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// fakeSandbox is a process in a user namespace and a network namespace of its own, waiting — which
// is the state the real sandbox is in between unsharing and exec'ing the workload, and the only
// state in which anything can wire it. It exists because the wiring is defined against a PROCESS
// now, not against a path: there is nothing to pin and nobody to hand a namespace to.
type fakeSandbox struct {
	cmd *exec.Cmd
	pid int
}

func newSandbox(t *testing.T) *fakeSandbox {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot unshare a user+network namespace here: %v", err)
	}
	s := &fakeSandbox{cmd: cmd, pid: cmd.Process.Pid}
	t.Cleanup(s.stop)
	// The namespace exists as soon as the child does; give the kernel the moment it takes for
	// /proc/<pid>/ns/net to be readable rather than racing the first call against it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := exec.Command("test", "-e", s.netnsPath()).Output(); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s
}

func (s *fakeSandbox) netnsPath() string { return fmt.Sprintf("/proc/%s/ns/net", strconv.Itoa(s.pid)) }

func (s *fakeSandbox) stop() {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
}
