package utils

import (
	"io"
	"os/exec"
)

// ProcessReadCloser adapts a running subprocess into an io.ReadCloser: reads come from its stdout,
// and Close kills the process and reaps it, so a streaming/`follow` command stops when the caller
// is done. Both the agent's rootless runtime and the systemd unit backend stream a workload's
// journal this way (journalctl), so the boilerplate lives here instead of duplicated in each
// adapter — they differ only in the argv they build.
type ProcessReadCloser struct {
	cmd *exec.Cmd
	out io.ReadCloser
}

// StartReader starts cmd with its stdout piped and returns a ProcessReadCloser over it. The caller
// builds cmd (typically exec.CommandContext); Close terminates it.
func StartReader(cmd *exec.Cmd) (*ProcessReadCloser, error) {
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &ProcessReadCloser{cmd: cmd, out: out}, nil
}

func (p *ProcessReadCloser) Read(b []byte) (int, error) { return p.out.Read(b) }

func (p *ProcessReadCloser) Close() error {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	_ = p.out.Close()
	_ = p.cmd.Wait()
	return nil
}
