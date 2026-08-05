//go:build linux

package sandbox

import (
	"runtime"

	api "github.com/ks-tool/horchestra/api/sandbox"
)

// The config is the CONTRACT, and it lives in api/sandbox because two programs speak it: the agent
// renders it, this one executes it. Aliased rather than wrapped so this package's own code and its
// public surface are unchanged by where the type is declared — a caller still writes
// sandbox.Config, and a caller that already did keeps compiling.
type (
	Config        = api.Config
	TmpfsMount    = api.TmpfsMount
	BindMount     = api.BindMount
	SecretMount   = api.SecretMount
	SeccompPolicy = api.SeccompPolicy
	Rlimit        = api.Rlimit
	RlimitValue   = api.RlimitValue
	Option        = api.Option
)

const (
	NetworkHost   = api.NetworkHost
	NetworkNone   = api.NetworkNone
	NetworkRouted = api.NetworkRouted
)

// Strict refuses a config that relaxes a protection or leaves a bound unset — see api/sandbox.
func Strict() Option { return api.Strict() }

// WithDigest verifies the file against a digest before decoding a byte of it — see api/sandbox.
func WithDigest(sum string) Option { return api.WithDigest(sum) }

// LoadConfig reads the contract and then checks the half only this program can.
//
// The split is not arbitrary: api/sandbox validates the SHAPE, which any renderer can be held to,
// while compiling a seccomp filter and resolving an rlimit resource name are questions about THIS
// build on THIS machine. A contract that answered them would be answering for a binary it is not.
func LoadConfig(path string, opts ...Option) (*Config, error) {
	cfg, err := api.Load(path, opts...)
	if err != nil {
		return nil, err
	}
	// Build the filter now, on the machine that will run it: a typo in a syscall name must be a
	// refusal to start, not a workload running under a filter missing the rule it was given.
	if _, err := seccompProgram(runtime.GOARCH, cfg.Seccomp); err != nil {
		return nil, err
	}
	if err := validateRlimits(cfg.Rlimits); err != nil {
		return nil, err
	}
	return cfg, nil
}
