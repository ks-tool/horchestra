// Package sandbox is the CONTRACT between the agent and the sandbox: the config one renders and
// the other executes, its validation, and the digest that binds them.
//
// It lives in api/ for the same reason api/node and api/netd do — it is spoken by two programs, so
// it belongs to neither. The agent writing a field the sandbox does not read, or hashing the file a
// different way than the sandbox verifies it, are both compile errors now instead of a workload
// that fails at start.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// rlimitInfinity is RLIM_INFINITY, spelled as a word in the config because the number it stands for
// is a platform detail no author should have to know.
const rlimitInfinity = "infinity"

// Config fully describes one sandboxed workload. The caller decides
// all policy (layers, command, environment, identity); sandbox only
// enforces it.
type Config struct {
	// LowerDirs are the read-only sources of the overlay root, bottom to
	// top: unpacked image layer directories prepared by oci-layouts, plus
	// any extra caller-provided layers.
	LowerDirs []string
	// Merged is the directory the assembled root is mounted on.
	Merged string
	// InitDir is the per-workload directory the mount-point skeleton tmpfs
	// is mounted on. It belongs under the workload's own state dir so
	// Remove reclaims it: the success path ends in execve, so nothing in
	// this process ever cleans it up.
	InitDir string
	// Command is the workload's argv; argv[0] is resolved against Env's PATH.
	Command []string
	// Env is the workload's exact environment — the sandbox process' own
	// environment is never inherited. PATH is defaulted if absent.
	Env []string
	// WorkingDir defaults to "/".
	WorkingDir string
	// Hostname defaults to "sandbox".
	Hostname string
	// TmpfsMounts are the paths that get a private writable tmpfs, e.g.
	// /tmp. Everything else in the root stays read-only.
	TmpfsMounts []TmpfsMount
	// BindMounts are the workload's persistent volumes, projected AFTER the tmpfs mounts above so
	// a volume is not masked by one, and BEFORE the secrets below so a secret placed inside a
	// volume still wins.
	BindMounts []BindMount
	// SecretMounts are the workload's secret volumes. Paths, never values: this config is a file,
	// and a secret in it would be a secret on disk.
	SecretMounts []SecretMount
	// UID and GID are the workload's identity inside the user namespace,
	// mapped onto the invoking unprivileged host user — no other host
	// identity exists inside the sandbox. Both must be non-root: see
	// validRunAsID.
	UID int
	GID int
	// SecretEnvDir, when set, is a caller-populated directory holding
	// secret files in rootfs layout (etc/environment and the like). It is
	// appended as the topmost overlay layer, so its files shadow the
	// image's. It must be on tmpfs: secrets are refused from disk-backed
	// sources.
	SecretEnvDir string
	// SecretEnvFile, when set, is a caller-populated RAM-backed file of NAME=value lines folded
	// into the workload's execve environment.
	//
	// Distinct from SecretEnvDir above, and not a variant of it: that one projects secret FILES as
	// the topmost overlay layer, this one supplies ENVIRONMENT. A workload sourcing a credential
	// from env cannot be served by a file appearing in its root, and the two are wanted together
	// often enough that collapsing them would mean writing one of the secrets to disk.
	//
	// It is read BEFORE pivot_root, because the host tmpfs holding it is unreachable afterwards —
	// which is the property that keeps the value out of the workload's filesystem entirely.
	SecretEnvFile string
	// StopSignal is the shutdown signal the workload expects — the image
	// config's StopSignal, a name ("SIGINT") or a number. systemd stops a
	// unit with its generic KillSignal (SIGTERM by default), so stage one
	// translates a received stop signal into this one before forwarding.
	// Empty forwards SIGTERM/SIGINT as received.
	StopSignal string
	// Seccomp adjusts the built-in syscall denylist for this workload.
	// Omit it to run the default filter.
	Seccomp *SeccompPolicy
	// Rlimits are per-process resource limits, keyed by systemd's Limit*
	// names without the prefix ("NOFILE", "NPROC", "CORE", …). They bound
	// what a cgroup limit cannot: a cgroup's is shared by everything in it,
	// while these are per process — and they are the only knob here for a
	// caller that writes the config but not the unit.
	//
	// Only lowering works. Raising a hard limit takes CAP_SYS_RESOURCE in
	// the INITIAL user namespace, which no rootless sandbox has, so a value
	// above what the unit passed down is refused with the config.
	Rlimits map[string]Rlimit
	// Network is "host" (the default, and what an empty value means) or
	// "none".
	//
	// On "host" the workload shares the host's network namespace: it
	// reaches the network with no address translation, and equally reaches
	// every service on the host's loopback and every ABSTRACT unix socket
	// there — those are scoped to the network namespace rather than the
	// filesystem, so they are what pivot_root cannot take away.
	//
	// "none" gives the workload a network namespace of its own, holding a
	// loopback interface and nothing else. It also lets /sys come up as a
	// real read-only sysfs: the kernel allows mounting one in a user
	// namespace only when that namespace owns a network namespace too.
	Network string
	// NetnsPidPath and NetworkReadyPath are the two ends of the handshake a routed network needs.
	//
	// A network namespace can only be created by the process that will live in it: entering one
	// requires CAP_SYS_ADMIN in BOTH the namespace's owning user namespace and the caller's
	// current one, so nothing can hand a wired namespace to an unprivileged sandbox (measured —
	// EPERM both ways). The sandbox therefore makes its own and asks to be wired: stage one
	// writes the namespaced child's HOST pid to NetnsPidPath, and stage two blocks on
	// NetworkReadyPath until the caller says the veth, address and routes are in place.
	//
	// The wait is the point. Without it the workload starts in a namespace with nothing in it but
	// loopback, and the failure looks like an application that cannot resolve or connect —
	// indistinguishable from its own bug, and reproducible only under load.
	NetnsPidPath     string
	NetworkReadyPath string
}

// Network values.
const (
	NetworkHost = "host"
	NetworkNone = "none"
	// NetworkRouted is a namespace of the sandbox's own that somebody else WIRES: created here,
	// because only the process that will live in it can create one, and given an address and a
	// route from outside while stage two waits.
	//
	// It is what separates this from "none", which is the same namespace with nothing in it: the
	// difference is not isolation, it is reachability. The name is this tree's own — a routed
	// workload, never a pod; there are no pods in this model and a borrowed word would be the
	// first of many.
	NetworkRouted = "routed"
)

// TmpfsMount is one writable tmpfs in the workload's root.
type TmpfsMount struct {
	// Path is where it is mounted, absolute, inside the sandbox.
	Path string
	// Size caps it, in the kernel's own spelling: a byte count with an
	// optional k/m/g suffix, or a percentage of RAM ("512m", "50%"). Empty
	// leaves the kernel default, which is half of the host's RAM per mount
	// — bounded only by the unit's MemoryMax, where a runaway write then
	// costs the workload an OOM kill instead of the ENOSPC it asked for.
	// The strict build refuses a mount that leaves it empty.
	Size string
	// Inodes caps how many files may exist on it (nr_inodes), a count with
	// an optional k/m/g suffix — no percentage, which tmpfs accepts for
	// size alone.
	//
	// It is a SEPARATE bound, not a consequence of Size: an empty file
	// occupies no blocks, so a million of them fit in any size= at all,
	// while each costs about a kilobyte of unswappable kernel memory. The
	// default is half the host's RAM in pages. Empty leaves that default;
	// the strict build refuses it.
	Inodes string
}

// SeccompPolicy customises the syscall filter. It adjusts the built-in
// denylist rather than replacing it: the sandbox filter is a denylist by
// design (see seccomp.go), and a config that could swap in an allowlist
// would be describing a filter this program cannot build.
//
// Entries are syscall names ("io_uring_setup") or decimal numbers, resolved
// against the running architecture's table. An unknown name is refused with
// the config — a policy that silently denied nothing is worse than no policy.
type SeccompPolicy struct {
	// Deny adds syscalls to the denylist. They are refused with EPERM, as
	// the built-in entries are.
	Deny []string
	// Allow removes syscalls from the built-in denylist — the escape hatch
	// for a workload that genuinely needs one (ptrace for a debugger,
	// io_uring for a database). It WEAKENS the sandbox: every entry is
	// there for a reason documented in the README's table. A syscall named
	// in both lists ends up allowed.
	Allow []string
}

// BindMount is a directory on the node projected into the workload — a persistent volume the
// caller resolved. The sandbox does not decide WHAT may be bound; it decides where it may land and
// how it is mounted, which is the half a workload could otherwise subvert.
type BindMount struct {
	// Source is the node-side directory. Absolute.
	Source string
	// Target is where it appears inside the workload. Absolute, and resolved inside the new root —
	// a target escaping it is refused rather than clamped.
	Target string
	// ReadOnly remounts it read-only. False by default, because a persistent volume exists to be
	// written to; a caller that means otherwise says so.
	ReadOnly bool
}

// SecretMount is a RAM-backed carrier the caller prepared, projected read-only.
//
// A separate type from BindMount and not a flag on it, because it is never writable and never
// optional about that: a workload that can write into its secret volume can replace a credential
// the caller is still rotating, and that value would then outlive the rotation under the
// application's own name. Recursive, since the carrier is itself a mount.
type SecretMount struct {
	Source string
	Target string
}

// Option adjusts how a config is loaded.
type Option func(*options)

type options struct {
	strict bool
	digest string
}

// Strict refuses a config that relaxes a protection or leaves a bound unset:
//
//   - Seccomp.Allow, which takes entries back out of the syscall denylist;
//   - a TmpfsMount with no Size or no Inodes, both of which the kernel then
//     defaults to a share of the host's RAM.
//
// It is the only difference between the sandbox-strict binary and sandbox,
// and the choice belongs to whoever installs the binary rather than to
// whoever writes the config: on a node where no workload may relax the
// filter or leave a mount unbounded, install the strict build and the lever
// does not exist, however the config gets there.
func Strict() Option { return func(o *options) { o.strict = true } }

// WithDigest makes LoadConfig verify the file against sum (hex sha256) before decoding a byte of it.
//
// The config lives where the caller's own user can rewrite it between two starts of the same unit,
// so a config accepted on trust is a workload somebody else defined running under the
// application's name. The digest is what the caller committed to when it rendered the file; an
// empty sum means the caller explicitly chose not to check, which a supervisor should have to
// decide out loud rather than by omission.
func WithDigest(sum string) Option { return func(o *options) { o.digest = sum } }

// Load reads, verifies, validates and defaults the config at path.
func Load(path string, opts ...Option) (*Config, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	if len(o.digest) > 0 {
		sum := sha256.New()
		if _, err := io.Copy(sum, f); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
		if got := hex.EncodeToString(sum.Sum(nil)); !strings.EqualFold(got, o.digest) {
			return nil, fmt.Errorf("config %s: sha256 %s, expected %s — it changed since it was rendered", path, got, o.digest)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
	}

	dec := json.NewDecoder(f)
	// A misspelled field silently ignored is a sandbox quietly weaker than
	// the caller believes it configured.
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if err := cfg.validate(o); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}

	if len(cfg.WorkingDir) == 0 {
		cfg.WorkingDir = "/"
	}
	if len(cfg.Hostname) == 0 {
		cfg.Hostname = "sandbox"
	}
	return &cfg, nil
}

func (cfg *Config) validate(o options) error {
	// Checked before anything else: a config this build will not honour must be refused whole,
	// not partly applied.
	if o.strict && cfg.Seccomp != nil && len(cfg.Seccomp.Allow) > 0 {
		return fmt.Errorf("Seccomp.Allow takes %d syscall(s) out of the denylist, which this build refuses; "+
			"use the non-strict sandbox binary if the workload genuinely needs them", len(cfg.Seccomp.Allow))
	}
	switch {
	case len(cfg.LowerDirs) == 0:
		return errors.New("LowerDirs must not be empty")
	case !filepath.IsAbs(cfg.Merged):
		return errors.New("merged must be an absolute path")
	case cfg.InitDir == cfg.Merged:
		return errors.New("InitDir and Merged must differ")
	case len(cfg.Command) == 0:
		return errors.New("command must not be empty")
	case len(cfg.WorkingDir) > 0 && !filepath.IsAbs(cfg.WorkingDir):
		return errors.New("WorkingDir must be an absolute path")
	case len(cfg.Hostname) > 64:
		return errors.New("hostname must be at most 64 characters")
	case len(cfg.Network) > 0 && cfg.Network != NetworkHost && cfg.Network != NetworkNone &&
		cfg.Network != NetworkRouted:
		return fmt.Errorf("Network %q must be %q, %q or %q", cfg.Network, NetworkHost, NetworkNone, NetworkRouted)
	case cfg.Network == NetworkRouted && (len(cfg.NetnsPidPath) == 0 || len(cfg.NetworkReadyPath) == 0):
		// Refused rather than degraded to "none": a workload that was promised an address and
		// silently got an empty namespace fails as a bug in itself, somewhere far from here.
		return fmt.Errorf("Network %q needs NetnsPidPath and NetworkReadyPath: the namespace is made here and wired from outside", NetworkRouted)
	}

	if err := ValidRunAsID("UID", cfg.UID); err != nil {
		return err
	}
	if err := ValidRunAsID("GID", cfg.GID); err != nil {
		return err
	}
	if err := validLowerPath("InitDir", cfg.InitDir); err != nil {
		return err
	}
	if len(cfg.SecretEnvDir) > 0 {
		if err := validLowerPath("SecretEnvDir", cfg.SecretEnvDir); err != nil {
			return err
		}
	}
	if len(cfg.SecretEnvFile) > 0 {
		if err := validLowerPath("SecretEnvFile", cfg.SecretEnvFile); err != nil {
			return err
		}
	}
	for _, m := range cfg.BindMounts {
		if err := validLowerPath("BindMounts.Source", m.Source); err != nil {
			return err
		}
		if err := validLowerPath("BindMounts.Target", m.Target); err != nil {
			return err
		}
	}
	for _, m := range cfg.SecretMounts {
		if err := validLowerPath("SecretMounts.Source", m.Source); err != nil {
			return err
		}
		if err := validLowerPath("SecretMounts.Target", m.Target); err != nil {
			return err
		}
	}
	if len(cfg.StopSignal) > 0 {
		if _, err := ParseSignal(cfg.StopSignal); err != nil {
			return err
		}
	}
	// The seccomp filter and the rlimit table are checked by the SANDBOX, not here: compiling a
	// filter and resolving a resource name are things only the program that will install them can
	// do, and a contract that pretended to check them would be checking a different build's idea
	// of what exists.
	for _, d := range cfg.LowerDirs {
		if err := validLowerPath("lower dir", d); err != nil {
			return err
		}
	}
	for _, m := range cfg.TmpfsMounts {
		if !filepath.IsAbs(m.Path) {
			return fmt.Errorf("tmpfs mount %q must be an absolute path", m.Path)
		}
		if o.strict {
			if len(m.Size) == 0 {
				return fmt.Errorf("tmpfs mount %q has no Size, which this build refuses: the kernel would "+
					"default it to half the host's RAM", m.Path)
			}
			if len(m.Inodes) == 0 {
				return fmt.Errorf("tmpfs mount %q has no Inodes, which this build refuses: Size bounds the "+
					"bytes but not the file count, and each file costs kernel memory of its own", m.Path)
			}
		}
		if err := validTmpfsSize(m.Path, m.Size); err != nil {
			return err
		}
		if err := validTmpfsInodes(m.Path, m.Inodes); err != nil {
			return err
		}
	}
	return nil
}

// tmpfsSize is what the kernel accepts for size=: a byte count with an optional k/m/g suffix,
// or a percentage of RAM. tmpfsCount is the same minus the percentage, which tmpfs takes for
// size alone and not for nr_inodes.
var (
	tmpfsSize  = regexp.MustCompile(`^[0-9]+([kKmMgG]|%)?$`)
	tmpfsCount = regexp.MustCompile(`^[0-9]+[kKmMgG]?$`)
)

// validTmpfsSize vets a size before it reaches the mount option string. The kernel answers a
// malformed one with a bare EINVAL from inside the trampoline, where the config that caused it
// is no longer in sight — so it is spelled out here instead.
func validTmpfsSize(path, size string) error {
	if len(size) == 0 {
		return nil
	}
	if !tmpfsSize.MatchString(size) {
		return fmt.Errorf("tmpfs mount %q: size %q must be a byte count with an optional k/m/g suffix, "+
			"or a percentage of RAM (e.g. 512m, 50%%)", path, size)
	}
	return nil
}

// validTmpfsInodes vets an nr_inodes value. A percentage is refused here rather than by the
// kernel: tmpfs accepts one for size only, so "50%" would fail the mount from inside the
// trampoline with the same bare EINVAL a typo produces.
func validTmpfsInodes(path, inodes string) error {
	if len(inodes) == 0 {
		return nil
	}
	if !tmpfsCount.MatchString(inodes) {
		return fmt.Errorf("tmpfs mount %q: inodes %q must be a count with an optional k/m/g suffix "+
			"(e.g. 4k); tmpfs takes a percentage for size alone", path, inodes)
	}
	return nil
}

// maxRunAsID is one past the largest id the kernel can represent. setresuid(2)
// takes the id in a register wide enough for the whole int, but the kernel
// reads a 32-bit uid_t: 1<<32 truncates to 0, so a "not root" test on the
// original value passes for a value that becomes root.
const maxRunAsID = 1 << 32

// validRunAsID rejects an identity the workload must never run as. Root is
// refused outright: the sandbox's single id mapping points the workload's id
// at the invoking host user, so a root workload would hold namespaced
// CAP_SYS_ADMIN across execve — enough to mount over the read-only root it is
// supposed to be confined by.
// ValidRunAsID is exported because the sandbox checks the same rule when it drops privileges, and
// two spellings of "is this a usable id" is one spelling too many.
func ValidRunAsID(what string, id int) error {
	if v := int64(id); v <= 0 || v >= maxRunAsID {
		return fmt.Errorf("%s must be a non-root id in 1..%d, got %d", what, maxRunAsID-1, id)
	}
	return nil
}

// validLowerPath vets a path destined for the overlayfs lowerdir option
// string, where ':' and ',' are separators: a path containing them would
// silently splice extra layers or options into the mount.
func validLowerPath(what, p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s %q must be an absolute path", what, p)
	}
	if strings.ContainsAny(p, ":,") {
		return fmt.Errorf("%s %q must not contain ':' or ','", what, p)
	}
	return nil
}

// ParseSignal resolves a stop signal by name or number. It is here rather than beside the code that
// sends the signal because validation has to reject an unknown one at render time — the alternative
// is a config the agent accepted and the sandbox refuses, discovered per workload.
func ParseSignal(s string) (os.Signal, error) {
	// 64 is the kernel's _NSIG on linux: the range realtime signals end at.
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 || n > 64 {
			return nil, fmt.Errorf("stop signal %d out of range", n)
		}
		return syscall.Signal(n), nil
	}
	if sig := unix.SignalNum(s); sig != 0 {
		return sig, nil
	}
	return nil, fmt.Errorf("unknown stop signal %q", s)
}

// Marshal renders a config and returns the bytes with their digest.
//
// Both halves in one place on purpose: the agent writes the file and the sandbox verifies it, and
// while the two were separate pieces of code they could disagree about what "the digest of this
// config" means — a disagreement that shows up as every workload refusing to start.
func Marshal(cfg Config) (blob []byte, sum string, err error) {
	blob, err = json.Marshal(cfg)
	if err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(blob)
	return blob, hex.EncodeToString(h[:]), nil
}

// Rlimit is one resource limit. Both values are required: leaving one out would silently mean
// zero, and a zero NOFILE is a workload that cannot open a file.
type Rlimit struct {
	Soft RlimitValue
	Hard RlimitValue
}

// RlimitValue is a limit value — a number, or "infinity".
type RlimitValue uint64

func (v *RlimitValue) UnmarshalJSON(b []byte) error {
	if s := strings.Trim(string(b), `"`); s == rlimitInfinity {
		*v = RlimitValue(unix.RLIM_INFINITY)
		return nil
	}
	var n uint64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("rlimit value %s: want a number or %q", b, rlimitInfinity)
	}
	*v = RlimitValue(n)
	return nil
}

func (v RlimitValue) MarshalJSON() ([]byte, error) {
	if uint64(v) == unix.RLIM_INFINITY {
		return []byte(`"` + rlimitInfinity + `"`), nil
	}
	return json.Marshal(uint64(v))
}

func (v RlimitValue) String() string {
	if uint64(v) == unix.RLIM_INFINITY {
		return rlimitInfinity
	}
	return strconv.FormatUint(uint64(v), 10)
}
