package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// validConfig is the baseline every case below perturbs in exactly one way.
func validConfig() Config {
	return Config{
		LowerDirs:   []string{"/var/lib/layers/a", "/var/lib/layers/b"},
		Merged:      "/run/app/rootfs",
		InitDir:     "/var/lib/app/init",
		Command:     []string{"/usr/bin/app"},
		TmpfsMounts: []TmpfsMount{{Path: "/tmp"}},
		UID:         1000,
		GID:         1000,
	}
}

func writeConfig(t *testing.T, cfg any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandbox.json")
	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WorkingDir != "/" {
		t.Errorf("WorkingDir = %q, want /", cfg.WorkingDir)
	}
	if cfg.Hostname != "sandbox" {
		t.Errorf("Hostname = %q, want sandbox", cfg.Hostname)
	}
}

// A root workload would keep a full namespaced capability set across execve — enough to mount
// over the read-only root it is meant to be confined by — so the config must not describe one.
func TestLoadConfigRefusesRootIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"uid 0", func(c *Config) { c.UID = 0 }},
		{"gid 0", func(c *Config) { c.GID = 0 }},
		{"negative uid", func(c *Config) { c.UID = -1 }},
		// 1<<32 truncates to 0 in the kernel's 32-bit uid_t, so it IS root despite passing a
		// naive non-zero test.
		{"uid wraps to root", func(c *Config) { c.UID = 1 << 32 }},
		{"gid wraps to root", func(c *Config) { c.GID = 1<<32 + 1000 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			if _, err := Load(writeConfig(t, cfg)); err == nil {
				t.Fatal("expected the config to be refused")
			}
		})
	}
}

// ':' and ',' separate entries in the overlayfs option string, so a path carrying one would
// splice extra layers or options into the mount.
func TestLoadConfigRefusesSeparatorsInLayerPaths(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"colon in lower dir", func(c *Config) { c.LowerDirs = []string{"/layers/a:/etc"} }},
		{"comma in lower dir", func(c *Config) { c.LowerDirs = []string{"/layers/a,rw"} }},
		{"colon in init dir", func(c *Config) { c.InitDir = "/state/init:x" }},
		{"colon in secret dir", func(c *Config) { c.SecretEnvDir = "/run/secrets:x" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			if _, err := Load(writeConfig(t, cfg)); err == nil {
				t.Fatal("expected the config to be refused")
			}
		})
	}
}

func TestLoadConfigRequiresAbsolutePathsAndCommand(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"relative lower dir", func(c *Config) { c.LowerDirs = []string{"layers/a"} }},
		{"no lower dirs", func(c *Config) { c.LowerDirs = nil }},
		{"relative merged", func(c *Config) { c.Merged = "rootfs" }},
		{"relative init dir", func(c *Config) { c.InitDir = "init" }},
		{"init dir equals merged", func(c *Config) { c.InitDir = c.Merged }},
		{"relative tmpfs", func(c *Config) { c.TmpfsMounts = []TmpfsMount{{Path: "tmp"}} }},
		{"relative workdir", func(c *Config) { c.WorkingDir = "srv" }},
		{"empty command", func(c *Config) { c.Command = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			if _, err := Load(writeConfig(t, cfg)); err == nil {
				t.Fatal("expected the config to be refused")
			}
		})
	}
}

// A field name that no longer exists (or never did) means the caller believes it configured
// something the sandbox is not doing.
func TestLoadConfigRefusesUnknownFields(t *testing.T) {
	path := writeConfig(t, map[string]any{
		"LowerDirs": []string{"/layers/a"}, "Merged": "/run/app/rootfs",
		"InitDir": "/var/lib/app/init", "Command": []string{"/bin/app"},
		"UID": 1000, "GID": 1000,
		"ReadOnly": false, // not a field: silently ignored, it would read as "writable root"
	})
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "ReadOnly") {
		t.Fatalf("err = %v, want it to name the unknown field", err)
	}
}

// A stop signal the kernel cannot deliver must be refused with the config, not discovered at
// shutdown time when the workload silently keeps running.
func TestLoadConfigStopSignal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signal string
		ok     bool
	}{
		{"name", "SIGINT", true},
		{"number", "2", true},
		{"empty means forward as-is", "", true},
		{"unknown name", "SIGBOGUS", false},
		{"zero", "0", false},
		{"negative", "-1", false},
		{"out of range", "1000", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.StopSignal = tc.signal
			_, err := Load(writeConfig(t, cfg))
			if tc.ok && err != nil {
				t.Fatalf("valid stop signal refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected the config to be refused")
			}
		})
	}
}

func TestParseSignal(t *testing.T) {
	if sig, err := ParseSignal("SIGINT"); err != nil || sig != syscall.SIGINT {
		t.Errorf("ParseSignal(SIGINT) = %v, %v; want SIGINT", sig, err)
	}
	if sig, err := ParseSignal("15"); err != nil || sig != syscall.SIGTERM {
		t.Errorf("ParseSignal(15) = %v, %v; want SIGTERM", sig, err)
	}
}

// The strict build refuses a config that takes syscalls back out of the denylist. Adding to it
// stays allowed: strict bounds what a config may weaken, not what it may tighten.
func TestLoadConfigStrictRefusesSeccompAllow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  *SeccompPolicy
		opts    []Option
		refused bool
	}{
		{"allow, strict", &SeccompPolicy{Allow: []string{"ptrace"}}, []Option{Strict()}, true},
		{"allow, default build", &SeccompPolicy{Allow: []string{"ptrace"}}, nil, false},
		{"deny only, strict", &SeccompPolicy{Deny: []string{"listen"}}, []Option{Strict()}, false},
		{"no policy, strict", nil, []Option{Strict()}, false},
		{"empty allow, strict", &SeccompPolicy{Allow: []string{}}, []Option{Strict()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			// Sized, so the seccomp policy is the only thing the strict build could object to.
			cfg.TmpfsMounts = []TmpfsMount{{Path: "/tmp", Size: "64m", Inodes: "4k"}}
			cfg.Seccomp = tc.policy
			_, err := Load(writeConfig(t, cfg), tc.opts...)
			if tc.refused && err == nil {
				t.Fatal("expected the strict build to refuse the config")
			}
			if !tc.refused && err != nil {
				t.Fatalf("config refused: %v", err)
			}
		})
	}
}

// A malformed size reaches the kernel as a bare EINVAL from inside the trampoline, where the
// config that caused it is out of sight, so it is refused at load time instead.
func TestLoadConfigTmpfsSize(t *testing.T) {
	for _, tc := range []struct {
		size string
		ok   bool
	}{
		{"", true}, {"512m", true}, {"64M", true}, {"1g", true}, {"1048576", true}, {"50%", true},
		{"512mb", false}, {"big", false}, {"-1", false}, {"512 m", false}, {"%", false},
	} {
		t.Run(tc.size, func(t *testing.T) {
			cfg := validConfig()
			cfg.TmpfsMounts = []TmpfsMount{{Path: "/tmp", Size: tc.size}}
			_, err := Load(writeConfig(t, cfg))
			if tc.ok && err != nil {
				t.Fatalf("valid size refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected the config to be refused")
			}
		})
	}
}

// An unsized tmpfs is half the host's RAM by kernel default, so the strict build makes the
// bound mandatory rather than merely available.
func TestLoadConfigStrictRequiresTmpfsSize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mounts  []TmpfsMount
		opts    []Option
		refused bool
	}{
		{"unsized, strict", []TmpfsMount{{Path: "/tmp"}}, []Option{Strict()}, true},
		{"unsized, default build", []TmpfsMount{{Path: "/tmp"}}, nil, false},
		{"sized, strict", []TmpfsMount{{Path: "/tmp", Size: "512m", Inodes: "4k"}}, []Option{Strict()}, false},
		{"sized but no inodes, strict", []TmpfsMount{{Path: "/tmp", Size: "512m"}}, []Option{Strict()}, true},
		{"one of two unsized, strict",
			[]TmpfsMount{{Path: "/tmp", Size: "512m", Inodes: "4k"}, {Path: "/run"}}, []Option{Strict()}, true},
		{"no mounts, strict", nil, []Option{Strict()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.TmpfsMounts = tc.mounts
			_, err := Load(writeConfig(t, cfg), tc.opts...)
			if tc.refused && err == nil {
				t.Fatal("expected the strict build to refuse the config")
			}
			if !tc.refused && err != nil {
				t.Fatalf("config refused: %v", err)
			}
		})
	}
}

// nr_inodes is bounded separately from size because an empty file occupies no blocks: any
// size= at all leaves room for millions of them, each costing kernel memory.
func TestLoadConfigTmpfsInodes(t *testing.T) {
	for _, tc := range []struct {
		inodes string
		ok     bool
	}{
		{"", true}, {"4k", true}, {"1024", true}, {"1M", true},
		// tmpfs takes a percentage for size alone, so the kernel would refuse this one.
		{"50%", false}, {"lots", false}, {"-1", false}, {"4 k", false},
	} {
		t.Run(tc.inodes, func(t *testing.T) {
			cfg := validConfig()
			cfg.TmpfsMounts = []TmpfsMount{{Path: "/tmp", Size: "64m", Inodes: tc.inodes}}
			_, err := Load(writeConfig(t, cfg))
			if tc.ok && err != nil {
				t.Fatalf("valid inode count refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected the config to be refused")
			}
		})
	}
}

// Network is the one field whose wrong value would silently leave the workload on the host's
// network, so anything but the two known modes is refused.
func TestLoadConfigNetwork(t *testing.T) {
	for _, tc := range []struct {
		network string
		ok      bool
	}{
		{"", true}, {"host", true}, {"none", true},
		{"bridge", false}, {"host ", false}, {"None", false},
	} {
		t.Run("network="+tc.network, func(t *testing.T) {
			cfg := validConfig()
			cfg.Network = tc.network
			_, err := Load(writeConfig(t, cfg))
			if tc.ok && err != nil {
				t.Fatalf("valid network refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected the config to be refused")
			}
		})
	}
}

// TestRoutedNetworkNeedsItsHandshake: a routed network without the two FIFOs would degrade to an
// empty namespace — a workload promised an address, silently given nothing, failing later as what looks
// like its own bug.
func TestRoutedNetworkNeedsItsHandshake(t *testing.T) {
	cfg := validConfig()
	cfg.Network = NetworkRouted
	if err := cfg.validate(options{}); err == nil {
		t.Fatal("a workload network with no handshake paths was accepted")
	}
	cfg.NetnsPidPath = "/run/x/pid"
	if err := cfg.validate(options{}); err == nil {
		t.Error("half a handshake was accepted: the sandbox would announce and never be told to go")
	}
	cfg.NetworkReadyPath = "/run/x/ready"
	if err := cfg.validate(options{}); err != nil {
		t.Errorf("a complete workload network config was refused: %v", err)
	}
}

// TestLoadConfigVerifiesTheDigest: the config lives where the caller's own user can rewrite it
// between two starts, so accepting one on trust is accepting a workload somebody else defined.
func TestLoadConfigVerifiesTheDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	body := []byte(`{"LowerDirs":["/l"],"Merged":"/m","InitDir":"/i","Command":["/bin/true"],"UID":1000,"GID":1000}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])

	if _, err := Load(path, WithDigest(good)); err != nil {
		t.Fatalf("the digest it was rendered with must be accepted: %v", err)
	}
	// Upper case is the same digest; a caller should not have to know which case we print in.
	if _, err := Load(path, WithDigest(strings.ToUpper(good))); err != nil {
		t.Errorf("digest comparison must be case-insensitive: %v", err)
	}
	// One byte changed after rendering is the whole attack, and it must not load.
	if err := os.WriteFile(path, append(body[:len(body)-1], []byte(`,"Hostname":"x"}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, WithDigest(good))
	if err == nil {
		t.Fatal("a config edited after rendering was accepted")
	}
	if !strings.Contains(err.Error(), "changed since it was rendered") {
		t.Errorf("the refusal should say what happened, got: %v", err)
	}
}

// TestBindAndSecretMountsAreValidated: both are paths the caller supplies, and a relative or
// separator-bearing one would be an overlay option or a target outside the root.
func TestBindAndSecretMountsAreValidated(t *testing.T) {
	base := Config{LowerDirs: []string{"/l"}, Merged: "/m", InitDir: "/i", Command: []string{"/bin/true"}, UID: 1000, GID: 1000}
	for _, tc := range []struct {
		name string
		mut  func(*Config)
	}{
		{"a relative bind source", func(c *Config) { c.BindMounts = []BindMount{{Source: "rel", Target: "/data"}} }},
		{"a relative bind target", func(c *Config) { c.BindMounts = []BindMount{{Source: "/src", Target: "data"}} }},
		{"a separator in a secret source", func(c *Config) { c.SecretMounts = []SecretMount{{Source: "/a:b", Target: "/s"}} }},
		{"a relative secret target", func(c *Config) { c.SecretMounts = []SecretMount{{Source: "/src", Target: "s"}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mut(&cfg)
			if err := cfg.validate(options{}); err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
		})
	}
	// The ordinary shape loads.
	ok := base
	ok.BindMounts = []BindMount{{Source: "/node/pv", Target: "/data", ReadOnly: true}}
	ok.SecretMounts = []SecretMount{{Source: "/run/secrets/x", Target: "/etc/creds"}}
	if err := ok.validate(options{}); err != nil {
		t.Fatalf("a well-formed config was refused: %v", err)
	}
}
