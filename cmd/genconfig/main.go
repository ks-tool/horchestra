//go:build linux

// Command genconfig renders a sandbox config for one image of an unpacked OCI layout — the
// layouts `oci-layouts` (and the node agent) write. The image supplies the layer stack, argv
// (entrypoint + cmd), environment, working directory and stop signal; identity and state
// locations come from flags.
//
//	genconfig -uid 999 -state-dir /var/lib/pg /var/lib/layers library/postgres:18-alpine
//
// The name is the one the layout recorded — `org.opencontainers.image.ref.name` in its
// index.json. Pass a name the layout does not have and the error lists the ones it does.
//
// It emits sandbox.Config itself rather than a struct shaped like it: the sandbox decodes with
// DisallowUnknownFields, so a field added on one side and missed on the other would be a config
// refused at run time. Sharing the type makes that a compile error instead. There is no
// -platform flag because there is nothing left to select — a layout stores one manifest per
// name, already resolved to a platform when it was pulled.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ks-tool/horchestra/agent/oci/layout"
	"github.com/ks-tool/horchestra/sandbox"
)

// defaultUID is the fallback identity when neither the flags nor the image's USER supply a
// numeric non-root id.
const defaultUID = 1000

type stringsFlag []string

func (f *stringsFlag) String() string     { return strings.Join(*f, ",") }
func (f *stringsFlag) Set(v string) error { *f = append(*f, v); return nil }

func main() {
	log.SetFlags(0)
	log.SetPrefix("genconfig: ")

	var (
		uid          = flag.Int("uid", 0, "workload uid (default: the image's numeric USER, else 1000)")
		gid          = flag.Int("gid", 0, "workload gid (default: the image's numeric group, else 1000)")
		stateDir     = flag.String("state-dir", "", "workload state dir; Merged=<dir>/rootfs, InitDir=<dir>/init (default /var/lib/sandbox/<name>)")
		hostname     = flag.String("hostname", "", "sandbox hostname (default: the image name's last element)")
		secretEnvDir = flag.String("secret-env-dir", "", "tmpfs-backed secret layer dir, passed through verbatim")
		network      = flag.String("network", "", `"none" for a private network namespace; empty or "host" shares the host's`)
		out          = flag.String("o", "", "write the config to this file (default stdout)")
		tmpfs        stringsFlag
		rlimits      stringsFlag
		seccompDeny  stringsFlag
		seccompAllow stringsFlag
	)
	flag.Var(&tmpfs, "tmpfs", "tmpfs mount as <path>[:<size>[:<inodes>]], e.g. /tmp:512m:4k; repeatable (default /tmp, /run, /var/tmp)")
	flag.Var(&rlimits, "rlimit", `per-process limit as NAME=soft:hard, e.g. NOFILE=1024:4096 or CORE=0:0; repeatable`)
	flag.Var(&seccompDeny, "seccomp-deny", "syscall to add to the seccomp denylist; repeatable")
	flag.Var(&seccompAllow, "seccomp-allow", "syscall to remove from the built-in seccomp denylist; repeatable")
	flag.Parse()
	if flag.NArg() != 2 {
		_, _ = fmt.Fprintln(os.Stderr, "usage: genconfig [flags] <layout-dir> <name>")
		os.Exit(2)
	}

	layoutDir, err := filepath.Abs(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	img, err := resolve(layoutDir, flag.Arg(1))
	if err != nil {
		log.Fatal(err)
	}

	name := img.Name
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	name = name[strings.LastIndexByte(name, '/')+1:]

	if *hostname == "" {
		*hostname = name
	}
	if *stateDir == "" {
		*stateDir = filepath.Join("/var/lib/sandbox", name)
	}
	if len(tmpfs) == 0 {
		tmpfs = stringsFlag{"/tmp", "/run", "/var/tmp"}
	}
	mounts, err := parseTmpfs(tmpfs)
	if err != nil {
		log.Fatal(err)
	}
	imgUID, imgGID := imageUser(img.Config.Config.User)
	if *uid == 0 {
		*uid = imgUID
	}
	if *gid == 0 {
		*gid = imgGID
	}

	cfg := sandbox.Config{
		LowerDirs:    img.LayerDirs,
		Merged:       filepath.Join(*stateDir, "rootfs"),
		InitDir:      filepath.Join(*stateDir, "init"),
		Command:      append(append([]string{}, img.Config.Config.Entrypoint...), img.Config.Config.Cmd...),
		Env:          img.Config.Config.Env,
		WorkingDir:   img.Config.Config.WorkingDir,
		Hostname:     *hostname,
		TmpfsMounts:  mounts,
		UID:          *uid,
		GID:          *gid,
		SecretEnvDir: *secretEnvDir,
		StopSignal:   img.Config.Config.StopSignal,
		Network:      *network,
	}
	if len(rlimits) > 0 {
		if cfg.Rlimits, err = parseRlimits(rlimits); err != nil {
			log.Fatal(err)
		}
	}
	if len(seccompDeny) > 0 || len(seccompAllow) > 0 {
		cfg.Seccomp = &sandbox.SeccompPolicy{Deny: seccompDeny, Allow: seccompAllow}
	}
	if len(cfg.Command) == 0 {
		log.Fatal("image declares no entrypoint or cmd; the config would be refused")
	}

	blob, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	blob = append(blob, '\n')
	if *out == "" {
		_, _ = os.Stdout.Write(blob)
		return
	}
	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		log.Fatal(err)
	}
}

// resolve reads the image out of the layout and checks that its layers really are unpacked
// directories. The layout must already exist: layout.Open reads an absent one as empty, so a
// mistyped path would otherwise report "image not found" rather than "that is not a layout".
func resolve(layoutDir, name string) (layout.Image, error) {
	if _, err := os.Stat(filepath.Join(layoutDir, "index.json")); err != nil {
		return layout.Image{}, fmt.Errorf("not an OCI layout: %w", err)
	}
	store, err := layout.Open(layoutDir)
	if err != nil {
		return layout.Image{}, err
	}
	img, err := store.Resolve(name)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return layout.Image{}, err
		}
		// Naming an image the layout does not have is the likely mistake, and the fix is
		// always one of the names it does have — so show them rather than the bare miss.
		images, e := store.List()
		if e != nil || len(images) == 0 {
			return layout.Image{}, fmt.Errorf("image %q is not in %s", name, layoutDir)
		}
		have := make([]string, 0, len(images))
		for _, i := range images {
			have = append(have, i.Name)
		}
		return layout.Image{}, fmt.Errorf("image %q is not in %s; it has:\n  %s",
			name, layoutDir, strings.Join(have, "\n  "))
	}
	for i, dir := range img.LayerDirs {
		st, err := os.Stat(dir)
		if err != nil {
			return layout.Image{}, fmt.Errorf("layer[%d]: %w", i, err)
		}
		if !st.IsDir() {
			return layout.Image{}, fmt.Errorf("layer[%d] %s is a blob, not an unpacked directory", i, dir)
		}
	}
	return img, nil
}

// parseRlimits turns NAME=soft:hard values into the config's map. The sandbox validates them
// against the limits of the machine that will actually run it, so nothing is judged here.
func parseRlimits(specs []string) (map[string]sandbox.Rlimit, error) {
	out := make(map[string]sandbox.Rlimit, len(specs))
	for _, s := range specs {
		name, values, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("-rlimit %q: want NAME=soft:hard", s)
		}
		soft, hard, ok := strings.Cut(values, ":")
		if !ok {
			return nil, fmt.Errorf("-rlimit %q: want NAME=soft:hard", s)
		}
		l, err := rlimitValue(soft)
		if err != nil {
			return nil, fmt.Errorf("-rlimit %q: %w", s, err)
		}
		h, err := rlimitValue(hard)
		if err != nil {
			return nil, fmt.Errorf("-rlimit %q: %w", s, err)
		}
		out[name] = sandbox.Rlimit{Soft: l, Hard: h}
	}
	return out, nil
}

// rlimitValue parses one limit. A non-numeric value is handed to the config type's own decoder
// rather than compared against a word spelled out here, so "infinity" is defined in exactly one
// place — the type that has to honour it.
func rlimitValue(s string) (sandbox.RlimitValue, error) {
	if n, err := strconv.ParseUint(s, 10, 64); err == nil {
		return sandbox.RlimitValue(n), nil
	}
	var v sandbox.RlimitValue
	if err := v.UnmarshalJSON([]byte(`"` + s + `"`)); err != nil {
		return 0, err
	}
	return v, nil
}

// parseTmpfs turns the -tmpfs values into mounts. The bounds are split off from the RIGHT, so a
// path may still contain a ':'; the sandbox validates their spelling itself, this only decides
// where the path ends.
func parseTmpfs(specs []string) ([]sandbox.TmpfsMount, error) {
	mounts := make([]sandbox.TmpfsMount, 0, len(specs))
	for _, s := range specs {
		var m sandbox.TmpfsMount
		switch parts := strings.Split(s, ":"); len(parts) {
		case 1:
			m = sandbox.TmpfsMount{Path: parts[0]}
		case 2:
			m = sandbox.TmpfsMount{Path: parts[0], Size: parts[1]}
		default:
			last := len(parts) - 1
			m = sandbox.TmpfsMount{
				Path:   strings.Join(parts[:last-1], ":"),
				Size:   parts[last-1],
				Inodes: parts[last],
			}
		}
		if !strings.HasPrefix(m.Path, "/") {
			return nil, fmt.Errorf("-tmpfs %q: want <path>[:<size>[:<inodes>]] with an absolute path", s)
		}
		mounts = append(mounts, m)
	}
	return mounts, nil
}

// imageUser turns the image config's USER ("uid", "uid:gid") into numeric defaults. A name, an
// empty value or root all fall back to defaultUID: the sandbox has no /etc/passwd lookup and
// refuses root outright.
func imageUser(user string) (uid, gid int) {
	uid, gid = defaultUID, defaultUID
	u, g, _ := strings.Cut(user, ":")
	if v, err := strconv.Atoi(u); err == nil && v > 0 {
		uid, gid = v, v
	}
	if v, err := strconv.Atoi(g); err == nil && v > 0 {
		gid = v
	}
	return uid, gid
}
