package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ks-tool/horchestra/cmd/internal/kubeconfig"

	"github.com/rs/zerolog/log"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// journalGroup owns read access to the system journal — where a ROOTLESS workload's output
// lands, because it writes as the id its user namespace maps it to rather than as the session
// user, and journald files those lines system-scope.
const journalGroup = "systemd-journal"

// adminCertTTL is the lifetime of the CN=admin kubeconfig certificates init and
// deploy-controller emit — a year, kubeadm's admin.conf cadence. Node credentials get
// the short pki.DefaultClientTTL instead, because only they rotate automatically.
const adminCertTTL = 365 * 24 * time.Hour

// fatal aborts the process with err when it is non-null — node-tool's commands are
// fail-fast, so each step logs and exits rather than unwinding an error.
func fatal(err error, msg string) {
	if err != nil {
		log.Fatal().Err(err).Msg(msg)
	}
}

// write writes data to path with mode, aborting on error.
func write(path string, data []byte, mode os.FileMode) {
	fatal(writeNoFollow(path, data, mode), "write "+path)
}

// writeNoFollow writes data to path fail-closed: node-tool writes CA keys and admin
// kubeconfigs, and os.WriteFile would follow a planted symlink and keep an existing
// file's permissive mode. The bytes land in a same-directory temp file created O_EXCL
// (a symlink at the temp name fails, not follows), get mode explicitly, and are renamed
// over the target — a rewrite still works, but never through a symlink and never
// inheriting a wider mode. An existing target that is not a regular file is refused.
func writeNoFollow(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s exists and is not a regular file (%s); refusing to write through it", path, fi.Mode().Type())
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ensurePrivateDir creates dir 0700 and refuses to proceed when it is a symlink, is
// writable by group or other, or is not owned by the caller — the directory receives
// the CA private key and system:masters kubeconfigs, so a shared or attacker-supplied
// directory would hand those to another local user.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to write PKI material through it", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is group- or world-writable (%#o); refusing to write PKI material into it", dir, perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot determine ownership", dir)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, not the caller (uid %d); refusing to write PKI material into it", dir, st.Uid, os.Geteuid())
	}
	return nil
}

// read reads path, aborting on error.
func read(path string) []byte {
	data, err := os.ReadFile(path)
	fatal(err, "read "+path)
	return data
}

// splitGroups parses a comma-separated group list (certificate Organization); an
// empty value yields no groups.
func splitGroups(s string) []string {
	if len(s) == 0 {
		return nil
	}
	return strings.Split(s, ",")
}

// newKubeconfig builds the single-context client config node-tool emits for controllers, admins
// and nodes — the shared assembly in cmd/internal/kubeconfig.
func newKubeconfig(name, user, server string, ca, cert, key []byte) clientcmdapi.Config {
	return kubeconfig.Build(name, user, server, ca, cert, key)
}

// writeKubeconfig marshals kc and writes it 0600 (it embeds a private key).
func writeKubeconfig(path string, kc clientcmdapi.Config) {
	data, err := clientcmd.Write(kc)
	fatal(err, "marshal kubeconfig "+path)
	write(path, data, 0o600)
}

// nodeToolFor is the node-tool binary to put ON the node: the one built for the node, taken from
// beside --binary the way horchestra-sandbox is.
//
// NOT this process's own executable, which is what it used to be and is wrong the moment the
// operator runs from a mac: `install` is a linux-only command, so shipping a darwin build produced
// a node whose install step died with an exec format error — after the binaries and credentials
// had already been written. `make node-tool` builds for the node's platform by default, so the
// file is normally right there.
func nodeToolFor(binary string) []byte {
	path := filepath.Join(filepath.Dir(binary), "node-tool")
	b, err := os.ReadFile(path)
	fatal(err, "read the node-tool binary beside "+binary+" (build it with `make node-tool`; it must be built for the NODE's platform, not this one)")
	return b
}
