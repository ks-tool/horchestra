//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ks-tool/horchestra/agent"
	"github.com/ks-tool/horchestra/pkg/config"
	"github.com/ks-tool/horchestra/pkg/systemd"

	"github.com/rs/zerolog/log"
)

// controllerAccount is the dedicated no-login system user the controller unit runs as. The
// controller is pure network + file IO — root would turn a controller compromise into host root
// plus the CA key and the whole bolt DB.
const controllerAccount = "horchestra"

// applyLocal is the on-host half of apply: it reads the entry describing THIS host and writes the
// units for the role it holds.
//
// It replaced a separate `install` command tree, and the reason is not that two commands were one
// too many. The two had to agree about a dozen values — where the binary is, where the auth-config
// is, which storage DSN, which rotation mode — and the only thing making them agree was that the
// deploy side ASSEMBLED the install side's command line. Every one of those values had two
// spellings and no compiler between them. Now both sides read the same file.
//
// Nothing tells it WHICH half to do. One host can need both — the agent's unit belongs to the user
// it runs as and must not be written as root, while the network helper's is a system unit that only
// root can write — but that is not a claim the caller has to pass in, because each half is gated on
// something this process can check about itself: the agent's unit is installed by the invocation
// running AS the agent's user, and the helper's by the one running as root.
//
// Deriving it beats being told. A flag can disagree with the privilege actually held, and the two
// invocations already differ by exactly that; with a root login they would not differ at all, and a
// flag would have been the only thing keeping them apart.
func applyLocal(f *Fleet, addr string) {
	n, ok := f.node(addr)
	if !ok {
		fatal(fmt.Errorf("no host %q in the inventory: --local names the entry describing this host", addr), "apply --local")
	}
	root := os.Geteuid() == 0

	if n.Role == roleController {
		if !root {
			fatal(errors.New("the controller runs as a hardened system unit, which only root can install"), "apply --local")
		}
		installControllerUnit(f, n)
		return
	}

	agentUser := f.sshFor(n).User
	me, err := osuser.Current()
	fatal(err, "current user")
	if me.Username == agentUser {
		installAgentUnit(f, n)
	}
	if root && n.Netd {
		installNetdUnits(f, n)
	}
	if me.Username != agentUser && !root {
		fatal(fmt.Errorf("running as %q, which is neither the agent's user (%q) nor root: nothing here is this user's to install",
			me.Username, agentUser), "apply --local")
	}
}

// installControllerUnit writes the controller's system unit and starts it. The flags baked into
// ExecStart come from ControllerSpec, so the served controller runs with what the file says.
func installControllerUnit(f *Fleet, n InventoryNode) {
	spec := f.Controller.Spec
	mode, err := spec.signerMode()
	fatal(err, "node-certificate signer")
	unitPath, err := resolveUnitPath("horchestra-controller.service", false)
	fatal(err, "resolve unit path")

	runtime, err := roleRuntime(n)
	fatal(err, n.Addr)
	execStart := roleArgs(runtime, "controller")
	args := []struct{ name, val string }{
		{"--auth-config", hostControllerConf}, {"--storage", spec.Storage}, {"--addr", spec.Addr},
		{"--routed-cidr", spec.RoutedCIDR}, {"--feature-gates", spec.FeatureGates},
	}

	// readable is what the unit's account must be able to open. The controller runs as an
	// unprivileged system user under ProtectSystem=strict, so a file it was handed but cannot
	// read is a controller that starts and then fails — which is why this list is built here
	// rather than left to whoever remembers to chown one more thing.
	readable := []string{hostControllerConf}
	switch mode {
	case signerLocal:
		args = append(args,
			struct{ name, val string }{"--cluster-ca", hostClusterCACrt},
			struct{ name, val string }{"--cluster-ca-key", hostClusterCAKey})
		readable = append(readable, hostClusterCACrt, hostClusterCAKey)
	case signerVault:
		// No --cluster-ca-key in this mode, and that absence IS the mode: the controller holds
		// a credential to something that signs, not a key that signs.
		v := spec.VaultPKI
		args = append(args,
			struct{ name, val string }{"--cluster-ca", hostClusterCACrt},
			struct{ name, val string }{"--pki-vault", v.Server},
			struct{ name, val string }{"--pki-vault-mount", v.Mount},
			struct{ name, val string }{"--pki-vault-role", v.Role},
			struct{ name, val string }{"--pki-vault-cert", hostVaultCert},
			struct{ name, val string }{"--pki-vault-key", hostVaultKey},
			struct{ name, val string }{"--pki-vault-auth-path", v.AuthPath},
			struct{ name, val string }{"--pki-vault-auth-role", v.AuthRole},
			struct{ name, val string }{"--pki-vault-self-role", v.SelfRole})
		readable = append(readable, hostClusterCACrt, hostVaultCert, hostVaultKey)
		if v.CABundle != "" {
			args = append(args, struct{ name, val string }{"--pki-vault-ca", hostVaultCA})
			readable = append(readable, hostVaultCA)
		}
	}

	for _, a := range args {
		if len(a.val) > 0 {
			execStart = append(execStart, a.name, a.val)
		}
	}

	u := systemd.Unit{
		Description: "horchestra controller",
		ExecStart:   execStart,
		Restart:     "on-failure",
		WantedBy:    installTarget(false),
	}
	hardenController(&u, readable, spec.Storage, spec.Addr)
	log.Info().Str("signer", mode).Msg("node certificates")

	rendered, err := u.Render()
	fatal(err, "render unit")
	write(unitPath, []byte(rendered), 0o644)
	log.Info().Str("path", unitPath).Msg("installed the controller unit")
	enableUnit(unitPath, false)
	log.Info().Msg("controller enabled and started")
}

// installAgentUnit writes the node-agent's unit and starts it.
//
// It is always a `systemd --user` unit, and that is not a preference: the agent supervises its
// workloads as transient units on its OWN user manager, reached through
// $XDG_RUNTIME_DIR/systemd/private. A system unit runs as root with no user manager and no
// XDG_RUNTIME_DIR, so it would start, connect to the controller, and then fail every converge —
// the worst shape an install can produce.
func installAgentUnit(f *Fleet, n InventoryNode) {
	spec := f.Node.Spec
	if len(spec.Heartbeat) > 0 {
		_, err := time.ParseDuration(spec.Heartbeat)
		fatal(err, "invalid heartbeat "+spec.Heartbeat)
	}

	// Fail fast on a bad controller URL here, at install time, not on every reconcile.
	cfg, err := agent.LoadAuthConfig(hostNodeConf)
	fatal(err, "load "+hostNodeConf)
	normalized, err := agent.NormalizeControllerURL(cfg.Host)
	fatal(err, "invalid controller URL "+cfg.Host)
	if agent.IsLoopbackHost(normalized) {
		log.Warn().Str("controller", normalized).
			Msg("the controller URL is loopback; this node cannot reach the controller there")
	}

	// Nothing selects a runtime and nothing names the node: the agent enters its user namespace
	// unconditionally, and its identity is the CN of the certificate in the auth-config, which
	// is also what the controller authorizes it as.
	runtime, err := roleRuntime(n)
	fatal(err, n.Addr)
	execStart := append(roleArgs(runtime, "agent"), "--auth-config", hostNodeConf)
	for _, a := range []struct{ name, val string }{
		{"--state-dir", spec.StateDir}, {"--heartbeat", spec.Heartbeat},
	} {
		if len(a.val) > 0 {
			execStart = append(execStart, a.name, a.val)
		}
	}

	unitPath, err := resolveUnitPath("horchestra-agent.service", true)
	fatal(err, "resolve unit path")

	// A workload runs as a subordinate uid from this user's namespace map, which is what puts
	// its output in the system journal rather than in a journal of its own.
	ensureJournalAccess()

	// No After= on a controller unit: the agent runs on a separate host in the target
	// architecture, and it tolerates an unreachable controller at start anyway (it dials inside
	// a backoff-retry loop), so systemd ordering would be a false co-location assumption.
	rendered, err := systemd.Unit{
		Description: "horchestra node-agent",
		ExecStart:   execStart,
		Restart:     "on-failure",
		WantedBy:    installTarget(true),
	}.Render()
	fatal(err, "render unit")
	write(unitPath, []byte(rendered), 0o644)
	log.Info().Str("path", unitPath).Msg("installed the node-agent unit")
	enableUnit(unitPath, true)
	log.Info().Msg("node-agent enabled and started")
}

// roleArgs is the argv a role's unit ExecStarts: the runtime, and the role SUBCOMMAND only when
// that runtime is the monolith.
//
// The split binaries make the role the process ROOT — `horchestra-agent` IS the agent, it has no
// `agent` subcommand — so handing one a role name is an "unknown command" exit at first start, on a
// unit that otherwise looks perfectly installed. Found exactly that way on a live fleet: every
// binary shipped, every unit written, and both roles dead in a restart loop.
func roleArgs(runtime, role string) []string {
	bin := remoteBin(runtime)
	if filepath.Base(runtime) == binNode {
		return []string{bin, role}
	}
	return []string{bin}
}

// installNetdUnits writes the network helper's two units and starts it.
//
// Two units, and the SOCKET is the one enabled: with socket activation the permissions live in a
// file an operator can read (SocketUser/SocketGroup/SocketMode) instead of in the helper's code,
// there is no window where the socket exists with the wrong mode because the process had not
// chmod'ed it yet, and the privileged process is not running at all until an agent asks it for
// something.
func installNetdUnits(f *Fleet, n InventoryNode) {
	spec := f.Node.Spec.Netd
	agentUser := f.sshFor(n).User
	if agentUser == "" {
		fatal(errors.New("no ssh.user in the inventory: the helper answers exactly one user, and there is no safe default"), "install the network helper")
	}
	binary := hostBinDir + "/" + binNode + "-netd"
	if _, err := os.Stat(binary); err != nil {
		fatal(err, "network helper binary (build it with `make netd`)")
	}

	const socketPath = "/run/horchestra/netd.sock"
	servicePath := filepath.Join("/etc/systemd/system", "horchestra-netd.service")
	socketUnitPath := filepath.Join("/etc/systemd/system", "horchestra-netd.socket")
	write(socketUnitPath, []byte(netdSocketUnit(socketPath, agentUser)), 0o644)
	write(servicePath, []byte(netdServiceUnit(binary, agentUser, socketPath, spec)), 0o644)
	log.Info().Str("service", servicePath).Str("socket", socketUnitPath).Msg("installed the network helper units")

	// The SOCKET is enabled, not the service: systemd starts the helper on the first connection
	// and the unit ordering brings it back on every later one.
	run := func(args ...string) {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		fatal(err, "systemctl "+strings.Join(args, " ")+": "+strings.TrimSpace(string(out)))
	}
	run("daemon-reload")
	run("enable", "--now", "horchestra-netd.socket")
	log.Info().Str("socket", socketPath).Str("agent-user", agentUser).Str("overlay", spec.Overlay).
		Msg("network helper enabled (socket-activated)")
}

// netdSocketUnit is the rendezvous point, owned by root and readable by the agent's user alone.
//
// The DIRECTORY is root's on purpose: whoever owns it owns who may squat the path, and a privileged
// process that took its orders from a path an unprivileged user controls would take them from
// whoever won the race to create it. The mode is belt to the helper's braces — it checks the peer's
// kernel-attested credentials on every call regardless, because a mode is one operator edit away
// from being wrong.
func netdSocketUnit(socketPath, agentUser string) string {
	return `[Unit]
Description=horchestra network helper socket

[Socket]
ListenStream=` + socketPath + `
SocketUser=root
SocketGroup=` + agentUser + `
SocketMode=0660
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
`
}

// netdServiceUnit is the helper itself: root, with exactly the capabilities its job needs and no
// others in its bounding set.
//
// `Restart=on-failure` does not fight the socket activation above, and it is here because of what
// this process holds: when it dies, wiring a new workload and updating the tables stop working, and
// with nothing pinned its programs would detach entirely. `on-failure` leaves "not running until
// asked" intact — a clean exit is still a clean exit.
//
// CAP_NET_ADMIN and CAP_NET_RAW make the veth, address it and route it — and attach the datapath to
// the cgroup, which is a network operation to the kernel. CAP_SYS_ADMIN enters the workload's
// network namespace to configure the far end. CAP_BPF loads the datapath's programs and maps; it is
// checked in the INITIAL user namespace, which is the whole reason a separate privileged process
// exists rather than the agent doing this itself. CAP_SYS_PTRACE is the one nobody expects and it is
// not optional: reading another process's namespace link goes through ptrace_may_access, so without
// it this helper — running as root — gets EACCES on /proc/<pid>/ns/net and can wire nothing at all.
// Measured on a stand, not inferred.
//
// The uplink and the overlay are baked in rather than left to netd's own defaults, because they are
// FLEET decisions and not host ones: a node that picked its own encapsulation would be a node the
// others cannot reach.
func netdServiceUnit(binary, agentUser, socketPath string, spec NetdSpec) string {
	caps := "CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_BPF"
	args := ""
	if spec.Uplink != "" {
		args += ` --uplink=` + spec.Uplink
	}
	if spec.Overlay != "" {
		args += ` --overlay=` + spec.Overlay
	}
	return `[Unit]
Description=horchestra network helper
Requires=horchestra-netd.socket
After=horchestra-netd.socket

[Service]
ExecStart=` + binary + ` --agent-user=` + agentUser + ` --socket=` + socketPath + args + `
Restart=on-failure
RestartSec=5
AmbientCapabilities=` + caps + `
CapabilityBoundingSet=` + caps + `
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
`
}

// resolveUnitPath picks where a role's unit file goes: a user unit lands in the caller's per-user
// unit dir (created if absent), a system unit in /etc/systemd/system.
func resolveUnitPath(name string, user bool) (string, error) {
	if !user {
		return filepath.Join("/etc/systemd/system", name), nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfg, "systemd", "user")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// installTarget is the [Install] WantedBy for the role: a user unit enables into the user manager's
// "default.target"; a system unit uses the renderer's "multi-user.target" default.
func installTarget(user bool) string {
	if user {
		return "default.target"
	}
	return ""
}

// enableUnit enables and (re)starts the written unit. A user install also turns on lingering so the
// unit starts at boot without a login session; linger failure (e.g. a restrictive polkit policy) is
// a warning, not fatal — the unit is installed and running, and an operator can enable linger out
// of band.
func enableUnit(unitPath string, user bool) {
	if user {
		if err := systemd.EnableLinger(); err != nil {
			log.Warn().Err(err).Msg("could not enable linger; the service will not start at boot until you run: loginctl enable-linger <user>")
		}
	}
	fatal(systemd.EnableAndRestart(unitPath, user), "enable unit")
}

// ensureJournalAccess reports whether the agent will be able to READ its workloads' output.
//
// A rootless workload runs as a subordinate uid from the user-namespace map, and journald files
// each entry under the sender's _UID. A subuid has no journal of its own, so the output lands in
// the SYSTEM journal — correctly tagged with the user unit, but in a file only root and the
// systemd-journal group may read. Without that membership the agent's journalctl returns nothing
// and `kubectl logs` is silently empty even though every line was captured.
//
// Adding the membership needs root, and this runs as the unprivileged user it installs for, so it
// reports the exact remedy rather than pretending it can fix it. (The operator's half does grant it
// over its own elevated channel; this is the fallback for when that failed.)
func ensureJournalAccess() {
	me, err := osuser.Current()
	if err != nil {
		return
	}
	gids, err := me.GroupIds()
	if err != nil {
		return
	}
	for _, gid := range gids {
		if g, err := osuser.LookupGroupId(gid); err == nil && g.Name == journalGroup {
			return
		}
	}
	log.Warn().Str("user", me.Username).Str("group", journalGroup).
		Str("remedy", fmt.Sprintf("sudo gpasswd -a %s %s  (then re-login)", me.Username, journalGroup)).
		Msg("agent cannot read the system journal, where a rootless workload's output lands; `kubectl logs` will be empty until this is granted")
}

// hardenController confines the controller unit: it runs as the dedicated horchestra account under
// the full hardening floor, with /var/lib/horchestra as its StateDirectory, and every file in
// readable re-owned to that account so the install never leaves a controller that cannot start.
func hardenController(u *systemd.Unit, readable []string, storage, addr string) {
	fatal(refusePrivilegedPort(addr), "listen address")
	uid, gid, err := ensureSystemUser(controllerAccount)
	fatal(err, "create controller system user")
	u.User, u.Group = controllerAccount, controllerAccount
	u.Hardened = true
	u.StateDirectory = controllerAccount

	for _, p := range readable {
		if len(p) > 0 {
			fatal(os.Chown(p, uid, gid), "chown "+p)
		}
	}

	// The bolt DB must be writable under ProtectSystem=strict: inside the StateDirectory systemd
	// re-owns it; anywhere else the install prepares the directory and punches it through as a
	// ReadWritePaths.
	storageCfg := config.Config{Storage: storage}
	boltPath, err := storageCfg.BoltPath()
	fatal(err, "resolve storage path")
	if !filepath.IsAbs(boltPath) {
		fatal(fmt.Errorf("storage %q must use an absolute path", storage), "resolve storage path")
	}
	dataDir := filepath.Dir(boltPath)
	if dataDir == filepath.Join("/var/lib", controllerAccount) {
		return
	}
	fatal(os.MkdirAll(dataDir, 0o700), "create data dir "+dataDir)
	fatal(chownTree(dataDir, uid, gid), "chown data dir "+dataDir)
	u.ReadWritePaths = []string{dataDir}
}

// refusePrivilegedPort rejects a listen address below 1024: the hardened unit runs unprivileged
// with an empty capability bounding set, so such a bind can only fail at start — fail at install
// instead (the default :8443 needs no capability).
func refusePrivilegedPort(addr string) error {
	if len(addr) == 0 {
		return nil
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid addr %q: %w", addr, err)
	}
	if port, err := strconv.Atoi(portStr); err == nil && port < 1024 {
		return fmt.Errorf("addr %s is a privileged port; the hardened controller unit runs unprivileged without CAP_NET_BIND_SERVICE — use a port >= 1024 (default :8443)", addr)
	}
	return nil
}

// ensureSystemUser looks up — or creates — the dedicated no-login system account the controller
// unit runs as, returning its uid/gid.
func ensureSystemUser(name string) (uid, gid int, err error) {
	u, err := osuser.Lookup(name)
	if err != nil {
		var unknown osuser.UnknownUserError
		if !errors.As(err, &unknown) {
			return 0, 0, err
		}
		out, cerr := exec.Command("useradd", "--system", "--user-group",
			"--home-dir", "/var/lib/"+name, "--no-create-home",
			"--shell", "/usr/sbin/nologin", name).CombinedOutput()
		if cerr != nil {
			return 0, 0, fmt.Errorf("useradd %s: %w: %s", name, cerr, bytes.TrimSpace(out))
		}
		if u, err = osuser.Lookup(name); err != nil {
			return 0, 0, err
		}
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return 0, 0, err
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// chownTree re-owns dir and everything beneath it (Lchown: a planted symlink is re-owned, never
// followed).
func chownTree(dir string, uid, gid int) error {
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}
