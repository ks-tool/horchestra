package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// sshOptions is the dial policy for a deploy: the login identity plus the host-key
// trust decision (a --host-key pin, --accept-new, or an interactive confirmation).
type sshOptions struct {
	user, addr, keyPath string
	hostKey             string // pinned host key: a known_hosts/public-key line or a SHA256:... fingerprint
	acceptNew           bool   // pin an unknown host key without prompting
	sudo                bool
	sudoPass            string
}

// connect opens an SSH session and returns a remote for running the privileged
// install steps, resolving the sudo password when elevation is needed.
func connect(o sshOptions) *remote {
	client, err := dialSSH(o)
	fatal(err, "ssh connect")
	r := &remote{client: client, sudo: o.sudo}
	if o.sudo {
		r.pass = sudoPassword(r, o.sudoPass)
	}
	return r
}

func dialSSH(o sshOptions) (*ssh.Client, error) {
	auths, err := sshAuth(o.keyPath)
	if err != nil {
		return nil, err
	}
	host := o.addr
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "22")
	}
	hostKey, err := hostKeyCallback(o.hostKey, o.acceptNew)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            o.user,
		Auth:            auths,
		HostKeyCallback: hostKey,
		Timeout:         15 * time.Second,
	}
	client, err := ssh.Dial("tcp", host, cfg)
	if err == nil {
		return client, nil
	}
	// A key mismatch is usually not a mismatch. Without HostKeyAlgorithms the client takes
	// whatever host key type the SERVER prefers, while known_hosts holds whichever type
	// OpenSSH happened to record — one line, usually ed25519. The two disagree on a host the
	// operator has used for years, and the tool cries MITM at them.
	//
	// knownhosts says what it actually has for this address, so the second attempt asks for
	// exactly those types. It is retried rather than pre-computed because the matching is
	// knownhosts' own: an entry may be hashed, and then no amount of string comparison here
	// would find it.
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) || len(ke.Want) == 0 {
		return nil, err
	}
	algos := make([]string, 0, len(ke.Want))
	for _, w := range ke.Want {
		if t := w.Key.Type(); !slices.Contains(algos, t) {
			algos = append(algos, t)
		}
	}
	cfg.HostKeyAlgorithms = algos
	return ssh.Dial("tcp", host, cfg)
}

// hostKeyCallback verifies the host's SSH key. deploy uploads private keys and streams
// the sudo password over this channel, so an unverified peer is a full compromise: an
// unknown host is accepted only on an explicit decision — a --host-key pin, --accept-new,
// or an interactive yes — and fails closed otherwise. A known host presenting a different
// key is always refused. Verification reads node-tool's own pin file plus the operator's
// ~/.ssh/known_hosts (read-only); accepted keys are pinned into the tool-owned file only.
func hostKeyCallback(pin string, acceptNew bool) (ssh.HostKeyCallback, error) {
	var matchPin func(ssh.PublicKey) bool
	if len(pin) > 0 {
		m, err := pinnedKeyMatcher(pin)
		if err != nil {
			return nil, err
		}
		matchPin = m
	}
	pinFile, err := toolKnownHosts()
	if err != nil {
		return nil, err
	}
	files := []string{pinFile}
	if home, err := os.UserHomeDir(); err == nil {
		if kh := filepath.Join(home, ".ssh", "known_hosts"); fileIsReadable(kh) {
			files = append(files, kh)
		}
	}
	verify, err := knownhosts.New(files...)
	if err != nil {
		return nil, err
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if matchPin != nil {
			// --host-key is authoritative: it accepts exactly the pinned key (also past a
			// changed-key refusal — the operator's explicit rotation path) and nothing else.
			if !matchPin(key) {
				return fmt.Errorf("host %s presented key %s, which does not match --host-key (possible MITM)", hostname, fp)
			}
			if verify(hostname, remote, key) == nil {
				return nil
			}
			return pinHostKey(pinFile, hostname, key)
		}
		switch err := verify(hostname, remote, key); {
		case err == nil:
			return nil
		case isUnknownHost(err):
			if !acceptNew && !confirmHostKey(hostname, fp) {
				return fmt.Errorf("unknown SSH host key for %s (fingerprint %s): verify it, then pass --host-key '%s' or --accept-new to pin it", hostname, fp, fp)
			}
			if err := pinHostKey(pinFile, hostname, key); err != nil {
				return err
			}
			log.Warn().Str("host", hostname).Str("fingerprint", fp).
				Msg("pinned a new SSH host key — verify it is the intended host")
			return nil
		default:
			return fmt.Errorf("SSH host key verification failed for %s (possible MITM): %w", hostname, err)
		}
	}, nil
}

// pinnedKeyMatcher parses a --host-key value — a SHA256:... fingerprint, a known_hosts
// line, or a bare public-key line — into a predicate over the presented host key.
func pinnedKeyMatcher(pin string) (func(ssh.PublicKey) bool, error) {
	pin = strings.TrimSpace(pin)
	if strings.HasPrefix(pin, "SHA256:") {
		return func(key ssh.PublicKey) bool { return ssh.FingerprintSHA256(key) == pin }, nil
	}
	if _, _, pub, _, _, err := ssh.ParseKnownHosts([]byte(pin)); err == nil {
		want := pub.Marshal()
		return func(key ssh.PublicKey) bool { return bytes.Equal(key.Marshal(), want) }, nil
	}
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pin)); err == nil {
		want := pub.Marshal()
		return func(key ssh.PublicKey) bool { return bytes.Equal(key.Marshal(), want) }, nil
	}
	return nil, fmt.Errorf("--host-key %q is neither a SHA256:... fingerprint nor a host public-key line", pin)
}

// toolKnownHosts returns node-tool's own known_hosts pin file, creating it (0600, in a
// 0700 directory) when missing. Accepted keys are recorded here, never in the
// operator's ~/.ssh/known_hosts.
func toolKnownHosts() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfg, "horchestra")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "known_hosts")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	return path, f.Close()
}

// pinHostKey appends the host's key to node-tool's pin file.
func pinHostKey(path, hostname string, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n")
	return errors.Join(werr, f.Close())
}

// confirmHostKey interactively asks the operator to accept an unknown host key,
// answering false when there is no terminal to ask on.
func confirmHostKey(hostname, fingerprint string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return false
	}
	_, _ = fmt.Fprintf(os.Stderr, "The authenticity of host %s can't be established.\nKey fingerprint is %s.\nContinue connecting and pin this key (yes/no)? ", hostname, fingerprint)
	var answer string
	if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
		return false
	}
	return strings.EqualFold(answer, "yes")
}

// fileIsReadable reports whether path is an existing file the caller may open.
func fileIsReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// isUnknownHost reports whether the verification error is "host not in known_hosts" (Want
// empty) rather than a key mismatch (Want populated).
func isUnknownHost(err error) bool {
	var ke *knownhosts.KeyError
	return errors.As(err, &ke) && len(ke.Want) == 0
}

func sshAuth(keyPath string) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod

	// A key file — the given --ssh-key, else the conventional defaults.
	paths := []string{keyPath}
	if len(keyPath) == 0 {
		home, _ := os.UserHomeDir()
		paths = []string{filepath.Join(home, ".ssh", "id_ed25519"), filepath.Join(home, ".ssh", "id_rsa")}
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if signer, err := ssh.ParsePrivateKey(data); err == nil {
			auths = append(auths, ssh.PublicKeys(signer))
			break
		}
	}

	// ssh-agent, when available.
	if sock := os.Getenv("SSH_AUTH_SOCK"); len(sock) > 0 {
		if conn, err := net.Dial("unix", sock); err == nil {
			auths = append(auths, ssh.PublicKeysCallback(sshagent.NewClient(conn).Signers))
		}
	}

	if len(auths) == 0 {
		return nil, fmt.Errorf("no SSH authentication available (provide --ssh-key or run ssh-agent)")
	}
	return auths, nil
}

// remote runs the privileged install steps on a node over SSH, elevating with sudo
// when the login user is not root.
type remote struct {
	client *ssh.Client
	sudo   bool
	pass   string // sudo password; empty selects passwordless sudo (sudo -n)
}

func (r *remote) close() { _ = r.client.Close() }

// exec runs cmd on the node, feeding stdin (may be nil) and streaming output.
func (r *remote) exec(cmd string, stdin io.Reader) error {
	sess, err := r.client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = sess.Close() }()
	sess.Stdin = stdin
	sess.Stdout, sess.Stderr = os.Stdout, os.Stderr
	return sess.Run(cmd)
}

// elevate wraps cmd with sudo when enabled. Password sudo consumes the password
// from stdin (-S), replacing any caller stdin.
func (r *remote) elevate(cmd string, stdin io.Reader) (string, io.Reader) {
	switch {
	case !r.sudo:
		return cmd, stdin
	case r.pass == "":
		return "sudo -n " + cmd, stdin
	default:
		return "sudo -S -p '' " + cmd, strings.NewReader(r.pass + "\n")
	}
}

// sudoRun runs a command, elevating it when sudo is enabled; fail-fast.
func (r *remote) sudoRun(cmd string) {
	c, stdin := r.elevate(cmd, nil)
	if err := r.exec(c, stdin); err != nil {
		log.Fatal().Err(err).Msg("remote command")
	}
}

// run runs a command AS THE LOGIN USER, never elevated; fail-fast. Some steps must not be
// elevated: a `systemd --user` install belongs to the user it will run as, and sudo would
// silently install it for root instead.
func (r *remote) run(cmd string) {
	if err := r.exec(cmd, nil); err != nil {
		log.Fatal().Err(err).Msg("remote command")
	}
}

// put streams data to dest with the given octal mode via `install`, elevating via
// sudo when needed.
func (r *remote) put(data []byte, dest, mode string) { r.putOwned(data, dest, mode, "") }

// putOwned uploads a file and, when owner is set, gives it to that user.
//
// Ownership matters for exactly one file and it is the important one: node.conf embeds the
// node's private key, so it is written 0600 — and under sudo that means root:root, which the
// agent cannot read, because the agent deliberately does NOT run as root. The install failed
// on its own output before this: the elevated step wrote a credential the unelevated step, and
// then the service, had no way to open.
func (r *remote) putOwned(data []byte, dest, mode, owner string) {
	install := "install -D -m" + mode + " "
	if owner != "" {
		install = "install -D -o" + owner + " -m" + mode + " "
	}

	// Password sudo can't share stdin between the password line and the file
	// bytes, so stage the file as the login user, then move it into place with
	// sudo and delete the stage.
	if r.sudo && r.pass != "" {
		stage := ".horchestra-stage/" + filepath.Base(dest)
		if err := r.exec(install+"/dev/stdin "+stage, bytes.NewReader(data)); err != nil {
			log.Fatal().Err(err).Str("remote", stage).Msg("upload")
		}
		c, stdin := r.elevate(install+stage+" "+dest+" && rm -f "+stage, nil)
		if err := r.exec(c, stdin); err != nil {
			log.Fatal().Err(err).Str("remote", dest).Msg("upload")
		}
		return
	}

	// No sudo, or passwordless sudo (-n does not read stdin): stream straight in.
	c, _ := r.elevate(install+"/dev/stdin "+dest, nil)
	if err := r.exec(c, bytes.NewReader(data)); err != nil {
		log.Fatal().Err(err).Str("remote", dest).Msg("upload")
	}
}

// sudoPassword resolves the sudo password: the --sudo-pass flag, then
// HORCHESTRA_SUDO_PASS, then a passwordless-sudo probe, then an interactive prompt.
// An empty result selects passwordless sudo.
func sudoPassword(r *remote, flagVal string) string {
	if len(flagVal) > 0 {
		return flagVal
	}
	if p, ok := os.LookupEnv("HORCHESTRA_SUDO_PASS"); ok {
		return p
	}
	if r.nopasswdSudo() {
		log.Info().Msg("remote sudo is passwordless; no password needed")
		return ""
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		log.Warn().Msg("remote sudo needs a password but no terminal to prompt and no --sudo-pass/HORCHESTRA_SUDO_PASS set")
		return ""
	}
	_, _ = fmt.Fprint(os.Stderr, "[sudo] password for remote user: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(b), "\r\n")
}

// nopasswdSudo reports whether the remote user may run sudo without a password.
func (r *remote) nopasswdSudo() bool {
	sess, err := r.client.NewSession()
	if err != nil {
		return false
	}
	defer func() { _ = sess.Close() }()
	return sess.Run("sudo -n true") == nil
}
