package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// connect opens an SSH session to addr and returns a remote for running the
// privileged install steps, resolving the sudo password when elevation is needed.
func connect(user, addr, sshKey string, sudo bool, sudoPass string) *remote {
	client, err := dialSSH(user, addr, sshKey)
	fatal(err, "ssh connect")
	r := &remote{client: client, sudo: sudo}
	if sudo {
		r.pass = sudoPassword(r, sudoPass)
	}
	return r
}

func dialSSH(user, addr, keyPath string) (*ssh.Client, error) {
	auths, err := sshAuth(keyPath)
	if err != nil {
		return nil, err
	}
	host := addr
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "22")
	}
	return ssh.Dial("tcp", host, &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
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

// put streams data to dest with the given octal mode via `install`, elevating via
// sudo when needed.
func (r *remote) put(data []byte, dest, mode string) {
	install := "install -D -m" + mode + " "

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
