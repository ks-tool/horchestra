//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ks-tool/horchestra/agent"
	"github.com/ks-tool/horchestra/agent/network"
	"github.com/ks-tool/horchestra/agent/oci"
	"github.com/ks-tool/horchestra/agent/runtime"
	"github.com/ks-tool/horchestra/agent/runtime/userns"
	"github.com/ks-tool/horchestra/agent/secret"
	"github.com/ks-tool/horchestra/agent/volume"
	"github.com/ks-tool/horchestra/cmd/internal/kubeconfig"
	"github.com/ks-tool/horchestra/pkg/nodeboot"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// agentCmd builds the node-agent command: it holds an mTLS gRPC session to the controller,
// reconciles this node off the pushed desired state and reports status on the heartbeat, through
// the injected runtime.Runtime (the rootless userns runtime) and volume.Volumes.
func agentCmd() *cobra.Command {
	var (
		authConfig, configFile, controller, cert, key, ca string
		stateDir, runtimeDir, sandboxBin                  string
		heartbeat                                         time.Duration
	)
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "run the node agent: converge every workload this node is assigned",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			// Enter the persistent user namespace (mapped-root + subuid range) before anything
			// else: a stage-1 child maps + re-execs, the outer process forks + waits + exits, and
			// past here the agent runs unprivileged with only namespaced caps — image pull,
			// overlay mounts and workloads are all rootless. This is unconditional: the agent
			// holds no host capability, so there is no privileged runtime left to select.
			fatal(userns.MapAndReexec(), "userns map")
			fatal(userns.EnterUserns(os.Stderr, userns.UsernsOptions{Flags: userns.AgentUsernsFlags}), "enter userns")
			// Read AFTER entering: this is the namespace whose ids the agent can actually use, and
			// SubordinateIDs reads its map rather than a file — inside here the process is root,
			// and /etc/subuid has no line for root. One reading, handed to every mechanism that
			// has to name a workload's identity on disk; two DERIVATIONS of that identity already
			// disagreed once, with the volume driver chowning to an in-namespace id the node has
			// no name for.
			subUID, subGID, idErr := userns.SubordinateIDs()
			fatal(idErr, "subordinate id ranges")
			cfg, err := restConfig(authConfig, controller, cert, key, ca)
			fatal(err, "load node credentials")
			nodeCfg, err := agent.LoadNodeConfig(configFile)
			fatal(err, "load node config")

			images := oci.NewStore(filepath.Join(stateDir, "images"), nodeCfg.Images)
			sandboxCmd, err := resolveSandboxCmd(sandboxBin)
			fatal(err, "sandbox binary")
			rt := userns.New(images, stateDir, runtimeDir, sandboxCmd, subUID, subGID)
			volumes := volume.NewLocal(stateDir, subUID, subGID)
			// NewAgent binds it to the certificate CN — the identity the controller authorized —
			// so it unseals a Secret only for an Application naming this node. The vault client
			// reuses the same client certificate as its Vault cert-auth credential.
			vault := secret.NewVault(clientCertSource(cfg))
			secrets := secret.NewControllerStore(vault)
			// The network helper, asked for rather than assumed: an unreachable one is not an
			// error here, it is a node where every workload runs on the host's network — which is
			// every node today. Only a workload that ASKS for its own network fails, and it fails
			// where it is started rather than silently running flat.
			net := &network.Netd{}
			if st, err := net.Status(context.Background()); err != nil {
				log.Info().Err(err).Msg("no network helper: every workload runs on the host's network")
			} else {
				log.Info().Bool("routedNetwork", st.GetRoutedNetwork()).
					Bool("datapath", st.GetDatapath()).Str("reason", st.GetReason()).
					Msg("network helper")
			}
			rt = rt.WithNetwork(net)
			a, err := agent.NewAgent(cfg, nodeCfg, rt, volumes, secrets, net)
			fatal(err, "agent")

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Keep cached Vault values current off the converge path. The reconcile goroutine is
			// the converge: a blocking Vault read there delays every workload, including those
			// referencing no secret at all, so only the first read of a value happens inline and
			// the renewals belong here — waking at the nearest deadline rather than on a tick,
			// since when a value goes stale is Vault's answer and not the heartbeat's.
			go vault.Refresh(ctx)

			// Renew the node certificate before it expires (only when running off a node.conf —
			// a cert-file agent is managed externally). Rotation exits the process for a systemd
			// restart onto the fresh credentials.
			if authConfig != "" {
				go rotateCertLoop(ctx, stop, authConfig)
			}

			log.Info().Str("controller", cfg.Host).Dur("heartbeat", heartbeat).Msg("node-agent connecting")
			err = a.Start(ctx, heartbeat)
			log.Info().Msg("node-agent stopped")
			fatal(err, "node-agent")
		},
	}

	fs := cmd.Flags()
	fs.StringVar(&authConfig, "auth-config", "", "node.conf bundling the client cert/key, CA and controller URL (from node-tool deploy)")
	fs.StringVar(&configFile, "config", "", "node-agent config file (resource limits)")
	fs.StringVar(&controller, "controller", "https://127.0.0.1:8443", "controller API URL (ignored when --auth-config is set)")
	fs.StringVar(&cert, "cert", "", "client certificate for mTLS")
	fs.StringVar(&key, "key", "", "client private key")
	fs.StringVar(&ca, "ca", "", "CA that verifies the controller")
	fs.StringVar(&stateDir, "state-dir", defaultStateDir(), "directory for layouts and rootfs mounts")
	// Secret material never touches persistent disk, so everything derived from a Secret lives
	// here: the RAM-backed overlay layer carrying /etc/environment (systemd runtime) and the
	// socket the rootless runtime's sandboxes fetch their environment over. It must be tmpfs —
	// /run for a system agent, $XDG_RUNTIME_DIR for a user one.
	fs.StringVar(&runtimeDir, "runtime-dir", defaultRuntimeDir(), "RAM-backed directory for secret-derived state (must be tmpfs)")
	fs.StringVar(&sandboxBin, "sandbox-bin", "", "binary each rootless workload's unit ExecStarts, run with its `sandbox` subcommand (default: this binary)")
	fs.DurationVar(&heartbeat, "heartbeat", 15*time.Second, "status heartbeat interval")

	cmd.AddCommand(purgeCmd())

	return cmd
}

// purgeCmd builds the image garbage-collection command: it reclaims the node's image store
// down to the --exclude keep-set through the runtime's GC (not a hardcoded oci-layout path).
func purgeCmd() *cobra.Command {
	var (
		stateDir string
		exclude  []string
	)
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "garbage-collect images from the node image store",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			// Purge never pulls, so the store needs no limits here.
			images := oci.NewStore(filepath.Join(stateDir, "images"), runtime.ImageLimits{})
			// GC only touches the image store, so it is asked of the store directly rather than
			// through a runtime that would exist here for nothing else.
			removed, err := runtime.GCImages(context.Background(), images, exclude)
			fatal(err, "purge")
			log.Info().Str("state-dir", stateDir).Strs("removed", removed).Int("count", len(removed)).Msg("purged images")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&stateDir, "state-dir", defaultStateDir(), "node state directory whose image store to purge")
	fs.StringArrayVar(&exclude, "exclude", nil, "image ref to keep; repeatable")
	return cmd
}

// resolveSandboxCmd is what a rootless workload's unit ExecStarts: the node binary and its
// `sandbox` subcommand.
//
// The default is THIS binary, and that is the whole point of merging them — the trampoline is the
// same build as the agent that wrote the unit, necessarily rather than by convention, because it is
// the same file. It used to be looked for beside this one, which is where a half-finished copy
// could leave a mismatched pair.
//
// It still fails LOUDLY when the path is wrong rather than deferring to the first workload: the
// unit would be written with something systemd cannot exec, every rootless workload on the node
// would fail at 203/EXEC, and the cause would only be visible per workload.
func resolveSandboxCmd(flagValue string) ([]string, error) {
	path := flagValue
	if path == "" {
		self, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("locate this binary to ExecStart its sandbox subcommand: %w", err)
		}
		path = self
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (build it with `make horchestra`, or pass --sandbox-bin)", abs, err)
	}
	if fi.IsDir() || fi.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("%s is not an executable file", abs)
	}
	return []string{abs, "sandbox"}, nil
}

// writeNodeConf writes the issued node credentials into a node.conf (kubeconfig) at path,
// using the shared single-context builder in cmd/internal/kubeconfig.
func writeNodeConf(path, controllerURL, node string, res *nodeboot.Result) error {
	kc := kubeconfig.Build("horchestra", node, controllerURL, res.CAPEM, res.CertPEM, res.KeyPEM)
	return clientcmd.WriteToFile(kc, path)
}

// rotateCertLoop renews the node's certificate before it expires: at ~2/3 of the cert's
// lifetime it re-enrolls authenticated by the CURRENT cert (the controller's selfnodeclient
// path signs it), rewrites node.conf, then cancels ctx so the process exits and systemd
// restarts it onto the new credentials — short TTL + rotation is the only revocation lever. A
// restart is non-disruptive: the agent is stateless and the workloads are independent units.
func rotateCertLoop(ctx context.Context, stop context.CancelFunc, path string) {
	kc, err := clientcmd.LoadFromFile(path)
	if err != nil {
		log.Warn().Err(err).Msg("cert rotation disabled: cannot load node.conf")
		return
	}
	c := kc.Contexts[kc.CurrentContext]
	if c == nil {
		return
	}
	cluster, user := kc.Clusters[c.Cluster], kc.AuthInfos[c.AuthInfo]
	if cluster == nil || user == nil || len(user.ClientCertificateData) == 0 {
		return
	}
	notAfter, cn, err := certInfo(user.ClientCertificateData)
	if err != nil {
		log.Warn().Err(err).Msg("cert rotation disabled: cannot parse node certificate")
		return
	}
	// Resolve the trust anchor before scheduling anything. A kubeconfig may carry the CA
	// inline or by path, and only the inline form was ever read — so a path-referenced CA
	// left this empty, rotation ran with server verification disabled, and the result was
	// written back over node.conf. That made the downgrade permanent: the node came back with
	// no anchor at all, so every later rotation was open to the same MITM. No CA now means no
	// rotation, loudly, rather than an unverified one.
	caPEM := cluster.CertificateAuthorityData
	if len(caPEM) == 0 && cluster.CertificateAuthority != "" {
		if b, rerr := os.ReadFile(cluster.CertificateAuthority); rerr == nil {
			caPEM = b
		} else {
			log.Warn().Err(rerr).Str("path", cluster.CertificateAuthority).Msg("cert rotation: cannot read the CA file")
		}
	}
	if len(caPEM) == 0 {
		log.Warn().Msg("cert rotation disabled: node.conf carries no certificate authority")
		return
	}
	// Renew at 2/3 of the time remaining when the agent started. The cert's NotBefore is
	// backdated for clock-skew tolerance, so it cannot serve as the lifetime start.
	renewAt := time.Now().Add(time.Until(notAfter) * 2 / 3)
	log.Info().Time("renewAt", renewAt).Time("expires", notAfter).Str("node", cn).Msg("certificate rotation scheduled")
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Until(renewAt)):
	}
	for ctx.Err() == nil && time.Now().Before(notAfter) {
		res, rerr := nodeboot.Enroll(ctx, nodeboot.Options{
			ControllerURL: cluster.Server, NodeName: cn, CA: caPEM,
			ClientCert: user.ClientCertificateData, ClientKey: user.ClientKeyData,
		})
		if rerr != nil {
			log.Warn().Err(rerr).Msg("cert rotation: re-enroll failed; retrying")
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Minute):
			}
			continue
		}
		if werr := writeNodeConf(path, cluster.Server, cn, res); werr != nil {
			log.Error().Err(werr).Msg("cert rotation: write node.conf")
			return
		}
		log.Info().Str("node", cn).Msg("certificate rotated; restarting to load the new node.conf")
		stop() // exit → systemd restarts onto the new cert
		return
	}
	log.Error().Str("node", cn).Msg("cert rotation: certificate expired before renewal succeeded")
}

// certInfo returns a PEM client certificate's expiry and common name.
func certInfo(certPEM []byte) (notAfter time.Time, cn string, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, "", fmt.Errorf("not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, "", err
	}
	return cert.NotAfter, cert.Subject.CommonName, nil
}

// clientCertSource is the node's client certificate as a TLS callback, for the vault
// client's cert-auth — the same identity the controller session authenticates with. A
// config with no client certificate yields nil, and cert auth then fails closed.
func clientCertSource(cfg *rest.Config) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	tlsCfg, err := rest.TLSConfigFor(cfg)
	if err != nil || tlsCfg == nil {
		return nil
	}
	return tlsCfg.GetClientCertificate
}

// restConfig resolves the node's REST client config: from node.conf when
// --auth-config is set, otherwise from the discrete --cert/--key/--ca files and the
// --controller URL.
func restConfig(authConfig, controller, certFile, keyFile, caFile string) (*rest.Config, error) {
	if len(authConfig) > 0 {
		return agent.LoadAuthConfig(authConfig)
	}
	var certPEM, keyPEM, caPEM []byte
	var err error
	if len(certFile) > 0 {
		if certPEM, err = os.ReadFile(certFile); err != nil {
			return nil, err
		}
		if keyPEM, err = os.ReadFile(keyFile); err != nil {
			return nil, err
		}
	}
	if len(caFile) > 0 {
		if caPEM, err = os.ReadFile(caFile); err != nil {
			return nil, err
		}
	}
	return agent.RESTConfig(controller, certPEM, keyPEM, caPEM), nil
}

// fatal aborts the process with err when it is non-nil — the node commands are fail-fast.
func fatal(err error, msg string) {
	if err != nil {
		log.Fatal().Err(err).Msg(msg)
	}
}

// defaultStateDir is where a node keeps its image layouts and rootfs mounts.
//
// User-scoped, because the agent REFUSES to run as root — it holds no host capability by
// design — so /var/lib/horchestra was a default no agent could ever create. An install that
// produced exactly that shape started, connected, and then failed every converge with
// "mkdir /var/lib/horchestra: permission denied", which is the worst way for a default to be
// wrong: everything looks up until a workload is asked for.
//
// It is home-relative rather than under $XDG_RUNTIME_DIR because this data must SURVIVE a
// reboot — images are expensive to fetch again — whereas the runtime dir is tmpfs on purpose,
// holding what must not.
func defaultStateDir() string {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "horchestra")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "horchestra")
	}
	return "/var/lib/horchestra"
}

// defaultRuntimeDir is the RAM-backed directory secret-derived state lives in: the user's runtime
// directory when the agent runs as a user service (XDG_RUNTIME_DIR, tmpfs and per-user 0700),
// /run/horchestra for a system one. Both are wiped by a reboot, which is the point.
func defaultRuntimeDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "horchestra")
	}
	return "/run/horchestra"
}
