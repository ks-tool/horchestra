//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"ks-tool.dev/horchestra/pkg/agent"
)

// The agent command holds an mTLS gRPC bidirectional session to the controller:
// it reconciles this node off the desired state the controller pushes down and
// reports the node's status up the same stream on the heartbeat interval.
func init() {
	var (
		authConfig, configFile, controller, cert, key, ca string
		node, stateDir, unitDir                           string
		heartbeat                                         time.Duration
	)
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "run the node reconcile session",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			creds, err := nodeCredentials(authConfig, controller, cert, key, ca)
			if err != nil {
				return fmt.Errorf("load node credentials: %w", err)
			}
			cfg, err := agent.LoadNodeConfig(configFile)
			if err != nil {
				return fmt.Errorf("load node config: %w", err)
			}
			r, err := agent.NewReconciler(creds.Controller, creds.CertPEM, creds.KeyPEM, creds.CAPEM, node, stateDir, unitDir, cfg)
			if err != nil {
				return fmt.Errorf("reconciler: %w", err)
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			log.Info().Str("controller", r.Controller).Dur("heartbeat", heartbeat).Msg("node-agent connecting")
			err = r.RunSession(ctx, heartbeat)
			log.Info().Msg("node-agent stopped")
			return err
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&authConfig, "auth-config", "", "node.conf bundling the client cert/key, CA and controller URL (from node-tool deploy)")
	fs.StringVar(&configFile, "config", "", "node-agent config file (resource limits)")
	fs.StringVar(&controller, "controller", "https://127.0.0.1:8443", "controller API URL (ignored when --auth-config is set)")
	fs.StringVar(&cert, "cert", "", "client certificate for mTLS")
	fs.StringVar(&key, "key", "", "client private key")
	fs.StringVar(&ca, "ca", "", "CA that verifies the controller")
	fs.StringVar(&node, "node", "", "node name (defaults to the client certificate CN)")
	fs.StringVar(&stateDir, "state-dir", "/var/lib/horchestra", "directory for layouts and rootfs mounts")
	fs.StringVar(&unitDir, "unit-dir", "/run/systemd/system", "directory for application systemd units")
	fs.DurationVar(&heartbeat, "heartbeat", 15*time.Second, "status heartbeat interval")

	rootCmd.AddCommand(cmd)
}

// The purge command deletes every image in the node's oci-layout that is not in
// the --exclude set, garbage-collecting blobs that no surviving image references.
func init() {
	var (
		layoutPath string
		exclude    []string
	)
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "garbage-collect images from the node oci-layout",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			removed, err := agent.Purge(context.Background(), layoutPath, exclude)
			if err != nil {
				return fmt.Errorf("purge: %w", err)
			}
			log.Info().Str("layout", layoutPath).Strs("removed", removed).Int("count", len(removed)).Msg("purged images")
			return nil
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&layoutPath, "layout", "/var/lib/horchestra/images", "node oci-layout directory to purge")
	fs.StringArrayVar(&exclude, "exclude", nil, "image ref to keep; repeatable")
	rootCmd.AddCommand(cmd)
}

// nodeCredentials resolves the node's mTLS material and controller URL from
// node.conf when --auth-config is set, otherwise from the individual
// --cert/--key/--ca files and the --controller flag — mirroring how the controller
// accepts either a kubeconfig or discrete --tls-* files.
func nodeCredentials(authConfig, controller, certFile, keyFile, caFile string) (agent.NodeCredentials, error) {
	if len(authConfig) > 0 {
		return agent.LoadAuthConfig(authConfig)
	}
	creds := agent.NodeCredentials{Controller: controller}
	if len(certFile) > 0 {
		cert, err := os.ReadFile(certFile)
		if err != nil {
			return creds, err
		}
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return creds, err
		}
		creds.CertPEM, creds.KeyPEM = cert, key
	}
	if len(caFile) > 0 {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return creds, err
		}
		creds.CAPEM = caPEM
	}
	return creds, nil
}
