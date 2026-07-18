//go:build linux && !controlleronly

package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ks-tool/horchestra/agent"
	"github.com/ks-tool/horchestra/pkg/oci"
	"github.com/ks-tool/horchestra/pkg/systemd/units"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
)

// The agent command holds an mTLS gRPC bidirectional session to the controller: it
// reconciles this node off the desired state the controller pushes down and reports
// the node's status up the same stream on the heartbeat interval. The OS work is
// done through the injected image/mount/unit backends.
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
		Run: func(_ *cobra.Command, _ []string) {
			cfg, err := restConfig(authConfig, controller, cert, key, ca)
			fatal(err, "load node credentials")
			nodeCfg, err := agent.LoadNodeConfig(configFile)
			fatal(err, "load node config")

			images := oci.NewStore(filepath.Join(stateDir, "images"))
			unitsPort := units.New(unitDir)
			a, err := agent.NewAgent(cfg, node, stateDir, nodeCfg, images, oci.Mounter{}, unitsPort)
			fatal(err, "agent")

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

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
	fs.StringVar(&node, "node", "", "node name (defaults to the client certificate CN)")
	fs.StringVar(&stateDir, "state-dir", "/var/lib/horchestra", "directory for layouts and rootfs mounts")
	fs.StringVar(&unitDir, "unit-dir", "/run/systemd/system", "directory for application systemd units")
	fs.DurationVar(&heartbeat, "heartbeat", 15*time.Second, "status heartbeat interval")

	rootCmd.AddCommand(cmd)
}

// The purge command deletes every image in the node's oci-layout that is not in the
// --exclude set, garbage-collecting blobs that no surviving image references.
func init() {
	var (
		layoutPath string
		exclude    []string
	)
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "garbage-collect images from the node oci-layout",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			removed, err := oci.NewStore(layoutPath).Purge(context.Background(), exclude)
			fatal(err, "purge")
			log.Info().Str("layout", layoutPath).Strs("removed", removed).Int("count", len(removed)).Msg("purged images")
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&layoutPath, "layout", "/var/lib/horchestra/images", "node oci-layout directory to purge")
	fs.StringArrayVar(&exclude, "exclude", nil, "image ref to keep; repeatable")
	rootCmd.AddCommand(cmd)
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
