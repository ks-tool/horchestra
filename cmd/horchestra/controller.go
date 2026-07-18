//go:build !agentonly

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/pb"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/apiserver"
	"github.com/ks-tool/horchestra/apiserver/admission"
	"github.com/ks-tool/horchestra/apiserver/authn"
	"github.com/ks-tool/horchestra/apiserver/authz"
	"github.com/ks-tool/horchestra/apiserver/nodeserver"
	"github.com/ks-tool/horchestra/apiserver/service"
	"github.com/ks-tool/horchestra/pkg/config"
	"github.com/ks-tool/horchestra/pkg/storage/bolt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

// The controller command runs the control-plane: REST /apis, discovery and Watch,
// authentication, authorization and the admission chain over BoltDB storage, plus
// the gRPC node transport on the same TLS port.
func init() {
	cfg := config.Default()
	cmd := &cobra.Command{
		Use:   "controller",
		Short: "run the control-plane API server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fatal(cfg.Complete(cmd.Flags()), "config")
			fatal(runController(cfg), "controller")
		},
	}
	cfg.AddFlags(cmd.Flags())
	rootCmd.AddCommand(cmd)
}

func runController(cfg config.Config) error {
	// Ensure the BoltDB's parent directory exists (e.g. /var/lib/horchestra for a
	// deployed service); bbolt creates the file but not the directory.
	if dir := filepath.Dir(cfg.DBPath); len(dir) > 0 {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create state dir %s: %w", dir, err)
		}
	}

	sch := scheme.New()
	corev1.AddToScheme(sch)
	rbacv1.AddToScheme(sch)

	store, err := bolt.Open(cfg.DBPath, sch)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	if err := authz.SeedDefaults(context.Background(), store); err != nil {
		return fmt.Errorf("seed default RBAC: %w", err)
	}

	svc := service.New(store, sch, admission.DefaultChain(store))

	var (
		authenticator authn.Authenticator
		authorizer    authz.Authorizer
	)
	if cfg.DisableAuth {
		authenticator, authorizer = authn.AllowAll{}, authz.AllowAll{}
		log.Warn().Msg("authentication and authorization disabled")
	} else {
		authenticator = authn.Chain{Tokens: map[string]authn.Identity{
			"dev-admin-token": {Name: "admin", Groups: []string{"system:masters"}},
		}}
		authorizer, err = buildAuthorizer(cfg, store)
		if err != nil {
			return fmt.Errorf("authorizer: %w", err)
		}
	}

	// The node-agent transport is a gRPC bidirectional stream (apiserver/nodeserver)
	// served on the same TLS port as the REST API: an HTTP/2 request carrying
	// application/grpc is dispatched to the gRPC server, everything else to the REST
	// mux. The gRPC handler reads the node's identity from the mTLS peer certificate,
	// so it needs no auth middleware of its own. It also backs `kubectl logs`.
	nodes := nodeserver.New(svc)
	grpcServer := grpc.NewServer()
	pb.RegisterNodeServiceServer(grpcServer, nodes)

	srv := apiserver.New(sch, svc,
		apiserver.AuditID,
		apiserver.Auth(authenticator),
		apiserver.Authz(authorizer),
	)
	srv.SetLogStreamer(nodes)
	srv.EmulatePodsAPI()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.Handle("/", srv)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})

	server := &http.Server{Addr: cfg.Addr, Handler: handler}
	if cfg.TLSEnabled() {
		tlsCfg, err := serverTLS(cfg)
		if err != nil {
			return fmt.Errorf("tls config: %w", err)
		}
		server.TLSConfig = tlsCfg
		log.Info().Str("addr", cfg.Addr).Bool("mtls", len(cfg.ClientCAPEM()) > 0).Msg("controller listening (https)")
		return server.ListenAndServeTLS("", "")
	}
	log.Info().Str("addr", cfg.Addr).Msg("controller listening (http)")
	return server.ListenAndServe()
}

// buildAuthorizer selects the authorization engine: "casbin" compiles the
// Role/RoleBinding objects into a Casbin enforcer kept in sync by a watch;
// anything else (default "rbac") queries those objects live per request.
func buildAuthorizer(cfg config.Config, store storage.Storage) (authz.Authorizer, error) {
	switch cfg.Authorizer {
	case "casbin":
		cb, err := authz.NewCasbin(cfg.AdminGroups)
		if err != nil {
			return nil, err
		}
		if err := cb.LoadFromStore(context.Background(), store); err != nil {
			return nil, err
		}
		go func() {
			if err := cb.Watch(context.Background(), store); err != nil {
				log.Error().Err(err).Msg("casbin: watch stopped")
			}
		}()
		log.Info().Msg("authorization: casbin")
		return cb, nil
	default:
		return &authz.RBAC{Store: store, AdminGroups: cfg.AdminGroups}, nil
	}
}

// serverTLS builds the TLS config from the resolved serving material; a configured
// client CA enables client-cert (mTLS) verification.
func serverTLS(cfg config.Config) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(cfg.ServingCertPEM(), cfg.ServingKeyPEM())
	if err != nil {
		return nil, err
	}
	t := &tls.Config{Certificates: []tls.Certificate{cert}}
	if caPEM := cfg.ClientCAPEM(); len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no CA certificates in client CA")
		}
		t.ClientCAs = pool
		t.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return t, nil
}
