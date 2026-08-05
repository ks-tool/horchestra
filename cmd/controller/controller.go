// controller — the control plane's command wiring. It sat in cmd/internal while the monolith and
// the standalone binary both built it; the monolith is gone, so it lives beside its one caller.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	certv1 "github.com/ks-tool/horchestra/api/certificates/v1"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
	"github.com/ks-tool/horchestra/api/features"
	nodeapipb "github.com/ks-tool/horchestra/api/node"
	"github.com/ks-tool/horchestra/api/pki"
	rbacv1 "github.com/ks-tool/horchestra/api/rbac/v1"
	"github.com/ks-tool/horchestra/api/scheme"
	secretsv1 "github.com/ks-tool/horchestra/api/secrets/v1"
	"github.com/ks-tool/horchestra/api/storage"
	"github.com/ks-tool/horchestra/controller"
	"github.com/ks-tool/horchestra/controller/admission"
	"github.com/ks-tool/horchestra/controller/authn"
	"github.com/ks-tool/horchestra/controller/authz"
	"github.com/ks-tool/horchestra/controller/clientset"
	"github.com/ks-tool/horchestra/controller/loop"
	"github.com/ks-tool/horchestra/controller/loops/appset"
	"github.com/ks-tool/horchestra/controller/loops/nodecsr"
	"github.com/ks-tool/horchestra/controller/loops/scheduler"
	"github.com/ks-tool/horchestra/controller/nodeserver"
	"github.com/ks-tool/horchestra/controller/oidc"
	"github.com/ks-tool/horchestra/controller/service"
	"github.com/ks-tool/horchestra/pkg/config"
	"github.com/ks-tool/horchestra/pkg/storage/bolt"
	"github.com/ks-tool/horchestra/pkg/vaultpki"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

// controllerCmd builds the controller command: run the control-plane (REST /apis, discovery and
// Watch, authentication, authorization and the admission chain over storage, plus the gRPC
// node transport on the same TLS port).
func controllerCmd() *cobra.Command {
	cfg := config.Default()
	cmd := &cobra.Command{
		Use:   "horchestra-controller",
		Short: "Horchestra control-plane API server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cfg.Complete(cmd.Flags()); err != nil {
				return err
			}
			return runController(cfg)
		},
	}
	cfg.AddFlags(cmd.Flags())
	return cmd
}

func runController(cfg config.Config) error {
	// Resolve the storage backend (bolt only today) and ensure the BoltDB's parent directory
	// exists (e.g. /var/lib/horchestra for a deployed service); bbolt creates the file but not
	// the directory.
	dbPath, err := cfg.BoltPath()
	if err != nil {
		return err
	}
	if dir := filepath.Dir(dbPath); len(dir) > 0 {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create state dir %s: %w", dir, err)
		}
	}

	sch := scheme.New()
	corev1.AddToScheme(sch)
	rbacv1.AddToScheme(sch)
	certv1.AddToScheme(sch)
	secretsv1.AddToScheme(sch)

	store, err := bolt.Open(dbPath, sch)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	var (
		authenticator authn.Authenticator
		authorizer    authz.Authorizer
	)
	// mTLS (client-cert CN/Org) is the identity path for people and nodes, and no static bearer
	// token is registered (a built-in one would be an unauthenticated system:masters backdoor,
	// since the serving TLS admits a cert-less caller under VerifyClientCertIfGiven); no bypass is
	// compiled in at all. A caller this cannot identify gets 401 — there is no build of this
	// binary where that is not true. The workload issuer is added below when one is configured:
	// a workload presenting the token this control plane minted FOR THIS API authenticates as
	// itself, which is how an edge reads the catalog without a shared secret in a config file.
	authenticator = authn.Chain{}
	authorizer, err = buildAuthorizer(store)
	if err != nil {
		return fmt.Errorf("authorizer: %w", err)
	}

	// Build the service with the admission chain plus the RBAC escalation guard, which needs the
	// authorizer to verify a non-admin only grants permissions it already holds.
	svc := service.New(store, sch, admission.WithEscalationCheck(
		admission.DefaultChain(store, cfg.Gates,
			admission.WithServiceCIDR(cfg.ServiceCIDR),
			admission.WithRoutedNetwork(cfg.RoutedCIDR != "")), authorizer, store))

	// The node-agent transport is a gRPC bidirectional stream (apiserver/nodeserver)
	// served on the same TLS port as the REST API: an HTTP/2 request carrying
	// application/grpc is dispatched to the gRPC server, everything else to the REST
	// mux. The gRPC handler reads the node's identity from the mTLS peer certificate,
	// so it needs no auth middleware of its own. It also backs `kubectl logs`.
	// One node certificate means one live stream; a session that stops reporting for longer than a
	// node may be stale-but-Ready can be taken over by a reconnect.
	nodeOpts := []nodeserver.Option{
		nodeserver.WithSessionStaleAfter(cfg.ReadyTimeout),
		// The fleet's workload range, if it has one. The push is where an address reaches a node,
		// so the choosing lives there too.
		nodeserver.WithRoutedCIDR(cfg.RoutedCIDR),
	}
	if cfg.StrictNodeRegistration {
		// A node may claim only the name DNS gives the host it connects from, checked once, when it
		// registers. The check lives here because a node cannot credibly police its own name.
		nodeOpts = append(nodeOpts, nodeserver.WithStrictRegistration(net.DefaultResolver))
		log.Info().Msg("strict node registration: a joining node's certificate CN must match its reverse DNS name")
	}
	// The workload-identity issuer for Vault's kubernetes auth method: the controller
	// mints per-workload tokens into the desired-state push and answers TokenReview below,
	// so Vault authorizes each fetch per workload without trusting the cluster CA.
	var issuer *oidc.Issuer
	if cfg.JWTSigningKey != "" {
		iss := cfg.JWTIssuer
		if iss == "" {
			iss = "horchestra"
		}
		var err error
		if issuer, err = oidc.LoadOrGenerate(cfg.JWTSigningKey, iss); err != nil {
			return fmt.Errorf("workload-identity issuer: %w", err)
		}
		nodeOpts = append(nodeOpts, nodeserver.WithTokenMinter(issuer))
		authenticator = authn.Chain{Workloads: issuer}
		log.Info().Str("issuer", iss).Msg("workload-identity issuer enabled (TokenReview at /apis/authentication.k8s.io/v1/tokenreviews)")
	}
	nodes := nodeserver.New(svc, nodeOpts...)
	// NOTE: because the gRPC service is dispatched through grpcServer.ServeHTTP (below) rather
	// than grpc.Server.Serve, the transport-level ServerOptions do NOT apply — ServeHTTP builds
	// a ServerHandlerTransport per request and handles exactly one stream, so
	// MaxConcurrentStreams, ConnectionTimeout and the keepalive parameters would all be inert
	// here. The connection is owned by net/http, so the real bounds live on the http.Server's
	// HTTP2Config and timeouts at the bottom of this function; per-node cost is bounded instead
	// by nodeserver.register, which admits one live session per node. Only the options that act
	// per-call, not per-connection, are set here.
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(4 << 20),
	)
	nodeapipb.RegisterNodeServiceServer(grpcServer, nodes)

	srv := apiserver.New(sch, svc,
		apiserver.Recover,
		apiserver.AuditID,
		apiserver.Auth(authenticator),
		apiserver.RequestLog,
		apiserver.Authz(authorizer),
	)
	srv.SetAuthenticator(authenticator)
	srv.SetLogStreamer(nodes)
	// The measured half of monitoring: nodes report what each workload consumed on their
	// heartbeat, the transport holds the last sample in memory, and the apiserver serves it
	// twice — per application at its metrics subresource, and for the fleet at /metrics.
	srv.SetMetricsSource(nodeMetrics{nodes})
	srv.SetRateSource(nodeRates{nodes})
	srv.EmulatePodsAPI()
	// Gated, and the gate IS the enforcement: off, the route is never registered, so the answer
	// is the router's ordinary 404 and there is no handler behind a permission check to reach.
	if cfg.Gates.Enabled(features.NodeLogs) {
		srv.EnableNodeLogs()
	}
	// The pods alias lives under /api/v1, which the Authz middleware classifies as a
	// non-resource request and lets through; it authorizes itself, per Application namespace.
	srv.SetAuthorizer(authorizer)
	srv.SetCatalogNamespace(cfg.CatalogNamespace)

	// Self-service namespace listing: a non-admin sees the namespaces it is bound into,
	// without a cluster-wide list permission.
	srv.SetNamespaceFilter(func(ctx context.Context, id *authn.Identity) (map[string]bool, bool, error) {
		return authz.AccessibleNamespaces(ctx, store, sch, id)
	})

	// Level-driven control loops on the shared Manager: it owns leader gating (single-node
	// AlwaysLeader here; an etcd/postgres elector plugs in for HA) and one coalesced watch per
	// Kind, fanned to the loops. The scheduler (automatic placement) and the ApplicationSet
	// controller register here; ipam/netconfig join as their epics land.
	{
		loopLog := log.With().Str("component", "controller-loops").Logger()
		cl := clientset.New(svc)
		mgr := loop.NewManager(cl.WatchKind, loop.Config{Elector: loop.AlwaysLeader{}, Logger: &loopLog})
		schedLog := log.With().Str("component", "scheduler").Logger()
		mgr.Add(scheduler.New(cl, scheduler.Config{
			Policy:       scheduler.Spread,
			ReadyTimeout: cfg.ReadyTimeout,
			Logger:       &schedLog,
		}))
		appsetLog := log.With().Str("component", "appset").Logger()
		mgr.Add(appset.New(cl, appset.Config{Logger: &appsetLog}))
		// Node join: auto-approve a node's own certificate-rotation CSR (the selfnodeclient
		// predicate — requester CN == subject CN, system:nodes group) and sign it. Always on;
		// with no signer CA it runs offline-CA mode (approves CSRs, signed out-of-band by node-tool).
		var signer nodecsr.Signer
		switch {
		case cfg.VaultPKI != nil:
			// The key is Vault's; this process holds none. What it does hold is the check on
			// the way back — the issued certificate is verified against the CSR and the groups
			// asked for, so the no-escalation guarantee stays enforced here even though the
			// signing moved.
			vs, verr := vaultpki.New(*cfg.VaultPKI)
			if verr != nil {
				return fmt.Errorf("vault PKI signer: %w", verr)
			}
			signer = vs
			// Keep this controller's OWN Vault credential current through the same engine, so
			// the hand-bootstrapped certificate is a one-time step. Without it the credential
			// expires quietly — nothing depends on it until a node tries to rotate.
			go vs.SelfRenew(context.Background())
			log.Info().Str("server", cfg.VaultPKI.Server).Str("mount", cfg.VaultPKI.Mount).
				Str("role", cfg.VaultPKI.Role).Msg("node-join signed through Vault PKI; this controller holds no CA key")
		case len(cfg.SignerCert) > 0:
			ca, cerr := pki.LoadCA(cfg.SignerCert, cfg.SignerKey)
			if cerr != nil {
				return fmt.Errorf("cluster signer CA: %w", cerr)
			}
			signer = ca
			log.Info().Msg("node-join signer CA loaded")
		default:
			log.Info().Msg("node-join in offline-CA mode (no --cluster-ca-key)")
		}
		csrLog := log.With().Str("component", "nodecsr").Logger()
		auto := cfg.Gates.Enabled(features.AutoNodeCertRotation)
		if !auto {
			log.Info().Msg("node certificate rotation waits for operator approval (--feature-gates=AutoNodeCertRotation=true signs it automatically)")
		}
		mgr.Add(nodecsr.New(cl, nodecsr.Config{Signer: signer, AutoApproval: auto, TTL: cfg.NodeCertTTLDuration(), Logger: &csrLog}))
		go func() {
			if err := mgr.Run(context.Background()); err != nil && !errors.Is(err, context.Canceled) {
				log.Error().Err(err).Msg("controller loops stopped")
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	// The TokenReview slice of the Kubernetes API, so Vault's stock kubernetes auth
	// method can point kubernetes_host at this controller. Self-authenticating: the
	// handler accepts only a reviewer bearer this issuer signed (the login JWT itself,
	// which is what the method sends when token_reviewer_jwt is unset).
	if issuer != nil {
		mux.HandleFunc("POST /apis/authentication.k8s.io/v1/tokenreviews", issuer.TokenReviewHandler())
	}
	mux.Handle("/", srv)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})

	// Bound what an unauthenticated peer can hold open. Only the two timeouts that cannot break
	// a legitimate long-lived response are set: ReadHeaderTimeout stops a slowloris that dribbles
	// request headers to pin a connection and its goroutine, and IdleTimeout reaps kept-alive
	// connections. ReadTimeout and WriteTimeout stay UNSET on purpose — watch streams and
	// `kubectl logs -f` are deliberately open-ended, and a WriteTimeout would cut them off. This
	// is the same split kube-apiserver makes.
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 32 * time.Second,
		IdleTimeout:       120 * time.Second,
		// net/http owns the HTTP/2 connection for both REST and the gRPC-over-ServeHTTP node
		// transport, so this is where a per-connection stream cap is actually enforced.
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: 64,
			PingTimeout:          20 * time.Second,
			WriteByteTimeout:     30 * time.Second,
		},
	}
	if cfg.ServerTLS != nil {
		server.TLSConfig = cfg.ServerTLS
		log.Info().Str("addr", cfg.Addr).Bool("mtls", len(cfg.ClientCA) > 0).Msg("controller listening (https)")
		return server.ListenAndServeTLS("", "")
	}
	log.Info().Str("addr", cfg.Addr).Msg("controller listening (http)")
	return server.ListenAndServe()
}

// buildAuthorizer compiles the Role/RoleBinding objects into a Casbin enforcer and keeps it in
// sync with a watch — Casbin is the only authorization engine.
func buildAuthorizer(store storage.Storage) (authz.Authorizer, error) {
	cb, err := authz.NewCasbin()
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
}

// nodeMetrics adapts the node transport's samples to what the apiserver serves. The two
// packages stay independent of each other — the composition root is where they meet, as it is
// for every other mechanism here.
type nodeMetrics struct{ srv *nodeserver.Server }

func (n nodeMetrics) Metrics(namespace, name string) (apiserver.Sample, bool) {
	s, ok := n.srv.Metrics(namespace, name)
	if !ok {
		return apiserver.Sample{}, false
	}
	return apiserver.Sample(s), true
}

func (n nodeMetrics) AllNodeMetrics() []apiserver.Sample {
	return convertSamples(n.srv.AllNodeMetrics())
}

func (n nodeMetrics) AllMetrics() []apiserver.Sample { return convertSamples(n.srv.AllMetrics()) }

func convertSamples(in []nodeserver.Sample) []apiserver.Sample {
	out := make([]apiserver.Sample, 0, len(in))
	for _, s := range in {
		out = append(out, apiserver.Sample(s))
	}
	return out
}

// nodeRates adapts the derived rates the same way, for the metrics.k8s.io surface `kubectl
// top` reads.
type nodeRates struct{ srv *nodeserver.Server }

func (n nodeRates) Rate(namespace, name string) (apiserver.Rate, bool) {
	r, ok := n.srv.Rate(namespace, name)
	return apiserver.Rate(r), ok
}

func (n nodeRates) NodeRate(node string) (apiserver.Rate, bool) {
	r, ok := n.srv.NodeRate(node)
	return apiserver.Rate(r), ok
}

func (n nodeRates) AllRates() map[string]apiserver.Rate { return convertRates(n.srv.AllRates()) }
func (n nodeRates) AllNodeRates() map[string]apiserver.Rate {
	return convertRates(n.srv.AllNodeRates())
}

func convertRates(in map[string]nodeserver.Rate) map[string]apiserver.Rate {
	out := make(map[string]apiserver.Rate, len(in))
	for k, v := range in {
		out[k] = apiserver.Rate(v)
	}
	return out
}
