//go:build linux

// netd — the `horchestra netd` command: the privileged network helper, as a subcommand of the node
// binary rather than a binary of its own.
//
// Sharing a FILE with the agent is not sharing a PROCESS. The privilege boundary this helper exists
// for is enforced by systemd, not by the linker: netd runs as a root system unit holding
// CAP_NET_ADMIN/CAP_BPF and friends, the agent runs as an unprivileged `systemd --user` unit with
// nothing, and neither can become the other by being in the same executable. What one file buys is
// that a node cannot end up with an agent and a helper from different builds — which was a real
// failure mode when they were copied separately.
//
// What it costs is honest and worth writing down: this root process now maps the agent's whole
// dependency closure, and the agent maps the eBPF loader. The compiler no longer refuses an import
// across that line, so the module boundary (netd/ is its own module) is what keeps it from
// happening by accident.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	netdapi "github.com/ks-tool/horchestra/api/netd"
	"github.com/ks-tool/horchestra/netd"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

// netdCmd builds the `netd` command.
func netdCmd(version string) *cobra.Command {
	var socket, agentUser, cgroupRoot, uplink, pinDir, overlay string
	cmd := &cobra.Command{
		Use:   "netd",
		Short: "serve the privileged network helper (root; a system unit, never the agent's)",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

			uid, err := resolveUID(agentUser)
			if err != nil {
				log.Fatal().Err(err).Msg("netd: --agent-user")
			}

			// The wiring half. The AGENT creates the namespace — a namespace made by root could
			// never be entered by the unprivileged sandbox that has to run in it (CAP_SYS_ADMIN in
			// the owning user namespace; measured, EPERM) — and this helper reaches in to give it a
			// veth, an address and routes.
			handler := &netd.Handler{Version: version, Link: &netd.VethLinker{}}

			// The datapath half, loaded at startup and NOT on demand: attaching to the cgroup root
			// is what makes a ClusterIP answer for every process on the node, and a node that
			// cannot do it must say so on its first heartbeat rather than at the first connect(2)
			// of the first workload that needed it. A failure is not fatal — the node still runs
			// workloads and routes them — so the reason is carried into Status, not into an exit.
			dp, err := netd.LoadSockLB(cgroupRoot, pinDir)
			if err != nil {
				handler.DatapathReason = err.Error()
				log.Warn().Err(err).Str("cgroup-root", cgroupRoot).Msg("netd: no service datapath on this node")
			} else {
				handler.Datapath = dp
				defer func() { _ = dp.Close() }()
			}

			// The forwarding half. Its programs, attachments and tables are PINNED, so what happens
			// here is usually ADOPTION: whatever the previous process left running kept running
			// while this one was not, and it is taken over rather than rebuilt. Rewire then
			// reconciles it against the interfaces the node actually has.
			fw, err := netd.LoadForwarder(uplink, pinDir, overlay)
			if err != nil {
				if handler.DatapathReason == "" {
					handler.DatapathReason = err.Error()
				}
				log.Warn().Err(err).Msg("netd: no forwarding datapath on this node")
			} else {
				handler.Forward = fw
				defer func() { _ = fw.Close() }()
				if err := handler.Rewire(); err != nil {
					log.Error().Err(err).Msg("netd: some workloads are not on the datapath")
				}
			}

			l, err := netd.Listen(socket)
			if err != nil {
				log.Fatal().Err(err).Str("socket", socket).Msg("netd: listen")
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			st, _ := handler.Status(ctx, &netdapi.StatusRequest{})
			log.Info().Str("socket", socket).Uint32("agent-uid", uid).
				Bool("routedNetwork", st.GetRoutedNetwork()).Bool("datapath", st.GetDatapath()).
				Str("overlay", overlay).Str("reason", st.GetReason()).Msg("netd: serving")

			srv := netd.NewServer(handler, uid, log)
			go func() {
				<-ctx.Done()
				// Graceful: a call in flight is a netlink write half done, and killing it would
				// leave the node in a state the next reconcile has to discover rather than be
				// told about.
				srv.GracefulStop()
			}()
			if err := srv.Serve(l); err != nil {
				log.Fatal().Err(err).Msg("netd: serve")
			}
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&socket, "socket", netdapi.SocketPath, "unix socket to serve on (ignored under socket activation)")
	fs.StringVar(&agentUser, "agent-user", "", "the user whose agent may call (name or uid); required")
	fs.StringVar(&cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "the cgroup v2 root to attach the datapath to")
	fs.StringVar(&uplink, "uplink", "", "the interface other nodes are reached on (default: the one carrying the default route)")
	fs.StringVar(&pinDir, "pin-dir", netd.DefaultPinDir, "bpffs directory the datapath is pinned in, so it outlives this process")
	fs.StringVar(&overlay, "overlay", netd.OverlayNone, "how another node is reached: none (native, needs an underlay that carries workload addresses), vxlan or ipip")
	return cmd
}

// resolveUID takes the agent's user by name or by number. It is REQUIRED rather than defaulted: the
// default would be root, and a helper that answered root alone would answer nobody the design
// intends — while a helper that guessed a name would be one typo away from answering a user
// somebody else controls.
func resolveUID(spec string) (uint32, error) {
	if spec == "" {
		return 0, fmt.Errorf("required: the agent's user is who this helper answers, and there is no safe default")
	}
	if n, err := strconv.ParseUint(spec, 10, 32); err == nil {
		return uint32(n), nil
	}
	u, err := user.Lookup(spec)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}
