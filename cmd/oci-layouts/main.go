//go:build linux

// Command oci-layouts downloads an image from a remote registry into a local OCI layout and
// unpacks each layer into a directory ready to be stacked with overlayfs — what
// `oci-packer copy --unpack` did, without oci-packer. It is a thin CLI over agent/oci/layout,
// which the node agent calls directly; this binary exists for preparing layers by hand.
//
//	oci-layouts postgres:18-alpine /var/lib/layers
//	oci-layouts -platform linux/arm64 -j 8 ghcr.io/team/app:v1 /var/lib/layers
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ks-tool/horchestra/agent/oci/layout"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("oci-layouts: ")

	var (
		platform = flag.String("platform", layout.DefaultPlatform(), "platform to select from a multi-platform index")
		creds    = flag.String("u", "", "registry credentials as user:password (default: the docker CLI's config.json)")
		insecure = flag.Bool("insecure", false, "talk plain HTTP to the registry")
		name     = flag.String("name", "", "ref name to store in index.json (default: the repository and tag as given)")
		owner    = flag.String("owner", "", "chown the unpacked tree to uid[:gid] — the id that will run the workload")
		jobs     = flag.Int("j", layout.DefaultJobs, "layers to fetch and unpack at once")
		retries  = flag.Int("retries", layout.DefaultRetries, "extra attempts for a request or a layer that fails retryably")
		qps      = flag.Float64("qps", layout.DefaultQPS, "cap on requests per second to the registry (0 for no cap)")
		timeout  = flag.Duration("timeout", layout.DefaultTimeout, "how long one request may take to produce its response headers")
	)
	flag.Parse()
	if flag.NArg() != 2 {
		_, _ = fmt.Fprintln(os.Stderr, "usage: oci-layouts [flags] <image> <layout-dir>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if *jobs < 1 || *retries < 0 {
		log.Fatal("-j must be at least 1 and -retries not negative")
	}

	var opts layout.Options
	ref, err := layout.ParseReference(flag.Arg(0), *insecure)
	if err != nil {
		log.Fatal(err)
	}
	if len(*name) > 0 {
		opts.Name = *name
	}
	layoutDir, err := filepath.Abs(flag.Arg(1))
	if err != nil {
		log.Fatal(err)
	}
	own, err := layout.ParseOwner(*owner)
	if err != nil {
		log.Fatal(err)
	}

	// A pull is long enough that being interrupted is normal. Cancelling the context unwinds every
	// in-flight layer, and each one's half-unpacked directory is removed by its own defer, so an
	// interrupted run leaves a layout holding only whole layers.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	opts.Platform, opts.Creds, opts.Owner = *platform, *creds, own
	opts.Jobs, opts.Retries, opts.QPS, opts.Timeout = *jobs, *retries, *qps, *timeout
	opts.Logf = log.Printf
	if _, err := layout.Pull(ctx, ref, layoutDir, opts); err != nil {
		log.Fatal(err)
	}
}
