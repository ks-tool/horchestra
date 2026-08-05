package layout

import (
	"context"
	"path/filepath"
	"runtime"
	"time"

	"github.com/opencontainers/go-digest"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Default pull tuning. They are the CLI's defaults too, so a caller that leaves Options zero
// gets what `oci-layouts` does with no flags.
const (
	DefaultJobs    = 4
	DefaultRetries = 3
	DefaultQPS     = 20
	DefaultTimeout = 30 * time.Second
)

// Reference is a parsed image reference — a registry host, a repository and either a tag or a
// digest. Build one with ParseReference; the fields it holds are the package's own business.
type Reference = reference

// Ownership is the uid/gid an unpacked tree is chowned to: the identity that will RUN the
// workload, since the layers become its read-only root and nothing later can chown them.
type Ownership = ownership

// Options tune one Pull. The zero value is valid: the platform defaults to this machine's,
// credentials come from the docker CLI's config.json, and the transfer uses the Default* above.
type Options struct {
	// Platform selects from a multi-platform index, e.g. "linux/arm64". Empty means
	// linux/<this GOARCH>.
	Platform string
	// Creds is "user:password" for the registry. Empty falls back to the docker config.
	Creds string
	// Insecure talks plain HTTP to the registry.
	Insecure bool
	// Name is the ref name recorded in index.json. Empty stores the repository and tag as given.
	Name string
	// NameByDigest records the entry under the image's OWN manifest digest instead of a name the
	// caller chose. It makes the entry idempotent across every spelling of the same image, which
	// is what a multi-tenant store needs: an index keyed by a tenant-supplied name lets one
	// tenant replace the entry another tenant's workload resolves through.
	NameByDigest bool
	// Approve is called once the manifest is fetched, digest-verified and within Bounds, with the
	// total its blobs declare — and before a single layer byte is fetched. A non-nil error
	// refuses the pull. It is the seam for limits the layout itself cannot know: disk budget,
	// free space, an operator's allow-list.
	Approve func(manifest ocispecv1.Manifest, declared int64) error
	// Owner chowns the unpacked tree; nil leaves the ids the layers carry.
	Owner *Ownership
	// Jobs is how many layers are fetched and unpacked at once; Retries is the extra attempts a
	// retryable failure gets; QPS caps requests per second (0 = uncapped); Timeout bounds one
	// request's time to produce response headers.
	Jobs, Retries int
	QPS           float64
	Timeout       time.Duration
	// Pin is the digest the resolved manifest MUST carry. Empty accepts whatever the registry
	// resolves; set, it is enforced before a byte is fetched.
	Pin digest.Digest
	// Bounds caps what the image may declare and what a layer may decompress to. A zero field
	// is unbounded.
	Bounds Bounds
	// Stall is how long a transfer may make no progress before it is abandoned; 0 selects
	// DefaultStall.
	Stall time.Duration
	// Logf receives per-layer progress. nil discards it — the agent has its own logger and the
	// CLI passes log.Printf.
	Logf func(format string, args ...any)
}

// DefaultPlatform is the platform of the machine this runs on, in the "os/arch" spelling an
// image index uses.
func DefaultPlatform() string { return "linux/" + runtime.GOARCH }

// ParseReference parses an image reference in the usual registry syntax —
// [host[:port]/]repository[:tag|@digest] — resolving the docker.io shorthands.
func ParseReference(s string, insecure bool) (Reference, error) { return parseReference(s, insecure) }

// ParseOwner parses "uid[:gid]" into an Ownership; an empty string yields nil (leave ids alone).
func ParseOwner(s string) (*Ownership, error) { return parseOwner(s) }

// Pull copies the image into the OCI layout at layoutDir: resolve the manifest, store it and the
// image config as blobs, unpack every layer into its own directory and publish the result in
// index.json. The index is written LAST, so a run interrupted anywhere leaves a layout that
// describes only what is complete, and a cancelled context unwinds each in-flight layer (its
// half-unpacked directory is removed by its own defer).
//
// It is idempotent by digest: a layer whose directory is already there and marked complete is
// not fetched again.
//
// It returns the index entry it published — the caller learns the manifest digest it resolved to,
// which is the only name it can look the image up by when Options.NameByDigest is set.
func Pull(ctx context.Context, ref Reference, layoutDir string, opts Options) (ocispecv1.Descriptor, error) {
	dir, err := filepath.Abs(layoutDir)
	if err != nil {
		return ocispecv1.Descriptor{}, err
	}
	if opts.Name != "" {
		ref.name = opts.Name
	}
	lim := limits{
		jobs:    or(opts.Jobs, DefaultJobs),
		retries: or(opts.Retries, DefaultRetries),
		qps:     opts.QPS,
		timeout: opts.Timeout,
	}
	if opts.QPS == 0 {
		lim.qps = DefaultQPS
	}
	if opts.Timeout == 0 {
		lim.timeout = DefaultTimeout
	}
	if opts.Stall == 0 {
		opts.Stall = DefaultStall
	}
	// The zero value has to mean "this machine", not "no platform": a caller that leaves it unset
	// is asking for the image it can actually run, and an empty string matches nothing in a
	// multi-platform index.
	if opts.Platform == "" {
		opts.Platform = DefaultPlatform()
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return copyImage(ctx, ref, dir, opts, lim)
}

// or is the zero-value default helper for the int knobs.
func or(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}
