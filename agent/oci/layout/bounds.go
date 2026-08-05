package layout

import (
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/opencontainers/go-digest"
	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// MaxManifestBytes is the distribution spec's ceiling on a manifest or index document. It also
// bounds any metadata blob whose descriptor declares no size — the resolved root, whose Size is
// whatever Content-Length the registry did or did not send.
const MaxManifestBytes = 4 << 20

// DefaultStall is how long a transfer may make no progress before it is abandoned.
const DefaultStall = 60 * time.Second

// Bounds is what the caller will let an image be, checked against the manifest before a single
// layer byte is fetched. The manifest is digest-verified first, so a registry cannot understate
// here and then overshoot on the wire: every transfer is separately held to the size its
// descriptor declared, which is what makes these caps real rather than advisory.
//
// A zero field is unbounded. The agent fills all of them; the CLI leaves them open.
type Bounds struct {
	// MaxLayers caps how many layers one manifest may declare.
	MaxLayers int
	// MaxImageBytes caps the total the manifest declares for its blobs — config plus
	// compressed layers.
	MaxImageBytes int64
	// MaxLayerBytes caps a single layer's DECOMPRESSED size: the guard against a
	// decompression bomb, applied as the layer streams into the extractor.
	MaxLayerBytes int64
}

// checkManifest validates a manifest's declared shape against b — layer count, well-formed and
// non-negative blob descriptors, and the declared total — and returns that total so a caller
// with a disk budget can reuse it.
//
// Digest.Validate is not decoration here: the layout derives a blob's path from the digest
// string, so a manifest listing a layer as "../../../..:name" would otherwise turn the unpack
// into a write anywhere the agent's uid can reach.
func checkManifest(manifest ocispecv1.Manifest, b Bounds) (declared int64, err error) {
	if b.MaxLayers > 0 && len(manifest.Layers) > b.MaxLayers {
		return 0, fmt.Errorf("image declares %d layers, above the %d-layer cap", len(manifest.Layers), b.MaxLayers)
	}
	for _, d := range slices.Concat([]ocispecv1.Descriptor{manifest.Config}, manifest.Layers) {
		if err := d.Digest.Validate(); err != nil {
			return 0, fmt.Errorf("blob with malformed digest %q: %w", d.Digest, err)
		}
		if d.Size < 0 {
			return 0, fmt.Errorf("blob %s declares a negative size", d.Digest)
		}
		declared += d.Size
		if declared < 0 {
			return 0, fmt.Errorf("image's declared blob sizes overflow")
		}
	}
	if b.MaxImageBytes > 0 && declared > b.MaxImageBytes {
		return 0, fmt.Errorf("image declares %d bytes of blobs, above the %d-byte cap", declared, b.MaxImageBytes)
	}
	return declared, nil
}

// checkPin enforces a digest-pinned reference as an EXPECTATION rather than a hint: the
// descriptor the registry resolved must carry exactly the pinned digest, checked before anything
// is fetched, so the whole verified tree anchors to the operator's pin. Without it the pin is
// decorative — the resolved digest comes from the server's own Docker-Content-Digest header, so a
// compromised registry could serve any image under the pinned name and every downstream hash
// check would happily verify the substitute against itself.
func checkPin(pin, resolved digest.Digest) error {
	if pin == "" {
		return nil
	}
	if resolved != pin {
		return fmt.Errorf("image is pinned to %s but the registry resolved it to %s: refusing the substituted image",
			pin, resolved)
	}
	return nil
}

// boundReader passes through at most remaining bytes and fails the transfer — with what, not
// io.EOF — once the stream exceeds them, so an endpoint cannot feed more bytes than its
// descriptor declared. A stream that ends at exactly the bound still yields the underlying
// io.EOF. (io.LimitReader would instead truncate silently and leave the digest check to raise a
// misleading mismatch.)
type boundReader struct {
	r         io.Reader
	remaining int64
	what      string // names the exceeded bound in the error
}

// bound wraps r at limit, or returns it unchanged when limit is zero (unbounded).
func bound(r io.Reader, limit int64, what string) io.Reader {
	if limit <= 0 {
		return r
	}
	return &boundReader{r: r, remaining: limit, what: what}
}

func (b *boundReader) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		// Probe one byte to tell "ended exactly at the bound" from "has more".
		var one [1]byte
		n, err := b.r.Read(one[:])
		if n > 0 {
			return 0, fmt.Errorf("stream exceeds %s", b.what)
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// stallReader fails a transfer that stops making progress, rather than waiting on it forever.
//
// The agent converges on ONE goroutine, and the registry a layer comes from is named by the
// tenant. A host that completes TLS, answers with a valid manifest and then dribbles the blob one
// byte per minute holds that goroutine indefinitely — which freezes convergence, teardown and the
// heartbeat for every OTHER workload on the node, not just its own. A total timeout would be the
// wrong instrument (a large layer on a slow link is not a stall); what matters is that bytes keep
// arriving.
type stallReader struct {
	r      io.Reader
	window time.Duration
}

func (s *stallReader) Read(p []byte) (int, error) {
	type result struct {
		n   int
		err error
	}
	// One goroutine per Read is affordable here: io.Copy uses a 32 KiB buffer, so this runs once
	// per chunk of a transfer that is already bounded by the network.
	ch := make(chan result, 1)
	go func() {
		n, err := s.r.Read(p)
		ch <- result{n, err}
	}()
	timer := time.NewTimer(s.window)
	defer timer.Stop()
	select {
	case res := <-ch:
		return res.n, res.err
	case <-timer.C:
		return 0, fmt.Errorf("no data for %s: abandoning the transfer rather than holding the node's reconcile", s.window)
	}
}
