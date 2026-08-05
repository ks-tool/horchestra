package runtime

import "k8s.io/apimachinery/pkg/api/resource"

// Default image-store bounds, applied where an ImageLimits field is zero.
const (
	// DefaultMaxLayers caps how many layers one image manifest may declare.
	DefaultMaxLayers = 128
	// DefaultMaxImageBytes caps the total size an image manifest declares for
	// its blobs (config + compressed layers): 8Gi.
	DefaultMaxImageBytes = int64(8) << 30
	// DefaultMaxLayerBytes caps the decompressed size of a single layer: 16Gi.
	DefaultMaxLayerBytes = int64(16) << 30
)

// ImageLimits bounds what a single image pull may put on the node's disk, enforced
// fail-closed by the Images implementation before and while blobs land. It is the
// `images` section of the node-agent -config file — the same seam that caps the
// node's advertised resources — so an operator tunes it per node, not per call
// site. A zero field selects its documented default; only StoreBudget's zero means
// "no budget" (a pull must still fit the free space actually left on the store's
// filesystem).
type ImageLimits struct {
	// MaxLayers caps how many layers one image manifest may declare
	// (default DefaultMaxLayers, 128).
	MaxLayers int `json:"maxLayers,omitempty"`
	// MaxImageSize caps the total size an image's manifest declares for its
	// blobs — config plus compressed layers (default DefaultMaxImageBytes, 8Gi).
	// The transfer is then held to exactly those declarations per blob.
	MaxImageSize resource.Quantity `json:"maxImageSize,omitzero"`
	// MaxLayerSize caps the decompressed size of a single layer, measured on the
	// spooled bytes before anything is extracted, so a decompression bomb never
	// reaches the filesystem (default DefaultMaxLayerBytes, 16Gi).
	MaxLayerSize resource.Quantity `json:"maxLayerSize,omitzero"`
	// StoreBudget caps the image store's total on-disk footprint: a pull whose
	// declared size would push the store past the budget is refused, and the
	// failure surfaces in the Application's status. Unset means no budget — the
	// store may grow until the free-space precondition stops it. Reclamation
	// stays manual (`agent purge` in a maintenance window), never automatic.
	StoreBudget resource.Quantity `json:"storeBudget,omitzero"`
}

// EffectiveMaxLayers is MaxLayers, or DefaultMaxLayers when unset.
func (l ImageLimits) EffectiveMaxLayers() int {
	if l.MaxLayers > 0 {
		return l.MaxLayers
	}
	return DefaultMaxLayers
}

// EffectiveMaxImageBytes is MaxImageSize in bytes, or DefaultMaxImageBytes when unset.
func (l ImageLimits) EffectiveMaxImageBytes() int64 {
	if v := l.MaxImageSize.Value(); v > 0 {
		return v
	}
	return DefaultMaxImageBytes
}

// EffectiveMaxLayerBytes is MaxLayerSize in bytes, or DefaultMaxLayerBytes when unset.
func (l ImageLimits) EffectiveMaxLayerBytes() int64 {
	if v := l.MaxLayerSize.Value(); v > 0 {
		return v
	}
	return DefaultMaxLayerBytes
}
