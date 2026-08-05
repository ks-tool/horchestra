package agent

import (
	"fmt"
	"os"

	"github.com/ks-tool/horchestra/agent/runtime"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"
)

// NodeConfig is the node-agent's operational config (the -config file). It
// carries the node's resource caps and image-store bounds; it is the seam for
// further node-local settings.
type NodeConfig struct {
	// Resources caps the capacity a node advertises, so an operator can dedicate
	// less than the machine's total to the orchestrator. An unset field is
	// uncapped — by default a node offers all of its resources.
	Resources corev1.ResourceAmounts `json:"resources,omitzero"`
	// Images bounds what the node's shared image store accepts from a registry:
	// layer count, declared image size, decompressed layer size and the store's
	// total on-disk budget. Zero fields take the runtime.ImageLimits defaults; only
	// the store budget defaults to uncapped (the free-space precondition still
	// applies).
	Images runtime.ImageLimits `json:"images,omitzero"`
}

// LoadNodeConfig reads and parses the node-agent -config file. An empty path yields
// the zero config (no limits — all of the node's resources).
func LoadNodeConfig(path string) (NodeConfig, error) {
	var cfg NodeConfig
	if len(path) == 0 {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse node config %s: %w", path, err)
	}
	return cfg, nil
}

// capped returns limit when it is set and below measured, otherwise measured — a
// -config limit may only reduce the advertised capacity, never inflate it.
func capped(measured, limit resource.Quantity) resource.Quantity {
	if !limit.IsZero() && limit.Cmp(measured) < 0 {
		return limit
	}
	return measured
}
