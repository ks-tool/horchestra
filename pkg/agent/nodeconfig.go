package agent

import (
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"

	v1 "ks-tool.dev/horchestra/api/v1"
)

// NodeConfig is the node-agent's operational config (the -config file). Today it
// carries only resource limits; it is the seam for further node-local settings.
type NodeConfig struct {
	// Resources caps the capacity a node advertises, so an operator can dedicate
	// less than the machine's total to the orchestrator. An unset field is
	// uncapped. Values are Kubernetes quantities — the same cpu/memory an
	// Application requests (e.g. cpu: "4", memory: 8Gi).
	Resources v1.ResourceAmounts `json:"resources,omitempty"`
}

// LoadNodeConfig reads and parses the node-agent -config file. An empty path
// yields the zero config (no limits).
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

// capped returns limit when it is set and below measured, otherwise measured —
// a -config limit may only reduce the advertised capacity, never inflate it.
func capped(measured, limit resource.Quantity) resource.Quantity {
	if !limit.IsZero() && limit.Cmp(measured) < 0 {
		return limit
	}
	return measured
}
