package agent

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

func TestLoadNodeConfig(t *testing.T) {
	yaml := "resources:\n  cpu: \"4\"\n  memory: 8Gi\n"
	path := filepath.Join(t.TempDir(), "node.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadNodeConfig(path)
	if err != nil {
		t.Fatalf("LoadNodeConfig: %v", err)
	}
	if cfg.Resources.CPU.Cmp(resource.MustParse("4")) != 0 || cfg.Resources.Memory.Cmp(resource.MustParse("8Gi")) != 0 {
		t.Fatalf("resources = %+v", cfg.Resources)
	}
}

func TestLoadNodeConfigEmpty(t *testing.T) {
	// No path -> zero config, no error, no limits.
	cfg, err := LoadNodeConfig("")
	if err != nil {
		t.Fatalf("LoadNodeConfig(\"\"): %v", err)
	}
	if !cfg.Resources.IsZero() {
		t.Errorf("empty config resources = %+v, want zero", cfg.Resources)
	}
}

func TestLoadNodeConfigInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("resources:\n  cpu: not-a-quantity\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeConfig(path); err == nil {
		t.Error("LoadNodeConfig(invalid cpu) = nil error, want error")
	}
}

func TestCapped(t *testing.T) {
	cases := []struct{ measured, limit, want string }{
		{"8", "4", "4"}, // limit reduces
		{"8", "0", "8"}, // no limit (zero is uncapped)
		{"4", "8", "4"}, // limit above measured cannot inflate
		{"4", "4", "4"}, // equal
		{"8Gi", "4Gi", "4Gi"},
	}
	for _, c := range cases {
		got := capped(resource.MustParse(c.measured), resource.MustParse(c.limit))
		if got.Cmp(resource.MustParse(c.want)) != 0 {
			t.Errorf("capped(%s, %s) = %s, want %s", c.measured, c.limit, got.String(), c.want)
		}
	}
}
