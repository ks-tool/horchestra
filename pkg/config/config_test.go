package config

import "testing"

func TestBoltPath(t *testing.T) {
	cases := []struct {
		dsn     string
		want    string
		wantErr bool
	}{
		{"bolt:horchestra.db", "horchestra.db", false},
		{"bolt:/var/lib/horchestra/controller.db", "/var/lib/horchestra/controller.db", false},
		{"bolt:///var/lib/x.db", "/var/lib/x.db", false},
		// Authority-style: url.Parse reads "var" as the host and would silently drop it,
		// pointing at the wrong path — BoltPath must reject it loudly (the #19 regression).
		{"bolt://var/lib/x.db", "", true},
		{"postgres://localhost/db", "", true}, // unsupported backend
		{"bolt:", "", true},                   // no path
	}
	for _, tc := range cases {
		t.Run(tc.dsn, func(t *testing.T) {
			cfg := Config{Storage: tc.dsn}
			got, err := cfg.BoltPath()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("BoltPath(%q) = %q, want error", tc.dsn, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("BoltPath(%q): unexpected error %v", tc.dsn, err)
			}
			if got != tc.want {
				t.Errorf("BoltPath(%q) = %q, want %q", tc.dsn, got, tc.want)
			}
		})
	}
}
