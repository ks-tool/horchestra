//go:build linux

package systemd

import (
	"strings"
	"testing"
)

func TestRenderHardened(t *testing.T) {
	out, err := Unit{
		Description:   "horchestra demo",
		RootDirectory: "/run/horchestra/demo",
		User:          "svc",
		Environment:   []string{"A=B"},
		ExecStart:     []string{"/app/run", "--serve"},
		Hardened:      true,
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"RootDirectory=/run/horchestra/demo",
		"ExecStart=/app/run --serve",
		"Environment=A=B",
		"User=svc",
		"NoNewPrivileges=yes",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("unit missing %q:\n%s", want, out)
		}
	}
}

func TestRenderVolumesAndEnvQuoting(t *testing.T) {
	out, err := Unit{
		Description:    "app",
		ExecStart:      []string{"/app/run"},
		Environment:    []string{"SIMPLE=1", "DEPS=llvm-dev \tclang"},
		Hardened:       true,
		BindPaths:      []string{"/var/lib/horchestra/volumes/app/data:/var/lib/app"},
		ReadWritePaths: []string{"/var/lib/app"},
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Environment=SIMPLE=1",
		`Environment="DEPS=llvm-dev \tclang"`, // value with whitespace is quoted
		"BindPaths=/var/lib/horchestra/volumes/app/data:/var/lib/app",
		"ReadWritePaths=/var/lib/app",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("unit missing %q:\n%s", want, out)
		}
	}
}

func TestRenderResources(t *testing.T) {
	out, err := Unit{
		Description: "app",
		ExecStart:   []string{"/app"},
		CPUWeight:   "10",
		CPUQuota:    "50%",
		MemoryLow:   "67108864",
		MemoryMax:   "268435456",
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CPUWeight=10", "CPUQuota=50%", "MemoryLow=67108864", "MemoryMax=268435456"} {
		if !strings.Contains(out, want) {
			t.Fatalf("unit missing %q:\n%s", want, out)
		}
	}
	// Unset resource fields must not emit an empty directive.
	bare, _ := Unit{ExecStart: []string{"/app"}}.Render()
	if strings.Contains(bare, "MemoryMax") || strings.Contains(bare, "CPUQuota") {
		t.Fatalf("bare unit should carry no resource limits:\n%s", bare)
	}
}

func TestRenderTmpfs(t *testing.T) {
	out, err := Unit{
		ExecStart:            []string{"/app"},
		TemporaryFileSystems: []string{"/run", "/tmp:size=67108864"},
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TemporaryFileSystem=/run", "TemporaryFileSystem=/tmp:size=67108864"} {
		if !strings.Contains(out, want) {
			t.Fatalf("unit missing %q:\n%s", want, out)
		}
	}
}

func TestRenderExecStartQuoting(t *testing.T) {
	// An image whose CMD carries a multi-word argument, e.g. nginx's default
	// `nginx -g "daemon off;"` (Entrypoint /docker-entrypoint.sh + that CMD).
	out, err := Unit{
		Description: "web",
		ExecStart:   []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;", "50%done"},
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	// The whitespace-bearing argument is a single quoted token (not re-split into
	// "daemon" + "off;"), plain args and the program path pass through, and a
	// literal percent is doubled so systemd does not read it as a specifier.
	want := `ExecStart=/docker-entrypoint.sh nginx -g "daemon off;" 50%%done`
	if !strings.Contains(out, want) {
		t.Fatalf("ExecStart not quoted correctly, want %q:\n%s", want, out)
	}
}

func TestRenderDaemon(t *testing.T) {
	out, err := Unit{
		Description: "horchestra node-agent",
		ExecStart:   []string{"/usr/bin/node-agent", "serve"},
		Restart:     "on-failure",
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ExecStart=/usr/bin/node-agent serve") {
		t.Fatalf("missing ExecStart:\n%s", out)
	}
	if !strings.Contains(out, "Restart=on-failure") {
		t.Fatalf("missing Restart:\n%s", out)
	}
	if strings.Contains(out, "NoNewPrivileges") {
		t.Fatalf("daemon unit must not be hardened:\n%s", out)
	}
}
