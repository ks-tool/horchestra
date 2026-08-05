package netd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheCommittedObjectIsTheCommittedSource is the gate a committed build artefact needs.
//
// The BPF objects are compiled by clang in a container (`make bpf`) and checked in, so nothing else
// in the tree needs a BPF toolchain — and so nothing else in the tree NOTICES when the C is edited
// and the object is not rebuilt. What ships then is the old program, silently: it loads, it
// verifies, it does the previous thing, and the only evidence is a behaviour that does not match
// the source anyone reads. (It has already happened once in this repo's history.)
//
// The stamp is written by the same target that compiles, so it cannot drift from the object; this
// compares it to the source on disk. It deliberately carries NO build tag — the machine where the C
// gets edited is a workstation, and a gate that only runs in the linux container is a gate that
// runs after the mistake is committed.
func TestTheCommittedObjectIsTheCommittedSource(t *testing.T) {
	// The sources are read relative to the package directory, which is where `go test` runs — but
	// not where a cross-compiled test BINARY is run from (the linux-only tests here are built on a
	// workstation and shipped). Absent directory: not the package, nothing to check. Present but
	// empty: somebody deleted the C, and that is a failure.
	if _, err := os.Stat("bpf"); err != nil {
		t.Skip("not running from the package directory: the sources are not here to compare")
	}
	sources, err := filepath.Glob("bpf/*.bpf.c")
	if err != nil || len(sources) == 0 {
		t.Fatalf("no BPF sources found: %v", err)
	}
	for _, src := range sources {
		object := strings.TrimSuffix(src, ".c") + ".o"
		if _, err := os.Stat(object); err != nil {
			t.Errorf("%s has no compiled object: run `make bpf`", src)
			continue
		}
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		stamp, err := os.ReadFile(strings.TrimSuffix(src, ".c") + ".sha256")
		if err != nil {
			t.Errorf("%s has no build stamp: run `make bpf`", src)
			continue
		}
		sum := sha256.Sum256(body)
		if want, _, _ := strings.Cut(string(stamp), " "); want != hex.EncodeToString(sum[:]) {
			t.Errorf("%s has changed since %s was built: run `make bpf` and commit the object", src, object)
		}
	}
}

// TestTheDatapathIsGPL guards a licensing statement by checking the thing the KERNEL checks.
//
// A BPF program carries a licence string, and the verifier refuses helpers marked gpl_only unless
// that string is GPL-compatible — so the string is not documentation, it is the difference between
// a datapath that can call bpf_fib_lookup or bpf_trace_printk and one that cannot. A new source
// added without it would lose them silently, and would also make LICENSING.md wrong: the repository
// says these files are GPL-2.0 while everything else is AGPL-3.0-or-later.
//
// Both marks are required. The SPDX header is what a human and a scanner read; the `_license[]`
// string is what the kernel reads. They can disagree, and then one of the two audiences is lied to.
func TestTheDatapathIsGPL(t *testing.T) {
	sources, err := filepath.Glob("bpf/*.bpf.c")
	if err != nil || len(sources) == 0 {
		if _, err := os.Stat("bpf"); err != nil {
			t.Skip("not running from the package directory")
		}
		t.Fatalf("no BPF sources found: %v", err)
	}
	for _, src := range sources {
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		text := string(body)
		if !strings.Contains(text, "// SPDX-License-Identifier: GPL-2.0") {
			t.Errorf("%s has no GPL-2.0 SPDX header — see LICENSING.md", src)
		}
		if !strings.Contains(text, `char _license[] SEC("license") = "GPL";`) {
			t.Errorf("%s does not declare GPL to the verifier: every gpl_only helper would be "+
				"refused at load, and the refusal reads as though the kernel could not do it", src)
		}
	}
}
