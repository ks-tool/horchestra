//go:build linux

package netd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// DefaultPinDir is where the datapath's kernel objects are pinned, and pinning them is what turns
// this helper dying into a DEGRADATION rather than an outage.
//
// Nothing here is pinned for the sake of remembering. A pin is a reference held by a FILESYSTEM
// instead of by a process, so the programs stay attached, the maps keep their contents and packets
// keep moving while netd is not running at all — established connections included. Without it
// everything the datapath does is bound to a file descriptor: the process exits, the links detach,
// the maps are freed, and on a node where `ip_forward` is 0 (which is every node nobody has
// configured) that is not a slower path but no path, for a workload's own node as much as for the
// cluster. What is lost while netd is down is only what needs netd: wiring a new workload, and
// updating the tables.
//
// The cost, stated plainly because the first version of this design refused to pay it: there is now
// something that can outlive its purpose. A pinned link for an interface that no longer exists is a
// dangling entry, so startup sweeps them (see Forwarder.ReclaimPins) — the same shape as the
// interface reclaim, one level down.
const DefaultPinDir = "/sys/fs/bpf/horchestra"

// Subdirectories of the pin root. The two link kinds are kept apart because the forwarder's pins are
// named by INTERFACE and are swept against the interfaces that exist — a socket-LB pin sharing that
// directory would be swept away as a workload that had gone.
const (
	pinMaps      = "maps"
	pinFwdLinks  = "links/fwd"
	pinSockLinks = "links/socklb"
)

// preparePinDir makes the pin directories and refuses a path that is not on a bpffs.
//
// It deliberately does NOT mount one. netd's unit has PrivateTmp/ProtectHome, which means systemd
// gives it a mount namespace of its own — a bpffs mounted from in here would be visible to nobody
// else and would die with the process, which is the exact opposite of the point. The host's
// /sys/fs/bpf (systemd mounts it at boot) is the same filesystem seen from inside that namespace, so
// pins made there outlive the unit. If it is missing, that is an operator's fix and not this
// process's to paper over.
func preparePinDir(dir string) error {
	parent := filepath.Dir(dir)
	var st unix.Statfs_t
	if err := unix.Statfs(parent, &st); err != nil {
		return fmt.Errorf("stat %s: %w", parent, err)
	}
	if st.Type != unix.BPF_FS_MAGIC {
		return fmt.Errorf("%s is not a bpf filesystem: the datapath cannot be pinned there, so it would "+
			"not survive this helper (mount one at %s — this process will not, its mount namespace is its own)",
			parent, parent)
	}
	for _, sub := range []string{pinMaps, pinFwdLinks, pinSockLinks} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return fmt.Errorf("create the pin directory: %w", err)
		}
	}
	return nil
}

// loadPinned loads a collection whose maps are pinned by name, reusing what is there — and replacing
// it when the layout has changed.
//
// The refusal it handles is the RIGHT one and is kept: a map whose value grew must not be adopted as
// if it were the old shape, because every entry in it would be read as something else. But refusing
// and stopping is not an answer either, and the stand said so plainly — a netd whose object gained a
// field came back reporting `datapath=false` with a correct explanation and a node that had stopped
// forwarding until somebody removed a file by hand.
//
// So an incompatible pin is REPLACED. The authority is the object linked into this binary, the
// contents are not lost in any way that matters (the control plane re-pushes them on the next
// heartbeat and the local half is restored from the host routes), and the programs already attached
// keep running on the old map until their links are pointed at the new program — which is one
// atomic Update per link, not a gap.
func loadPinned(spec *ebpf.CollectionSpec, pinPath string) (*ebpf.Collection, error) {
	for name, m := range spec.Maps {
		// Only the datapath's own maps. A compiler-generated one — `.rodata`, `.bss`, `.data`, which
		// appear the moment the C gains a global or a format string — belongs to the program's
		// image and not to the node's state: pinning it is refused outright (EPERM), and the whole
		// load fails with it. Found the first time a bpf_printk was added for debugging.
		if strings.HasPrefix(name, ".") {
			continue
		}
		m.Pinning = ebpf.PinByName
	}
	opts := ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinPath}}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err == nil {
		return coll, nil
	}
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		return nil, err
	}
	for name := range spec.Maps {
		if strings.HasPrefix(name, ".") {
			continue
		}
		if rmErr := os.Remove(filepath.Join(pinPath, name)); rmErr != nil && !os.IsNotExist(rmErr) {
			return nil, fmt.Errorf("%w (and the stale pin could not be removed: %v)", err, rmErr)
		}
	}
	return ebpf.NewCollectionWithOptions(spec, opts)
}
