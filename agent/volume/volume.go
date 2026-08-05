// Package volume is the agent's Volumes mechanism: it defines the Volumes port the
// agent drives and the one implementation of it, which backs a PersistentVolume with a
// directory on the node's disk, bind-mounted into the workload, with a lifecycle
// independent of any app. tmpfs mounts are ephemeral and never routed through the
// driver — Resolve passes them straight through.
package volume

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"

	"github.com/rs/zerolog/log"
)

// Volumes provisions the PersistentVolumes assigned to this node and resolves an app's
// volume mounts into the resolved volumes the Runtime attaches. A PV is a store of data
// with a lifecycle independent of any app; its data is reclaimed only when the PV is
// gone cluster-wide and no wanted app still mounts it.
type Volumes interface {
	// Provision ensures the backing store exists for each PV assigned to this node
	// (keyed by name), recording it so its data can later be reclaimed. Best-effort
	// per PV — one failure never stops the others — but the failures are returned
	// joined, not swallowed.
	Provision(ctx context.Context, pvs map[string]corev1.PersistentVolume) error
	// Fits reports whether every PersistentVolume the app mounts is backed on this
	// node (pvs are the PVs assigned here). An app with no volumes always fits; an
	// app whose volume is not backed here is left for the node that backs it.
	Fits(app workload.App, pvs map[string]corev1.PersistentVolume) bool
	// Resolve maps the app's volume mounts to the resolved volumes the Runtime attaches,
	// against the PVs provisioned on this node, erroring if a mounted PV is not among them.
	Resolve(app workload.App, pvs map[string]corev1.PersistentVolume) ([]workload.Volume, error)
	// Reclaim removes the data of volumes this node provisioned whose PV is gone from
	// allPVs (the cluster-wide set) and that no wanted app still mounts. Best-effort
	// per volume — one failure never stops the others — but the failures are returned
	// joined, not swallowed.
	Reclaim(ctx context.Context, allPVs map[string]bool, wanted map[string]workload.App) error
}

// pvRecord is a provisioned volume's crash-safe ledger entry: what this node needs to know
// to reclaim (or retain) the data correctly after the PV is deleted cluster-wide, once its
// spec is no longer in desired state. It carries the reclaim policy captured at provision
// time.
type pvRecord struct {
	ReclaimPolicy string `json:"reclaimPolicy,omitempty"`
}

// defaultVolumeMode is what a PersistentVolume directory is created with when spec.mode is
// absent or unusable: owner and group only, never world. It is paired with the chown in
// Provision — the directory belongs to the workload's default identity, so an app can write to
// its own volume without the mode having to be world-writable. Before that pairing the
// directory stayed root-owned, which left "0777" as the only way to make a PV usable and turned
// the design itself into the exposure.
const defaultVolumeMode = os.FileMode(0o770)

// subPathMode is what a subPath directory is created with. The workload reaches it through the
// GROUP because the directory itself belongs to the agent (see subPathRef), and the sticky bit
// keeps a deeper subPath nested inside it out of the workload's reach for the same reason the
// volume root's does. It is strictly more access than a subPath used to get: these directories
// were created 0755 root:root, which the workload could not write to at all.
const subPathMode = os.FileMode(0o770) | os.ModeSticky

// local backs PersistentVolumes with directories under stateDir/volumes, keyed by PV
// name and independent of any app. provisioned is the crash-safe ledger of the volumes
// this node has created, so a deleted PV's data can be reclaimed (or retained) exactly once.
type local struct {
	stateDir string
	// subUID/subGID are the node's subordinate ranges. A volume is handed to the identity the
	// workload actually holds on this node, which is what these map an in-namespace id onto.
	subUID, subGID corev1.IDRange
	provisioned    map[string]pvRecord
}

// NewLocal builds the local-directory volume driver bound to stateDir, loading its
// ledger of already-provisioned volumes.
func NewLocal(stateDir string, subUID, subGID corev1.IDRange) Volumes {
	l := &local{stateDir: stateDir, subUID: subUID, subGID: subGID}
	l.provisioned = loadRecords(l.provisionedFile())
	return l
}

var _ Volumes = (*local)(nil)

// Provision records each of this node's PersistentVolumes in the provisioned set and
// creates its backing directory once, with the PV's mode. The mode is set only at
// creation, so a workload's own adjustment of the mount point is left in place.
// Best-effort: a directory that cannot be created is skipped and collected into the
// returned (joined) error rather than aborting the rest.
func (l *local) Provision(_ context.Context, pvs map[string]corev1.PersistentVolume) error {
	changed := false
	var errs []error
	for name, pv := range pvs {
		rp := reclaimPolicyOf(pv)
		if rec, ok := l.provisioned[name]; !ok || rec.ReclaimPolicy != rp {
			l.provisioned[name] = pvRecord{ReclaimPolicy: rp} // record/refresh the captured policy
			changed = true
		}
		dir := l.pvDir(name)
		if _, err := os.Lstat(dir); err == nil {
			continue
		}
		mode := volumeMode(pv.Spec.Mode)
		if err := os.MkdirAll(dir, mode); err != nil {
			errs = append(errs, fmt.Errorf("provision volume %q: %w", name, err))
			continue
		}
		_ = os.Chmod(dir, mode) // MkdirAll is umask-masked; set the exact mode once
		// Give the directory to the workload identity so an owner-only mode is enough for the
		// app to use it. Only ever done at creation, so an existing volume's ownership (and any
		// data under it) is left exactly as the operator has it. A volume that goes on to back a
		// subPath mount is taken back by ensureAgentOwned at that point, and only then.
		// The floor identity, MAPPED: Provision sees volumes, not the apps that will mount them,
		// so it hands the directory to the id every workload falls back to and Resolve then adds
		// the mounting app's group. Chowning to the unmapped number is what this did before, and
		// on a node it either failed or named an id no workload holds.
		owner := int(workload.AgentID(l.subUID, corev1.DefaultRunAsID))
		if err := os.Chown(dir, owner, owner); err != nil {
			log.Warn().Err(err).Str("volume", name).Int("owner", owner).
				Msg("chown volume dir to the workload identity")
		}
	}
	if changed {
		l.saveProvisioned()
	}
	return errors.Join(errs...)
}

// Fits reports whether every PersistentVolume the app mounts is backed on this node.
// An app with no pv volumes always fits.
func (l *local) Fits(app workload.App, pvs map[string]corev1.PersistentVolume) bool {
	for _, m := range app.Volumes {
		if !m.IsPV() {
			continue
		}
		if _, ok := pvs[corev1.WorkloadID(app.Namespace, m.PVName(app.Name))]; !ok {
			return false
		}
	}
	return true
}

// Resolve maps an app's volume mounts to the resolved volumes the Runtime attaches: a
// tmpfs mount passes straight through; a pv mount resolves to the host directory backing
// it (a VolumeHostPath). It errors if a pv mount names a PersistentVolume not provisioned
// on this node.
func (l *local) Resolve(app workload.App, pvs map[string]corev1.PersistentVolume) ([]workload.Volume, error) {
	var vols []workload.Volume
	for _, m := range app.Volumes {
		if m.IsTmpfs() {
			vols = append(vols, workload.Volume{Kind: workload.VolumeTmpfs, MountPath: m.MountPath, Size: m.Volume.Size.String()})
			continue
		}
		if m.IsSecret() {
			continue // secrets are materialized by the Secrets port, not by storage
		}
		name := m.PVName(app.Name)
		id := corev1.WorkloadID(app.Namespace, name)
		if _, ok := pvs[id]; !ok {
			return nil, fmt.Errorf("volume %q: PersistentVolume %q is not provisioned on this node", m.MountPath, name)
		}
		ref, err := l.subPathRef(id, m.SubPath)
		if err != nil {
			return nil, fmt.Errorf("volume %q: %w", m.MountPath, err)
		}
		if err := applyVolumeGroup(ref, l.volumeGroupOf(app)); err != nil {
			return nil, fmt.Errorf("volume %q: %w", m.MountPath, err)
		}
		vols = append(vols, workload.Volume{Kind: workload.VolumeHostPath, Ref: ref, MountPath: m.MountPath, ReadOnly: m.ReadOnly})
	}
	return vols, nil
}

// volumeGroupOf is the group a workload's volume data belongs to, as the AGENT addresses it. Every
// workload has its own uid, so a uid can no longer be what lets two of them share a volume — this
// group is, and admission hands every workload in a namespace the same one.
//
// The mapping is the point. A workload's securityContext names an id INSIDE its namespace; the
// file on the node belongs to the id that one maps to. Chowning to the in-namespace number was
// what this used to do, and on a real node it failed every converge with EINVAL — 1000000000 is
// not an id the agent's own namespace has — leaving the group bits pointing at nobody.
func (l *local) volumeGroupOf(app workload.App) int64 {
	if sc := app.SecurityContext; sc != nil && sc.RunAsGroup != nil {
		return workload.AgentID(l.subGID, *sc.RunAsGroup)
	}
	return 0
}

// floorGID is the group every workload falls back to, as the agent addresses it. The raw constant
// is an id inside the WORKLOAD's namespace; chowning to it here names a different host group than
// any workload holds, which is a bug that reports itself only as a volume nobody can write to.
func (l *local) floorGID() int { return int(workload.AgentID(l.subGID, corev1.DefaultRunAsID)) }

// keepBits is the part of a mode a chmod here must carry over: the permission bits plus setgid and
// sticky. os.FileMode.Perm() drops the last two, and two functions rebuilding the mode from Perm()
// alone each silently strip what the other set — on a live node the volume root ended up sticky
// without setgid or setgid without sticky, decided by the order the app happens to declare its
// mounts in. Both bits are load-bearing: setgid keeps a shared volume's contents in the group the
// namespace meets on, sticky is what stops the workload removing the agent-owned directories a
// subPath bind source is made of.
func keepBits(m os.FileMode) os.FileMode {
	return m.Perm() | m&(os.ModeSetgid|os.ModeSticky)
}

// applyVolumeGroup makes the bind source reachable through the workload's group rather than through
// its uid: owned by that group, group-rwx, and SETGID so everything created inside inherits the
// group instead of the creator's own. That last bit is what makes the volume still readable by
// the next workload that mounts it — they run as different uids and only ever meet in the group.
func applyVolumeGroup(path string, gid int64) error {
	if gid <= 0 {
		return nil // nothing allocated (no namespace block): leave ownership as it is
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := os.Chown(path, os.Getuid(), int(gid)); err != nil {
		log.Warn().Err(err).Str("path", path).Int64("group", gid).Msg("chgrp volume to the workload group")
	}
	return os.Chmod(path, keepBits(fi.Mode())|0o070|os.ModeSetgid)
}

// subPathRef is the host path a pv mount binds: the volume's own directory, or a
// subdirectory of it when subPath is set. The subdirectory is created on demand and may not
// escape the volume — neither lexically ("..", absolute) nor through a symlink.
//
// The symlink half is not theoretical, and it is not a one-shot. The volume's contents belong
// to the workload, so it can drop a symlink to / inside its own PV; and the path returned here
// does not become a mount, it becomes a systemd BindPaths= SOURCE STRING, which systemd
// re-resolves from scratch at every start of the unit — including the restarts systemd itself
// performs under Restart=always. Resolving the path once and trusting the result is therefore
// a check-then-use over a tree the tenant controls: it need only swap a component for a symlink
// while the unit is down, and the next restart binds that symlink's target instead. A reconcile
// that later notices only logs the error and skips the app, leaving the installed unit in place.
//
// So containment here is structural, not checked-once. Every component of the returned path is
// created and owned by the AGENT, inside directories the workload cannot write to, under a
// volume root the workload cannot chmod (it is not the owner) and whose sticky bit stops it
// removing entries it does not own. A component that already exists and does not meet that bar
// — a symlink, or a directory the workload owns because it got there first — fails the mount
// closed rather than being adopted.
func (l *local) subPathRef(name, subPath string) (string, error) {
	dir := l.pvDir(name)
	if subPath == "" {
		return dir, nil
	}
	// ValidRelPath, not an ad-hoc "not absolute, no ..": the resolved path becomes the SOURCE of
	// a systemd bind directive, whose list syntax is whitespace- and ':'-separated. A subPath of
	// " /var/lib/horchestra/volumes" is relative, clean and free of "..", yet it appends a second
	// bind mounting every tenant's PV data into this workload. The shared validator rejects
	// whitespace, ':' and control characters as well as traversal, and guarantees a clean path —
	// so splitting on '/' below yields exactly the components to create, with no "." or "" among
	// them.
	if err := corev1.ValidRelPath(subPath); err != nil {
		return "", fmt.Errorf("subPath: %w", err)
	}
	// Everything below rests on the volume root being agent-owned and sticky. A volume only
	// becomes so when it first backs a subPath mount, which is here.
	if err := ensureAgentOwned(dir, l.floorGID()); err != nil {
		return "", fmt.Errorf("subPath: %w", err)
	}
	cur := dir
	for _, part := range strings.Split(subPath, "/") {
		cur = filepath.Join(cur, part)
		// Mkdir is the atomic form of the check: it never follows a symlink at the final
		// component, so it either creates a directory this agent owns or reports that something
		// is already there — which is then held to the same bar. Intermediates stay agent-owned
		// and not group-writable, so the workload cannot rename anything inside them.
		if err := os.Mkdir(cur, 0o755); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("create subPath: %w", err)
		}
		if err := agentOwnedDir(cur); err != nil {
			return "", fmt.Errorf("subPath: %w", err)
		}
	}
	// The leaf is what systemd binds and what the workload writes into, so it is granted to the
	// workload's group — but, like the volume root, not its ownership: an owner could rename the
	// directory away and so choose what the next restart mounts.
	if err := os.Chown(cur, os.Getuid(), l.floorGID()); err != nil {
		log.Warn().Err(err).Str("subPath", cur).Msg("chown subPath dir to the workload group")
	}
	if err := os.Chmod(cur, subPathMode); err != nil {
		return "", fmt.Errorf("subPath: %w", err)
	}
	return cur, nil
}

// ensureAgentOwned puts a volume root into the state a subPath bind source needs, and is called
// only when one is actually being built — a volume nobody takes a subPath of keeps the
// workload-owned directory Provision gave it, so ordinary mounts are unaffected.
//
// Two facts have to hold. The directory must be owned by the AGENT, because an owner may chmod
// the sticky bit away and may unlink or rename anything inside the directory whoever created it.
// And it must be STICKY, because the workload still has group write here — that is its volume —
// so sticky is what stops it removing the agent-owned subPath directories the bind source is
// made of. The workload keeps rwx through the group, and its own files stay entirely its own.
//
// Provision hands a fresh volume to the workload outright, so taking it back here is the normal
// path for the first subPath mount on any volume, not a repair of something historical.
//
// floorGID is the fallback group AS THE AGENT ADDRESSES IT (see local.floorGID); the caller maps
// it, because this function does not know the node's subordinate ranges and a raw in-namespace id
// would name a host group no workload holds.
func ensureAgentOwned(dir string, floorGID int) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, defaultVolumeMode|os.ModeSticky); err != nil {
			return err
		}
		if err := os.Chmod(dir, defaultVolumeMode|os.ModeSticky); err != nil {
			return err
		}
		if err := os.Chown(dir, os.Getuid(), floorGID); err != nil {
			log.Warn().Err(err).Str("dir", dir).Msg("chown volume dir to the workload group")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("volume dir %q is not a directory", dir)
	}
	uid, ok := ownerUID(fi)
	if !ok {
		return fmt.Errorf("volume dir %q: cannot read its owner", dir)
	}
	// The data inside, and the permission bits, are left as they are; only the two facts
	// containment rests on are asserted.
	if int(uid) != os.Getuid() {
		if err := os.Chown(dir, os.Getuid(), floorGID); err != nil {
			return fmt.Errorf("volume dir %q is owned by uid %d rather than the agent, and taking it back for a subPath mount failed: %w", dir, uid, err)
		}
		log.Info().Str("dir", dir).Uint32("was", uid).
			Msg("reconcile: took ownership of a volume dir backing a subPath mount; the workload keeps access through its group")
	}
	if fi.Mode()&os.ModeSticky == 0 {
		if err := os.Chmod(dir, keepBits(fi.Mode())|os.ModeSticky); err != nil {
			return fmt.Errorf("volume dir %q: set the sticky bit: %w", dir, err)
		}
	}
	return nil
}

// agentOwnedDir reports whether an existing subPath component can be built on. It must be a
// real directory the agent owns: a symlink is resolved by the bind mount at every unit start,
// and a directory the workload owns can be renamed away between now and any later restart, so
// neither is a source systemd can be given.
func agentOwnedDir(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%q is a symlink; the bind mount would resolve it out of the volume", p)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%q is not a directory", p)
	}
	uid, ok := ownerUID(fi)
	if !ok {
		return fmt.Errorf("%q: cannot read its owner", p)
	}
	if int(uid) != os.Getuid() {
		return fmt.Errorf("%q is owned by uid %d rather than the agent, so it can be replaced "+
			"before the next unit start and is not a safe bind source", p, uid)
	}
	return nil
}

// ownerUID reads a stat'ed path's owning uid.
func ownerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// Reclaim removes the data of volumes this node provisioned whose PersistentVolume has
// been deleted cluster-wide and that no wanted app still mounts. Conservative: it only
// touches directories this node provisioned, keeps a volume whose PV was merely
// reassigned to another node, and treats an empty PV list as suspicious (controller
// state loss) rather than "reclaim everything".
func (l *local) Reclaim(_ context.Context, allPVs map[string]bool, wanted map[string]workload.App) error {
	if len(allPVs) == 0 {
		return nil
	}
	inUse := map[string]bool{}
	for _, app := range wanted {
		for _, m := range app.Volumes {
			if m.IsPV() {
				inUse[corev1.WorkloadID(app.Namespace, m.PVName(app.Name))] = true
			}
		}
	}
	changed := false
	var errs []error
	for name, rec := range l.provisioned {
		if allPVs[name] || inUse[name] {
			continue
		}
		// The PV is gone cluster-wide and no wanted app mounts it. Retain keeps the data
		// (the agent stops managing it — an existing dir is re-adopted if the PV returns);
		// Delete (the default) reclaims the backing store.
		if rec.ReclaimPolicy == corev1.ReclaimRetain {
			delete(l.provisioned, name)
			changed = true
			log.Info().Str("volume", name).Msg("reconcile: PersistentVolume deleted; retaining its data (reclaimPolicy=Retain)")
			continue
		}
		if err := os.RemoveAll(l.pvDir(name)); err != nil {
			errs = append(errs, fmt.Errorf("reclaim volume %q: %w", name, err))
			continue
		}
		delete(l.provisioned, name)
		changed = true
		log.Info().Str("volume", name).Msg("reconcile: reclaimed deleted PersistentVolume's data")
	}
	if changed {
		l.saveProvisioned()
	}
	return errors.Join(errs...)
}

// pvDir is the host directory backing a PersistentVolume, keyed by the PV's name and
// independent of any app — it survives app deletes.
func (l *local) pvDir(name string) string { return filepath.Join(l.stateDir, "volumes", name) }

func (l *local) provisionedFile() string { return filepath.Join(l.stateDir, "provisioned.json") }

func (l *local) saveProvisioned() { saveJSON(l.provisionedFile(), l.provisioned) }

// reclaimPolicyOf is a PV's reclaim policy: Retain only when it is explicitly asked for. An
// unset or unrecognized value takes Delete, so a volume nobody claimed responsibility for does
// not outlive its PV and quietly fill the node's disk.
func reclaimPolicyOf(pv corev1.PersistentVolume) string {
	if pv.Spec.ReclaimPolicy == corev1.ReclaimRetain {
		return corev1.ReclaimRetain
	}
	return corev1.ReclaimDelete
}

// volumeMode parses a claim's octal mode string into a FileMode, translating the
// setuid/setgid/sticky bits, and defaults to defaultVolumeMode when unset or malformed.
func volumeMode(s string) os.FileMode {
	if len(s) == 0 {
		return defaultVolumeMode
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return defaultVolumeMode
	}
	// spec.mode is a tenant-supplied string applied by a root agent to a directory the tenant's
	// workload then bind-mounts, so the bits that let OTHER local accounts in are not the
	// tenant's to grant. setuid/setgid are never meaningful on a data directory and setgid-root
	// is an escalation aid, so they are dropped unconditionally; world access is dropped because
	// it hands every unprivileged account on the node read — and with 0777, write — of that
	// tenant's data, which is a tampering primitive against the workload that reads it.
	mode := os.FileMode(n & 0o770)
	if n&0o1000 != 0 {
		mode |= os.ModeSticky // harmless, and meaningful for a shared directory
	}
	if mode.Perm()&0o700 == 0 {
		return defaultVolumeMode // a mode the owner cannot use is a typo, not a request
	}
	return mode
}

// loadRecords reads the provisioned-volume ledger. A missing file is the ordinary first-boot
// state; a file that will not read or parse is REPORTED and the ledger starts empty, from which
// the next Provision re-records every PV in desired state and adopts the existing data dirs.
// Losing it only costs reclamation — a volume whose PV was deleted while the ledger was gone is
// retained rather than reclaimed — so starting empty is the safe direction, but never a silent one.
func loadRecords(path string) map[string]pvRecord {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warn().Err(err).Str("path", path).Msg("reconcile: read the provisioned-volume ledger; starting empty")
		}
		return map[string]pvRecord{}
	}
	m := map[string]pvRecord{}
	if err := json.Unmarshal(data, &m); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("reconcile: the provisioned-volume ledger does not parse; starting empty")
		return map[string]pvRecord{}
	}
	return m
}

func saveJSON(path string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("reconcile: save state")
		return
	}
	_ = os.Rename(tmp, path)
}
