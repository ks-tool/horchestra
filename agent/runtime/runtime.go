// Package runtime is the agent's Runtime mechanism: it defines the Runtime port the
// agent drives and the systemd implementation of it, which runs a workload as an OCI
// image, overlay-mounted into a rootfs, supervised as a hardened systemd service. That
// implementation composes three finer backends the application injects — an image store
// (Images), a rootfs assembler (Mounts) and a service supervisor (Units) — owning the
// cross-step ordering itself so the agent's reconcile loop never sequences them.
//
// The runtime set is closed: this package's NewSystemd, the rootless userns runtime in
// ./userns, and firecracker. The package was called `cri` while a Kubernetes CRI adapter
// was still planned; it speaks no CRI and the name said otherwise.
package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ks-tool/horchestra/agent/workload"
	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// Runtime runs and supervises the node's workloads. Apply/Remove/List/GC/Logs are the
// whole surface the reconciler needs: it never sees the image store, the rootfs mount
// or the init system — those are folded inside the runtime, which owns the cross-step
// ordering. States is the actual-state source (self-heal is level-driven off it, not a
// persisted record).
type Runtime interface {
	// Name is the runtime's class name — the RuntimeClass an Application targets via
	// spec.runtimeClassName (e.g. "systemd"). A node advertises the names of the runtimes it
	// runs in status.runtimes, and the scheduler filters an app's runtimeClassName against
	// that set; it is also the key a multi-runtime agent selects on.
	Name() string
	// Apply converges one workload to match app: ensure its image is present (the
	// reboot fast-path — no registry round-trip if already local), (re)assemble its
	// rootfs and attach the resolved volumes, install/update its service and start it.
	// Idempotent and level-driven — a converged workload is a no-op — folding the
	// changed→stop→remount→start ordering inside the runtime.
	Apply(ctx context.Context, app workload.App, volumes []workload.Volume) error
	// Remove tears a workload down completely: stop and delete its service, drop its rootfs
	// mount and state. grace is how long the stop waits before the kill — the workload's own
	// terminationGracePeriodSeconds, which reaches here because the object outlives the delete
	// request that started the teardown. A zero grace means the caller has no spec to read (a
	// workload the node holds that desired state does not mention at all) and the runtime's
	// default stands in.
	Remove(ctx context.Context, name string, grace time.Duration) error
	// States returns every workload this runtime holds on the node, with the state it is
	// actually in — the node's own record of what it runs, used to tear down the ones no
	// longer wanted, to self-heal after a reboot, and to report each workload's phase.
	//
	// It reports workloads in EVERY state, including terminal ones: a job that has exited and
	// a service whose unit failed are both still this node's to tear down, and a caller that
	// only wanted the live ones filters on Phase. That filtering used to be missing, which is
	// how a finished job reported itself as Running.
	States(ctx context.Context) ([]workload.State, error)
	// Reap finishes stops this runtime has already begun and that have outstayed their own
	// budget — a workload the init system asked to leave and that did not, which for a
	// shared-kernel runtime is the ordinary fate of an image that installs no signal handler:
	// it is PID 1 of its namespace and the kernel discards the signal.
	//
	// It takes NO desired state and returns nothing but an error, deliberately. This is local
	// state and nothing else: a unit whose stop is already running is one the agent decided to
	// end, so finishing that decision needs no controller and must not wait for one. Everything
	// that requires knowing what SHOULD run belongs to Apply and Remove, which do wait.
	Reap(ctx context.Context) error
	// GC reclaims the runtime's image store down to the keep-set (the image refs of
	// the workloads still wanted), returning the store tags it removed. Best-effort.
	GC(ctx context.Context, keep []string) (removed []string, err error)
	// Logs streams a workload's log output; follow tails it, tail bounds the backlog.
	// The caller closes the reader to stop the stream.
	Logs(ctx context.Context, name string, follow bool, tail int64) (io.ReadCloser, error)
	// Metrics is what the workload has actually consumed. Only the runtime can answer it: a
	// shared-kernel workload is a cgroup, a microVM is a hypervisor's accounting, and neither
	// is reachable from the reconcile loop. A workload that is not running has nothing to
	// report and returns an error, which the caller treats as "no sample", not as a failure.
	Metrics(ctx context.Context, name string) (workload.Usage, error)
}

// Images is the node's shared, layer-deduplicated image backend (an oci-layout
// today). An implementation binds its own on-disk layout. Every entry is keyed
// per (namespace, source): blobs are still deduplicated node-wide, but one
// namespace's spelling of an image can never evict or rename another's entry —
// a shared, un-namespaced key let one tenant force a co-tenant into a permanent
// registry re-resolve loop and destroy its reboot fast-path.
type Images interface {
	// Pull fetches the image at source into the store for namespace, unpacked
	// ready to mount. Idempotent: blobs already present are reused, not refetched.
	Pull(ctx context.Context, namespace, source string) error
	// Spec returns the launch specification of namespace's image at source: its
	// config plus the ordered unpacked layer directories to mount.
	Spec(ctx context.Context, namespace, source string) (*LaunchSpec, error)
	// Remove drops namespace's entry for source, GC-ing blobs no surviving
	// entry (in any namespace) references.
	Remove(ctx context.Context, namespace, source string) error
	// Purge removes every stored image whose source is not in keep — matched
	// across all namespaces, so a kept ref protects the image for every tenant —
	// returning the entries removed. Best-effort: a still-mounted image is
	// skipped, not fatal.
	Purge(ctx context.Context, keep []string) (removed []string, err error)
}

// ApplyResult is what a unit Apply reports: whether the unit definition changed (so the
// runtime remounts and restarts), and any out-of-band drift it reverted — a tampered unit
// corrected back to the desired state, surfaced for the audit seam (WARN-logged today).
type ApplyResult struct {
	DefinitionChanged bool
	Reverted          []DriftEvent
}

// DriftEvent records one out-of-band change to a workload's unit that Apply reverted. These
// detection types are runtime-local; mapping them to a wire/audit record is a later,
// deliberate step, so DriftEvent stays inside agent/runtime for now.
type DriftEvent struct {
	Unit      string // the workload id whose unit drifted
	Dimension string // what drifted (DriftFile, …)
	Detail    string // a short human description
}

// Drift dimensions.
const (
	// DriftFile means the on-disk unit file was changed out-of-band and rewritten to desired.
	DriftFile = "file"
)

// LaunchSpec is an image's launch specification: the ordered unpacked layer
// directories to mount and the config (entrypoint/cmd/env/user/workdir) needed to
// run it. Rootfs is filled in by the runtime with the workload's mount target. It is
// runtime-internal — the agent seam carries an image ref and mount intents, not
// layer directories.
type LaunchSpec struct {
	Rootfs     string
	LayerDirs  []string
	Entrypoint []string
	Cmd        []string
	Env        []string
	User       string
	WorkingDir string
	// SecretEnvFile is the workload's RAM-backed Secret-sourced environment file (empty when
	// it sources none). The runtime delivers it as real process environment at spawn — the
	// systemd runtime via EnvironmentFile=, the rootless sandbox by folding it into the
	// execve envp — never via Environment= (a bus-readable property) and never into the
	// rootfs.
	SecretEnvFile string
}

// SecretEnvFile is the workload's RAM-backed file carrying its Secret-sourced environment,
// under the agent's runtime directory. It is a delivery CARRIER, never part of the rootfs:
// the systemd runtime points EnvironmentFile= at it (PID1 reads it at spawn, outside the
// bus-readable Environment= property), and the rootless sandbox folds it into the execve
// envp — either way the workload sees real process environment, Kubernetes-style.
func SecretEnvFile(runtimeDir, id string) string {
	return filepath.Join(runtimeDir, "secretenv", id)
}

// WriteSecretEnvFile (re)writes the workload's RAM-backed environment file and returns its
// path, or "" when the app sources no environment from a Secret. Every name and value is
// re-validated first: a runtime trusts nothing that arrived over the wire, the same rule
// ValidateVolumes applies to mount destinations. Idempotent on unchanged content, so the
// change detector's view and the file never disagree mid-converge.
//
// The file lives in tmpfs and is 0600 under an owner-only parent: a resolved secret must
// not outlive the agent that fetched it, so it may never land on persistent disk, in a
// backup, or reappear after a reboot with no one to re-authorize it.
func WriteSecretEnvFile(runtimeDir, id string, secretEnv []string) (string, error) {
	path := SecretEnvFile(runtimeDir, id)
	if len(secretEnv) == 0 {
		_ = os.RemoveAll(path) // an app that stopped sourcing env leaves no file behind
		return "", nil
	}
	content, err := RenderSecretEnv(secretEnv)
	if err != nil {
		return "", err
	}
	if cur, rerr := os.ReadFile(path); rerr == nil && string(cur) == content {
		return path, nil
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(parent, 0o700); err != nil { // MkdirAll is umask-masked and skips existing
		return "", err
	}
	_ = os.RemoveAll(path) // may be the retired per-workload layer DIRECTORY; a plain file replaces it
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// IDs is the identity a workload's files must belong to, as the AGENT addresses it — the numbers
// workload.AgentID produces. A zero value leaves ownership alone, which is what a caller with no
// id mapping (a test, an off-node tool) gets.
type IDs struct{ UID, GID int }

// chown gives path to the workload, if an identity was supplied. Failure is an error rather than a
// warning: a secret the workload cannot read is a workload that will not start, and finding that
// out at converge is better than at exec.
func (o IDs) chown(path string) error {
	if o.UID <= 0 && o.GID <= 0 {
		return nil
	}
	if err := os.Chown(path, o.UID, o.GID); err != nil {
		return fmt.Errorf("chown %s to the workload identity %d:%d: %w", path, o.UID, o.GID, err)
	}
	return nil
}

// replaceSecretFile puts data at path so that a reader either sees the whole old value or the
// whole new one, and never the gap between them.
//
// The value is written to a temporary name in the SAME directory, given its mode and its owner
// there, and only then renamed over the destination — rename(2) within one filesystem is
// atomic, so the destination name never refers to a half-written, absent or
// wrong-owner file. The obvious version (remove, write, chown) has three windows instead: a
// reader between the remove and the write gets ENOENT, one during the write gets a short read,
// and one between the write and the chown gets EACCES on a 0400 file it does not yet own.
//
// Those windows used to be rare enough to look theoretical, because a secret only changed when
// an operator rotated it. A Vault static role changes on VAULT's schedule while the workload
// runs, and the whole point of a file mount over an environment variable is that the process
// re-reads it — so the race is now on the normal path, not an unlucky one.
//
// A temporary file left by a crash needs no special handling: it is not among the projected
// keys, so the sweep at the end of writeSecretDir removes it as an unwanted entry.
func replaceSecretFile(path string, data []byte, owner IDs) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Removed on every failure path; after a successful rename the name is gone and this is a
	// harmless ENOENT.
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Mode and owner are settled BEFORE the file is reachable under its real name. Doing either
	// afterwards would put the wrong one behind a name a workload is already reading.
	if err := os.Chmod(tmp, secretFileMode); err != nil {
		return err
	}
	if err := owner.chown(tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SecretMount is one materialized secret volume: the RAM-backed directory the agent projected a
// Secret's keys into, and the path inside the workload it belongs at. The sandbox binds Source
// read-only at Target — a bind, not a copy, so the directory the workload reads IS the one the
// agent writes and a rotated value is live under the running process.
type SecretMount struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// SecretVolumeRoot is where all of one workload's secret volumes live, so teardown reclaims them
// in one call.
func SecretVolumeRoot(runtimeDir, id string) string {
	return filepath.Join(runtimeDir, "secretvol", id)
}

// SecretVolumeDir is the RAM-backed directory holding one secret volume's projected files. It is
// keyed by the mount path so the same workload's several secret mounts cannot collide, and so a
// mount that moves takes its files with it.
func SecretVolumeDir(runtimeDir, id, mountPath string) string {
	sum := sha256.Sum256([]byte(mountPath))
	return filepath.Join(SecretVolumeRoot(runtimeDir, id), hex.EncodeToString(sum[:8]))
}

// secretFileMode and secretDirMode are what a projected key and its directory are written with.
// The workload reads them through a read-only BIND of this directory, as a uid this process
// cannot chown to — it holds no CAP_CHOWN in the namespace that owns the file — so the mode has
// to be what grants the read. That costs nothing: the carrier lives under the agent's
// $XDG_RUNTIME_DIR at 0700, so reaching these files at all already requires being the agent's
// user, and inside the workload the only processes that can see the mount are its own.
// The projected files belong to the WORKLOAD: the agent chowns them to the identity the sandbox
// will run as, which its own user namespace lets it address (workload.AgentID). So the mode grants
// nothing to anyone else — no group, no world — and the value is readable by exactly the process it
// was fetched for. Owner-write on the directory is the agent's: it has to replace files there when
// a secret rotates, and it can, because it stays the directory's owner in its own namespace.
const (
	secretFileMode = 0o400
	secretDirMode  = 0o500
)

// WriteSecretVolumes materializes every VolumeSecret in volumes into the RAM-backed runtime dir
// and returns the mounts the sandbox should assemble, sorted by target so the config they land in
// is byte-stable. It reports whether anything CHANGED, which is what makes a rotation reach the
// workload: the content lives outside the sandbox config (only paths go in there), so nothing
// else about a rotated secret would move, and the workload would keep the value it started with.
//
// Values are written to tmpfs and nowhere else — the same rule as the environment carrier, for
// the same reason: a resolved secret that reaches persistent storage outlives the agent that
// fetched it and survives a reboot with nothing left to re-authorize it.
func WriteSecretVolumes(runtimeDir, id string, volumes []workload.Volume, owner IDs) ([]SecretMount, error) {
	var mounts []SecretMount
	kept := map[string]bool{}
	for _, v := range volumes {
		if v.Kind != workload.VolumeSecret || v.MountPath == "" {
			continue
		}
		dir := SecretVolumeDir(runtimeDir, id, v.MountPath)
		kept[dir] = true
		if err := writeSecretDir(dir, v.Content, owner); err != nil {
			return nil, fmt.Errorf("secret volume %s: %w", v.MountPath, err)
		}
		mounts = append(mounts, SecretMount{Source: dir, Target: v.MountPath})
	}
	// A mount the app no longer declares leaves no values behind on the node.
	entries, _ := os.ReadDir(SecretVolumeRoot(runtimeDir, id))
	for _, e := range entries {
		if dir := filepath.Join(SecretVolumeRoot(runtimeDir, id), e.Name()); !kept[dir] {
			// The directory is 0500 and owned by the workload, so take it back before reclaiming
			// it — otherwise the values of a mount the app dropped stay on the node.
			_ = os.Chmod(dir, 0o700)
			_ = os.RemoveAll(dir)
		}
	}
	slices.SortFunc(mounts, func(a, b SecretMount) int { return strings.Compare(a.Target, b.Target) })
	return mounts, nil
}

// writeSecretDir makes dir hold exactly content. A key already present with the same bytes is
// left alone; one that changed is REPLACED, so a workload that re-opens the path reads the new
// value and one holding an open descriptor keeps the old — the same bargain a file rotation
// makes anywhere.
//
// This directory is what the workload has mounted, so a write here IS the rotation: nothing
// restarts, nothing is copied, and the value is live the moment it lands.
func writeSecretDir(dir string, content map[string][]byte, owner IDs) error {
	// The parents stay owner-only; only the leaf the workload mounts is widened.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Writable while the files are landed, then narrowed: the directory ends up owned by the
	// workload with no write bit, and the agent puts values in it through the privilege it holds
	// in its own user namespace rather than through a mode anyone else could use. The parent is
	// owner-only throughout, and what the workload sees is a read-only bind either way.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	defer func() {
		_ = owner.chown(dir) // the directory too, or its owner cannot open what is inside it
		_ = os.Chmod(dir, secretDirMode)
	}()
	for rel, data := range content {
		if strings.Contains(rel, "/") || rel == "" || rel == "." || rel == ".." {
			return fmt.Errorf("key %q is not a plain file name", rel)
		}
		path := filepath.Join(dir, rel)
		if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, data) {
			continue
		}
		if err := replaceSecretFile(path, data, owner); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if _, want := content[e.Name()]; !want {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return nil
}

// RenderSecretEnv is the file's exact content for a resolved set: one validated assignment per
// line. It is the single source of that text, so the writer and the change detector can never
// disagree about what "already applied" looks like.
func RenderSecretEnv(secretEnv []string) (string, error) {
	var b strings.Builder
	for _, assignment := range secretEnv {
		name, value, ok := strings.Cut(assignment, "=")
		if !ok {
			return "", fmt.Errorf("secret env %q is not an assignment", assignment)
		}
		if err := corev1.ValidEnvName(name, "env name"); err != nil {
			return "", err
		}
		if err := corev1.ValidEnvValue(name, value); err != nil {
			return "", err
		}
		b.WriteString(assignment)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// SecretEnvChanged reports whether the workload's written environment file differs from the
// desired one. It is the rotation trigger: a rotated value moves no byte of the unit (which
// carries only the file's path), and the environment is spawn-time state — so the change is
// delivered by rewriting the file and restarting the unit.
func SecretEnvShapeChanged(runtimeDir, id string, secretEnv []string) bool {
	onDisk, err := os.ReadFile(SecretEnvFile(runtimeDir, id))
	if err != nil {
		return !os.IsNotExist(err) || len(secretEnv) > 0
	}
	want, err := RenderSecretEnv(secretEnv)
	if err != nil {
		return true // unrenderable: the assemble that follows reports why
	}
	return !slices.Equal(envNames(string(onDisk)), envNames(want))
}

// envNames is the sorted variable NAMES of a rendered environment file — its shape, with the
// values dropped.
func envNames(rendered string) []string {
	var out []string
	for _, line := range strings.Split(rendered, "\n") {
		if name, _, ok := strings.Cut(line, "="); ok {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// ImageSource is the canonical form of an image reference: the plain reference
// with any leading oci://|cr:// scheme (included by a caller out of habit)
// stripped. It is the form the store records per namespace and the form GC
// keep-sets are matched in — never a store key on its own.
func ImageSource(source string) string {
	for _, scheme := range []string{"oci://", "cr://"} {
		if after, ok := strings.CutPrefix(source, scheme); ok {
			return after
		}
	}
	return source
}

// ValidateVolumes rejects a volume whose mount destination or secret projection path could
// inject a systemd mount directive (space/':'-separated list) or traverse the node filesystem
// via '..' — a node-side backstop to admission's ValidMountPath/ValidRelPath, since a runtime
// trusts the desired state pushed to it.
func ValidateVolumes(vols []workload.Volume) error {
	for _, v := range vols {
		if err := corev1.ValidMountPath(v.MountPath); err != nil {
			return err
		}
		// A host-path volume IS its source, so an unusable one must fail here rather than be
		// skipped at mount time: a relative Ref would resolve against whatever directory the
		// sandbox happens to be in, and an empty one would silently leave the workload writing
		// to the ephemeral overlay while its status said the volume was attached. It is also
		// the zero VolumeKind, so this is what stops an unset Kind reaching a bind of nothing.
		if v.Kind == workload.VolumeHostPath && !filepath.IsAbs(v.Ref) {
			return fmt.Errorf("volume at %q: host path %q must be absolute", v.MountPath, v.Ref)
		}
		for relPath := range v.Content {
			if err := corev1.ValidRelPath(relPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// EnsureImage returns the launch spec for namespace's source image, pulling it only on a
// local miss (the reboot fast-path answers an already-present image with no registry
// round-trip). Shared by the runtimes so the fast-path lives in one place.
func EnsureImage(ctx context.Context, images Images, namespace, source string) (*LaunchSpec, error) {
	if ls, err := images.Spec(ctx, namespace, source); err == nil {
		return ls, nil
	}
	if err := images.Pull(ctx, namespace, source); err != nil {
		return nil, err
	}
	return images.Spec(ctx, namespace, source)
}

// GCImages purges the image store down to the keep-set, first normalizing each kept ref
// (ImageSource strips the scheme) so a scheme-prefixed keep ref still matches the stored
// source — otherwise a still-wanted image would be purged. Shared by the runtimes.
func GCImages(ctx context.Context, images Images, keep []string) ([]string, error) {
	sources := make([]string, 0, len(keep))
	for _, ref := range keep {
		sources = append(sources, ImageSource(ref))
	}
	return images.Purge(ctx, sources)
}
