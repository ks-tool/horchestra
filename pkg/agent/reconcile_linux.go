package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/arenadata/oci-packer/pkg/overlay"
	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "ks-tool.dev/horchestra/api/v1"
)

type Reconciler struct {
	Controller string
	Node       string
	StateDir   string
	UnitDir    string
	limits     v1.ResourceAmounts
	// endpoint is the controller's host:port for the gRPC session; creds is the
	// mTLS transport credentials built from the node's certificate.
	endpoint string
	creds    credentials.TransportCredentials
	// want is the last desired set the controller pushed (in memory, not persisted
	// — the controller is the single source of truth). It is read only to report
	// the node's allocation; what is actually running is derived from the node's
	// real systemd units, so a reboot can never leave a stale "already deployed".
	want map[string]App
	// provisioned is the set of PersistentVolume names this node has created a
	// directory for. Reclamation is confined to these, so a genuine PV deletion is
	// distinguished from a leftover directory (e.g. an old layout) that this node
	// never provisioned — the latter is never reclaimed.
	provisioned map[string]bool
}

func NewReconciler(controller string, certPEM, keyPEM, caPEM []byte, node, stateDir, unitDir string, cfg NodeConfig) (*Reconciler, error) {
	controller, err := NormalizeControllerURL(controller)
	if err != nil {
		return nil, err
	}
	endpoint, serverName, err := grpcEndpoint(controller)
	if err != nil {
		return nil, err
	}
	creds, err := grpcCreds(certPEM, keyPEM, caPEM, serverName)
	if err != nil {
		return nil, err
	}
	name := node
	if len(certPEM) > 0 {
		if name, err = certCN(certPEM); err != nil {
			return nil, err
		}
	}
	// A ':' in the state dir would be mis-parsed as the layout/tag separator when
	// building "oci://<imagesDir>:<tag>" references (reference.Parse splits on the
	// first ':'), silently relocating the layout. Reject it up front.
	if strings.ContainsRune(stateDir, ':') {
		return nil, fmt.Errorf("state dir must not contain ':': %q", stateDir)
	}
	r := &Reconciler{
		Controller: controller,
		Node:       name,
		StateDir:   stateDir,
		UnitDir:    unitDir,
		limits:     cfg.Resources,
		endpoint:   endpoint,
		creds:      creds,
	}
	// Rebuild only the volume-provisioning set (which PV data this node owns, so a
	// PV deleted while the agent was down is still reclaimed). What applications
	// run is NOT persisted — it is reconciled from the node's actual systemd units
	// against the controller's desired state, so a reboot self-heals rather than
	// trusting a stale record.
	r.provisioned = loadSet(r.provisionedFile())
	return r, nil
}

// provisionedFile persists the set of PersistentVolume names this node has
// provisioned, so reclamation survives restarts and is scoped to volumes this
// node actually created.
func (r *Reconciler) provisionedFile() string { return filepath.Join(r.StateDir, "provisioned.json") }

func loadSet(path string) map[string]bool {
	set := map[string]bool{}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &set)
	}
	return set
}

func (r *Reconciler) saveProvisioned() { saveJSON(r.provisionedFile(), r.provisioned) }

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

// imagesDir is the node's single shared oci-layout holding every application
// image; layers are deduplicated across applications.
func (r *Reconciler) imagesDir() string { return filepath.Join(r.StateDir, "images") }

// rootfsDir is the per-application overlay mount target assembled from the
// shared layout's layers.
func (r *Reconciler) rootfsDir(name string) string { return filepath.Join(r.StateDir, "rootfs", name) }

// Apply reconciles this node against the desired set the controller pushed over
// the session stream: it provisions this node's PersistentVolumes, brings its
// applications in line (pull/mount/start new or changed apps, tear down removed
// ones, GC unused images) and reclaims deleted volumes' data. The node's status
// is reported separately, up the same stream. Errors are collected, not fatal:
// one failing app never stops the others, teardown or GC.
func (r *Reconciler) Apply(ctx context.Context, apps []App, pvList []v1.PersistentVolume) error {
	// Provision this node's PersistentVolumes before deploying apps that mount
	// them. allPVs (cluster-wide names) separates a genuine deletion from a
	// reassignment; myPVs are the ones this node backs on its disk.
	myPVs := map[string]v1.PersistentVolume{}
	allPVs := map[string]bool{}
	for i := range pvList {
		allPVs[pvList[i].Name] = true
		if pvList[i].Spec.Node == r.Node {
			myPVs[pvList[i].Name] = pvList[i]
		}
	}
	r.provisionPVs(myPVs)
	want := appsForNode(apps, r.Node)
	r.want = want
	errs := r.reconcileApps(ctx, want, myPVs)
	r.gcVolumes(allPVs, want)
	return errors.Join(errs...)
}

// reconcileApps converges the node's actual runtime to want (the applications
// pinned to this node). Actual state is read from the node itself — the systemd
// units on disk — not from a persisted record, so this self-heals: a unit wiped
// by a reboot, a stopped one, or a drifted one is repaired. Units for
// applications no longer wanted (or reassigned to another node) are torn down. It
// returns per-app errors; one app's failure never stops the others, teardown or
// GC.
func (r *Reconciler) reconcileApps(ctx context.Context, want map[string]App, pvs map[string]v1.PersistentVolume) []error {
	var errs []error
	for name, a := range want {
		if !fitsNode(a, pvs) {
			continue // this node does not back all of a's volumes
		}
		if err := r.converge(ctx, a, pvs); err != nil {
			errs = append(errs, fmt.Errorf("converge %s: %w", name, err))
		}
	}
	for _, name := range r.runningApps() {
		if _, ok := want[name]; !ok {
			r.teardownRuntime(ctx, name)
		}
	}
	r.gcImages(ctx, want)
	return errs
}

// fitsNode reports whether every PersistentVolume the app mounts is backed on
// this node (present in pvs). An app with no volumes always fits.
func fitsNode(a App, pvs map[string]v1.PersistentVolume) bool {
	for _, m := range a.VolumeMounts {
		if m.Tmpfs != nil {
			continue // a tmpfs is in-memory; it needs no PersistentVolume
		}
		if _, ok := pvs[m.PV]; !ok {
			return false
		}
	}
	return true
}

// nodeStatus is the node's reported status: measured capacity (capped by the
// -config limits) and the allocation summed from the effective requests of the
// applications pinned to this node.
func (r *Reconciler) nodeStatus() v1.NodeStatus {
	capacity, osName := nodeCapacity(r.limits)
	var alloc v1.ResourceAmounts
	for _, a := range r.want {
		alloc = alloc.Add(a.effectiveRequests())
	}
	return v1.NodeStatus{
		Capacity:  capacity,
		Allocated: alloc,
		OS:        osName,
		IP:        nodeIP(r.Controller),
		Ready:     true,
		Heartbeat: metav1.Now(),
	}
}

// converge makes the node run a exactly as desired, idempotently: it ensures the
// image is present, (re)mounts the rootfs, writes the unit and starts it. A
// converged app is a cheap no-op; a missing unit (reboot wiped /run), a dropped
// mount, a stopped unit or a drifted spec are all repaired — this is the self-heal.
func (r *Reconciler) converge(ctx context.Context, a App, pvs map[string]v1.PersistentVolume) (err error) {
	// Resolve volume mounts first, before any side effect: a missing PV must not
	// leave a pulled image and an orphan overlay mount behind.
	binds, tmpfs, err := r.binds(a, pvs)
	if err != nil {
		return err
	}
	spec, err := r.ensureImage(ctx, a.Image)
	if err != nil {
		return err
	}
	rootfs := r.rootfsDir(a.Name)
	spec.Rootfs = rootfs
	desired, err := Unit(a, spec, binds, tmpfs).Render()
	if err != nil {
		return err
	}

	unitPath := r.unitPath(a.Name)
	onDisk, _ := os.ReadFile(unitPath)
	if len(onDisk) > 0 && string(onDisk) != desired {
		// Spec drifted (source, env or volumes): tear the old runtime down so the
		// new image is mounted fresh rather than reusing the previous overlay.
		r.teardownRuntime(ctx, a.Name)
		onDisk = nil
	}

	// (Re)mount if the rootfs is not currently mounted — a fresh deploy, or a
	// reboot dropped the mount. Never stack a second mount on a live rootfs.
	mounted, err := overlay.MountedUnder(rootfs)
	if err != nil {
		return err
	}
	mountedNow := false
	if len(mounted) == 0 {
		if err = overlay.Mount(overlay.MountOptions{LowerDirs: spec.LayerDirs, Target: rootfs}); err != nil {
			return err
		}
		mountedNow = true
	}
	defer func() {
		if err != nil && mountedNow {
			_ = overlay.Unmount(rootfs, true)
			_ = os.RemoveAll(rootfs)
		}
	}()

	if string(onDisk) != desired {
		if err = os.WriteFile(unitPath, []byte(desired), 0o644); err != nil {
			return err
		}
		return reloadAndStart(ctx, r.unitName(a.Name)) // new/changed unit: reload + start
	}
	// Unit already matches; start it only if it is not running (self-heal a unit
	// that was stopped, e.g. a crash the unit's own Restart= did not recover).
	if unitActive(ctx, r.unitName(a.Name)) {
		return nil
	}
	return startUnit(ctx, r.unitName(a.Name))
}

// binds splits an app's volume mounts into PersistentVolume bind specs
// ("hostDir:mountPath") and tmpfs specs (an ephemeral in-memory mount at the
// path). It errors if a PersistentVolume a non-tmpfs mount names is not
// provisioned on this node.
func (r *Reconciler) binds(a App, pvs map[string]v1.PersistentVolume) (binds, tmpfs []string, err error) {
	for _, m := range a.VolumeMounts {
		if m.Tmpfs != nil {
			tmpfs = append(tmpfs, tmpfsSpec(m.Path, m.Tmpfs.Size))
			continue
		}
		if _, ok := pvs[m.PV]; !ok {
			return nil, nil, fmt.Errorf("volume %q: PersistentVolume %q is not provisioned on this node", m.Path, m.PV)
		}
		binds = append(binds, r.pvDir(m.PV)+":"+m.Path)
	}
	return binds, tmpfs, nil
}

// ensureImage returns the launch spec for source, pulling the image only if it is
// not already in the local layout — so a reboot self-heal from a cached image
// needs no registry access.
func (r *Reconciler) ensureImage(ctx context.Context, source string) (*LaunchSpec, error) {
	tag := ImageTag(source)
	if spec, err := Spec(ctx, r.imagesDir(), tag); err == nil {
		return spec, nil
	}
	if err := Pull(ctx, source, r.imagesDir(), tag); err != nil {
		return nil, err
	}
	return Spec(ctx, r.imagesDir(), tag)
}

// appUnitPrefix namespaces application units so they can be enumerated on the node
// (the actual-state source) and never collide with a system unit of the same name.
const appUnitPrefix = "horchestra-app-"

func (r *Reconciler) unitName(app string) string { return appUnitPrefix + app + ".service" }
func (r *Reconciler) unitPath(app string) string { return filepath.Join(r.UnitDir, r.unitName(app)) }

// runningApps lists the applications this node currently has units for, read from
// the unit directory — the node's own record of what it runs, so teardown of a no
// longer wanted app needs no persisted state.
func (r *Reconciler) runningApps() []string {
	matches, _ := filepath.Glob(filepath.Join(r.UnitDir, appUnitPrefix+"*.service"))
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), appUnitPrefix), ".service"))
	}
	return names
}

// pvDir is the host directory backing a PersistentVolume. Keyed by the PV's name
// (a cluster resource), it is independent of any app: it survives app deletes and
// is removed only when the PersistentVolume itself is deleted.
func (r *Reconciler) pvDir(name string) string {
	return filepath.Join(r.StateDir, "volumes", name)
}

// provisionPVs records each of this node's PersistentVolumes in the provisioned
// set and creates its backing directory once, with the PV's mode (default 0755,
// root-owned). The mode is set only at creation — it is not re-applied every
// reconcile, so a workload's own adjustment of the mount point (e.g. a socket
// dir the entrypoint chowns) is left in place.
func (r *Reconciler) provisionPVs(pvs map[string]v1.PersistentVolume) {
	changed := false
	for name, pv := range pvs {
		if !r.provisioned[name] {
			r.provisioned[name] = true
			changed = true
		}
		dir := r.pvDir(name)
		if _, err := os.Stat(dir); err == nil {
			continue // already provisioned; leave its mode to the workload
		}
		mode := volumeMode(pv.Spec.Mode)
		if err := os.MkdirAll(dir, mode); err != nil {
			log.Warn().Err(err).Str("pv", name).Msg("reconcile: provision volume")
			continue
		}
		_ = os.Chmod(dir, mode) // MkdirAll is umask-masked; set the exact mode once
	}
	if changed {
		r.saveProvisioned()
	}
}

// gcVolumes reclaims the on-disk data of volumes this node provisioned whose
// PersistentVolume has been deleted cluster-wide and that no deployed app still
// mounts. It is deliberately conservative: it only touches directories this node
// provisioned (never a leftover from another scheme), keeps a volume whose PV was
// merely reassigned to another node (still present in allPVs → not reclaimed),
// and treats an empty PV list as suspicious (controller state loss) rather than
// "reclaim everything", so ambiguous absence never destroys data.
func (r *Reconciler) gcVolumes(allPVs map[string]bool, want map[string]App) {
	if len(allPVs) == 0 {
		return // no PVs anywhere: do not mass-reclaim on a possibly-stale empty list
	}
	inUse := map[string]bool{}
	for _, a := range want {
		for _, m := range a.VolumeMounts {
			if m.Tmpfs == nil {
				inUse[m.PV] = true // only PersistentVolumes are reclaimable; tmpfs has none
			}
		}
	}
	changed := false
	for name := range r.provisioned {
		if allPVs[name] || inUse[name] {
			continue // PV still exists (possibly on another node), or an app mounts it
		}
		if err := os.RemoveAll(r.pvDir(name)); err != nil {
			log.Warn().Err(err).Str("volume", name).Msg("reconcile: reclaim volume")
			continue
		}
		delete(r.provisioned, name)
		changed = true
		log.Info().Str("volume", name).Msg("reconcile: reclaimed deleted PersistentVolume's data")
	}
	if changed {
		r.saveProvisioned()
	}
}

// volumeMode parses a claim's octal mode string into a FileMode, translating the
// setuid/setgid/sticky bits, and defaults to 0755 when unset or malformed.
func volumeMode(s string) os.FileMode {
	if len(s) == 0 {
		return 0o755
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0o755
	}
	mode := os.FileMode(n & 0o777)
	if n&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if n&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if n&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

// teardownRuntime stops the named application's unit and unmounts/removes its
// rootfs. It does not touch the shared image layout — image reclamation is done
// by gcImages, which is authoritative over the whole layout.
func (r *Reconciler) teardownRuntime(ctx context.Context, name string) {
	stopUnit(ctx, r.unitName(name))
	_ = os.Remove(r.unitPath(name))
	daemonReload(ctx)
	_ = overlay.Unmount(r.rootfsDir(name), true)
	_ = os.RemoveAll(r.rootfsDir(name))
}

// gcImages reclaims the shared layout down to the images still desired: it
// purges every image whose tag is not the source of some wanted app. This is
// authoritative (independent of per-app teardown outcomes) and best-effort — an
// image whose layers are still overlay-mounted is skipped by oci-packer and
// retried next reconcile, so it converges even when tags and sources diverge
// (e.g. two sources resolving to one manifest digest).
func (r *Reconciler) gcImages(ctx context.Context, want map[string]App) {
	if _, err := os.Stat(r.imagesDir()); err != nil {
		return // no layout yet
	}
	keep := make([]string, 0, len(want))
	for _, a := range want {
		keep = append(keep, ImageTag(a.Image))
	}
	if _, err := Purge(ctx, r.imagesDir(), keep); err != nil {
		log.Warn().Err(err).Msg("reconcile: image gc")
	}
}

// reloadAndStart daemon-reloads systemd and starts unit, waiting for the job.
func reloadAndStart(ctx context.Context, name string) error {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.ReloadContext(ctx); err != nil {
		return err
	}
	ch := make(chan string, 1)
	if _, err := conn.StartUnitContext(ctx, name, "replace", ch); err != nil {
		return err
	}
	if res := <-ch; res != "done" {
		return fmt.Errorf("start %s: %s", name, res)
	}
	return nil
}

// startUnit starts unit and waits for the job. Unlike reloadAndStart it does not
// daemon-reload — used to (re)start a unit whose file is unchanged on disk.
func startUnit(ctx context.Context, name string) error {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	ch := make(chan string, 1)
	if _, err := conn.StartUnitContext(ctx, name, "replace", ch); err != nil {
		return err
	}
	if res := <-ch; res != "done" {
		return fmt.Errorf("start %s: %s", name, res)
	}
	return nil
}

// unitActive reports whether unit is running (or coming up). A unit systemd does
// not know, or one it cannot report on, reads as not active.
func unitActive(ctx context.Context, name string) bool {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return false
	}
	defer conn.Close()
	prop, err := conn.GetUnitPropertyContext(ctx, name, "ActiveState")
	if err != nil {
		return false
	}
	switch prop.Value.Value() {
	case "active", "activating", "reloading":
		return true
	default:
		return false
	}
}

// stopUnit stops unit and waits for the job; best-effort (teardown).
func stopUnit(ctx context.Context, name string) {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return
	}
	defer conn.Close()
	ch := make(chan string, 1)
	if _, err := conn.StopUnitContext(ctx, name, "replace", ch); err == nil {
		<-ch
	}
}

// daemonReload reloads the systemd manager configuration; best-effort (teardown).
func daemonReload(ctx context.Context) {
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.ReloadContext(ctx)
}
