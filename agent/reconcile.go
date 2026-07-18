package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// Reconcile brings this node in line with the desired set the controller pushed: it
// provisions this node's PersistentVolumes, converges its applications (pull image
// → mount rootfs → install and start the service, all through the ports), tears
// down the ones no longer wanted and reclaims deleted volumes' data. Actual state
// is read from the node itself (the installed services, via Units.List), never a
// persisted record, so it self-heals across crashes and reboots. Errors are
// collected, not fatal: one failing app never stops the others.
func (a *Agent) Reconcile(ctx context.Context, applications []corev1.Application, pvList []corev1.PersistentVolume) error {
	apps := make([]App, 0, len(applications))
	for i := range applications {
		apps = append(apps, appFromV1(applications[i]))
	}

	myPVs := map[string]corev1.PersistentVolume{}
	allPVs := map[string]bool{}
	for i := range pvList {
		allPVs[pvList[i].Name] = true
		if pvList[i].Spec.Node == a.node {
			myPVs[pvList[i].Name] = pvList[i]
		}
	}
	a.provisionPVs(myPVs)
	want := appsForNode(apps, a.node)
	a.want = want
	errs := a.reconcileApps(ctx, want, myPVs)
	a.gcVolumes(allPVs, want)
	return errors.Join(errs...)
}

// reconcileApps converges the wanted applications and tears down the rest. What is
// actually running is read from the node via Units.List, so a unit wiped by a
// reboot, stopped, or drifted is repaired.
func (a *Agent) reconcileApps(ctx context.Context, want map[string]App, pvs map[string]corev1.PersistentVolume) []error {
	var errs []error
	for name, app := range want {
		if !fitsNode(app, pvs) {
			continue // this node does not back all of the app's volumes
		}
		if err := a.converge(ctx, app, pvs); err != nil {
			errs = append(errs, fmt.Errorf("converge %s: %w", name, err))
		}
	}
	running, _ := a.units.List(ctx)
	for _, name := range running {
		if _, ok := want[name]; !ok {
			a.teardown(ctx, name)
		}
	}
	a.gcImages(ctx, want)
	return errs
}

// fitsNode reports whether every PersistentVolume the app mounts is backed on this
// node. An app with no volumes always fits.
func fitsNode(a App, pvs map[string]corev1.PersistentVolume) bool {
	for _, m := range a.VolumeMounts {
		if m.Tmpfs != nil {
			continue
		}
		if _, ok := pvs[m.PV]; !ok {
			return false
		}
	}
	return true
}

// converge makes the node run the app exactly as desired, idempotently and only
// through the ports: ensure the image is present, install the service (writing its
// unit only if changed), (re)mount the rootfs and start it. A converged app is a
// cheap no-op; a missing/stopped/drifted service is repaired.
func (a *Agent) converge(ctx context.Context, app App, pvs map[string]corev1.PersistentVolume) error {
	binds, tmpfs, err := a.binds(app, pvs)
	if err != nil {
		return err
	}
	spec, err := a.ensureImage(ctx, app.Image)
	if err != nil {
		return err
	}
	rootfs := a.rootfsDir(app.Name)
	spec.Rootfs = rootfs

	changed, err := a.units.Apply(ctx, app.Name, app, spec, binds, tmpfs)
	if err != nil {
		return err
	}
	if changed {
		// Spec drifted: stop the old service and drop its mount so the new image is
		// assembled fresh rather than reusing the previous overlay.
		_ = a.units.Stop(ctx, app.Name)
		_ = a.mounts.Unmount(ctx, rootfs)
	}
	mounted, err := a.mounts.IsMounted(ctx, rootfs)
	if err != nil {
		return err
	}
	if !mounted {
		if err := a.mounts.Mount(ctx, rootfs, spec.LayerDirs); err != nil {
			return err
		}
	}
	if changed || !a.units.IsActive(ctx, app.Name) {
		return a.units.Start(ctx, app.Name)
	}
	return nil
}

// ensureImage returns the launch spec for source, pulling it only if it is not
// already in the store — so a reboot self-heal from a cached image needs no
// registry access.
func (a *Agent) ensureImage(ctx context.Context, source string) (*LaunchSpec, error) {
	tag := ImageTag(source)
	if spec, err := a.images.Spec(ctx, tag); err == nil {
		return spec, nil
	}
	if err := a.images.Pull(ctx, source, tag); err != nil {
		return nil, err
	}
	return a.images.Spec(ctx, tag)
}

// binds splits an app's volume mounts into PersistentVolume binds and tmpfs mounts.
// It errors if a non-tmpfs mount names a PersistentVolume not provisioned on this
// node.
func (a *Agent) binds(app App, pvs map[string]corev1.PersistentVolume) (binds []Bind, tmpfs []Tmpfs, err error) {
	for _, m := range app.VolumeMounts {
		if m.Tmpfs != nil {
			tmpfs = append(tmpfs, Tmpfs{Path: m.Path, Size: m.Tmpfs.Size})
			continue
		}
		if _, ok := pvs[m.PV]; !ok {
			return nil, nil, fmt.Errorf("volume %q: PersistentVolume %q is not provisioned on this node", m.Path, m.PV)
		}
		binds = append(binds, Bind{HostPath: a.pvDir(m.PV), MountPath: m.Path})
	}
	return binds, tmpfs, nil
}

// teardown removes the app's service and unmounts/removes its rootfs. It does not
// touch the shared image store — image reclamation is gcImages' job.
func (a *Agent) teardown(ctx context.Context, name string) {
	_ = a.units.Remove(ctx, name)
	_ = a.mounts.Unmount(ctx, a.rootfsDir(name))
	_ = os.RemoveAll(a.rootfsDir(name))
}

// gcImages reclaims the shared store down to the images still desired: it purges
// every image whose tag is not the source of some wanted app.
func (a *Agent) gcImages(ctx context.Context, want map[string]App) {
	keep := make([]string, 0, len(want))
	for _, app := range want {
		keep = append(keep, ImageTag(app.Image))
	}
	if _, err := a.images.Purge(ctx, keep); err != nil {
		log.Warn().Err(err).Msg("reconcile: image gc")
	}
}

// nodeStatus is the node's reported status: measured capacity (capped by the
// -config limits) and the allocation summed from the effective requests of the
// applications pinned to this node.
func (a *Agent) nodeStatus() corev1.NodeStatus {
	capacity, osName := nodeCapacity(a.limits)
	var alloc corev1.ResourceAmounts
	for _, app := range a.want {
		alloc = alloc.Add(app.effectiveRequests())
	}
	return corev1.NodeStatus{
		Capacity:  capacity,
		Allocated: alloc,
		OS:        osName,
		IP:        nodeIP(a.controller),
		Ready:     true,
		Heartbeat: metav1.Now(),
	}
}

// rootfsDir is the per-application mount target assembled from the image's layers.
func (a *Agent) rootfsDir(name string) string { return filepath.Join(a.stateDir, "rootfs", name) }

// pvDir is the host directory backing a PersistentVolume, keyed by the PV's name
// and independent of any app — it survives app deletes.
func (a *Agent) pvDir(name string) string { return filepath.Join(a.stateDir, "volumes", name) }

// provisionPVs records each of this node's PersistentVolumes in the provisioned set
// and creates its backing directory once, with the PV's mode. The mode is set only
// at creation, so a workload's own adjustment of the mount point is left in place.
func (a *Agent) provisionPVs(pvs map[string]corev1.PersistentVolume) {
	changed := false
	for name, pv := range pvs {
		if !a.provisioned[name] {
			a.provisioned[name] = true
			changed = true
		}
		dir := a.pvDir(name)
		if _, err := os.Stat(dir); err == nil {
			continue
		}
		mode := volumeMode(pv.Spec.Mode)
		if err := os.MkdirAll(dir, mode); err != nil {
			log.Warn().Err(err).Str("pv", name).Msg("reconcile: provision volume")
			continue
		}
		_ = os.Chmod(dir, mode) // MkdirAll is umask-masked; set the exact mode once
	}
	if changed {
		a.saveProvisioned()
	}
}

// gcVolumes reclaims the data of volumes this node provisioned whose PersistentVolume
// has been deleted cluster-wide and that no deployed app still mounts. Conservative:
// it only touches directories this node provisioned, keeps a volume whose PV was
// merely reassigned to another node, and treats an empty PV list as suspicious
// (controller state loss) rather than "reclaim everything".
func (a *Agent) gcVolumes(allPVs map[string]bool, want map[string]App) {
	if len(allPVs) == 0 {
		return
	}
	inUse := map[string]bool{}
	for _, app := range want {
		for _, m := range app.VolumeMounts {
			if m.Tmpfs == nil {
				inUse[m.PV] = true
			}
		}
	}
	changed := false
	for name := range a.provisioned {
		if allPVs[name] || inUse[name] {
			continue
		}
		if err := os.RemoveAll(a.pvDir(name)); err != nil {
			log.Warn().Err(err).Str("volume", name).Msg("reconcile: reclaim volume")
			continue
		}
		delete(a.provisioned, name)
		changed = true
		log.Info().Str("volume", name).Msg("reconcile: reclaimed deleted PersistentVolume's data")
	}
	if changed {
		a.saveProvisioned()
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

func (a *Agent) provisionedFile() string { return filepath.Join(a.stateDir, "provisioned.json") }

func (a *Agent) saveProvisioned() { saveJSON(a.provisionedFile(), a.provisioned) }

func loadSet(path string) map[string]bool {
	set := map[string]bool{}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &set)
	}
	return set
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

// nodeIP returns this node's source IP toward the controller — the address it
// reaches the control plane on. A UDP "connect" sends no packets; it just resolves
// the route and yields the local address. Empty if it cannot be determined.
func nodeIP(controller string) string {
	u, err := url.Parse(controller)
	if err != nil {
		return ""
	}
	host, port := u.Hostname(), u.Port()
	if len(port) == 0 {
		port = "443"
	}
	conn, err := net.Dial("udp", net.JoinHostPort(host, port))
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}
