package agent

import (
	"strings"

	corev1 "github.com/ks-tool/horchestra/api/core/v1"
)

// App is a desired application, projected from an Application the controller pushed
// — the reconcile-facing form the ports operate on.
type App struct {
	Name            string
	Node            string
	Image           string
	Command         []string
	Args            []string
	Requests        corev1.ResourceAmounts
	Limits          corev1.ResourceAmounts
	Env             map[string]string
	RestartPolicy   string
	SecurityContext *corev1.SecurityContext
	VolumeMounts    []corev1.VolumeMount
}

// LaunchSpec is an image's launch specification: the ordered unpacked layer
// directories to mount and the config (entrypoint/cmd/env/user/workdir) needed to
// run it. Rootfs is filled in by the reconciler with the app's mount target.
type LaunchSpec struct {
	Rootfs     string
	LayerDirs  []string
	Entrypoint []string
	Cmd        []string
	Env        []string
	User       string
	WorkingDir string
}

// Bind is a PersistentVolume's host directory to bind-mount into the container at
// MountPath. Tmpfs is an ephemeral in-memory mount at Path (Size empty = the
// backend default). Both are backend-neutral — the Units implementation renders
// them into its own mount directives.
type Bind struct {
	HostPath  string
	MountPath string
}

type Tmpfs struct {
	Path string
	Size string
}

// appFromV1 projects a pushed Application into the reconciler's App form.
func appFromV1(it corev1.Application) App {
	return App{
		Name:            it.Name,
		Node:            it.Spec.NodeName,
		Image:           it.Spec.Image,
		Command:         it.Spec.Command,
		Args:            it.Spec.Args,
		Requests:        it.Spec.Resources.Requests,
		Limits:          it.Spec.Resources.Limits,
		Env:             it.Spec.Env,
		RestartPolicy:   it.Spec.RestartPolicy,
		SecurityContext: it.Spec.SecurityContext,
		VolumeMounts:    it.Spec.VolumeMounts,
	}
}

// appsForNode keys the applications pinned to node by name. spec.nodeName pins each
// application to exactly one node, so a node runs only the applications naming it.
func appsForNode(apps []App, node string) map[string]App {
	want := make(map[string]App, len(apps))
	for _, a := range apps {
		if a.Node == node {
			want[a.Name] = a
		}
	}
	return want
}

// effectiveRequests are the resources this app reserves on its node.
func (a App) effectiveRequests() corev1.ResourceAmounts {
	return corev1.ResourceRequirements{Requests: a.Requests, Limits: a.Limits}.EffectiveRequests()
}

// ImageTag is the ref name under which a source image is stored in the node's
// shared image store: the plain image reference, with any leading oci://|cr://
// scheme stripped, so apps sharing a source share one deduplicated image.
func ImageTag(source string) string {
	for _, scheme := range []string{"oci://", "cr://"} {
		if strings.HasPrefix(source, scheme) {
			return strings.TrimPrefix(source, scheme)
		}
	}
	return source
}
