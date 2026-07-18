package agent

import (
	"context"
	"io"
)

// The node agent's job is to run each application the controller assigns this node
// as a service confined to the resources the node grants it — all of the node's
// resources unless the config file caps them. This module owns the reconcile
// algorithm and the controller session; the OS-specific work is done behind the
// ports below, which the agent defines and the application (root module, cmd)
// implements and injects via NewAgent. So a different image store, mount mechanism
// or init system is a matter of passing a different implementation — the reconcile
// logic never changes.

// Images is the node's shared, layer-deduplicated image backend (an oci-layout
// today). An implementation binds its own on-disk layout.
type Images interface {
	// Pull fetches the image at source into the store under tag, unpacked ready to
	// mount. Idempotent: layers already present are reused.
	Pull(ctx context.Context, source, tag string) error
	// Spec returns the launch specification of the image stored under tag: its
	// config plus the ordered unpacked layer directories to mount.
	Spec(ctx context.Context, tag string) (*LaunchSpec, error)
	// Remove deletes the image tagged tag, GC-ing blobs no surviving image uses.
	Remove(ctx context.Context, tag string) error
	// Purge removes every stored image whose tag is not in keep, returning the tags
	// removed. Best-effort: a still-mounted image is skipped, not fatal.
	Purge(ctx context.Context, keep []string) (removed []string, err error)
}

// Mounts assembles an application's root filesystem from an image's layers (an
// overlay mount today).
type Mounts interface {
	// Mount assembles lowerDirs (an image's unpacked layers) read-only at target.
	Mount(ctx context.Context, target string, lowerDirs []string) error
	// Unmount tears down the mount at target.
	Unmount(ctx context.Context, target string) error
	// IsMounted reports whether target currently has a mount.
	IsMounted(ctx context.Context, target string) (bool, error)
}

// Units runs and supervises application services (systemd today), with each
// service's resource limits enforced as cgroup properties by the implementation.
type Units interface {
	// Apply renders and installs name's service unit for the app, writing it only
	// when it differs from the installed one and reloading the init system; it
	// reports whether the definition changed. It does not start the service — the
	// reconciler mounts the rootfs and then starts it.
	Apply(ctx context.Context, name string, app App, spec *LaunchSpec, binds []Bind, tmpfs []Tmpfs) (changed bool, err error)
	// Start activates the named service; a no-op if already active.
	Start(ctx context.Context, name string) error
	// Restart (re)starts the named service — used after its definition changed.
	Restart(ctx context.Context, name string) error
	// Stop deactivates the named service.
	Stop(ctx context.Context, name string) error
	// Remove stops the named service and deletes its unit.
	Remove(ctx context.Context, name string) error
	// IsActive reports whether the named service is running (or coming up).
	IsActive(ctx context.Context, name string) bool
	// List returns the names of the application services installed on this node —
	// the node's own record of what it runs, used to tear down no-longer-wanted
	// applications.
	List(ctx context.Context) ([]string, error)
	// Logs streams the named service's journal; follow tails it, tail bounds the
	// backlog. The caller closes the reader to stop the stream.
	Logs(ctx context.Context, name string, follow bool, tail int64) (io.ReadCloser, error)
}
