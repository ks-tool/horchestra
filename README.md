# horchestra

Declarative control plane for running applications on a fleet of Linux hosts.

## Binaries

- **`horchestra`** (`cmd/horchestra`) — the single control-plane **+** node-agent binary. The same executable runs the controller (`horchestra controller`) and the per-node reconcile daemon (`horchestra agent`), installs a role as a systemd unit (`horchestra install controller` / `install agent`) and garbage-collects node images (`horchestra purge`); `node-tool` (a separate operator tool) deploys it onto hosts. The `controller` run command builds **cross-platform** (handy for local control-plane dev); `agent`, `purge` and the `install` subcommands are **linux only** — they drive systemd over D-Bus and mount overlay rootfs. So an off-linux `go build` yields a controller-only binary; a plain linux build is the **control-plane binary** (`controller` + `agent` runtime + `purge` + `install controller`); and the **`agent` build tag** switches it to the node role — `go build -tags agent` on linux drops the controller (its `controller` command and its `install controller` subcommand) and enables `install agent`, producing a **node binary** (`agent` + `purge` + `install agent`) that never links the control-plane (no apiserver, storage, authz, …). `node-tool` pushes the control-plane binary to the controller host and the `-tags agent` binary to nodes.
- **`node-tool`** (`cmd/node-tool`) — the operator CLI (PKI + SSH deploy). Cross-platform; runs on your workstation.

Both use [cobra](https://github.com/spf13/cobra) for their command trees; long flags take a `--` prefix.

## Layers

- `pkg/storage` — the `Storage` interface (data access); `pkg/storage/bolt` is the embedded BoltDB backend with an in-process watch bus.
- `pkg/admission` — the request pipeline (mutation, then validation plugins) applied before persistence. Plugins work on **typed `api/v1` objects** (the service decodes the request through the scheme before admission), so `NodeRestriction` and the capacity check read real Go structs rather than unstructured maps.
- `pkg/service` — business logic over the `Storage` interface; the HTTP layer never touches storage directly. On create/update it **validates the request against the Kind's input schema**, decodes it to its typed `api/v1` value, runs admission on that, then re-encodes for storage.
- `pkg/apiserver` — HTTP transport: a `bunrouter` static router that binds each route to a GVK, plus discovery and error mapping. Compatible enough for `kubectl` (see below).
- `pkg/nodeapi`, `pkg/nodeserver` — the **controller↔node-agent transport**: a gRPC bidirectional stream (`pkg/nodeapi`, from `proto/node.proto`) over which the controller pushes each node its desired state and the agent reports status. `pkg/nodeserver` is the controller side; it is served on the same TLS port as the REST API and reads the node's identity from the mTLS peer certificate.
- `pkg/authn`, `pkg/authz` — authentication (mTLS + Bearer — Bearer today is a single built-in development token, `dev-admin-token`, mapping to cluster-admin; mTLS is the real identity path) and RBAC authorization over `Role`/`RoleBinding`. Two interchangeable engines (`--authorizer`): `rbac` (default) queries the objects live per request; `casbin` compiles them into a Casbin enforcer refreshed by a watch.
- `api/v1` — API groups (`orch.ks-tool.dev/v1`, `rbac.ks-tool.dev/v1`), the built-in kinds, the **scheme** (GVK → typed constructor) and the **input schemas**. The JSON schemas are **generated from the Go types by reflection at startup** and kept in memory (the Kubernetes approach, without hand-written schema files): a field is required unless its json tag has `,omitempty`, a `jsonschema:"minLength=1"` tag forbids an empty value, and unknown `spec` fields are rejected — so `spec.source`/`spec.node` being required falls out of the struct definition. `Validate(gvk, obj)` checks a request against its Kind's schema and the failure surfaces as HTTP 422 Invalid.

## Kinds

`Application`, `Node`, `PersistentVolume` (`orch.ks-tool.dev/v1`), `Role`, `RoleBinding` (`rbac.ks-tool.dev/v1`).

## Build and run

```
go build ./...          # off linux this builds a controller-only horchestra; on linux the control-plane build
go test ./...
go run ./cmd/horchestra controller --disable-auth --db /tmp/horchestra.db --addr :8080   # controller runs cross-platform

GOOS=linux go build ./cmd/horchestra                    # control-plane: controller + agent + purge + install controller
GOOS=linux go build -tags agent ./cmd/horchestra        # node-only: agent + purge + install agent, control-plane not linked
```

Configuration is supplied through flags or a YAML file (`--config path.yaml`); environment variables are not read. For a TLS deployment, `node-tool init` bundles the serving material into the **controller auth-config** (a kubeconfig) so the controller launches from a single file — the way `kubeadm init` writes `admin.conf`:

```
node-tool init --host <controller-host>          # writes pki/ + controller.conf + admin.conf
go run ./cmd/horchestra controller --auth-config pki/controller.conf --db /tmp/horchestra.db
```

`controller.conf` carries the serving certificate/key, the client CA (which enables mTLS) and the address; the listen address is taken from its `server` URL unless `--addr` overrides it. The individual `--tls-cert`/`--tls-key`/`--tls-ca` flags remain as an alternative to the auth-config.

On a linux host the controller installs itself as a `systemd` service, the way `horchestra install agent` does — `horchestra install controller` writes the unit (`ExecStart=horchestra controller --auth-config … --db … [--config … --addr …]`) and enables/restarts it over D-Bus (both install subcommands share `--enable=false`, to write the unit without starting it, and `--unit`, to relocate it). `node-tool deploy-controller <addr>` does the whole thing over SSH: it issues a serving certificate for the address from the existing CA, writes `controller.conf` (and, unless `--admin-conf=false`, refreshes `admin.conf` so kubectl targets the new address), copies the `horchestra` binary and `controller.conf` to the host, and runs `horchestra install controller`.

```
node-tool deploy-controller <addr> [--db /var/lib/horchestra/controller.db] [--user root] [--ssh-key <path>] [--sudo] [--sudo-pass <pw>]
```

```
curl -s localhost:8080/apis
curl -s -XPOST localhost:8080/apis/orch.ks-tool.dev/v1/applications \
  -d '{"apiVersion":"orch.ks-tool.dev/v1","kind":"Application","metadata":{"name":"demo"},"spec":{"source":"reg/app:v1"}}'
curl -s localhost:8080/apis/orch.ks-tool.dev/v1/applications
```

## kubectl

The server speaks enough of the Kubernetes API for `kubectl` to drive it: legacy
`/api` and the `/apis` discovery documents, cluster-scoped resources with short
names (`kubectl get app`), create/get/list/update/delete/watch plus **PATCH** (JSON
Merge Patch and JSON Patch, what `kubectl apply`/`edit` need), and **server-side
Table printing** so `kubectl get` shows real columns (and prints "No resources
found", not "…in default namespace", for these cluster-scoped kinds). `node-tool
init` already writes `admin.conf` (a cluster-admin client config, CA and
client certificate/key embedded); point kubectl at it directly. Not implemented:
OpenAPI (`kubectl explain`) and server-side apply.

**`kubectl logs`.** The legacy core group carries a read-only **`pods` alias of
`Application`**: `GET /api/v1/pods` lists every application as a Pod (so `kubectl
get pods` works), `GET /api/v1/pods/<app>` projects one app into a one-container Pod
(so `kubectl logs <app>` resolves it), and `GET /api/v1/pods/<app>/log` streams
the logs. The controller resolves the app's `spec.node`, opens a stream to that
node **over the existing agent gRPC session** (no inbound port on the node), and
the agent tails the application's unit with `journalctl -u horchestra-app-<app>`,
forwarding chunks back up; `--follow` and `--tail` are honoured, and disconnecting
stops the node-side stream. (Since one app is one node is one process is one unit,
there is no container to pick.) Log history for a deleted app — a central store —
is future work; today it is the live unit journal.

```
node-tool init --host <controller-host>          # writes admin.conf (cluster-admin)
kubectl --kubeconfig pki/admin.conf get app
```

To mint a scoped kubeconfig for a different identity, `node-tool kubeconfig <cn>
[--group g1,g2] [--server URL] [--out file]` issues a fresh client certificate (its
CN/Organization become the request identity/groups) and emits the kubeconfig,
defaulting to stdout. `--group system:masters` grants admin (the default admin
group); drop it and bind a `Role`/`RoleBinding` for scoped access. The lower-level
`node-tool cert <cn>` still issues a bare certificate pair on its own.

## Agent (`horchestra agent`)

Linux only. The node-agent is a daemon (the kubelet analogue): it reconciles this node's applications against the controller's desired state. `horchestra install agent` writes the daemon's own `systemd` unit (`ExecStart=horchestra agent`) and — unless `--enable=false` — enables and starts it via systemd over D-Bus (`go-systemd`); `horchestra agent` opens a **gRPC bidirectional session** to the controller (Transport, below) and reconciles off it.

Credentials come from `node.conf` — the node-side analogue of `controller.conf`, a single kubeconfig bundling the node's client certificate/key, the CA and the controller URL (kubelet's `kubelet.conf`), passed as `--auth-config`. `node-tool deploy` generates it and installs the agent with `--auth-config /etc/horchestra/node.conf`; the controller URL is validated at install time, so a bad address fails fast instead of looping at reconcile. The discrete `--controller`/`--cert`/`--key`/`--ca` flags remain as an alternative to `node.conf`.

The agent reports its `status` up the session (on connect, on the `--heartbeat` interval, and after each apply), and the controller recreates its `Node` if it was deleted — `kubectl delete node` self-heals on the next heartbeat. `status` carries a **`ready`** flag and a **`heartbeat`** timestamp, resource **capacity** — **CPU and memory** as Kubernetes resource quantities (`"8"`, `16Gi`), plus OS — reduced by any `--config` limit, and the **allocation**, which is the sum of the resource **requests** of the applications running on the node (an app's requests, defaulting to its limits, are subtracted from the node's available capacity when it is placed). An application's `spec.resources` are also **enforced on the node via the unit's cgroup**: `requests` become `CPUWeight` (relative share) and `MemoryLow` (reclaim protection), `limits` become `CPUQuota` (a hard `%`-of-a-core cap) and `MemoryMax` (a hard cap — the workload is OOM-killed past it). Compute resources are only CPU and memory; **disk is not a compute resource** — an application requests storage by mounting a `PersistentVolume` under `spec.volumes`. `kubectl get nodes` shows **STATUS** (`Ready`/`NotReady`) and **CPU**/**MEM** as `allocated/capacity` amounts (CPU in cores, memory in GiB — e.g. `2/8` and `0.5/7.8Gi` — the amounts convey utilization directly); `-o wide` adds the node's **IP** (its source address toward the controller) and **OS**. Readiness is heartbeat-driven: a node is `Ready` only while its heartbeat is fresh (within the controller's `--node-ready-timeout` / `nodeReadyTimeout`, default `45s`), so a stopped agent shows `NotReady` on its own without a separate liveness controller. `--config` is a small YAML that caps advertised capacity:

```yaml
resources: { cpu: "4", memory: 8Gi }   # advertise at most this much
```

Storage is a separate **`PersistentVolume`** resource with a lifecycle independent of any app: a `PersistentVolume` is a directory on a node's disk, and an `Application` mounts it by name under `spec.volumes`. Deleting the `Application` leaves the volume and its data; deleting the `PersistentVolume` reclaims the data from disk on the next reconcile. Reclamation is deliberately conservative — it only reclaims volumes this node provisioned, only once no deployed app still mounts them (delete the app first, then the PV), keeps a volume whose PV was merely reassigned to another node, and skips an empty PV list entirely (treated as possible controller state loss rather than "reclaim everything"). A consequence of that last guard: if you delete *every* PersistentVolume at once, the last ones' data lingers until at least one PV exists again.

```yaml
apiVersion: orch.ks-tool.dev/v1
kind: PersistentVolume
metadata: { name: pg-data }
spec: { size: 10Gi, node: sav-01 }        # size is advisory; node backs the volume on its disk
---
kind: Application
metadata: { name: pg }
spec:
  source: docker.io/library/postgres:18-alpine
  node: sav-01                                # required: the node this app runs on
  resources: { requests: { cpu: 500m, memory: 256Mi } }
  env: { POSTGRES_HOST_AUTH_METHOD: trust }   # plain config; secrets belong in a mounted file, not env
  volumes:
    - { name: pg-data, path: /var/lib/postgresql }        # PV → mount path (must exist in the image)
    - { name: run, path: /run/postgresql, tmpfs: true }   # ephemeral (socket): in-memory, no PV
```

`spec.env` is layered over the image's own environment (the app's values win). Each `PersistentVolume` is a directory (`<state-dir>/volumes/<pv-name>`, mode `0755` root-owned by default — the image's entrypoint chowns its own data dir — or the PV's octal `mode`), provisioned only by the node named in `spec.node`, and bind-mounted into the app's otherwise read-only rootfs at the mount `path` (exempted from `ProtectSystem=strict`). The mount destination must already exist in the image (a read-only overlay can't create a new mountpoint). A volume marked **`tmpfs: true`** is instead an **ephemeral in-memory mount** (systemd `TemporaryFileSystem=`) that needs **no `PersistentVolume`** — for temporary paths that hold no data worth keeping (pid files, sockets, caches) such as `/run`; an optional `size` caps it, and its memory is charged to the app's memory limit anyway. The image entrypoint is resolved to an absolute path via the image's `PATH` (systemd needs an absolute `ExecStart`, but OCI entrypoints are often bare like `docker-entrypoint.sh`). A multi-arch image tag is resolved to the **host platform only** before pulling, so a manifest list (e.g. `postgres:18-alpine`) doesn't drag every architecture's layers onto the node. Together these run a real Docker image such as `docker.io/library/postgres:18-alpine`.

`spec.expose` declares the ports the application listens on, as a list — `expose: [{ name: http, port: 8080 }, { port: 9090 }]`, where `name` is an optional label and `port` is required (1–65535). It is a **pure declaration**: the orchestrator runs no data-plane of its own, so an app is reachable at its node's address on these ports, and an external edge/load balancer (e.g. Traefik, via a provider that reads `expose`) is what routes to them. An app with no `expose` is simply not fronted by an edge.

Those exposed ports are published for service discovery at **`GET /sd/consul`**, a read-only projection in **Consul catalog format** (with no Enterprise `Namespace` field — horchestra is single-project/cluster-wide), so any Consul-catalog-aware consumer (Prometheus `consul_sd`, Traefik `consulCatalog`, …) can discover services without running a Consul agent. The bare `/sd/consul` and Consul's own paths both work: `GET /sd/consul/v1/catalog/services` returns the service→tags map, `GET /sd/consul/v1/catalog/service/<name>` the instances. Each `Application` contributes one service per exposed port — an unnamed port under the app's own name, a named port as `<app>-<name>` (the port name becomes a Consul tag) — reachable at the app node's reported address on that port. A port whose node has not reported an address yet is omitted (nothing to advertise). Reads are gated by authentication, like the `pods` alias.

An `Application` is pinned to exactly one node through the **required `spec.node`** field — one application runs on one node (one process, one systemd unit); the node-agent runs only the applications naming it. Two admission checks (in the default chain) guard it. **`spec.node` must name an existing `Node`**: an application pinned to an unknown node (a typo, or a node that has not registered) is rejected `422 Invalid` (`spec.node: node "a" does not exist`) rather than silently created and never run — this runs regardless of resource requests. Then **capacity is enforced per node**: creating or updating an `Application` is rejected `403 Forbidden` if the sum of the effective CPU/memory requests of the applications on its `spec.node` would exceed that node's reported capacity (a no-op while the node has not reported capacity yet — the app is admitted and waits — and freed on delete).

```
horchestra install agent --auth-config node.conf [--config node.yaml]   # or: [--controller <url>] [--cert node.crt --key node.key --ca ca.crt]
horchestra agent         --auth-config node.conf [--config node.yaml] [--heartbeat 15s]   # or: [--controller <url>] [--cert … --key … --ca …] [--node <name>] [--state-dir <d>] [--unit-dir <d>]
horchestra purge         [--layout <oci-layout-dir>] [--exclude <ref> ...]
```

A node's client certificate carries the `system:nodes` group and a CN equal to
the node name. Two layers gate what it may do, and both are configured for you at
startup. First, RBAC must grant the group access at all: the controller seeds a
default `system:node` `Role` (`create`/`get`/`update`/`patch` on `nodes`,
`get`/`list`/`watch` on `applications` and `persistentvolumes`) bound to
`Group: system:nodes`, so a node registers itself and reads its desired
applications **out of the box** with no manual setup. Seeding is idempotent — it
runs on every startup and reconciles the default `Role` up to the current rules
(so a permission added across an upgrade reaches a cluster first seeded by an
older version), while leaving an operator-added binding subject untouched and
recreating a deleted binding on the next restart, the way kube-apiserver
reconciles its own default RBAC. Second, the built-in **NodeRestriction**
admission plugin confines a `system:nodes` identity to writing only the single
`Node` whose name equals its CN: it may register and update its own `Node`, but
creating or deleting another node's `Node`, or writing any other resource, is
rejected with `403 Forbidden`. NodeRestriction is always on (part of the default
admission chain) and is a no-op for non-node identities, so it never widens what
an admin or user can reach. Both apply whenever mTLS identifies the caller; under
`--disable-auth` every caller is `system:masters` and nothing is restricted.

The node keeps **one shared oci-layout** for the whole host (`<state-dir>/images`);
every application image is stored in it, tagged by its source, so common layers are
**deduplicated across applications**. Each application gets its own read-only overlay
mount (`<state-dir>/rootfs/<app>`) assembled from that shared layout's layers. The
layout is protected two ways: `oci-packer`'s cross-process advisory lock serialises
pulls against a concurrent `purge`/delete, and the image config/manifest blobs (which
decide what runs and from which layers) are made immutable (`FS_IMMUTABLE_FL`) so they
cannot be swapped out of band (best-effort — skipped where the filesystem or
privileges don't allow it). Layer contents are protected by directory permissions and
the read-only overlay rather than the immutable flag, which would strip the exec bits
the rootfs needs.

Reconcile is a **level-driven self-heal**, not an optimistic diff: the **controller is the single source of truth** for what should run, and the node's **own systemd units are the source of truth for what is running** — the agent keeps no persisted "deployed" record. Each app is _converged_ idempotently: ensure the image is present (pull only if missing — a cached image needs no registry), (re)mount the rootfs if it is not mounted, write the unit if it differs, and start it if it is not active. So a **reboot recovers on its own** — after `/run` (tmpfs) is wiped and the overlay mounts are gone, the enabled `horchestra-agent` unit restarts, reconnects, and re-converges every desired app from the images and volume data still on disk. Convergence runs both on every desired-state push and on the heartbeat interval, so a unit that died or drifted between pushes is repaired without waiting for a change; app units also carry `Restart=on-failure`, so systemd restarts a crash immediately. App units are named `horchestra-app-<name>.service` (namespaced, so they never collide with a system unit and can be enumerated to tear down what is no longer wanted). An app whose spec changed is torn down and redeployed on the new image; a removed or reassigned app is stopped and unmounted; the shared layout is then garbage-collected down to the images still in use. One app's failure never blocks the others, teardown, or GC.

`horchestra purge` reclaims disk on a node: it lists the images in the shared
layout (via `oci-packer`'s `Layout.List`) and deletes every one whose ref name is not
passed in `--exclude`, garbage-collecting layers no surviving image references
(`Layout.Delete`). A layer directory currently overlay-mounted under a running
application is never removed.

### Transport (gRPC)

The controller↔agent link is a **gRPC bidirectional stream over mTLS**, not REST polling — the transport the architecture always specified. The agent dials the controller (`grpc.NewClient`, the same host:port as the REST API — the controller serves gRPC and REST on one TLS port, dispatching by HTTP/2 + `application/grpc`), opens one `Session` stream, and reconnects with backoff if it drops. It carries both directions:

- **down (controller → agent):** the node's desired state — the `Application`s pinned to it (`spec.node`) plus every `PersistentVolume` — pushed on connect and re-pushed whenever an Application or PV changes (the controller watches storage). The node's identity is the mTLS peer certificate's CN, read on the server with no auth middleware of its own; the stream is refused (`PermissionDenied`) unless that certificate's Organization carries the `system:nodes` group, so only a node certificate can open a session.
- **up (agent → controller):** the node's `status`, reported on connect, on the `--heartbeat` interval, and after each apply. The controller persists it as the node's own `Node` object **through the service** (so admission — `NodeRestriction` — still confines the node to its own object), creating it if it was deleted (`kubectl delete node` self-heals on the next heartbeat).

When the controller pushes a new Application the agent **pulls** it in-process into the shared layout (reusing `oci-packer`'s registry client to copy the image with unpacked layers — no external `oci-packer`/`skopeo` binary on the node, and blobs already present from another application are reused), **overlay-mounts** the layers read-only (via `oci-packer`'s `pkg/overlay`), renders a hardened application `systemd` unit (`RootDirectory`/`ExecStart`/`Environment`/`User` + `NoNewPrivileges`/`ProtectSystem`/`ProtectHome`/`PrivateTmp`) from the image config (serialized with `go-systemd`), and starts it via systemd over D-Bus; an application removed from the desired state is stopped, unmounted and cleaned up over D-Bus, and its image is dropped from the shared layout unless another application still uses the same source.

`pkg/agent` holds the controller session and reconciles off it, pulls and reads the shared OCI layout and overlay-mounts it (all via `oci-packer`), and controls units over systemd D-Bus (`go-systemd`); `pkg/systemd` serializes unit files (`go-systemd`). Logging is `zerolog`.

## node-tool

Manages the local PKI and deploys both the controller and the agent — both from the same `horchestra` binary. `init` creates the CA and the controller server certificate; `cert` issues a client certificate (for operators); `deploy` issues a node certificate, writes the node's `node.conf` (client cert/key + CA + controller URL) and installs the agent on a host over an in-process SSH connection (`golang.org/x/crypto/ssh`; no `scp`/`ssh` binaries required — works from inside a container); `deploy-controller` does the same for the control plane (serving cert + `controller.conf` + `horchestra install controller`). `--node` sets the node name (its certificate CN and identity), defaulting to the address; `--controller` defaults to the local address the node can reach back on (a warning is logged if that auto-selected address is in a different subnet than the node — e.g. a VPN/tunnel address the node cannot route back to, or a single-node host where the controller lives on the node itself — so pass `--controller` explicitly there); `sudo` is auto-enabled when `--user` is not `root`; its password comes from `--sudo-pass` / `HORCHESTRA_SUDO_PASS`, and with neither the tool probes the remote (`sudo -n`) and only prompts when a password is actually required and a terminal is attached — so passwordless-sudo hosts (e.g. CI) stay non-interactive.

```
node-tool init  [--pki-dir pki] [--host <ip|dns> ...]          # CA + controller server cert
node-tool cert  <cn> [--group system:masters] [--out admin]    # a client certificate
node-tool deploy <node-addr> [--node <name>] [--controller <url>] [--binary horchestra] [--user root] [--ssh-key <path>] [--sudo] [--sudo-pass <pw>]
node-tool deploy-controller <addr> [--binary horchestra] [--db <path>] [--admin-conf=false] [--user root] [--ssh-key <path>] [--sudo] [--sudo-pass <pw>]
```

Both `deploy` commands push the same `horchestra` binary to `/usr/local/bin/horchestra` and differ only in which unit they install (`horchestra install controller` vs `horchestra install agent`). The controller enables mTLS with `--tls-cert server.crt --tls-key server.key --tls-ca ca.crt`; clients (agents, operators) present certificates issued by the same CA, and their CN/Organization become the request identity/groups.
