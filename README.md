# horchestra

> **⚠️ Early Development**: This project is in active development and not yet production-ready. APIs, configuration
> formats, and behavior may change without notice. Use at your own risk.

Declarative, Kubernetes-flavored control plane for running OCI applications on a fleet of Linux hosts. Applications are pinned to nodes and run as hardened `systemd` units from overlay-mounted OCI images; the controller speaks enough of the Kubernetes API to be driven by `kubectl`.

## Modules

The repo is a **four-module Go workspace** bound by a root `go.work` (`use ( . ./agent ./api ./apiserver )`, no cross-module `require`/`replace` — it builds only under the workspace). Dependency direction is one-way: **`api` ← {`apiserver`, `agent`} ← root**.

- **`github.com/ks-tool/horchestra/api`** (`./api`) — the shared kernel every other module builds on:
  - `api/core/v1`, `api/rbac/v1` — the Kinds.
  - `api/scheme` — the GVK → typed-constructor registry, plus the resource registry (plural/singular/short names) and defaulters.
  - `api/storage` — the `Storage` interface (`Create`/`Update`/`UpdateSubresource`/`Rollback`/`Delete`/`Get`/`List`/`Watch`/`Close`; per-GVK monotonic `resourceVersion`; `ErrNotFound`/`ErrAlreadyExists`/`ErrConflict`).
  - `api/types` (`Object`, `ObjectMeta`), `api/utils`.
  - `api/pb` — the **single shared** generated gRPC transport package (node.proto stubs), imported by both the agent (client) and the apiserver (server).
- **`github.com/ks-tool/horchestra/apiserver`** (`./apiserver`) — the control-plane server (REST + gRPC):
  - `apiserver` — the HTTP layer: a `bunrouter` router binding each route to a GVK, `/api`+`/apis` discovery, server-side Table printing, a read-only `pods` alias of `Application`, and authn/authz middleware.
  - `apiserver/service` — business logic over `api/storage`; the HTTP layer never touches storage directly.
  - `apiserver/admission` — the typed admission chain (`defaulting → appPolicy → nodeRestriction → nodeExists → capacityCheck`).
  - `apiserver/authn`, `apiserver/authz` — mTLS/Bearer identity, and RBAC over `Role`/`RoleBinding` (live `rbac` engine or compiled `casbin`).
  - `apiserver/nodeserver` — the controller side of the gRPC node transport; also the `pods/log` log streamer.
- **`github.com/ks-tool/horchestra/agent`** (`./agent`) — the node agent: it holds the controller session and owns the reconcile algorithm, converging every application pinned to its node through three injected **ports** (`Images`/`Mounts`/`Units`). The OS-specific code is *not* here — it is supplied by the application.
- **`github.com/ks-tool/horchestra`** (root, `.`) — the application. It composes the other three into `cmd/horchestra` and `cmd/node-tool` and supplies the concrete port adapters and node-side libraries: `pkg/oci` (the `Images`+`Mounts` adapter — shared OCI layout + overlay), `pkg/systemd` + `pkg/systemd/units` (the `Units` adapter), `pkg/storage/bolt` (the `Storage` implementation), `pkg/pki`, `pkg/config`, `pkg/log`.

Both binaries use [cobra](https://github.com/spf13/cobra); long flags take a `--` prefix.

## Binaries

`cmd/horchestra` builds in one of **three modes**, selected by build tag, and `cmd/node-tool` is a separate operator CLI.

- **`horchestra`** — the default build (no tags): a **monolith** with *both* roles. On linux it carries `controller`, `agent`, `purge`, and `install controller` + `install agent`; off-linux only `controller` (the agent commands are linux-only, so an off-linux build is effectively controller-only).
- **`-tags controlleronly`** — the control plane alone (`controller` [+ `install controller` on linux]). Builds on **any OS** — handy for local control-plane dev.
- **`-tags agentonly`** — the node role alone (`agent` + `purge` + `install agent`). **Linux only** (it drives systemd over D-Bus and mounts overlay rootfs).

The monolith works because the agent (gRPC client) and the apiserver (gRPC server) import **one** shared transport package, `api/pb`, so `node.proto` is registered once. Two per-module copies would register the same file/service/message names twice in protobuf's global registry and panic at init — hence a single `api/pb`.

`node-tool` deploys the chosen `horchestra` binary onto hosts and installs the role's systemd unit. It is cross-platform and runs on your workstation.

## Build

A `Makefile` is the build entrypoint (`make help` lists every target). Because `OS` defaults to `linux`, a bare `make` cross-compiles the deployable **linux** binaries even from a mac (`CGO_ENABLED=0`, `-trimpath`, `-ldflags '-s -w'`); override `OS=`/`ARCH=`/`LDFLAGS=` as needed.

```
make                 # bin/horchestra (monolith) + bin/node-tool (host)
make all             # + bin/horchestra-controller (-tags controlleronly) + bin/horchestra-agent (-tags agentonly)
make horchestra      # bin/horchestra          (both roles)
make controller      # bin/horchestra-controller (control plane, any OS)
make agent           # bin/horchestra-agent    (node, linux)
make node-tool       # bin/node-tool           (host platform)
make test            # per-module tests (apiserver with -race)
make lint            # gofmt check + go vet across modules
make proto           # regenerate api/pb from proto/node.proto
```

Or build directly under the workspace (whole-repo `go build ./...` spans modules — build/test per module or via a `./cmd/...` path):

```
go build ./cmd/horchestra                          # monolith (controller-only off-linux)
GOOS=linux go build -tags controlleronly ./cmd/horchestra   # control plane only (builds on any OS)
GOOS=linux go build -tags agentonly     ./cmd/horchestra    # node only (linux)
go run ./cmd/horchestra controller --disable-auth --db /tmp/horchestra.db --addr :8080   # controller runs cross-platform
```

Configuration is supplied through flags or a YAML file (`--config path.yaml`); environment variables are not read. For a TLS deployment, `node-tool init` bundles the serving material into the **controller auth-config** (a kubeconfig) so the controller launches from a single file — the way `kubeadm init` writes `admin.conf`:

```
node-tool init --host <controller-host>          # writes pki/ + controller.conf + admin.conf
go run ./cmd/horchestra controller --auth-config pki/controller.conf --db /tmp/horchestra.db
```

`controller.conf` carries the serving certificate/key, the client CA (which enables mTLS) and the address; the listen address is taken from its `server` URL unless `--addr` overrides it. The individual `--tls-cert`/`--tls-key`/`--tls-ca` flags remain as an alternative to the auth-config.

On a linux host the controller installs itself as a `systemd` service — `horchestra install controller` writes the unit (`ExecStart=horchestra controller --auth-config … --db … [--config … --addr …]`) and enables/restarts it over D-Bus (both install subcommands share `--enable=false`, to write the unit without starting it, and `--unit`, to relocate it). `node-tool deploy-controller <addr>` does the whole thing over SSH.

```
curl -s localhost:8080/apis
curl -s -XPOST localhost:8080/apis/horchestra.io/v1/applications \
  -d '{"apiVersion":"horchestra.io/v1","kind":"Application","metadata":{"name":"demo"},"spec":{"image":"reg/app:v1","nodeName":"sav-01"}}'
curl -s localhost:8080/apis/horchestra.io/v1/applications
```

## Kinds

`Application`, `Node`, `PersistentVolume` (`horchestra.io/v1`); `Role`, `RoleBinding` (`rbac.horchestra.io/v1`). All are cluster-scoped. Short names: `app`/`apps`, `no`, `pv`.

`ApplicationSpec` uses Kubernetes Pod vocabulary on a flat, single-container shape (one application = one process = one systemd unit, so there is no `containers[]`):

- **`image`** — a plain OCI image reference (required).
- **`nodeName`** — pins the application to exactly one node (required; author-supplied, no scheduler fills it).
- `command` / `args` — override the image ENTRYPOINT / CMD (literal argv, never interpolated).
- `env` — a plain map layered over the image's env (no `valueFrom`, so a secret cannot be referenced here).
- `ports` — `[{ name?, port }]`, a pure declaration for an external edge/LB (horchestra runs no data-plane of its own).
- `resources` — `{ requests, limits }`, each `{ cpu, memory }` (Kubernetes quantities).
- `restartPolicy` — `Always` (default) | `OnFailure` | `Never`; `Never` marks a run-to-completion job.
- `securityContext` — `runAsUser`/`runAsGroup`/`runAsNonRoot`/`allowPrivilegeEscalation`/`capabilities.drop` (drop-only — capabilities can never be granted). Unset falls back to the image's own USER; the hardened floor always applies.
- `volumeMounts` — `[{ path, (pv | tmpfs) }]`, a discriminated union: each entry sets **exactly one** of `pv` (a `PersistentVolume` by name) or `tmpfs` (a `{ size? }` object — an ephemeral in-memory mount needing no PV).
- `values` — free-form horchestra-native config (no Pod analog).

`PersistentVolumeSpec` is `{ size, node, mode }` — `size` advisory, `node` the disk that backs it (note: PV uses `node`, `Application` uses `nodeName`), `mode` the directory's octal permission (default `0755`).

Input validation runs in the service: it decodes the request body to its typed value (rejecting malformed JSON) and runs the admission chain over that typed object. The Go types carry `jsonschema:"…"` tags (e.g. `minLength=1` on `image`/`nodeName`) for a planned reflection-generated input-schema layer, but that schema check is **not yet wired** — today the enforced invariants are the admission chain's (see below), not per-field schema validation.

```yaml
apiVersion: horchestra.io/v1
kind: PersistentVolume
metadata: { name: pg-data }
spec: { size: 10Gi, node: sav-01 }             # size advisory; node backs the volume on its disk
---
apiVersion: horchestra.io/v1
kind: Application
metadata: { name: pg }
spec:
  image: docker.io/library/postgres:18-alpine  # required
  nodeName: sav-01                             # required: the one node this app runs on
  restartPolicy: Always                        # Always (default) | OnFailure | Never
  resources: { requests: { cpu: 500m, memory: 256Mi }, limits: { cpu: "1", memory: 512Mi } }
  env: { POSTGRES_HOST_AUTH_METHOD: trust }    # plain config; secrets belong in a mounted file, not env
  ports: [ { name: postgres, port: 5432 } ]    # pure declaration for an external edge/LB
  volumeMounts:
    - { pv: pg-data, path: /var/lib/postgresql }   # PersistentVolume by name → mount path (must exist in the image)
    - { path: /run/postgresql, tmpfs: {} }         # ephemeral in-memory mount (no PV); tmpfs: { size: 64Mi } to cap
```

## kubectl

The server speaks enough of the Kubernetes API for `kubectl` to drive it: legacy `/api` and the `/apis` discovery documents, cluster-scoped resources with short names (`kubectl get app`), create/get/list/update/delete/watch and **PATCH** — JSON Merge Patch (`application/merge-patch+json`) and JSON Patch (`application/json-patch+json`); Strategic Merge Patch is **not** supported (any other patch type is `415`). `kubectl get` gets **server-side Table** columns (and prints "No resources found", not "…in default namespace", for these cluster-scoped kinds): `Application` → NAME/IMAGE/AGE, `Node` → NAME/STATUS/CPU/MEM/AGE (+ IP/OS with `-o wide`), `PersistentVolume` → NAME/SIZE/NODE/AGE, `RoleBinding` → NAME/ROLE/AGE, everything else NAME/AGE.

There is **no OpenAPI document** (no `/openapi/v3`), so `kubectl explain` does not work and — since kubectl cannot fetch a schema for client-side validation — **`kubectl apply`/`create` may need `--validate=false`**. Server-side apply is not implemented. Point kubectl at the `admin.conf` that `node-tool init` writes (a cluster-admin client config with CA and client cert/key embedded).

**`kubectl logs`.** The core group carries a read-only **`pods` alias of `Application`** (opt-in via `EmulatePodsAPI`, wired in the controller): `GET /api/v1/pods` lists every application as a Pod, `GET /api/v1/pods/<app>` projects one app into a one-container Pod (image = `spec.image`, `nodeName` = `spec.nodeName`, phase `Running`), and `GET /api/v1/pods/<app>/log` streams the logs. The controller resolves the app's `spec.nodeName`, opens a stream to that node **over the existing agent gRPC session** (no inbound port on the node), and the agent tails the app's unit with `journalctl -u horchestra-app-<app>`, forwarding chunks back; `--follow` (`?follow=true`) and `--tail` (`?tailLines=`) are honoured, and disconnecting stops the node-side stream. Without a log streamer wired, `pods/<app>/log` returns `503`.

```
node-tool init --host <controller-host>          # writes admin.conf (cluster-admin)
kubectl --kubeconfig pki/admin.conf get app
kubectl --kubeconfig pki/admin.conf apply --validate=false -f app.yaml
```

To mint a scoped kubeconfig for a different identity, `node-tool kubeconfig <cn> [--group g1,g2] [--server URL] [--out file]` issues a fresh client certificate (its CN/Organization become the request identity/groups) and emits a self-contained kubeconfig, defaulting to stdout. `--group system:masters` grants admin; drop it and bind a `Role`/`RoleBinding` for scoped access. The lower-level `node-tool cert <cn>` still issues a bare certificate pair.

## Agent (`horchestra agent`)

Linux only. The node-agent is a daemon (the kubelet analogue): it reconciles this node's applications against the controller's desired state. `horchestra install agent` writes the daemon's `systemd` unit (`ExecStart=horchestra agent`) and — unless `--enable=false` — enables and starts it via systemd over D-Bus; `horchestra agent` opens a **gRPC bidirectional session** to the controller (Transport, below) and reconciles off it.

Credentials come from `node.conf` — the node-side analogue of `controller.conf`, a single kubeconfig bundling the node's client certificate/key, the CA and the controller URL (kubelet's `kubelet.conf`), passed as `--auth-config`. `node-tool deploy` generates it and installs the agent with `--auth-config /etc/horchestra/node.conf`; the controller URL is validated at install time, so a bad address fails fast. The discrete `--controller`/`--cert`/`--key`/`--ca` flags remain as an alternative.

The agent reports its `status` up the session (on connect, on the `--heartbeat` interval — default `15s` — and after each apply), and the controller recreates its `Node` if it was deleted, so `kubectl delete node` self-heals on the next heartbeat. `status` carries a **`ready`** flag and a **`heartbeat`** timestamp, resource **capacity** — CPU and memory as Kubernetes quantities — reduced by any `--config` limit, plus OS and IP, and the **allocation** (the sum of the CPU/memory **requests** of the applications on the node). An application's `spec.resources` are also **enforced on the node via the unit's cgroup**: `requests.cpu`→`CPUWeight` (relative share), `requests.memory`→`MemoryLow` (reclaim protection), `limits.cpu`→`CPUQuota` (a hard %-of-a-core cap), `limits.memory`→`MemoryMax` (a hard cap — OOM-killed past it). Disk is **not** a compute resource — an application requests storage by mounting a `PersistentVolume`. `kubectl get nodes` shows **STATUS** (`Ready`/`NotReady`) and **CPU**/**MEM** as `allocated/capacity` (CPU in cores, memory in GiB — e.g. `2/8`, `0.5/7.8Gi`); `-o wide` adds **IP** and **OS**. Readiness is heartbeat-driven: a node is `Ready` only while its heartbeat is fresh (within `--node-ready-timeout`, default `45s`), so a stopped agent shows `NotReady` on its own. `--config` is a small YAML that caps advertised capacity (it can only reduce it, never inflate):

```yaml
resources: { cpu: "4", memory: 8Gi }   # advertise at most this much
```

Storage is a separate **`PersistentVolume`** resource with a lifecycle independent of any app: a directory on a node's disk (`<state-dir>/volumes/<pv-name>`, mode `0755` root-owned by default or the PV's octal `mode`), provisioned only by the node named in its `spec.node`, and bind-mounted (`BindPaths` + `ReadWritePaths`) into the app's otherwise read-only rootfs at the mount `path` (which must already exist in the image — a read-only overlay can't create a mountpoint). Deleting the `Application` leaves the volume and its data; deleting the `PersistentVolume` reclaims the data on the next reconcile. Reclamation is deliberately conservative: the agent records which volumes it provisioned in `<state-dir>/provisioned.json` and only reclaims those, only once no deployed app still mounts them, keeps a volume whose PV was merely reassigned to another node, and skips an empty PV list entirely (treated as possible controller state loss). A `tmpfs` volume mount is instead an ephemeral in-memory mount (systemd `TemporaryFileSystem=`) that needs no `PersistentVolume` — for paths holding nothing worth keeping (pid files, sockets) such as `/run`; an optional `size` caps it.

An `Application` is pinned to exactly one node through the **required `spec.nodeName`** field; the node-agent runs only the applications naming it. Two admission checks (part of the default chain `defaulting → appPolicy → nodeRestriction → nodeExists → capacityCheck`) guard it. **`spec.nodeName` must name an existing `Node`** — an app pinned to an unknown node is rejected `422 Invalid` (`spec.nodeName: node "a" does not exist`), regardless of requests. Then **capacity is enforced per node** — creating/updating an `Application` is rejected `403 Forbidden` if the sum of the effective CPU/memory requests of the applications on its `spec.nodeName` would exceed that node's reported capacity (a no-op while the node hasn't reported capacity, or when the app declares no requests). `appPolicy` additionally enforces `request ≤ limit` and that `runAsNonRoot` has a non-zero `runAsUser`.

```
horchestra install agent --auth-config node.conf [--config node.yaml]   # or: [--controller <url>] [--cert node.crt --key node.key --ca ca.crt]
horchestra agent         --auth-config node.conf [--config node.yaml] [--heartbeat 15s]   # or: [--controller …] [--cert … --key … --ca …] [--node <name>] [--state-dir <d>] [--unit-dir <d>]
horchestra purge         [--layout <oci-layout-dir>] [--exclude <ref> ...]
```

A node's client certificate carries the `system:nodes` group and a CN equal to the node name. Two layers gate what it may do, both configured for you at startup. First, RBAC: the controller **seeds a default `system:node` `Role`** (`create`/`get`/`update`/`patch` on `nodes`, `get`/`list`/`watch` on `applications` and `persistentvolumes`) bound to `Group: system:nodes`, so a node registers and reads its desired apps out of the box. Seeding is idempotent and runs on every startup — the `Role` is **upserted to the current rules** (so a permission added across an upgrade reaches an old cluster, and an ad-hoc edit is reverted), while the binding is only recreated if deleted (operator-added extra subjects are preserved). Second, **NodeRestriction** (in the default admission chain over the REST path) confines a `system:nodes` identity to writing only the single `Node` whose name equals its CN — any other GVK or another node's `Node` is `403`. It is a no-op for non-node identities. On the gRPC status path (which carries no HTTP identity) NodeRestriction is a no-op; instead the node-server enforces own-node confinement with an explicit check that the reported `Node`'s name equals the peer certificate CN. Under `--disable-auth` every caller is `system:masters` and nothing is restricted.

The node keeps **one shared oci-layout** for the whole host (`<state-dir>/images`), opened in **unpack mode** so layers are stored as unpacked directories ready to overlay-mount (not tar blobs); every application image is stored in it, tagged by its source, so common layers are **deduplicated across applications**. Each app gets its own read-only overlay mount (`<state-dir>/rootfs/<app>`) assembled from that layout. `pull` materialises the layout (in unpack mode); every read/probe path opens it with `Open` and never creates it, so probing an image before a pull can't leave behind a poison tar-mode layout. The layout is protected several ways: `oci-packer`'s cross-process advisory lock serialises pulls against a concurrent `purge`/delete; a second horchestra-owned lock (`<layout>/horchestra.lock`), held outer to it, stops a concurrent pull from re-freezing a blob between a delete's immutable-thaw and its removal; and the image config/manifest/index metadata blobs are made immutable (`FS_IMMUTABLE_FL`, best-effort) so they cannot be swapped out of band. Layer directories are left mutable-in-name (protected by permissions and the read-only overlay) so their exec bits survive. A multi-arch image is resolved to the **host platform only** — at pull *and* on spec read — so a manifest list doesn't drag every architecture's layers onto the node.

Reconcile is a **level-driven self-heal**, not an optimistic diff: the **controller is the single source of truth** for what should run, and the node's **own systemd units are the source of truth for what is running** (the agent keeps no persisted "deployed" record — it reads actual state from `Units.List`). Each app is _converged_ idempotently: ensure the image is present (`Images.Spec` first, pull only if that fails — a cached image needs no registry), write the unit if it differs (daemon-reload), and on a change stop + unmount and re-assemble the rootfs, mount it if not mounted, and start it if it changed or is not active. So a **reboot recovers on its own** — after `/run` (tmpfs) is wiped and the overlay mounts are gone, the enabled `horchestra-agent` unit restarts, reconnects, and re-converges every desired app from the images and volume data still on disk. Convergence runs on every desired-state push and on the heartbeat interval, so a unit that died or drifted is repaired without waiting for a change. App units are named `horchestra-app-<name>.service` and carry a hardened floor (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`) plus a `Restart=` derived from `restartPolicy` (`Always`→`always`, `OnFailure`→`on-failure`, `Never`→`oneshot`/`no`). An app whose spec changed is re-converged **in place** — its unit rewritten, the old unit stopped and its rootfs re-assembled, then restarted (nothing is deleted). A removed or reassigned app is instead fully torn down: stop, delete the unit file, unmount, and remove its rootfs. The shared layout is then garbage-collected down to the images still in use. One app's failure never blocks the others, teardown, or GC.

`horchestra purge` reclaims disk on a node: it lists the images in the shared layout and deletes every one whose ref name is not passed in `--exclude`, garbage-collecting layers no surviving image references (untagged entries are left untouched). A layer directory currently overlay-mounted under a running application is never removed; per-image failures are collected and skipped so the rest are still reclaimed.

### Transport (gRPC)

The controller↔agent link is a **gRPC bidirectional stream over mTLS**, not REST polling. It is defined in the single shared `api/pb` package (`proto/node.proto`, service `horchestra.node.v1.NodeService`, one method `Session`), served by `apiserver/nodeserver` and dialled by the agent. The controller serves gRPC and REST on **one TLS port**, dispatching by HTTP/2 + `application/grpc`; the agent opens one `Session` stream and reconnects with a fixed 5s backoff (the default port is `8443` when a URL omits it). It carries both directions:

- **down (controller → agent):** the node's desired state — the `Application`s whose `spec.nodeName` equals this node, plus **every** `PersistentVolume` (as JSON) — pushed on connect and re-pushed whenever an Application or PV changes (the controller watches storage). The node's identity is the mTLS peer certificate's CN, read on the server with no auth middleware of its own; the stream is refused (`PermissionDenied`) unless that certificate's Organization carries `system:nodes`.
- **up (agent → controller):** the node's `status` (on connect, on the `--heartbeat` interval, and after each apply) and log chunks. The status is persisted as the node's own `Node` object **through the service** (so defaulting and admission run), creating it if it was deleted; own-node confinement is enforced by the CN check described above.

When the controller pushes an Application the agent **pulls** it in-process into the shared layout (reusing `oci-packer`'s registry client — no external `oci-packer`/`skopeo` binary, and blobs already present are reused), **overlay-mounts** the layers read-only, renders a hardened application `systemd` unit from the image config, and starts it via systemd over D-Bus. Logging is `zerolog`.

## node-tool

Manages the local PKI and deploys the controller and the agent — both from the same `horchestra` binary, over an in-process SSH connection (`golang.org/x/crypto/ssh`; no `scp`/`ssh` binaries required — works from inside a container). Subcommands:

- `init` — creates the CA and controller serving certificate, and bundles them into `controller.conf` (the serving identity) and `admin.conf` (cluster-admin client, CN `admin` / group `system:masters`); also writes raw `ca.crt`/`ca.key`/`server.crt`/`server.key`.
- `cert <cn>` — issues a bare client certificate pair (its Organization = `--group`).
- `kubeconfig <cn>` — issues a client certificate and emits a self-contained kubeconfig for `kubectl` (CA + cert/key embedded).
- `deploy <node-addr>` — issues a node certificate (CN = node name, group `system:nodes`), writes `node.conf`, copies the binary to `/usr/local/bin/horchestra` and `node.conf` to `/etc/horchestra/node.conf`, and runs `horchestra install agent --auth-config /etc/horchestra/node.conf`.
- `deploy-controller <addr>` — issues a serving certificate for the address, writes `controller.conf` (and, unless `--admin-conf=false`, refreshes `admin.conf` so kubectl targets the new address), copies the binary to `/usr/local/bin/horchestra` and `controller.conf` to `/etc/horchestra/controller.conf`, and runs `horchestra install controller --auth-config … --db … --addr :8443`.

```
node-tool init  [--pki-dir pki] [--host <ip|dns> ...]
node-tool cert  <cn> [--group system:masters] [--out admin]
node-tool kubeconfig <cn> [--group g1,g2] [--server <url>] [--name horchestra] [--out file]
node-tool deploy <node-addr> [--node <name>] [--controller <url>] [--binary horchestra] [--user root] [--ssh-key <path>] [--sudo] [--sudo-pass <pw>]
node-tool deploy-controller <addr> [--binary horchestra] [--db <path>] [--admin-conf=false] [--user root] [--ssh-key <path>] [--sudo] [--sudo-pass <pw>]
```

`--node` sets the node name (its certificate CN/identity), defaulting to the address; `deploy`'s `--controller` defaults to the local address the node can reach back on (a warning is logged if that auto-selected address is in a different subnet, or is loopback the node cannot route to — pass `--controller` explicitly there, e.g. on a single-node host). TLS material is embedded in the `.conf` kubeconfig passed via `--auth-config`; there are no separate `--tls-*` flags on `install`. `sudo` is auto-enabled when `--user` is not `root`; its password comes from `--sudo-pass` / `HORCHESTRA_SUDO_PASS`, and with neither the tool probes the remote (`sudo -n`) and only prompts when a password is actually required and a terminal is attached — so passwordless-sudo hosts (CI) stay non-interactive.
