# horchestra

> **⚠️ Alpha version.** Not production-ready. APIs, configuration formats and behaviour change without
> notice.

**A control plane for running containerised applications on a fleet of ordinary Linux hosts — without running
Kubernetes.**

You describe what should run; horchestra makes it so. Applications are declared as objects, applied with
`kubectl`, and end up as hardened `systemd` units started from OCI images. There is no cluster to bootstrap, no etcd, no
container daemon, and nothing on a node that runs as root without a reason you can name.

## Who it is for

Fleets in the awkward middle: more hosts than you want to configure by hand, fewer than justify Kubernetes and the team
it needs. A dozen machines running an application and its dependencies. Edge sites. A product shipped as "some Linux
boxes" into somebody else's datacentre.

If you already run Kubernetes and it fits, keep running it. horchestra is for when the operational surface costs more
than the orchestration is worth.

## What it does differently

**systemd supervises workloads, not a daemon of ours.** A workload is a transient `systemd` unit. It keeps running while
the agent restarts, is upgraded, or crashes — the agent converges state, it does not babysit processes. There is no
container runtime daemon on the node at all.

**Nothing privileged runs by default.** The agent holds no capabilities and enters its own user namespace
unconditionally. Workloads run rootless, in namespaces of their own, from a read-only overlay root, under a seccomp
filter with an empty capability bounding set. The one privileged component is a small network helper that exists
precisely so the agent can hold nothing.

**The API is Kubernetes-flavoured; the model is not.** `kubectl` works — discovery, `explain`, tables, logs, RBAC —
because it is a good client and everyone already has it. But there are no pods, no kubelet, no CNI plugins and no CRDs:
an Application *is* the unit of work, and its schema is the Go type.

**One flat network, no per-node address ranges.** Workload addresses come from a single fleet-wide range, and an eBPF
datapath answers "which host holds this address" from a map rather than from a routing table. Service addresses are
translated at the socket, before a packet exists — so there is no per-flow state anywhere and no return path to rewrite.

**Secrets stay in memory.** A resolved secret reaches a workload through RAM-backed carriers and its process
environment. It is never written into the unit file, never to disk, and never readable over the message bus.

## What it looks like

One file describes a fleet, two commands stand it up:

```yaml
# node-tool.yaml
apiVersion: node-tool.horchestra.io/v1
kind: Inventory
ssh:
  user: deploy
nodes:
  - addr: 10.0.0.1
    role: controller
    binaries: [ ./bin/horchestra-controller ]
  - addr: 10.0.0.2
    role: agent
    netd: true
    binaries: [ ./bin/horchestra ]
```

```console
$ node-tool init --local-pki --controller 10.0.0.1 --agent 10.0.0.2
$ node-tool apply -f node-tool.yaml
```

From there it is `kubectl`:

```yaml
apiVersion: horchestra.io/v1
kind: Application
metadata:
  name: web
  namespace: default
spec:
  image: docker.io/library/nginx:alpine
  ports:
    - name: http
      port: 8080
```

```console
$ kubectl apply -f web.yaml
$ kubectl get app -o wide
NAME   IMAGE                            STATUS    NODE       IP           AGE
web    docker.io/library/nginx:alpine   Running   10.0.0.2   10.244.0.1   12s
$ kubectl logs web
```

## What ships

|                         |                                                                                                    |
|-------------------------|----------------------------------------------------------------------------------------------------|
| `horchestra`            | the node — agent, network helper and workload sandbox in one binary: three units, three privileges |
| `horchestra-controller` | the control plane — API, scheduler, store                                                          |
| `node-tool`             | the operator's CLI — the fleet's PKI, and `apply -f` for the fleet itself                          |

Build with `make`; `make help` lists every target. The deployable binaries are Linux-only; the operator's tools build
anywhere.

## Licence

**AGPL-3.0-or-later** ([`LICENSE`](LICENSE)) — with one deliberate exception: the eBPF datapath sources
`netd/bpf/*.bpf.c` and the objects compiled from them are **GPL-2.0**. The kernel's verifier refuses
`gpl_only` helpers to a program that declares anything else, so the licence there is a technical requirement rather than
a preference. [`LICENSING.md`](LICENSING.md) has the reasoning, the scope, and the test that keeps it true.
