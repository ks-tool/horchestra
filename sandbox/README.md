# sandbox

Runs a workload in a **read-only** overlayfs root assembled from prepared layer directories, in **rootless** namespaces,
with an unprivileged id, an emptied capability bounding set and a seccomp filter. Its only dependency is
`golang.org/x/sys`.

Division of labour: `oci-layouts` downloads images and unpacks layers into an
OCI layout; **sandbox** only mounts and runs. It is the `ExecStart=` stage of a systemd unit — the caller prepares the unit, the layer
directories, the state dir and the secrets; sandbox enforces the config and ends in the workload's `execve`. It cleans
up nothing: every mount lives in a private mount namespace that dies with the unit's cgroup.

## Layout

| File                | Purpose                                                             |
|---------------------|---------------------------------------------------------------------|
| `cmd/`              | the two binaries: `sandbox` and `sandbox-strict`                    |
| `cli.go`            | `Main` (flags, exit codes) and `Run` (stage dispatch)               |
| `config.go`         | the `Config` contract, its validation and the load options          |
| `path.go`           | the `lowerdir` string, the escape check, mount ordering             |
| `userns.go`         | stage 1 — clone into fresh namespaces with an id map                |
| `sandbox.go`        | stage 2 — assemble the rootfs, `pivot_root`, `execve`               |
| `mount.go`          | the individual mounts: overlay, tmpfs, `/dev`, `/proc`, `/sys`      |
| `privileges.go`     | the privilege drop immediately before `exec`                        |
| `seccomp.go`        | the syscall filter: building the BPF program and installing it      |
| `syscalls.go`       | generated per-architecture syscall name tables (`hack/gensyscalls`) |
| `hack/probe/`       | in-sandbox self-check, injected as an extra layer                   |

Everything is `//go:build linux` — the program is meaningful only on Linux, and on any other OS the build fails honestly
with "build constraints exclude all Go files" rather than producing a stub that pretends to work.

## Build and test

```sh
go build ./cmd/...                       # on Linux, both binaries
GOOS=linux GOARCH=amd64 go build ./cmd/sandbox   # cross-compile from anywhere

go test ./...                    # on Linux
docker run --rm -v "$PWD":/src -w /src golang:1.26 go test ./...   # in a container
GOOS=linux go vet ./...          # type-check from another OS, without running
```

The tests cover what decides security questions and needs no kernel: config parsing and validation, layer direction in
the `lowerdir` string, the symlink escape check, and the whole seccomp denylist (`seccomp_test.go` runs the BPF program
through an interpreter that mirrors the kernel). An architecture table that quietly stopped filtering is exactly the
failure they exist to catch.

## Usage

```sh
# layers are prepared by oci-layouts (an unpacked oci-layout)
oci-layouts registry.example.com/team/app:v1 /var/lib/layers

sandbox --config /etc/sandbox/myapp.json
```

`genconfig` renders the config below from an unpacked layout, taking argv, environment, working directory and stop
signal from the image itself. It lives in the horchestra tree (`cmd/genconfig`) rather than here, so that it can emit
`sandbox.Config` itself instead of a struct shaped like it — the sandbox decodes with `DisallowUnknownFields`, so a
field added on one side and missed on the other is a config refused at run time, and sharing the type makes that a
compile error instead:

```sh
genconfig -uid 999 -state-dir /var/lib/pg \
    /var/lib/layers library/postgres:18-alpine > /etc/sandbox/pg.json
```

The config (JSON, the fields of `sandbox.Config`):

```json
{
  "LowerDirs": [
    "/var/lib/layers/blobs/sha256/aaa...",
    "/var/lib/layers/blobs/sha256/bbb..."
  ],
  "Merged": "/run/user/1000/myapp/rootfs",
  "InitDir": "/var/lib/myapp/init",
  "Command": [
    "/usr/bin/app",
    "--serve"
  ],
  "Env": [
    "LANG=C.UTF-8"
  ],
  "WorkingDir": "/srv",
  "Hostname": "myapp",
  "TmpfsMounts": [
    {
      "Path": "/tmp",
      "Size": "512m",
      "Inodes": "4k"
    },
    {
      "Path": "/run"
    }
  ],
  "UID": 1000,
  "GID": 1000,
  "SecretEnvDir": "/run/user/1000/myapp/secrets",
  "StopSignal": "SIGINT",
  "Network": "none",
  "Rlimits": {
    "NOFILE": {
      "Soft": 1024,
      "Hard": 4096
    },
    "CORE": {
      "Soft": 0,
      "Hard": 0
    }
  },
  "Seccomp": {
    "Allow": [
      "ptrace"
    ],
    "Deny": [
      "listen"
    ]
  }
}
```

- **LowerDirs** — absolute paths to the layer directories, **bottom to top**
  (manifest order): the unpacked image layers plus any extra caller-supplied layer.
- **UID / GID** — required, and must **not** be 0: see the security model.
- **SecretEnvDir** — a directory holding secrets in rootfs layout (`etc/environment` and the like), added as the
  **topmost** layer so its files shadow the image's. It must be on tmpfs — secrets are refused from disk.
- **InitDir** — the directory the mount-point skeleton tmpfs is mounted on (`/dev`, `/proc`, `/sys`, `WorkingDir`, every
  `TmpfsMounts` entry). It is added as the **bottommost** layer, so mount points and the working directory exist even in
  images that ship neither, while nothing in the image is shadowed. Keep it inside the workload's state dir: the success
  path ends in
  `execve`, so nothing here cleans it up.
- **TmpfsMounts** are mounted parents-first, so a volume at `/run/state` is not masked by a `/run` mounted after it.
  `/tmp` and `/var/tmp` come up `mode=1777`, `/run` `mode=0755`. **Size** caps one, in the kernel's own spelling — a
  byte count with an optional k/m/g suffix, or a percentage of RAM (`512m`, `50%`). Left empty the kernel's default
  applies, which is half the host's RAM *per mount*: bounded in practice only by the unit's `MemoryMax`, where a runaway
  write costs the workload an OOM kill instead of the `ENOSPC` it asked for. **Inodes** is a separate bound, not a
  consequence of the first: an empty file occupies no blocks, so a million of them fit inside any `size=` at all, while
  each costs about a kilobyte of unswappable kernel memory. It takes a count with an optional k/m/g suffix (`4k`) — no
  percentage, which tmpfs accepts for size alone. A malformed value of either is refused with the config rather than
  surfacing as a bare `EINVAL` from inside the trampoline.
- **StopSignal** — the image config's stop signal (a name or a number). Stage 1 forwards every signal to the workload
  verbatim (HUP reloads nginx, USR1 rotates logs); only the two generic stop signals are translated — a received SIGTERM
  or SIGINT leaves as `StopSignal`, which for postgres is SIGINT, its fast shutdown. Empty forwards those two as
  received.
- **Seccomp** — adjusts the built-in denylist for this workload; see below.
- **Network** — `host` (the default) or `none`. See the security model: it is the one isolation left off by default.
- **Rlimits** — per-process limits keyed by systemd's `Limit*` names without the prefix, each with a `Soft` and a
  `Hard` value (a number, or `"infinity"`). They bound what a cgroup limit cannot, since a cgroup's is shared by
  everything in it, and they are the only such knob for a caller that writes the config but not the unit. Only
  *lowering* works: raising a hard limit takes `CAP_SYS_RESOURCE` in the initial user namespace, which no rootless
  sandbox has, so a value above what the unit passed down is refused with the config and names the `Limit*=` that would
  grant it. Two things to know: `NPROC` is counted by the kernel per *real uid*, so with this sandbox's single id
  mapping it bounds the invoking user's processes across the host rather than this workload's (`TasksMax` is the
  per-workload bound) — and a Go workload raises its own `NOFILE` soft limit to the hard one at startup, so for those
  the hard value is the one that bites.

## systemd

`systemd/sandbox@.service` is a unit template, one instance per workload; a calling manager that renders its own units
should still read it, since every directive in it is annotated with why it is there.

```sh
install -Dm644 systemd/sandbox@.service ~/.config/systemd/user/sandbox@.service
loginctl enable-linger "$USER"          # so the workload survives logout and reboot
systemctl --user daemon-reload
systemctl --user enable --now sandbox@myapp
journalctl --user -u sandbox@myapp -f
```

The instance name selects the config (`%E/sandbox/%i.json`: `~/.config` for a
`--user` unit, `/etc` for a system one).

`KillMode=mixed` is load-bearing. The manager stops a unit with its generic
`KillSignal`, and sandbox translates that into the workload's `StopSignal`, so the signal has to reach stage 1 alone.
Under `control-group` the workload receives the untranslated signal too, and which of the two it acts on comes down to
their numbers — pending signals are delivered lowest-first — and to whether its handler exits before the other arrives.

The hardening directives are a second line: sandbox drops all of that itself before the workload starts, and setting
them on the unit means a misconfigured or replaced binary still cannot hand out more than the unit allows. What must
*not* be added is systemd's mount-based sandboxing (`ProtectSystem=`,
`PrivateTmp=` and friends) — it is applied before sandbox clones its own mount namespace, and a read-only `/` stops it
from creating the directories it assembles the rootfs in.

**The workload has to handle whatever signal it is stopped with.** It runs as PID 1 of its own PID namespace, and the
kernel silently discards a signal sent there from outside unless the process installed a handler for it — the default
action never applies to a namespace's init. A workload with no handler therefore ignores the stop entirely: systemd
waits out `TimeoutStopSec` and then SIGKILLs the cgroup. That is what `StopSignal` is for, and why a mismatch shows up
as a 30-second stop rather than an error (observed exactly that way: without `StopSignal` a shell trapping only INT sat
through the whole timeout, and with it the same workload stopped in under a second).

`RestrictNamespaces=` must list `net` for a workload configured with `"Network": "none"`. The directive is itself a
seccomp filter on `clone`, so a set that omits `net` refuses the namespace and the sandbox stops at
`fork/exec /proc/self/exe: operation not permitted`. Listing it costs the workload nothing: the sandbox's own filter
denies it every `CLONE_NEW*` regardless.

Per-workload limits belong in a drop-in (`systemctl --user edit sandbox@myapp`). They reach the workload with no help
from the sandbox — its processes are the unit's processes, already in its cgroup — but two things decide whether they
bite:

**`MemoryMax` is not a memory ceiling on a host with swap.** The workload is throttled into swapping rather than killed.
Measured: a 300 MiB allocation under `MemoryMax=48M` peaked at 48M of RAM and 258M of *swap*, and ran to completion;
adding `MemorySwapMax=0` turned the same run into `Result=oom-kill`.

**A limit whose controller is not delegated is accepted and then does nothing.** For a `--user` unit the defaults differ
by version — systemd 258 delegates `cpu memory pids`, older ones only `memory pids` — and `io`/`cpuset` always need a
system-wide drop-in:

```ini
# /etc/systemd/system/user@.service.d/delegate.conf   (root; cpuset needs systemd >= 244)
[Service]
Delegate=cpu cpuset io memory pids
```

```sh
cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers
```

## Security model

**The root is immutable.** `MS_RDONLY|MS_NOSUID|MS_NODEV` are set by the same syscall that creates the overlay mount —
there is no window in which the mount is live without them. Only the tmpfs mounts from `TmpfsMounts` (also
`nosuid,nodev`), `/dev` and `/dev/shm` are writable. Every mount target is checked with `ensureWithin`: a symlink inside
the image cannot steer a mount onto the host.

**Rootless isolation.** Fresh user, mount, pid, uts and ipc namespaces with the single mapping
`UID/GID (inside) ← the invoking user (outside)` — no other host identity exists inside. The root is entered by
`pivot_root` with the old root detached (`MNT_DETACH`): no path or file descriptor leads back to the host filesystem.
`/proc` is a fresh procfs of the sandbox's own pid namespace.

**The network namespace is the one isolation left off by default**, and `"Network": "none"` turns it on. Sharing the
host's network is not only about addresses: the workload reaches every service on the host's loopback, binds host ports
(any the invoking user may bind — all of them, on a host that set `net.ipv4.ip_unprivileged_port_start=0`, as the
rootless guides suggest), and reaches every **abstract** unix socket there. Abstract sockets are scoped to the network
namespace rather than the filesystem, which makes them precisely the thing `pivot_root` and the detached old root cannot
take away. With `none` the workload gets a namespace holding a loopback interface and nothing else — sandbox raises `lo`
itself, since the kernel creates it DOWN and the workload will have no `CAP_NET_ADMIN` to raise it later.

`/sys` follows from that choice: the kernel allows mounting sysfs in a user namespace only when it owns a network
namespace too, so `none` gets a real read-only sysfs, while the host-network default gets an empty read-only tmpfs —
never a bind of the host's.

**Capabilities live in the ambient set, and are dropped before `execve`.** The clone gives stage 1's child a full
namespaced capability set, but that set does not survive stage 2's own `execve`: with a non-zero uid — root is never
mapped here — the kernel recalculates every set to exactly the *ambient* set. Stage 2 therefore carries `CAP_SYS_ADMIN`
(to mount and pivot) and `CAP_SETPCAP` (to empty the bounding set) across in the ambient set. `dropPrivileges` then, in
order: sets `NO_NEW_PRIVS`, empties the capability bounding set, clears the ambient set — which would otherwise ride
into the workload's `execve` the same way — empties the inheritable set the ambient mechanism had to populate — installs
the seccomp filter, and re-asserts the non-root uid/gid. The workload starts with every capability set empty, which is
why a root identity is refused in the config.

**A pristine signal table.** An ignored signal disposition survives both fork and `execve` — bash backgrounds children
with INT and QUIT at `SIG_IGN` — and a POSIX shell refuses to trap a signal that was ignored on entry. Since delivering
a signal to a pid-namespace init from outside requires exactly that handler, an inherited `SIG_IGN` would make the stop
signal undeliverable. Stage 2 takes every catchable signal over before `execve`, which resets each of them to its
default (`execve` preserves only `SIG_IGN`).

**Thread pinning.** `NO_NEW_PRIVS`, the bounding set and seccomp are per- *thread*
attributes that survive `execve`, so stage 2 holds `runtime.LockOSThread()` from its first instruction through
`syscall.Exec`. Without it the Go scheduler may move the goroutine to another thread, and the workload would start
without any of them — silently.

**The config** is decoded with `DisallowUnknownFields`, requires absolute paths, and refuses `:` and `,` in layer paths
(they separate entries in the `lowerdir`
string).

**Layer integrity is the puller's job.** Verify digests at delivery time; sandbox trusts the directories in `LowerDirs`
exactly as far as the caller does.

## The seccomp filter

A pure-Go classic-BPF program installed with `prctl(PR_SET_SECCOMP)` — no libseccomp, no cgo. It is a **denylist**:
syscalls are allowed by default and the entries below are refused with EPERM (the action Docker's default profile uses,
so a workload degrades instead of dying on SIGSYS). On an architecture with no table sandbox **refuses to start** rather
than running unfiltered.

The filter is what keeps the read-only root read-only. An emptied bounding set and a non-root id do not by themselves
stop a workload from calling
`unshare(CLONE_NEWUSER)`, holding a full `CAP_SYS_ADMIN` in a namespace of its own and mounting a writable tmpfs over
any path. Denying the namespace and mount syscalls is what closes that door.

Denying them buys a second thing, and it is the reason to keep the denial even where the mount escape would not matter.
Unprivileged user namespaces are the kernel's most vulnerability-prone interface — they hand ordinary users code paths
that used to require root, and the rootless-container community says so plainly ("the user namespace implementation in
the kernel tends to have vulnerabilities"). This sandbox needs exactly one of them, created before the workload exists;
the workload itself never needs to create another, so the syscalls that would let it reach that surface are refused
rather than trusted.

`clone` cannot be denied outright — the Go runtime and every threading libc create threads with it — so it is allowed
unless it requests a new namespace.
`clone3` answers ENOSYS, which makes libc fall back to the `clone` that *is*
filtered; its flags live behind a pointer seccomp cannot read. A foreign ABI — the `arch` field mismatching — is denied
outright: the numbers below would otherwise mean something else entirely.

So is **every syscall number above the highest one the build knows**, which is the ceiling that closes a denylist at the
top. Without it a syscall added by a later kernel would be allowed by default, precisely because nobody had yet decided
about it — the one structural advantage an allowlist has. The ceiling comes from the generated table in `syscalls.go`,
so `make generate` is what raises it, and the same comparison catches an x32 call on x86_64: that ABI keeps
`AUDIT_ARCH_X86_64` and ORs `0x40000000` into the number, landing far above any real one.

| Syscall                                                                                                                 | Why it is denied                                                                                                                        |
|-------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `mount`, `umount2`, `pivot_root`, `mount_setattr`, `move_mount`, `open_tree`, `fsopen`, `fsconfig`, `fsmount`, `fspick` | mounting over the read-only root, by every syscall that can                                                                             |
| `unshare`, `setns`, `clone(CLONE_NEW*)`                                                                                 | a namespace of one's own is a full `CAP_SYS_ADMIN` and, with it, the mount family again — and it is the kernel's most CVE-prone surface |
| `chroot`                                                                                                                | the classic companion to a mount escape                                                                                                 |
| `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `pidfd_getfd`, `process_madvise`                             | reaching into another process' memory, fds or identity                                                                                  |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register`                                                                 | a large kernel surface whose operations run on kernel worker threads, historically outside the submitter's own filter                   |
| `bpf`, `perf_event_open`, `userfaultfd`                                                                                 | kernel-programmable surfaces and a page-fault handler in userspace                                                                      |
| `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `reboot`                               | replacing or rebooting the kernel the sandbox depends on                                                                                |
| `add_key`, `request_key`, `keyctl`                                                                                      | the kernel keyring, which is not namespaced by user namespaces                                                                          |
| `syslog`                                                                                                                | the kernel ring buffer — readable without any capability when `kernel.dmesg_restrict=0`                                                 |
| `open_by_handle_at`, `fanotify_init`                                                                                    | reaching a file by handle rather than by path; filesystem-wide notification                                                             |
| `iopl`, `ioperm` (amd64)                                                                                                | direct port I/O                                                                                                                         |
| `swapon`, `swapoff`, `quotactl`, `quotactl_fd`, `acct`, `vhangup`, `lookup_dcookie`                                     | host-wide storage, accounting and tty administration                                                                                    |
| `settimeofday`, `clock_settime`                                                                                         | the host clock, which is not namespaced                                                                                                 |
| `sethostname`, `setdomainname`                                                                                          | the sandbox's own identity, set once before the filter is installed                                                                     |
| `personality`                                                                                                           | switching execution domains, a known exploit-mitigation bypass                                                                          |
| `mbind`, `set_mempolicy`, `get_mempolicy`, `set_mempolicy_home_node`, `move_pages`                                      | host-wide NUMA placement                                                                                                                |

Everything in that table is also denied by Docker's default profile for a process with no capabilities. The differences
run the other way: sandbox additionally denies `ptrace`, `process_vm_readv/writev` and `personality`
outright (Docker allows them), and refuses any foreign ABI instead of mapping sub-architectures. The direction of the
two filters still differs — one names what is allowed, the other what is not — but the practical consequence of that, a
future kernel's syscall arriving unjudged, is closed here by the ceiling above.

### Custom policies

`Seccomp` adjusts the built-in list for one workload. Entries are syscall names or decimal numbers, resolved against the
running architecture's table:

```json
"Seccomp": {
  "Deny": [
    "listen",
    "accept",
    "accept4"
  ],
  "Allow": [
    "ptrace"
  ]
}
```

- **Deny** adds syscalls, refused with EPERM like the built-in ones.
- **Allow** takes syscalls *out* of the built-in denylist — the escape hatch for a workload that genuinely needs one
  (`ptrace` for a debugger, `io_uring` for a database). It weakens the sandbox: every entry in the table above is there
  for the reason next to it. A syscall named in both lists ends up allowed.

The filter is built when the config is loaded, so an unknown syscall name is a refusal to start, not a workload running
under a filter quietly missing a rule.
`clone` and `clone3` cannot appear in a policy — they are branches of the program, not denylist entries. The denylist is
capped at 250 entries, the furthest a classic-BPF 8-bit jump can reach.

The name tables in `syscalls.go` are generated from `x/sys/unix`; regenerate them after bumping that dependency:

```sh
go run ./hack/gensyscalls
```

### The strict build

`sandbox-strict` is the same command, refusing a config that relaxes a protection or leaves a bound unset:

- **`Seccomp.Allow`** — the field that takes syscalls back out of the denylist. `Deny` keeps working: strict bounds what
  a config may weaken, not what it may tighten.
- **a `TmpfsMount` missing either bound** — `Size`, or the `Inodes` that `size=` does not imply. Both default to a share
  of the host's RAM.

Install it where no workload may do either, whatever its config says.

```sh
go build ./cmd/sandbox-strict
sandbox-strict --config /etc/sandbox/myapp.json
```

The distinction is a separate binary rather than a flag or a config field, and deliberately so: a switch travelling with
the config would be set by the same party the strict build exists to bound, and a flag in `ExecStart=` is one drop-in
away from being dropped. Which binary is installed is the node operator's decision, visible in the unit and in `ps`.

## Verifying a sandbox

`hack/probe` reports the confinement as the workload experiences it, rather than as the config describes it. It is
injected as an extra overlay layer, so any real rootfs can be inspected without being rebuilt:

```sh
make probe                                              # -> bin/probe, for the target platform
install -Dm755 bin/probe /var/lib/probe/usr/local/bin/probe
# then append "/var/lib/probe" to LowerDirs and set Command to ["/usr/local/bin/probe", "caps"]
```

| Subcommand           | Answers                                                                    |
|----------------------|----------------------------------------------------------------------------|
| `caps`               | are all five capability sets empty, is NO_NEW_PRIVS on, is a filter loaded |
| `syscall <nr>...`    | EPERM (the filter refused) vs ENOSYS (the kernel never had it)             |
| `net [addr] [@name]` | is a host loopback port or abstract socket reachable                       |
| `mem <MiB>`          | does `MemoryMax` stop an allocation, or does it merely swap                |
| `files <dir> [max]`  | where the `Inodes` cap actually bites                                      |
| `write <path>...`    | which paths are read-only and which are the writable tmpfs                 |
| `rlimits`            | the per-process limits as the workload has them                            |
| `exec <cmd> [args]`  | runs any command under this confinement and names what stopped it          |

`exec` keeps one config usable for every ad-hoc check — `["/usr/local/bin/probe", "exec", "sh", "-c", "…"]` — and turns
the two verdicts a unit gives you into a specific one: it distinguishes a missing binary from a missing dynamic loader
from a `noexec` mount, and reports a fatal signal by name with the wall it came from (`SIGKILL` → `MemoryMax` or
`systemctl stop`, `SIGXCPU` → `RLIMIT_CPU`). It forks rather than replacing itself so it can report at all, and forwards
the caller's signals to the command, so `systemctl stop` still reaches it.

Entering a *running* sandbox from outside is deliberately not here: `setns(2)` refuses `CLONE_NEWUSER` from a
multithreaded process, and joining the mount namespace additionally needs `CAP_SYS_ADMIN` in the caller's own user
namespace — neither is reachable from a `CGO_ENABLED=0` Go binary, which is why runc carries `nsexec.c`. Use `nsenter`
instead, against the sandbox's CHILD:

```sh
inner=$(pgrep -P "$(systemctl show -p MainPID --value the-unit.service)" | head -1)
nsenter -t "$inner" -U -m -p -i -u --preserve-credentials -- <cmd>
```

Not `MainPID` itself: stage 1 stays in the host's namespaces to fork stage 2 and wait for it (so systemd sees one main
process for the workload's lifetime), and `nsenter -U` against it fails with `EINVAL` — it is being asked to join the
user namespace it is already in. `-r` is not needed; entering the mount namespace already lands in the workload's root.

It earns its place: the `caps` check is what found a non-empty inheritable set left behind by the ambient-capability
mechanism, which is now cleared before exec.

## Host prerequisites

Creating an unprivileged user namespace is a host policy decision, and every distribution expresses it differently.
Sandbox reads those settings back when a clone is refused and names the one that explains it, so the failure says what
to change rather than `operation not permitted`.

**Ubuntu 24.04 and later** ship `kernel.apparmor_restrict_unprivileged_userns=1`, which stops an unconfined process from
creating a user namespace at all — sandbox fails at
`fork/exec /proc/self/exe: operation not permitted` before it does anything else. Install the profile that grants it:

```sh
sudo make install-apparmor      # -> /etc/apparmor.d/sandbox
sudo systemctl reload apparmor
```

The profile attaches to `/usr/local/bin/sandbox` and `/usr/local/bin/sandbox-strict`; edit the paths if the binaries
live elsewhere, or it silently never applies. It is `flags=(unconfined)`
with a single `userns` grant on purpose: the sandbox's confinement is its own namespaces, capability drop and syscall
filter, and an AppArmor policy layered on top would have to be maintained against every image a workload runs. The blunt
alternative,
`kernel.apparmor_restrict_unprivileged_userns=0`, lifts the restriction for every program on the host instead of these
two.

Two older gates exist elsewhere and are reported the same way:
`kernel.unprivileged_userns_clone=1` is needed on older Debian and Arch, and
`user.max_user_namespaces` was shipped at zero on RHEL/CentOS 7.

## Deliberate limitations

- Linux only, kernel ≥ 5.11 (rootless overlayfs in a user namespace), with unprivileged user namespaces enabled.
- Networking is the host's by default, or none at all (`"Network": "none"`); there is nothing in between, since a
  translated network would mean slirp4netns or pasta and a second process to supervise. Put `resolv.conf` and other
  etc-files in `SecretEnvDir` or a layer of their own if needed.
- One id mapping: layer files owned by other (subordinate) uids are readable only through their world bits. Layers
  unpacked rootless by the same user do not have this problem.
- The layer directories have to be on a filesystem overlayfs will take as a lowerdir, which rules out NFS, FUSE, CIFS
  and FAT, and another overlayfs without `index=on`. A layout on one of those fails the mount with `EINVAL`, and the fix
  belongs where the layout lives rather than here. NFS has a second problem besides: its support for a user-namespaced
  `CAP_DAC_OVERRIDE` is not sufficient for rootless use.
- `setgroups` is permanently denied by the kernel for this namespace (the precondition for writing an unprivileged gid
  map), so the supplementary group set can never be widened — strictly stronger than calling `setgroups` would be.
