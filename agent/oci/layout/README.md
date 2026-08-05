# oci-layouts

Downloads an image from a remote container registry into a local OCI layout and unpacks each layer into a directory,
ready to be stacked with overlayfs. It is what `oci-packer copy --unpack` does — without oci-packer, and without a
registry library: the registry v2 API is a handful of GETs, and the only dependencies are the OCI type definitions and
`golang.org/x/sys`.

```sh
oci-layouts postgres:18-alpine /var/lib/layers
oci-layouts -platform linux/arm64 -j 8 ghcr.io/team/app:v1 /var/lib/layers
oci-layouts -owner 999 -u user:token registry.example.com/team/app@sha256:… /var/lib/layers
```

Linux only. The source is entirely behind `//go:build linux`, on purpose: a whiteout is a `mknod`
and an opaque directory is a `trusted.overlay.*` xattr, so a build for any other OS could only produce a binary that
writes silently wrong layer trees.

```sh
make                      # -> bin/oci-layouts (cross-compiles from a mac)
make test                 # natively on linux, otherwise in a golang container
go install github.com/ks-tool/oci-layouts@latest
```

## What it writes

An ordinary OCI layout, with one difference — a layer blob is an unpacked **directory** rather than a tar:

```
/var/lib/layers
├── oci-layout
├── index.json                     # artifactType: application/vnd.oci.layout.blobs.unpack
└── blobs/sha256/
    ├── 3a1b…                      # the manifest, as received
    ├── 7f2c…                      # the image config, as received
    ├── c0ff…/                     # a layer, unpacked
    └── bada…/                     # a layer, unpacked
```

The `artifactType` on `index.json` is oci-packer's marker (`MediaTypeUnpackLayout`), and writing it is what makes the
output interchangeable with oci-packer's — and what lets a consumer refuse a layout of plain tars instead of stacking
them as if they were trees.

A layout holds as many images as have been copied into it; they share whatever layers they have in common, since a layer
directory is named by its content digest. Re-running over an existing layout skips the layers already there and replaces
only the `index.json` entry for that ref name.

A successful run prints the lower stack it just wrote — the layers in reverse manifest order, since overlayfs takes the
topmost first:

```sh
mount -t overlay overlay -o lowerdir=<top>:…:<base>,ro /mnt
```

## Whiteouts, and why this tool exists

An image layer records a deletion the AUFS way: a file named `.wh.<name>` for a deleted path, and
`.wh..wh..opq` inside a directory that hides the lower layers' version of itself entirely. **overlayfs understands
neither.** It reads a deletion as a character device `0:0` and an opaque directory as the `trusted.overlay.opaque`
xattr.

Unpacking without translating the two produces a stack that looks right and is wrong: deleted files come back, replaced
directories show both versions, and stray `.wh.*` files appear in the mount. That is what `oci-packer copy --unpack`
currently does — it passes `WhiteoutFormat: -1` to
`moby/go-archive`, which installs no converter, so `.wh.*` entries land as ordinary empty files.

|                              | `oci-layouts`        | `oci-packer --unpack`          |
|------------------------------|----------------------|--------------------------------|
| a file the top layer deleted | absent               | **present, old content**       |
| an opaque directory          | only the new entries | **new and old entries merged** |
| `.wh.*` files in the mount   | none                 | **present**                    |

Translating them is also why the unpack needs privilege — see below. Nothing else here does.

## Privilege

`mknod` for a character device needs **CAP_MKNOD**, and the `trusted.*` xattr namespace needs **CAP_SYS_ADMIN**, both in
the initial user namespace. So the unpack runs as root:

```sh
sudo oci-layouts alpine:3.21 /var/lib/layers
```

An image whose layers delete nothing unpacks fine as an ordinary user. One that does fails immediately, with a message
naming the capability — it is not retried, because a fourth download will not change what this machine allows.

This is the privileged half of a division of labour: root prepares the layers once, and a rootless runtime only mounts
them. Nothing at mount time needs privilege.

### The layout cannot live on an overlayfs

Privilege is not the only thing that can refuse a whiteout — the destination filesystem can too, and
`--privileged` does not help:

```
$ docker run --rm --privileged alpine mknod /tmp/wh c 0 0
mknod: /tmp/wh: Operation not permitted
```

overlayfs refuses to create device nodes at all, and rejects `trusted.overlay.*` on its own files. So an unpack run
inside a container must write to a **volume**, not to the container's own filesystem. The error says which of the two it
hit, and checks the capability rather than the uid before blaming privilege — root in a plain container holds CAP_MKNOD
but not CAP_SYS_ADMIN, so
"operation not permitted" means different things a few lines apart.

**Ownership is the opposite of a faithful restore.** The layer's own uid/gid are discarded unless
`-owner` says otherwise. A rootless consumer maps a single host id into its user namespace, so anything owned by another
id appears inside as the overflow uid (65534) — restoring root ownership faithfully is what makes an image unreadable to
a rootless workload, not what makes it correct. Use
`-owner uid[:gid]` to hand the whole tree to the id that will run it.

## Flags

| flag        | default                         |                                                                 |
|-------------|---------------------------------|-----------------------------------------------------------------|
| `-platform` | `linux/<host arch>`             | which manifest to take from a multi-platform index              |
| `-owner`    | —                               | `uid[:gid]` to chown the unpacked tree to                       |
| `-name`     | the repository and tag as given | the ref name stored in `index.json`                             |
| `-u`        | the docker CLI's `config.json`  | `user:password`                                                 |
| `-insecure` | off                             | talk plain HTTP                                                 |
| `-j`        | 4                               | layers fetched and unpacked at once                             |
| `-retries`  | 3                               | extra attempts for a request or a layer that fails retryably    |
| `-qps`      | 20                              | cap on requests per second (0 for no cap)                       |
| `-timeout`  | 30s                             | how long one request may take to produce its response *headers* |

`-j` and `-qps` are separate knobs because a registry's rate limit is per client, not per connection: `-j` bounds how
many layers are in flight, `-qps` bounds how hard the API is hit.

`-timeout` deliberately bounds the response headers rather than the whole exchange — a layer body takes as long as the
layer is big, and a client-wide timeout would kill large images on slow links.

Retries are exponential with jitter (0.5s, doubling, capped at 30s), floored by the server's own
`Retry-After` when it sends one. `408`, `429`, `500`, `502`, `503` and `504` are retried; everything else is not. A
`401` mid-pull is an expired token, not a refusal: it is answered again and does not consume an attempt. The retry unit
for a layer is the whole layer, because the body is extracted as it streams — once bytes have gone into the tar reader
there is no resuming, only starting over.

## What it deliberately does not do

- **Credential helpers.** Only the plain `auth` entry in `config.json` is read. Honouring
  `credsStore` would mean executing whatever the config names.
- **zstd layers.** They need a compressor outside the standard library. The tool says so instead of guessing.
- **Pushing, deleting, converting.** It copies one image, one way.
- **Restoring a layer's uid/gid** without being asked — see above.

Layers land in a temporary directory beside their final home and are renamed into place only after the digest verifies,
so an interrupted run leaves a layout holding only whole layers. `index.json`
is written last, so a failed run describes nothing.
