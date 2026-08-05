# Licensing

This repository carries **two** licences, and the split is deliberate.

| What                                                                       | Licence                                                           |
|----------------------------------------------------------------------------|-------------------------------------------------------------------|
| Everything, unless listed below                                            | **AGPL-3.0-or-later** (see [`LICENSE`](LICENSE))                  |
| `netd/bpf/*.bpf.c` and the objects compiled from them (`netd/bpf/*.bpf.o`) | **GPL-2.0** ([SPDX](https://spdx.org/licenses/GPL-2.0-only.html)) |

Every file states its own licence in an `SPDX-License-Identifier` header, which is the authority; this document explains
the split rather than defining it.

## Why the datapath is GPL-2.0

Not preference — the kernel's BPF verifier. A BPF program carries a licence string, and helpers the kernel marks
`gpl_only` are **refused at load** unless that string is GPL-compatible. The refusal is not subtle:

```
cannot call GPL-restricted function from non-GPL compatible program
```

Measured on a live kernel, twice, at real cost:

- **`bpf_fib_lookup`** — the helper that answers "which interface and which neighbour reach that node". Under a non-GPL
  string the forwarder would not load at all, so the egress interface was supplied from userspace instead. (It is still
  supplied from userspace, for an unrelated reason — see the note on `struct workload` in `netd/bpf/fwd.bpf.c`.)
- **`bpf_trace_printk`** — unavailable entirely, so the one debugging session that needed to ask the program what it was
  doing had to build a counter map instead.

Declaring GPL-2.0 on those two files buys the whole helper table for the datapath and changes nothing else in the tree.

## Why the two coexist

The BPF objects are **data** in the Go program: embedded with `go:embed`, handed to the kernel, and executed by the
kernel as programs of their own. They are not linked into the Go binary as code. This is the same arrangement Cilium
ships (Apache-2.0 Go, GPL-2.0 BPF), and it is why an AGPL-3.0 program can carry them.

That reasoning is about **these** files and this mechanism. It does not extend to linking GPL-2.0 code into the Go
binary proper, which would be a different question with a different answer. Nothing in the tree does that today, and the
guard below is what keeps the statement above checkable rather than remembered.

## Keeping it true

`TestTheDatapathIsGPL` (in `netd`) reads every `netd/bpf/*.bpf.c` and requires both marks: the SPDX header and the
`_license[]` string the verifier actually reads. A new datapath source that carries neither would silently lose every
`gpl_only` helper — and would make this document wrong — so the test fails instead.
