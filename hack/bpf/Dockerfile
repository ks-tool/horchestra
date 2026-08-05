# The BPF toolchain, in a container because it is not a Go toolchain.
#
# A BPF object is compiled by clang, against the kernel's UAPI headers and libbpf's macros — none of
# which a mac has, and none of which belong in a developer's PATH for the sake of one object file.
# Building it here means `make bpf` needs docker and nothing else, and that the compiler that
# produced the committed object is named and pinned rather than being whatever the person who last
# regenerated it happened to have installed.
#
# The object it produces is architecture-neutral: the datapath uses only fixed-width types and UAPI
# structs (struct bpf_sock_addr), never a kernel-internal layout or a PT_REGS macro, so an object
# built on an arm64 workstation is the object an amd64 node loads. BPF bytecode is JITed by the
# target kernel either way — what would make it arch-specific is the C, and this C is not.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libbpf-dev linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*
