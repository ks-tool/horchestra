# horchestra build — multi-module Go workspace (see CLAUDE.md).
#
# cmd/horchestra builds in three modes, selected by build tag:
#   - default        -> horchestra: BOTH roles in one binary (the monolith).
#                       Linux = controller + agent; off-linux = controller only.
#   - controlleronly -> controller: control plane only, builds on ANY OS.
#   - agentonly      -> agent: node role only, linux only.
# agent and controller share one generated transport package (api/node), so the
# monolith registers node.proto once instead of panicking on two copies.
# node-tool is the operator-side PKI/SSH deploy CLI, built for the host platform.
# Everything resolves only under the workspace (go.work) — build/test per module.

GO      ?= go
BIN     ?= bin
ARCH    ?= amd64
# LDFLAGS: strip debug info by default; pass LDFLAGS= for a debug build.
LDFLAGS ?= -s -w
GCFLAGS ?= -N -l

GO_BUILD := GOEXPERIMENT=jsonv2 CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -gcflags '$(GCFLAGS)' -trimpath

.DEFAULT_GOAL := build

.PHONY: build all horchestra controller agent netd node-tool sandbox oci-layouts genconfig \
	test test-api test-controller test-agent test-root test-linux \
	lint vet fmt proto bpf comments work-sync fix-workspace clean help

## build: the node binary + operator CLI
build: horchestra controller node-tool

## all: every binary — the node binary, the controller, the by-hand tools and node-tool
all: horchestra controller oci-layouts genconfig node-tool

## horchestra: the NODE binary — agent, netd and sandbox in one file (linux only)
##
## Three roles, one build, because they are one deployment: the agent writes a unit that ExecStarts
## the sandbox and speaks a typed protocol to netd, so a node running mixed versions of them is a
## node running a bug. They stay three PROCESSES at three privileges — systemd draws that line, not
## the linker. The `horchestra-*` aliases are argv[0] symlinks, made on the node by node-tool.
horchestra: | $(BIN)
	# Build horchestra node binary ...
	@GOOS=linux GOARCH=$(ARCH) $(GO_BUILD) -o $(BIN)/horchestra ./cmd/horchestra

## controller: the control plane, its own binary — builds on any OS
##
## Separate from the node binary on purpose, and it is what lets the sandbox be a subcommand: a
## workload's supervisor path must not exec anything that serves clients or holds the store.
controller: | $(BIN)
	# Build controller binary ...
	@$(GO_BUILD) -o $(BIN)/horchestra-controller ./cmd/controller

## oci-layouts: CLI over agent/oci/layout — pull an image into an unpacked OCI layout (linux only)
oci-layouts: | $(BIN)
	# Build oci-layouts binary ...
	@GOOS=linux GOARCH=$(ARCH) $(GO_BUILD) -o $(BIN)/oci-layouts ./cmd/oci-layouts

## genconfig: render a sandbox config from an unpacked OCI layout (linux only)
genconfig: | $(BIN)
	# Build genconfig binary ...
	@GOOS=linux GOARCH=$(ARCH) $(GO_BUILD) -o $(BIN)/genconfig ./cmd/genconfig

## node-tool: host-platform PKI/SSH deploy CLI -> bin/node-tool
node-tool: | $(BIN)
	# Build node-tool binary ...
	@$(GO_BUILD) -o $(BIN)/node-tool ./cmd/node-tool

$(BIN):
	@mkdir -p $(BIN)

## test: per-module tests (whole-workspace `go test ./...` spans modules)
test: test-api test-controller test-agent test-root test-hack
test-api:
	cd api && $(GO) test ./...
test-controller:
	cd controller && $(GO) test ./... -race
# The agent module is LINUX ONLY — it drives systemd, D-Bus, overlayfs, user namespaces and
# mknod/xattr, and it is never run anywhere else, so nothing in it carries a portability stub.
# A darwin host therefore cannot RUN its tests; it type-checks them (vet compiles test files
# too) and `make test-linux` or a linux box runs them for real.
test-agent:
	cd agent && GOOS=linux GOARCH=$(ARCH) $(GO) vet ./...
	cd netd && GOOS=linux GOARCH=$(ARCH) $(GO) vet ./...
	cd sandbox && GOOS=linux GOARCH=$(ARCH) $(GO) vet ./...
# hack/ is outside the workspace, so `./...` never reaches it and its tests were never run by
# anything. What they cover is which checkout linuxtest mounts and which gates it can run there —
# decided before a container exists, and wrong three times because nothing checked it.
test-hack:
	cd hack && $(GO) test ./...
test-root:
	$(GO) test ./...
# netd's own tests are linux-only save one: that the committed BPF objects were compiled from the
# committed C. That one needs no kernel and must run on the machine where the .c is edited.
	cd netd && $(GO) test ./...

# test-linux drives hack/linuxtest (testcontainers): the same gofmt/vet/test gates,
# run inside a linux container as the CALLING uid. Half the tree is behind
# `//go:build linux` — the systemd unit renderer and installers, the OCI image store,
# node-tool's file and SSH trust rules — so a darwin `make test` never sees it, and
# the ownership/symlink refusals those tests assert are vacuous for root. The hack
# module is outside go.work (GOWORK=off) so testcontainers and the Docker client stay
# out of the shipped modules' dependency graphs. LINUXTEST_FLAGS passes flags
# through: -image, -race=false, -only, -keep, -timeout (see hack/linuxtest).
LINUXTEST_FLAGS ?=

## test-linux: the gates inside a linux container via testcontainers (LINUXTEST_FLAGS=...)
test-linux:
	cd hack && $(GO) run ./linuxtest $(LINUXTEST_FLAGS)

## lint: gofmt check + go vet (per module)
lint: vet
	@out="$$(gofmt -l api controller agent netd sandbox cmd pkg)"; \
	if [ -n "$$out" ]; then echo "gofmt needs formatting:"; echo "$$out"; exit 1; fi; \
	echo "gofmt: clean"

## vet: go vet each module
vet:
	$(GO) vet ./...
	cd api && $(GO) vet ./...
	cd controller && $(GO) vet ./...
	cd agent && GOOS=linux GOARCH=$(ARCH) $(GO) vet ./...   # linux-only module (see test-agent)
	cd netd && GOOS=linux GOARCH=$(ARCH) $(GO) vet ./...    # linux-only module (netlink, netns, BPF)
	cd sandbox && GOOS=linux GOARCH=$(ARCH) $(GO) vet ./... # linux-only module (namespaces, seccomp)

## fmt: gofmt -w the live modules
fmt:
	gofmt -w api controller agent netd sandbox cmd pkg

## proto: regenerate the shared node gRPC stubs into api/node
proto:
	sh proto/gen.sh

# bpf compiles the datapath's eBPF objects with clang, in a container (hack/bpf/Dockerfile) so a
# workstation needs no BPF toolchain at all. The OBJECT IS COMMITTED — netd embeds it, so an
# ordinary `make` and every `go build` stay toolchain-free, and this target is only run when the C
# changes. -g is not optional: the map definitions live in the object's BTF, and without it the
# loader finds a .maps section it cannot read.
BPF_IMAGE ?= horchestra-bpf
BPF_DIR   := netd/bpf
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -mcpu=v3

## bpf: recompile the datapath's eBPF objects in a container (needs docker; the objects are committed)
bpf:
	docker build -q -t $(BPF_IMAGE) hack/bpf
	docker run --rm -u $$(id -u):$$(id -g) -v $(CURDIR)/$(BPF_DIR):/src -w /src $(BPF_IMAGE) \
		sh -c 'for c in *.bpf.c; do clang $(BPF_CFLAGS) -I/usr/include/$$(uname -m)-linux-gnu -c $$c -o $${c%.c}.o || exit 1; \
			sha256sum $$c > $${c%.c}.sha256 || exit 1; done'
	@echo "$(BPF_DIR)/*.bpf.o rebuilt — commit them"

## comments: re-extract the API doc comments into the published schemas (kubectl explain)
comments:
	cd api && $(GO) run ./internal/gencomments

## work-sync: refresh indirect requires + go.sum across modules
work-sync:
	$(GO) work sync

## fix-workspace: drop intra-workspace replaces the IDE mirrors into go.mod (they belong only in go.work; see CLAUDE.md)
fix-workspace:
	@for f in go.mod agent/go.mod api/go.mod controller/go.mod; do \
		for m in agent api controller; do \
			$(GO) mod edit -dropreplace=github.com/ks-tool/horchestra/$$m@v0.0.0 $$f; \
		done; \
	done
	@echo "dropped intra-workspace go.mod replaces (kept in go.work)"

## clean: remove build output
clean:
	rm -rf $(BIN)

## help: list targets
help:
	@grep -hE '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
