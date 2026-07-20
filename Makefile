# horchestra build — multi-module Go workspace (see CLAUDE.md).
#
# cmd/horchestra builds in three modes, selected by build tag:
#   - default        -> horchestra: BOTH roles in one binary (the monolith).
#                       Linux = controller + agent; off-linux = controller only.
#   - controlleronly -> controller: control plane only, builds on ANY OS.
#   - agentonly      -> agent: node role only, linux only.
# agent and apiserver share one generated transport package (api/pb), so the
# monolith registers node.proto once instead of panicking on two copies.
# node-tool is the operator-side PKI/SSH deploy CLI, built for the host platform.
# Everything resolves only under the workspace (go.work) — build/test per module.

GO      ?= go
BIN     ?= bin
# OS/ARCH: target platform for the deployable binaries (controller builds on any
# OS; the monolith is controller-only off-linux; agent is always linux).
OS      ?= linux
ARCH    ?= amd64
# LDFLAGS: strip debug info by default; pass LDFLAGS= for a debug build.
LDFLAGS ?= -s -w
GCFLAGS ?= -N -l

.DEFAULT_GOAL := build

.PHONY: build all horchestra controller agent node-tool \
	test test-api test-apiserver test-agent test-root \
	lint vet fmt proto work-sync fix-workspace clean help

## build: the monolith + operator CLI (single-binary deploy)
build: horchestra node-tool

## all: every binary — monolith, split controller/agent, and node-tool
all: horchestra controller agent node-tool

## horchestra: one binary with BOTH roles (linux; controller-only off-linux)
horchestra: | $(BIN)
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) $(GO) build -ldflags '$(LDFLAGS)' -gcflags '$(GCFLAGS)' -trimpath -o $(BIN)/horchestra ./cmd/horchestra

## controller: controller-only binary (-tags controlleronly; builds on any OS)
controller: | $(BIN)
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) $(GO) build -tags controlleronly -ldflags '$(LDFLAGS)' -gcflags '$(GCFLAGS)' -trimpath -o $(BIN)/horchestra-controller ./cmd/horchestra

## agent: node-only binary (-tags agentonly; linux only)
agent: | $(BIN)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -tags agentonly -ldflags '$(LDFLAGS)' -gcflags '$(GCFLAGS)' -trimpath -o $(BIN)/horchestra-agent ./cmd/horchestra

## node-tool: host-platform PKI/SSH deploy CLI -> bin/node-tool
node-tool: | $(BIN)
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -gcflags '$(GCFLAGS)' -trimpath -o $(BIN)/node-tool ./cmd/node-tool

$(BIN):
	@mkdir -p $(BIN)

## test: per-module tests (whole-workspace `go test ./...` spans modules)
test: test-api test-apiserver test-agent test-scheduler test-root
test-api:
	cd api && $(GO) test ./...
test-apiserver:
	cd apiserver && $(GO) test ./... -race
test-agent:
	cd agent && $(GO) test ./...
test-scheduler:
	cd scheduler && $(GO) test ./...
test-root:
	$(GO) test ./...

## lint: gofmt check + go vet (per module)
lint: vet
	@out="$$(gofmt -l api apiserver agent scheduler cmd pkg)"; \
	if [ -n "$$out" ]; then echo "gofmt needs formatting:"; echo "$$out"; exit 1; fi; \
	echo "gofmt: clean"

## vet: go vet each module
vet:
	$(GO) vet ./...
	cd api && $(GO) vet ./...
	cd apiserver && $(GO) vet ./...
	cd agent && $(GO) vet ./...
	cd scheduler && $(GO) vet ./...

## fmt: gofmt -w the live modules
fmt:
	gofmt -w api apiserver agent scheduler cmd pkg

## proto: regenerate the shared node gRPC stubs into api/pb
proto:
	sh proto/gen.sh

## work-sync: refresh indirect requires + go.sum across modules
work-sync:
	$(GO) work sync

## fix-workspace: drop intra-workspace replaces the IDE mirrors into go.mod (they belong only in go.work; see CLAUDE.md)
fix-workspace:
	@for f in go.mod agent/go.mod api/go.mod apiserver/go.mod; do \
		for m in agent api apiserver; do \
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
