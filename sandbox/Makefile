# sandbox build.
#
# Two binaries from one package: sandbox, and sandbox-strict, which refuses a
# config that takes syscalls back out of the seccomp denylist (see README).
# Everything is behind `//go:build linux`, so OS defaults to linux and a bare
# `make` cross-compiles the deployable binaries even from a mac. The tools under
# hack/ are the exception — they run where you develop, so they build for the
# host platform.

GO      ?= go
BIN     ?= bin
# OS/ARCH: the platform the sandbox binaries are built FOR. Only linux is a
# valid OS; ARCH must be one the seccomp filter has a table for (amd64, arm64),
# since sandbox refuses to start without one.
OS      ?= linux
ARCH    ?= amd64
# LDFLAGS: strip debug info by default; pass LDFLAGS= for a debug build.
LDFLAGS ?= -s -w
# IMAGE: the container `make test` uses off-linux.
IMAGE   ?= golang:1.26-alpine

GO_BUILD  := CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) $(GO) build -ldflags '$(LDFLAGS)' -trimpath

.DEFAULT_GOAL := build

.PHONY: build sandbox sandbox-strict probe generate \
	test test-docker lint vet fmt install-apparmor clean help

## build: both sandbox binaries (OS/ARCH, default linux/amd64)
build: sandbox sandbox-strict

## sandbox: the sandbox binary -> bin/sandbox
sandbox: OS=linux
sandbox: | $(BIN)
	@$(GO_BUILD) -o $(BIN)/sandbox ./cmd/sandbox

## sandbox-strict: the build that refuses Seccomp.Allow -> bin/sandbox-strict
sandbox-strict: OS=linux
sandbox-strict: | $(BIN)
	@$(GO_BUILD) -o $(BIN)/sandbox-strict ./cmd/sandbox-strict

## probe: in-sandbox self-check, injected as an extra layer -> bin/probe
probe: OS=linux
probe: | $(BIN)
	@$(GO_BUILD) -o $(BIN)/probe ./hack/probe

$(BIN):
	@mkdir -p $(BIN)

## generate: regenerate syscalls.go from x/sys/unix (after bumping it)
generate:
	$(GO) run ./hack/gensyscalls

## test: the tests — natively on linux, in an IMAGE container elsewhere
test:
	@if [ "$$($(GO) env GOHOSTOS)" = linux ]; then \
		$(GO) test ./...; \
	else \
		echo "host is not linux; running the tests in $(IMAGE)"; \
		$(MAKE) test-docker; \
	fi

## test-docker: the tests inside the IMAGE container, whatever the host is
test-docker:
	docker run --rm -v "$(CURDIR)":/src -w /src $(IMAGE) go test ./...

## lint: gofmt check + go vet
lint: vet
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needs formatting:"; echo "$$out"; exit 1; fi; \
	echo "gofmt: clean"

## vet: go vet both modules (GOOS=OS, since the sandbox is linux-only source)
vet:
	GOOS=$(OS) $(GO) vet ./...

## fmt: gofmt -w the tree
fmt:
	gofmt -w .

## install-apparmor: install the userns profile (Ubuntu 24.04+; needs root)
install-apparmor:
	install -Dm 0644 apparmor/sandbox /etc/apparmor.d/sandbox
	@echo "installed; load it with: systemctl reload apparmor"
	@echo "it attaches to /usr/local/bin — edit the profile if the binaries live elsewhere"

## clean: remove build output
clean:
	rm -rf $(BIN)

## help: list targets
help:
	@grep -hE '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
