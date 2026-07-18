#!/usr/bin/env sh
# Regenerate the node transport stubs from proto/node.proto into the shared
# api/pb package.
#
# NodeService is a bidirectional stream; protoc-gen-go-grpc emits both a client
# and a server into ONE package. The node agent uses the client, the control
# plane (apiserver) the server — both import the same generated package
# (github.com/ks-tool/horchestra/api/pb). One copy is required, not a convenience:
# two copies register the same node.proto (package/service/message names) in
# protobuf's global registry, so a single binary linking both — the `horchestra`
# monolith — panics at init.
#
# Requires protoc + protoc-gen-go + protoc-gen-go-grpc on PATH.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

pkg=api/pb
mkdir -p "$pkg"
protoc -I proto \
	--go_out="$pkg" --go_opt=paths=source_relative \
	--go-grpc_out="$pkg" --go-grpc_opt=paths=source_relative \
	node.proto
