#!/usr/bin/env bash
# Build the Go host-discover binary.
# Output: monitor/go-discover/bin/host-discover
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin
CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o bin/host-discover .
echo "[build] $(pwd)/bin/host-discover"
