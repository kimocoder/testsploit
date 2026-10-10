#!/usr/bin/env bash
# Build the Go env-scanner binary.
# Output: monitor/go-scanner/bin/env-scanner
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin
# CGO_ENABLED=0 keeps the binary fully static; -ldflags trims symbols.
CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o bin/env-scanner .
echo "[build] $(pwd)/bin/env-scanner"
