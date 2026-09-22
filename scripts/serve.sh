#!/usr/bin/env bash
# Runs the service in a container with the port published, for manual probing.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then HOSTPATH="$(cygpath -w "$ROOT")"; else HOSTPATH="$ROOT"; fi
MSYS_NO_PATHCONV=1 exec docker run --rm --name pdguard-dev -p 8080:8080 \
  -v "${HOSTPATH}:/src" -v pdguard-gocache:/root/.cache/go-build -v pdguard-gomod:/go/pkg/mod \
  -w /src golang:1.25-alpine go run ./cmd/server/ -addr :8080 "$@"
