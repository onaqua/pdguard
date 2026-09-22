#!/usr/bin/env bash
# Per-file syntax check that does not require sibling files to be complete —
# useful while several authors write into the same package concurrently.
#   bash scripts/gofmt.sh -l -e internal/pd/detect/fio.go
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then HOSTPATH="$(cygpath -w "$ROOT")"; else HOSTPATH="$ROOT"; fi
MSYS_NO_PATHCONV=1 exec docker run --rm -v "${HOSTPATH}:/src" -w /src golang:1.25-alpine gofmt "$@"
