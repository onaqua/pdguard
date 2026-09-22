#!/usr/bin/env bash
# The host has no Go toolchain; everything runs inside a golang:1.25 image.
# Named volumes keep the build and module caches warm between invocations.
#
#   bash scripts/go.sh build ./...
#   bash scripts/go.sh test ./... -count=1
#   bash scripts/go.sh test ./... -count=1 -race
#   bash scripts/go.sh vet ./...
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then
  HOSTPATH="$(cygpath -w "$ROOT")"
else
  HOSTPATH="$ROOT"
fi

# The race detector needs cgo, and cgo needs a C toolchain that the alpine
# image does not ship. Rather than fail on "-race requires cgo", switch to the
# Debian-based image for those runs only: it carries gcc, so -race works with
# no apk install and no network. Everything else keeps using the small alpine
# image. The two images get separate build-cache volumes because their
# toolchain/libc differ; the module cache is identical and stays shared.
IMAGE="golang:1.25-alpine"
CACHE="pdguard-gocache"
CGO=0
for arg in "$@"; do
  if [ "$arg" = "-race" ] || [ "$arg" = "--race" ]; then
    IMAGE="golang:1.25"
    CACHE="pdguard-gocache-race"
    CGO=1
    break
  fi
done

MSYS_NO_PATHCONV=1 exec docker run --rm \
  -v "${HOSTPATH}:/src" \
  -v "${CACHE}:/root/.cache/go-build" \
  -v pdguard-gomod:/go/pkg/mod \
  -e GOFLAGS=-mod=mod \
  -e "CGO_ENABLED=${CGO}" \
  -w /src "${IMAGE}" go "$@"
