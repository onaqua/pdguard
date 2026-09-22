#!/usr/bin/env bash
# End-to-end load run without a Go toolchain on the host.
#
# The host cannot execute the Linux binaries the golang image produces, and the
# bench has to talk to the server over real HTTP, so both processes live inside
# one container: the server is started in the background, the bench runs
# against 127.0.0.1, and the container exits when the bench is done.
#
#   bash scripts/bench-local.sh                       # the default ladder
#   bash scripts/bench-local.sh -rps 2000 -duration 30s -concurrency 256
#
# With arguments, a single bench run is performed with exactly those flags.
# Without arguments, the ladder below is run: 200, 1000 and 2000 requests per
# second, plus one JSON run for machine consumption.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then
  HOSTPATH="$(cygpath -w "$ROOT")"
else
  HOSTPATH="$ROOT"
fi

if [ "$#" -gt 0 ]; then
  RUNS="/tmp/bench -url http://127.0.0.1:8080/process $*"
else
  RUNS='
/tmp/bench -url http://127.0.0.1:8080/process -rps 200  -duration 10s -warmup 2s -concurrency 32
/tmp/bench -url http://127.0.0.1:8080/process -rps 1000 -duration 15s -warmup 3s -concurrency 128
/tmp/bench -url http://127.0.0.1:8080/process -rps 2000 -duration 15s -warmup 3s -concurrency 256
/tmp/bench -url http://127.0.0.1:8080/process -rps 1000 -duration 5s  -warmup 1s -concurrency 128 -json
'
fi

# The server is told to log errors only: an info line per request would make the
# container's stdout, not the masking, the bottleneck at 2000 RPS.
INNER="
set -e
cd /src
go build -o /tmp/server ./cmd/server
go build -o /tmp/bench  ./cmd/bench
echo '--- binaries built ---'
PDGUARD_LOG_LEVEL=error /tmp/server -addr 127.0.0.1:8080 &
SRV=\$!
ready=0
for i in \$(seq 1 80); do
  if wget -q -O /dev/null http://127.0.0.1:8080/ready 2>/dev/null; then ready=1; break; fi
  sleep 0.25
done
if [ \"\$ready\" != '1' ]; then echo 'SERVER DID NOT BECOME READY'; kill \$SRV || true; exit 1; fi
echo \"--- server ready, nproc=\$(nproc) ---\"
${RUNS}
echo '--- /stats ---'
wget -q -O - http://127.0.0.1:8080/stats || true
echo
kill \$SRV || true
wait \$SRV 2>/dev/null || true
"

MSYS_NO_PATHCONV=1 exec docker run --rm \
  -v "${HOSTPATH}:/src" \
  -v pdguard-gocache:/root/.cache/go-build \
  -v pdguard-gomod:/go/pkg/mod \
  -e GOFLAGS=-mod=mod \
  -e CGO_ENABLED=0 \
  -w /src golang:1.25-alpine sh -c "$INNER"
