# pdguard — multi-stage image.
#
# The build needs no network access after the sources are copied. pdguard has
# zero external dependencies (standard library only, go.mod lists no require
# block), so there is nothing to fetch and `go mod download` would be a no-op.
# To make that a guarantee rather than a hope, the builder sets GOPROXY=off and
# GOFLAGS=-mod=mod: if anyone ever adds a dependency, the build fails loudly
# here instead of silently reaching out to a proxy on the judges' machine.
# GOTOOLCHAIN=local pins the same rule for the toolchain itself — a bumped `go`
# directive in go.mod must not trigger a toolchain download.

# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
FROM golang:1.25-alpine AS builder

# VERSION is stamped into the binary via -ldflags; it shows up in /health,
# /stats and the pdguard_build_info metric, which is how a judge tells two
# demo containers apart.
ARG VERSION=dev

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOPROXY=off \
    GOFLAGS=-mod=mod \
    GOTOOLCHAIN=local

WORKDIR /src

# go.mod is copied first so that the (empty) dependency graph is its own layer:
# editing Go sources does not invalidate it.
COPY go.mod ./

COPY cmd ./cmd
COPY internal ./internal

# -s -w drop the symbol table and DWARF data, which is roughly a third of the
# binary; -trimpath removes the build machine's paths so the image is
# reproducible and leaks no local directory names.
RUN go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION} -X pdguard/internal/metrics.Version=${VERSION}" \
        -o /out/pdguard ./cmd/server

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
# alpine:3 rather than scratch, on purpose. The binary is fully static
# (CGO_ENABLED=0) and would run on scratch, but Docker's HEALTHCHECK executes
# its command *inside* the container, and scratch has no executable to run one
# with. A ~8 MB busybox base buys a working healthcheck, a shell for `docker
# exec` during the demo, and the ca-certificates bundle — worth more here than
# the few megabytes saved.
FROM alpine:3 AS runtime

ARG VERSION=dev

LABEL org.opencontainers.image.title="pdguard" \
      org.opencontainers.image.description="Personal-data masking proxy for LLM requests" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/alfabank-hackathon/pdguard"

# ca-certificates is not needed by pdguard itself (it makes no outbound calls),
# but an operator who fronts it with a sidecar or curls out of the container
# expects a sane trust store. wget comes from busybox and is what HEALTHCHECK
# uses below.
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 -S pdguard \
    && adduser -u 10001 -S -G pdguard -H -s /sbin/nologin pdguard

WORKDIR /app

COPY --from=builder /out/pdguard /app/pdguard

# The default configuration is baked in so the image runs standalone; a
# docker-compose bind mount over /app/configs overrides it without a rebuild.
COPY --chown=root:root configs /app/configs

# Nothing in /app needs to be writable: the store is in memory and the logs go
# to stdout. Running as a non-root user with a read-only root filesystem (see
# docker-compose.yml) is therefore free.
USER 10001:10001

ENV PDGUARD_ADDR=":8080" \
    PDGUARD_CONFIG="/app/configs/config.json" \
    PDGUARD_LOG_FORMAT="json" \
    PDGUARD_LOG_LEVEL="info"

EXPOSE 8080

# /health is liveness only — it never checks a dependency, so a healthy process
# with a degraded dictionary still reports healthy instead of being restarted
# into the same state. start-period is short because pdguard binds in
# milliseconds; there is nothing to warm up.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/app/pdguard"]
