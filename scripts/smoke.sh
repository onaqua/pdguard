#!/usr/bin/env bash
# End-to-end contract check for pdguard.
#
# It exercises the only thing the graders actually run: POST /process twice
# with the same payload_id — first to mask, then to unmask — and verifies that
# the second answer is byte-for-byte the text we started with. A service that
# masks beautifully but cannot restore scores zero, so this is the single check
# that must never be skipped before a submission.
#
#   bash scripts/smoke.sh                       # build + start via docker compose, test, stop
#   bash scripts/smoke.sh --keep                # leave the stack running afterwards
#   PDGUARD_URL=http://localhost:8080 bash scripts/smoke.sh   # test an already-running service
#
# Dependencies: bash, curl, and the usual coreutils. No jq: the response is a
# one-field JSON object and the probe text below deliberately contains no
# double quote and no backslash, so a sed extraction is exact rather than
# approximate.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Every compose invocation below is path-free on purpose: on git bash a
# "-f /c/..." argument is rewritten into a Windows path that docker cannot
# open, so the working directory does the addressing instead.
cd "$ROOT" || exit 2

PORT="${PDGUARD_PORT:-8080}"
URL="${PDGUARD_URL:-}"
KEEP=0
STARTED=0
COMPOSE=()

for arg in "$@"; do
  case "$arg" in
  --keep) KEEP=1 ;;
  -h | --help)
    sed -n '2,20p' "${BASH_SOURCE[0]}"
    exit 0
    ;;
  *)
    echo "unknown argument: $arg" >&2
    exit 2
    ;;
  esac
done

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }

fail() {
  red "FAIL: $*"
  cleanup
  exit 1
}

cleanup() {
  if [ "$STARTED" = "1" ] && [ "$KEEP" = "0" ]; then
    info "stopping the stack"
    "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
# Bring the service up
# ---------------------------------------------------------------------------
if [ -z "$URL" ]; then
  # `docker compose` (v2 plugin) is the normal case; the old `docker-compose`
  # binary is accepted so the script still works on an older laptop.
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    echo "docker compose not found; start the service yourself and set PDGUARD_URL" >&2
    exit 2
  fi

  echo "==> building and starting pdguard"
  if ! "${COMPOSE[@]}" up -d --build pdguard; then
    fail "docker compose up failed"
  fi
  STARTED=1
  URL="http://127.0.0.1:${PORT}"
fi

# ---------------------------------------------------------------------------
# Wait for /health
# ---------------------------------------------------------------------------
echo "==> waiting for ${URL}/health"
ready=0
for _ in $(seq 1 60); do
  if curl -fsS -m 2 "${URL}/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[ "$ready" = "1" ] || fail "service did not become healthy within 60s at ${URL}/health"
info "healthy"

# ---------------------------------------------------------------------------
# The probe text
# ---------------------------------------------------------------------------
# One sentence per PD family the specification names, plus deliberate
# false-positive bait: a poet's name and a branch address are not client
# personal data and must survive untouched. No quotes or backslashes — see the
# note about sed above.
ORIGINAL='Клиент Иванов Иван Иванович, паспорт 4509 123456, карта 4276 3800 1234 5679, телефон +7 916 123-45-67, почта ivanov.ivan@example.com. Читал Александра Пушкина в отделении банка на улице Вавилова, дом 19.'
PAYLOAD_ID="smoke-$(date +%s)-$$"

BODY_FILE="$(mktemp -t pdguard-smoke.XXXXXX)"
trap 'rm -f "$BODY_FILE"' EXIT

# curl reads the file itself, and on git bash that is a Windows process which
# cannot open an MSYS path such as /tmp/pdguard-smoke.ab12cd. cygpath exists
# only there, so on Linux and macOS this leaves the path untouched.
if command -v cygpath >/dev/null 2>&1; then
  BODY_ARG="$(cygpath -w "$BODY_FILE")"
else
  BODY_ARG="$BODY_FILE"
fi

# post <payload_id> <payload> — prints the "result" field, or exits non-zero.
#
# The request body travels through a file rather than a --data argument. On git
# bash curl is a native Windows executable, and the MSYS layer re-encodes
# command-line arguments into the system code page — which silently destroys
# Cyrillic before it reaches the socket. The service then sees mojibake and
# correctly masks nothing, so the test fails for a reason that has nothing to
# do with the service. A shell redirection is byte-exact; the file route is the
# only portable one.
post() {
  local id="$1" text="$2" resp
  # printf, not a heredoc: a heredoc appends a newline that would end up inside
  # the payload we later compare byte for byte.
  printf '{"payload":"%s","payload_id":"%s"}' "$text" "$id" >"$BODY_FILE"
  resp=$(curl -fsS -m 10 -X POST "${URL}/process" \
    -H 'Content-Type: application/json; charset=utf-8' \
    --data-binary "@${BODY_ARG}") || return 1
  printf '%s' "$resp" | tr -d '\r\n' | sed -n 's/.*"result":"\(.*\)".*/\1/p'
}

# ---------------------------------------------------------------------------
# 1. Mask
# ---------------------------------------------------------------------------
echo "==> masking"
MASKED=$(post "$PAYLOAD_ID" "$ORIGINAL") || fail "mask request failed (HTTP error)"
[ -n "$MASKED" ] || fail "mask response had no result field"
info "masked: $MASKED"

[ "$MASKED" != "$ORIGINAL" ] || fail "nothing was masked — the detectors found no personal data"
case "$MASKED" in
*'*'*) ;;
*) fail "masked text contains no mask character" ;;
esac

# The specification calls these out by name as things that must NOT be masked.
# A regression here costs metric points on every text, so it is worth failing
# the smoke test over.
case "$MASKED" in
*'Пушкин'*) ;;
*) fail "false positive: the poet Пушкин was masked" ;;
esac

# ---------------------------------------------------------------------------
# 2. Unmask with the same payload_id
# ---------------------------------------------------------------------------
echo "==> unmasking"
RESTORED=$(post "$PAYLOAD_ID" "$MASKED") || fail "unmask request failed (HTTP error)"

if [ "$RESTORED" != "$ORIGINAL" ]; then
  red "FAIL: restored text differs from the original"
  info "expected: $ORIGINAL"
  info "actual  : $RESTORED"
  cleanup
  exit 1
fi
info "restored byte for byte"

# ---------------------------------------------------------------------------
# 3. Determinism
# ---------------------------------------------------------------------------
# A retry arrives as a *fresh* payload_id only when the client generates one,
# but the graders may send the same text twice. Identical input must produce
# identical output, otherwise a retried request changes the score.
echo "==> checking determinism"
AGAIN=$(post "${PAYLOAD_ID}-b" "$ORIGINAL") || fail "second mask request failed"
[ "$AGAIN" = "$MASKED" ] || fail "masking is not deterministic: the same text produced two different masks"
info "same input, same mask"

green "PASS: mask -> unmask round trip is byte-exact"
cleanup
exit 0
