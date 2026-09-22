#!/usr/bin/env bash
# Switch the masking format of pdguard in one command.
#
# The quality metric compares our mask against a reference mask we have never
# seen. The shipped default (stars_keep2) reproduces the single worked example
# in the specification exactly, but it is still a bet. If the real reference
# format becomes known during the hackathon, this script is how the bet is
# changed — on the RUNNING service, in seconds, with no rebuild and no restart.
#
#   bash scripts/preset.sh list               # what is available
#   bash scripts/preset.sh show               # what is active right now
#   bash scripts/preset.sh diff labels        # how a preset differs from active
#   bash scripts/preset.sh apply labels       # PUT it to the live service
#   bash scripts/preset.sh apply labels --file # write configs/config.json instead
#
# Environment:
#   PDGUARD_URL           service base URL, default http://localhost:8080
#   PDGUARD_ADMIN_TOKEN   sent as X-Admin-Token when set
#
# Dependencies: bash, curl, awk, sed. No jq — the admin endpoint returns the
# canonical two-space-indented form that config.Marshal writes, so a line-shaped
# reader is exact rather than approximate, and one less tool has to be present
# on a borrowed laptop at 3am.
#
# Applying NEVER changes secrets. Every api_key and the admin token travel as
# the "***" placeholder the admin endpoint understands, so the live service
# keeps the credentials it already has (see restoreSecrets in httpapi/admin.go).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRESET_DIR="$ROOT/configs/presets"
CONFIG_FILE="$ROOT/configs/config.json"
URL="${PDGUARD_URL:-http://localhost:8080}"
TOKEN="${PDGUARD_ADMIN_TOKEN:-}"

# The control string. One value per family that the presets actually render
# differently, including a label ("серия") so the span hedge is visible too.
# No double quote and no backslash anywhere: the body is built with printf and
# the result is read back with sed, and both are exact only for such a string.
CONTROL='Клиент Иванов Иван Иванович, паспорт серия 4509 номер 123456, телефон +7 916 123-45-67, почта ivanov.ivan@example.com.'

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die() {
  red "error: $*"
  exit 1
}

TMPDIR_SELF="$(mktemp -d -t pdguard-preset.XXXXXX)" || die "cannot create a temp directory"
trap 'rm -rf "$TMPDIR_SELF"' EXIT

# winpath prints a path curl can open. On git bash curl is a native Windows
# binary and cannot open an MSYS path such as /tmp/pdguard-preset.ab12cd.
winpath() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

curl_admin() {
  if [ -n "$TOKEN" ]; then
    curl -sS -m 10 -H "X-Admin-Token: $TOKEN" "$@"
  else
    curl -sS -m 10 "$@"
  fi
}

preset_path() {
  local name="${1%.json}"
  printf '%s/%s.json' "$PRESET_DIR" "$name"
}

# describe prints the one-line purpose of a preset. Kept here rather than read
# out of docs/PRESETS.md so `list` works even from a stripped checkout.
describe() {
  case "${1%.json}" in
  stars-keep2) echo "default — first 2 and last 2 kept: 4509 123456 -> 45** ****56" ;;
  stars-all) echo "everything starred, length preserved — if the reference hides all" ;;
  labels) echo "bracketed category labels: [ФИО], [ПАСПОРТ], [ТЕЛЕФОН]" ;;
  tokens) echo "deterministic pseudonyms: PD_FIO_a1b2c3 (bonus: tokenisation)" ;;
  synthetic) echo "plausible fake of the same shape (bonus: synthetic replacement)" ;;
  keep-domain) echo "stars-keep2, but e-mail keeps its domain: iv****@mail.ru" ;;
  span-with-labels) echo "stars-keep2 + spans swallow the label word (серия 4509)" ;;
  *) echo "custom preset" ;;
  esac
}

# ---------------------------------------------------------------------------
# Signature
#
# A signature is the part of a configuration this script is about: the mask
# strategy of every PD type of the DEFAULT system, plus the span hedge. Two
# configurations with the same signature mask identically, so comparing
# signatures answers both "which preset is live" and "what would change".
# ---------------------------------------------------------------------------
signature() {
  awk '
    /^  "masking"/                  { inmask = 1 }
    inmask && /"span_include_labels"/ {
      v = $0; sub(/.*: /, "", v); sub(/,$/, "", v)
      print "_span_include_labels=" v; inmask = 0
    }
    /^      "id": "/                { sid = $0; sub(/^ *"id": "/, "", sid); sub(/".*$/, "", sid) }
    /^        "[A-Z_]+": \{/        { t = $0;   sub(/^ *"/, "", t);         sub(/".*$/, "", t) }
    sid == "default" && /^          "strategy": "/ {
      s = $0; sub(/^ *"strategy": "/, "", s); sub(/".*$/, "", s)
      print t "=" s
    }
  ' "$1" | sort
}

# live_config saves the running configuration to $1; non-zero when unreachable.
live_config() {
  curl_admin -f -o "$(winpath "$1")" "${URL}/admin/config" >/dev/null 2>&1
}

# unreachable_reason explains a failed live_config in one line. A service that
# answers /health but refuses /admin/config is not down, it is guarded — and
# telling those two apart is the difference between "start the service" and
# "export PDGUARD_ADMIN_TOKEN", which is not a guess anybody should have to
# make while a run is going.
unreachable_reason() {
  if curl -sS -f -m 5 "${URL}/health" >/dev/null 2>&1; then
    if [ -n "$TOKEN" ]; then
      printf '%s' "$URL refused /admin/config — PDGUARD_ADMIN_TOKEN is set but wrong"
    else
      printf '%s' "$URL refused /admin/config — export PDGUARD_ADMIN_TOKEN"
    fi
  else
    printf '%s' "$URL is not answering"
  fi
}

# ---------------------------------------------------------------------------
# Control-string probe
#
# Switching a format blind is not acceptable, so every apply masks the same
# sentence before and after and prints both. That is the only evidence that the
# new configuration reached the process rather than a file nobody reloaded.
# ---------------------------------------------------------------------------
probe() {
  local id="pdguard-preset-$(date +%s)-$$-${RANDOM}"
  local body="$TMPDIR_SELF/body.json"
  printf '{"payload":"%s","payload_id":"%s"}' "$CONTROL" "$id" >"$body"
  curl -sS -f -m 10 -X POST "${URL}/process" \
    -H 'Content-Type: application/json; charset=utf-8' \
    --data-binary "@$(winpath "$body")" 2>/dev/null |
    tr -d '\r\n' | sed -n 's/.*"result":"\(.*\)".*/\1/p'
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
# show_span reports the span hedge. A build older than the masking block simply
# has no such line, and saying so beats printing nothing at all.
show_span() {
  local v
  v="$(sed -n 's/^_span_include_labels=//p' "$1")"
  if [ -n "$v" ]; then
    info "masking.span_include_labels=$v"
  else
    info "masking.span_include_labels: not reported (build predates the masking block)"
  fi
}

cmd_list() {
  local found=0 f name
  echo "presets in configs/presets:"
  for f in "$PRESET_DIR"/*.json; do
    [ -e "$f" ] || continue
    found=1
    name="$(basename "$f" .json)"
    printf '  %-18s %s\n' "$name" "$(describe "$name")"
  done
  [ "$found" = "1" ] || die "no presets found in $PRESET_DIR"
}

cmd_show() {
  local live="$TMPDIR_SELF/live.json" src sig f
  if live_config "$live"; then
    src="live service at $URL"
  elif [ -f "$CONFIG_FILE" ]; then
    live="$CONFIG_FILE"
    src="configs/config.json — $(unreachable_reason)"
  else
    die "$(unreachable_reason), and $CONFIG_FILE does not exist"
  fi

  sig="$TMPDIR_SELF/sig.live"
  signature "$live" >"$sig"
  [ -s "$sig" ] || die "could not read a configuration from $src"

  echo "active configuration: $src"
  for f in "$PRESET_DIR"/*.json; do
    [ -e "$f" ] || continue
    if signature "$f" | diff -q - "$sig" >/dev/null 2>&1; then
      green "  preset: $(basename "$f" .json)"
      info "$(describe "$(basename "$f" .json)")"
      show_span "$sig"
      return 0
    fi
  done
  echo "  preset: custom (matches none of the shipped presets)"
  info "strategies in use:"
  awk -F= '$1 !~ /^_/ { print $2 }' "$sig" | sort -u | sed 's/^/    /'
  show_span "$sig"
}

cmd_diff() {
  local name="$1" path live
  path="$(preset_path "$name")"
  [ -f "$path" ] || die "unknown preset: $name (try: bash scripts/preset.sh list)"

  live="$TMPDIR_SELF/live.json"
  if live_config "$live"; then
    echo "comparing preset '$name' against the live service at $URL"
  elif [ -f "$CONFIG_FILE" ]; then
    live="$CONFIG_FILE"
    echo "comparing preset '$name' against configs/config.json — $(unreachable_reason)"
  else
    die "$(unreachable_reason), and $CONFIG_FILE does not exist"
  fi

  signature "$live" >"$TMPDIR_SELF/sig.live"
  signature "$path" >"$TMPDIR_SELF/sig.preset"
  if diff -q "$TMPDIR_SELF/sig.live" "$TMPDIR_SELF/sig.preset" >/dev/null; then
    green "  identical — this preset is already active"
    return 0
  fi
  # join on the key so the report reads "TYPE: from -> to" instead of a
  # unified diff the reader has to reassemble mentally.
  join -t= -a1 -a2 -o '0,1.2,2.2' -e '(absent)' \
    "$TMPDIR_SELF/sig.live" "$TMPDIR_SELF/sig.preset" |
    awk -F= '$2 != $3 { printf "  %-22s %s -> %s\n", $1, $2, $3 }'
}

cmd_apply() {
  local name="$1" to_file="$2" path put_body before after
  path="$(preset_path "$name")"
  [ -f "$path" ] || die "unknown preset: $name (try: bash scripts/preset.sh list)"

  if [ "$to_file" = "1" ]; then
    cp "$path" "$CONFIG_FILE" || die "cannot write $CONFIG_FILE"
    green "wrote configs/config.json from preset '$name'"
    info "$(describe "$name")"
    info "takes effect on the next start; use 'apply $name' without --file for the live service"
    return 0
  fi

  # Fail before the PUT, not after: knowing the service is reachable AND that
  # the admin route accepts us turns a half-applied switch into a no-op.
  live_config "$TMPDIR_SELF/pre.json" || die "$(unreachable_reason)"
  before="$(probe)"
  [ -n "$before" ] || die "the service at $URL did not answer POST /process — is it running?"

  # Secrets are replaced by the placeholder the admin endpoint restores from
  # the running configuration, so a format switch can never wipe an api_key or
  # lock us out by clearing the admin token.
  put_body="$TMPDIR_SELF/put.json"
  sed -e 's/"api_key": "[^"]*"/"api_key": "***"/' \
    -e 's/"fail_open": \(true\|false\)/"fail_open": \1,\n    "admin_token": "***"/' \
    "$path" >"$put_body"

  local resp
  resp="$(curl_admin -X PUT "${URL}/admin/config" \
    -H 'Content-Type: application/json; charset=utf-8' \
    --data-binary "@$(winpath "$put_body")")" || die "PUT ${URL}/admin/config failed"

  # The response is read AFTER the live signature, not instead of it. A
  # configuration that is valid but cannot be written back — the compose file
  # mounts configs read-only on purpose — takes effect in the process and still
  # reports an error, so trusting the status field alone would report a failure
  # that did not happen. The running process is the authority.
  local live="$TMPDIR_SELF/verify.json"
  live_config "$live" || die "cannot read ${URL}/admin/config back: $resp"
  signature "$live" >"$TMPDIR_SELF/sig.live"
  signature "$path" >"$TMPDIR_SELF/sig.preset"
  diff -q "$TMPDIR_SELF/sig.live" "$TMPDIR_SELF/sig.preset" >/dev/null ||
    die "the service did not switch to preset '$name': $resp"

  local persisted=1
  case "$resp" in
  *'"status":"applied"'*) ;;
  *) persisted=0 ;;
  esac

  after="$(probe)"
  [ -n "$after" ] || die "applied, but the service stopped answering POST /process"

  green "applied preset '$name' to $URL"
  info "$(describe "$name")"
  echo
  echo "  control: $CONTROL"
  echo "  before : $before"
  echo "  after  : $after"
  echo
  if [ "$before" = "$after" ]; then
    info "note: the mask is unchanged — this preset was already active"
  fi
  if [ "$persisted" = "0" ]; then
    info "note: live only, not written to disk (configs is mounted read-only)"
    info "      a restart returns to configs/config.json — add --file to make it stick"
  fi
}

# usage prints the comment header of this file. Reading the header rather than
# repeating it keeps --help and the file in step; the walk stops at the first
# non-comment line so an edit to the header can never leak code into the help.
usage() {
  awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
  list) cmd_list ;;
  show) cmd_show ;;
  diff)
    [ $# -ge 1 ] || die "usage: preset.sh diff <name>"
    cmd_diff "$1"
    ;;
  apply)
    local name="" to_file=0 a
    for a in "$@"; do
      case "$a" in
      --file) to_file=1 ;;
      -*) die "unknown option: $a" ;;
      *) name="$a" ;;
      esac
    done
    [ -n "$name" ] || die "usage: preset.sh apply <name> [--file]"
    cmd_apply "$name" "$to_file"
    ;;
  "" | -h | --help | help) usage ;;
  *) die "unknown command: $cmd (try: list, show, diff, apply)" ;;
  esac
}

main "$@"
