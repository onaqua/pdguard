#!/usr/bin/env bash
# Packages the solution archive exactly as section 7.1 of the track brief requires:
# source only, no dependency, build or service directories, no bulky files.
#
# This is the same logic the Makefile's `zip` target runs, extracted into a script
# so it also works where make is unavailable (a stock git bash on Windows).
#
#   bash scripts/zip.sh            -> dist/pdguard-solution.zip
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STAGE="dist/pdguard"
ARCHIVE="dist/pdguard-solution.zip"

rm -rf "$STAGE" "$ARCHIVE"
mkdir -p "$STAGE"

# Staging through tar keeps one authoritative exclusion list and gives the archive a
# single clean root directory, which the automated check prefers.
tar -cf - \
  --exclude=./.git --exclude=./dist --exclude=./node_modules --exclude=./.venv \
  --exclude=./venv --exclude=./env --exclude=./target --exclude=./build \
  --exclude=./out --exclude=./bin --exclude=./obj --exclude=./coverage \
  --exclude=./.idea --exclude=./.vscode --exclude=./__pycache__ \
  --exclude=./.spec --exclude=./.tmp --exclude=./AGENTS.md \
  --exclude='*.zip' --exclude='*.pdf' --exclude='*.exe' --exclude='*.log' \
  --exclude='*.test' --exclude='*.out' --exclude='*.prof' \
  . | ( cd "$STAGE" && tar -xf - )

big="$(find "$STAGE" -type f -size +2M || true)"
if [ -n "$big" ]; then
  echo "refusing to package large files:" >&2
  echo "$big" >&2
  exit 1
fi

if command -v zip >/dev/null 2>&1; then
  ( cd dist && zip -q -r "$(basename "$ARCHIVE")" pdguard )
elif command -v python >/dev/null 2>&1; then
  ( cd dist && python -m zipfile -c "$(basename "$ARCHIVE")" pdguard )
elif command -v python3 >/dev/null 2>&1; then
  ( cd dist && python3 -m zipfile -c "$(basename "$ARCHIVE")" pdguard )
elif command -v powershell.exe >/dev/null 2>&1; then
  MSYS_NO_PATHCONV=1 powershell.exe -NoProfile -NonInteractive -Command \
    "Compress-Archive -Path '$STAGE' -DestinationPath '$ARCHIVE' -Force" >/dev/null
else
  echo "no archiver found (tried zip, python, python3, powershell.exe)" >&2
  exit 1
fi

echo "$ARCHIVE"
echo "  size:  $(du -h "$ARCHIVE" | cut -f1)"
echo "  files: $(find "$STAGE" -type f | wc -l | tr -d ' ')"
