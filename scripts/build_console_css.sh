#!/usr/bin/env bash
# Compile the operator console's Tailwind utilities into a static stylesheet.
#
# The console previously loaded cdn.tailwindcss.com, the Tailwind Play CDN,
# which compiles CSS in the browser at runtime. That made the console depend on
# a third-party origin to render and ruled out any restrictive CSP. This
# produces the same utilities as a fixed local file instead.
#
# Requires node/npx and network access for the first run. The output is
# committed, so the console renders without a node toolchain present.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TAILWIND_VERSION="3.4.17"
OUTPUT="dashboard/vendor/tailwind.css"

command -v npx >/dev/null 2>&1 || {
  printf 'npx is required to rebuild the console stylesheet.\n' >&2
  printf 'The committed %s stays valid without it.\n' "$OUTPUT" >&2
  exit 1
}

printf 'compiling %s with tailwindcss@%s\n' "$OUTPUT" "$TAILWIND_VERSION"
npx --yes "tailwindcss@${TAILWIND_VERSION}" \
  --config dashboard/build/tailwind.config.js \
  --input dashboard/build/tailwind.input.css \
  --output "$OUTPUT" \
  --minify

printf 'wrote %s (%s bytes)\n' "$OUTPUT" "$(stat -c '%s' "$OUTPUT")"
printf 'Now re-record the integrity manifest:\n'
printf '  python3 scripts/vendor_console_assets.py --record-generated\n'
