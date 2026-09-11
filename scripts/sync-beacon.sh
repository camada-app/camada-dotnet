#!/usr/bin/env sh
# Re-vendors @camada/browser's auto build into src/Camada/Resources/b.js (an embedded resource, served
# at /_cam/b.js with no runtime file read) and records its version + sha256 in beacon.json.
# Usage: scripts/sync-beacon.sh [path/to/camada-browser]   (defaults to the sibling checkout)
# Run `npm run build` in camada-browser first; tests/Camada.Tests/BeaconTests.cs fails until the two agree.
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
browser="${1:-$root/../camada-browser}"
src="$browser/dist/auto.global.js"
[ -f "$src" ] || { echo "beacon build missing: $src (run npm run build in camada-browser)" >&2; exit 1; }
version="$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$browser/package.json" | head -1)"
sha="$(shasum -a 256 "$src" | cut -d' ' -f1)"
cp "$src" "$root/src/Camada/Resources/b.js"
printf '{\n  "version": "%s",\n  "sha256": "%s"\n}\n' "$version" "$sha" > "$root/src/Camada/Resources/beacon.json"
echo "Resources/b.js: @camada/browser/$version, $(wc -c < "$src" | tr -d ' ') bytes"
