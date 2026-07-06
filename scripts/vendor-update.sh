#!/usr/bin/env bash
# vendor-update.sh — manage vendored dependencies in lib/vendor/
#
# NATIVE-FIRST POLICY (see lib/vendor/README.md)
#   @blamejs/pki ships ZERO npm runtime dependencies and currently vendors
#   NOTHING. Its cryptography runs entirely on Node's built-in node:crypto
#   (OpenSSL 3.5 — the classical set AND the FIPS 203/204/205 post-quantum
#   algorithms via the engine floor, Node >=24.18). A platform built-in
#   ships zero bytes, has nothing to hash-pin, and is interoperable by
#   construction — so there is no reason to vendor a crypto library.
#
#   Vendoring is a DELIBERATE, JUSTIFIED EXCEPTION, added ONLY when a
#   specific operation is confirmed missing from the engine floor. When you
#   add one, record its reason + re-open condition alongside the MANIFEST
#   entry, and add its attribution to the top-level NOTICE.
#
# Usage:
#   ./scripts/vendor-update.sh --check                # show vendored packages (+ whether outdated)
#   ./scripts/vendor-update.sh --diff <package>       # show vendored vs latest + changelog url
#   ./scripts/vendor-update.sh --diff-all             # diff every outdated package
#   ./scripts/vendor-update.sh <package> [version]    # bundle/update a vendored package
#
# What the update path does:
#   1. resolves the requested spec to an integrity-pinned lockfile in an
#      isolated staging workspace (scripts/vendor-stage.js, metadata-only),
#      then installs it there via `npm ci --ignore-scripts` — every package
#      verified against its lockfile integrity hash, no script executed,
#      the repo's own node_modules untouched
#   2. bundles a CommonJS rollup with esbuild (--format=cjs --platform=node)
#      from the verified staged tree
#   3. updates lib/vendor/MANIFEST.json (version + bundledAt)
#   4. removes the staging workspace
#   5. require()s the bundle to verify it has no unresolved imports
#   6. refreshes the MANIFEST sha256 hashes (scripts/refresh-vendor-manifest.js)
#
# After running:
#   node test/smoke.js
#   node scripts/test-integration.js        # openssl interop cross-check

set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST="lib/vendor/MANIFEST.json"
DATE=$(date +%Y-%m-%d)

# Packages we vendor — kept in sync with MANIFEST.json.packages. Empty by
# default (native-first). Add a name here when you vendor its bundle.
VENDORED_PACKAGES=()

get_vendored_ver() {
  node -e "var m=require('./$MANIFEST'); var p=(m.packages||{})['$1']; console.log(p?p.version:'?')"
}

show_pkg_diff() {
  local pkg="$1"
  local vendored latest repo
  vendored=$(get_vendored_ver "$pkg")
  latest=$(npm view "$pkg" version 2>/dev/null || echo "?")
  if [ "$vendored" = "$latest" ]; then
    echo "$pkg: v$vendored — already up to date"
    return
  fi
  repo=$(node -e "var m=require('./$MANIFEST'); var p=(m.packages||{})['$1']; console.log(p&&p.source?p.source:'')")

  echo ""
  echo "=== $pkg: v$vendored -> v$latest ==="
  echo ""
  echo "Versions published since v$vendored:"
  npm view "$pkg" versions --json 2>/dev/null | node -e "
    var versions = JSON.parse(require('fs').readFileSync(0,'utf8'));
    if (!Array.isArray(versions)) versions = [versions];
    var found = false;
    versions.forEach(function(v) {
      if (v === '$vendored') found = true;
      else if (found) console.log('  ' + v);
    });
  " 2>/dev/null || echo "  (could not fetch version list)"

  if [ -n "$repo" ]; then
    echo ""
    echo "Changelog: $repo/releases"
    echo "Compare:   $repo/compare/v${vendored}...v${latest}"
  fi
  echo ""
}

if [ "${1:-}" = "--check" ]; then
  if [ ${#VENDORED_PACKAGES[@]} -eq 0 ]; then
    echo "No packages are vendored — @blamejs/pki runs native-first on node:crypto."
    echo "See lib/vendor/README.md for the policy on when something IS vendored."
    exit 0
  fi
  echo "Checking vendored package versions..."
  echo ""
  printf "%-30s %-15s %-15s %-12s %s\n" "Package" "Vendored" "Latest" "Bundled" "Status"
  printf "%-30s %-15s %-15s %-12s %s\n" "-------" "--------" "------" "-------" "------"
  for pkg in "${VENDORED_PACKAGES[@]}"; do
    vendored=$(get_vendored_ver "$pkg")
    bundled=$(node -e "var m=require('./$MANIFEST'); var p=(m.packages||{})['$pkg']; console.log(p&&p.bundledAt?p.bundledAt:'?')")
    latest=$(npm view "$pkg" version 2>/dev/null || echo "?")
    if [ "$vendored" = "$latest" ]; then status="up to date"; else status="UPDATE AVAILABLE"; fi
    printf "%-30s %-15s %-15s %-12s %s\n" "$pkg" "$vendored" "$latest" "$bundled" "$status"
  done
  exit 0
fi

if [ "${1:-}" = "--diff" ]; then
  PKG="${2:?Usage: vendor-update.sh --diff <package>}"
  show_pkg_diff "$PKG"
  exit 0
fi

if [ "${1:-}" = "--diff-all" ]; then
  if [ ${#VENDORED_PACKAGES[@]} -eq 0 ]; then
    echo "No packages are vendored — nothing to diff (native-first)."
    exit 0
  fi
  any=false
  for pkg in "${VENDORED_PACKAGES[@]}"; do
    vendored=$(get_vendored_ver "$pkg")
    latest=$(npm view "$pkg" version 2>/dev/null || echo "?")
    if [ "$vendored" != "$latest" ]; then
      show_pkg_diff "$pkg"
      any=true
    fi
  done
  [ "$any" = false ] && echo "All vendored packages are up to date."
  exit 0
fi

# ---- update mode ----
PKG="${1:?Usage: vendor-update.sh <package> [version]}"
VER="${2:-latest}"

echo "=== Vendoring $PKG@$VER ==="
echo ""
echo "REMINDER (lib/vendor/README.md): vendoring is the exception to native-first."
echo "Only vendor an operation confirmed MISSING from the engine floor (Node >=24.18,"
echo "OpenSSL 3.5). Record the reason + re-open condition beside the MANIFEST entry and"
echo "add attribution to NOTICE. Ctrl-C now if node:crypto already provides this."
echo ""

# Stage the package in an isolated throwaway workspace, integrity-verified:
# vendor-stage.js resolves the requested spec to a package-lock.json
# (metadata-only — no tarball fetched, no script run), then `npm ci`
# installs the tree with every package checked against its recorded
# integrity hash. Nothing touches the repo's own node_modules, and no
# install script ever runs.
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
node scripts/vendor-stage.js "$PKG" "$VER" "$STAGE"
npm ci --prefix "$STAGE" --ignore-scripts --no-audit --no-fund
INSTALLED_VER=$(node -p "require(process.argv[1] + '/node_modules/' + process.argv[2] + '/package.json').version" "$STAGE" "$PKG")
echo "Staged: $PKG@$INSTALLED_VER"

# Generic CommonJS rollup. A package with a bespoke export surface should
# replace this entry with an explicit named-export entry (see the esbuild
# invocation documented in lib/vendor/README.md). The entry lives inside
# the staging workspace so esbuild resolves the package from the verified
# staged tree, never from the repo's node_modules.
BUNDLE_BASENAME=$(echo "$PKG" | sed 's#^@##; s#/#-#g')
OUTFILE="lib/vendor/${BUNDLE_BASENAME}.cjs"
echo "module.exports = require(\"${PKG}\");" > "$STAGE/_entry.cjs"
npx esbuild "$STAGE/_entry.cjs" --bundle --format=cjs --minify --platform=node \
  --external:node:crypto --external:crypto \
  --outfile="$OUTFILE"
sed -i "1s|^|// ${PKG} v${INSTALLED_VER} — vendored. Bundled with esbuild (cjs, node platform).\n// See lib/vendor/README.md for the native-first policy + re-open condition.\n|" "$OUTFILE"

# Update (or create) the MANIFEST.json entry.
PKG="$PKG" INSTALLED_VER="$INSTALLED_VER" DATE="$DATE" OUTFILE="$OUTFILE" node -e "
var fs = require('fs');
var manifestPath = '$MANIFEST';
var m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
m.packages = m.packages || {};
var pkg = process.env.PKG;
var entry = m.packages[pkg] || {};
entry.version = process.env.INSTALLED_VER;
entry.bundledAt = process.env.DATE;
entry.files = entry.files || {};
entry.files.server = process.env.OUTFILE;
if (!entry.source) entry.source = '';
if (!entry.license) entry.license = '';
m.packages[pkg] = entry;
fs.writeFileSync(manifestPath, JSON.stringify(m, null, 2) + '\n');
console.log('Updated MANIFEST.json: ' + pkg + ' -> ' + process.env.INSTALLED_VER);
console.log('NOTE: fill in source + license (SPDX) + reason + re-open condition for ' + pkg + ' by hand.');
"

echo ""
echo "=== Verifying bundle integrity ==="
node -e "
var m = require('./$MANIFEST');
var p = (m.packages || {})['$PKG'];
if (!p || !p.files) { console.log('  (no files entry; skipping)'); process.exit(0); }
var ok = true;
Object.values(p.files).forEach(function(f) {
  if (typeof f !== 'string' || !f.endsWith('.cjs')) return;
  try { require('./' + f); console.log('  ' + f + ': OK'); }
  catch(e) { console.log('  ' + f + ': FAIL — ' + e.message); ok = false; }
});
if (!ok) process.exit(1);
" || { echo "Bundle verification failed — do not commit."; exit 1; }

echo ""
echo "=== Refreshing MANIFEST.json sha256 hashes ==="
node scripts/refresh-vendor-manifest.js || { echo "Manifest hash refresh failed."; exit 1; }

echo ""
echo "=== Done: $PKG v$INSTALLED_VER vendored ==="
echo ""
echo "Next steps:"
echo "  1. Fill in source/license/reason/re-open in $MANIFEST + add NOTICE attribution."
echo "  2. node test/smoke.js"
echo "  3. node scripts/test-integration.js"
echo "  4. git add lib/vendor/ NOTICE && git commit"
