#!/bin/bash -eu
#
# ClusterFuzzLite / OSS-Fuzz build script for @blamejs/pki.
#
# Wires every `fuzz/<name>.fuzz.js` harness into a libFuzzer-shaped
# runnable via the base-builder-javascript image's
# `compile_javascript_fuzzer` helper. The matching
# `fuzz/<name>_seed_corpus/` directory is zipped into the seed corpus
# the engine bootstraps from.
#
# Local debug:
#   docker run -it -v "$PWD:/src/pkijs" gcr.io/oss-fuzz-base/base-builder-javascript
#   cd /src/pkijs && bash .clusterfuzzlite/build.sh

cd "$SRC/pkijs"

# Install the harness workspace's pinned jazzer.js at the repo root BEFORE
# compiling. compile_javascript_fuzzer generates each wrapper to resolve
# @jazzer.js/core from the project's node_modules ($OUT/pkijs/node_modules, copied
# from here), so without this the compiled targets reference a jazzer that isn't
# present and cannot run. The version is the single source of the pin in
# fuzz/package.json; --engine-strict=false lets it install under the base image's
# older Node without the toolkit's own `engines` field aborting the install.
jazzer_version=$(node -p "require('./fuzz/package.json').dependencies['@jazzer.js/core']")
npm install --no-save --omit=dev --no-audit --no-fund --engine-strict=false "@jazzer.js/core@${jazzer_version}"

# NOTE: the compiled targets RUN only when the base image's Node satisfies
# jazzer.js + the toolkit's `engines` (>=24.18). The pinned base-builder-javascript
# currently ships Node 20, so a canonical OSS-Fuzz run needs a newer base image
# (re-open condition). The fuzzing that actually gates PRs runs jazzer.js directly
# on Node 24 (.github/workflows/cflite_*.yml); this script is the OSS-Fuzz mirror.

# Stage every harness into $OUT/<base>. compile_javascript_fuzzer
# resolves the module via Node's normal resolution from the repo root,
# so `require("..")` in each harness picks up the toolkit entry-point.
for fuzzer in fuzz/*.fuzz.js; do
  base=$(basename "$fuzzer" .fuzz.js)
  echo "[pkijs build] compiling $base"
  compile_javascript_fuzzer pkijs "$fuzzer" --sync

  # Zip the seed corpus if it exists, named after the COMPILED WRAPPER so
  # OSS-Fuzz / ClusterFuzzLite attaches it. compile_javascript_fuzzer derives
  # the wrapper name with `basename -s .js` (strips only `.js`), so
  # fuzz/<base>.fuzz.js -> $OUT/<base>.fuzz, and the corpus must be
  # $OUT/<base>.fuzz_seed_corpus.zip (NOT <base>_seed_corpus.zip).
  seed_dir="fuzz/${base}_seed_corpus"
  if [ -d "$seed_dir" ]; then
    echo "[pkijs build] packaging seed corpus for ${base}.fuzz"
    ( cd "$seed_dir" && zip -q -r "$OUT/${base}.fuzz_seed_corpus.zip" . )
  fi
done

echo "[pkijs build] done — $(find "$OUT" -mindepth 1 -maxdepth 1 | wc -l) artifacts in \$OUT"
