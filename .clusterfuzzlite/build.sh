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

# Stage every harness into $OUT/<base>. compile_javascript_fuzzer
# resolves the module via Node's normal resolution from the repo root,
# so `require("..")` in each harness picks up the toolkit entry-point.
for fuzzer in fuzz/*.fuzz.js; do
  base=$(basename "$fuzzer" .fuzz.js)
  echo "[pkijs build] compiling $base"
  compile_javascript_fuzzer pkijs "$fuzzer" --sync

  # Zip the seed corpus if it exists.
  seed_dir="fuzz/${base}_seed_corpus"
  if [ -d "$seed_dir" ]; then
    echo "[pkijs build] packaging seed corpus for $base"
    ( cd "$seed_dir" && zip -q -r "$OUT/${base}_seed_corpus.zip" . )
  fi
done

echo "[pkijs build] done — $(find "$OUT" -mindepth 1 -maxdepth 1 | wc -l) artifacts in \$OUT"
