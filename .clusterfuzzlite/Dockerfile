# ClusterFuzzLite build image for @blamejs/pki.
#
# Inherits from oss-fuzz's JavaScript base-builder (jazzer.js +
# libFuzzer + the compile_javascript_fuzzer helper pre-installed).
# Copy the toolkit source + harnesses, then build.sh wires each fuzz
# target into a libFuzzer-shaped runnable.
#
# This directory is the canonical ClusterFuzzLite / OSS-Fuzz
# integration spec. The fuzzing that actually runs in CI drives
# jazzer.js directly (`.github/workflows/cflite_*.yml`) because the
# CFLite v1 action image refuses JavaScript projects; this Dockerfile is
# what an OSS-Fuzz upstream submission would mirror, and what OpenSSF
# Scorecard's Fuzzing check keys on.
#
# The base is digest-pinned for a reproducible fuzz toolchain
# (Dependabot bumps it via the docker ecosystem entry for
# /.clusterfuzzlite).
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:25cc43d106d54c297d00f947804fb55b61497f09fe7350fc8cd860d458555a6f

# The whole repo is the fuzzed project: each harness require("..")s the
# toolkit root, which ships zero npm runtime dependencies.
COPY . $SRC/pkijs

# Build script wires compile_javascript_fuzzer for each harness.
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/pkijs
