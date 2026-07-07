# Fuzz harnesses

Coverage-guided fuzz targets against the parser surface most likely to
crash on adversarial input — the strict DER codec and every format
parser. Each `<name>.fuzz.js` file is a libFuzzer-compatible
harness (jazzer.js format), run two ways:

- **CI** — jazzer.js drives every harness on each PR (60s per target)
  and on a nightly batch schedule (30 min per target). See
  `.github/workflows/cflite_*.yml`.
- **OSS-Fuzz** — continuous upstream fuzzing once the submission lands.

`.clusterfuzzlite/` is the canonical ClusterFuzzLite / OSS-Fuzz build
integration (the Dockerfile + `build.sh` an upstream submission mirrors);
the CI workflows invoke jazzer.js directly rather than through the CFLite
action wrapper, which does not support JavaScript targets.

## Targets

| File                     | Target                                                |
| ------------------------ | ----------------------------------------------------- |
| `asn1-der.fuzz.js`       | `pki.asn1.decode`                                     |
| `x509-parse.fuzz.js`     | `pki.schema.x509.parse`                               |
| `cms-parse.fuzz.js`      | `pki.schema.cms.parse`                                |
| `ocsp-parse.fuzz.js`     | `pki.schema.ocsp.parseRequest` / `parseResponse`      |
| `tsp-parse.fuzz.js`      | `pki.schema.tsp.parse`                                |
| `attrcert-parse.fuzz.js` | `pki.schema.attrcert.parse`                           |
| `crmf-parse.fuzz.js`     | `pki.schema.crmf.parse`                               |
| `pkcs12-parse.fuzz.js`   | `pki.schema.pkcs12.parse`                             |
| `pkix-ext-parse.fuzz.js` | the shared PKIX extension decoders                    |

Each harness exports a `fuzz(data)` function the engine drives with
mutated bytes. The contract for every target is the same: decoding or
parsing attacker-controlled bytes may only ever succeed or throw a
`pki.errors.PkiError` (`Asn1Error` / `OidError` / `CertificateError`).
The harness catches that class and returns normally. Any other throw —
`RangeError`, a stack overflow from unbounded recursion, a bare
`TypeError`, a hang — escapes as a finding; libFuzzer records the
reproducer and persists it in the corpus so future runs catch the
regression.

Per-target seed corpora live in `fuzz/<name>_seed_corpus/`. Each file
is a single seed input; the build script zips them at compile time, and
the CI workflow passes the directory to jazzer as the starting corpus.
Every format seed is also a DER SEQUENCE, so the codec target benefits
from the same samples.
Add new seeds whenever a real-world input class isn't covered (raw
attack payloads, regression inputs from past bug fixes, etc.).

Only these curated seeds are committed. libFuzzer writes the inputs it
discovers back into the corpus directory during a local run; those
generated entries are not tracked — drop new seeds in by hand.

## Run locally

Pure-Node mode (no Docker, no coverage guidance — useful for a sanity
check on a harness edit):

```sh
npm install                                             # once, in fuzz/
npx --yes @jazzer.js/core fuzz/asn1-der.fuzz.js -- -max_total_time=60
npx --yes @jazzer.js/core fuzz/x509-parse.fuzz.js -- -max_total_time=60
```

The seed corpus is discovered automatically when passed as a directory
argument:

```sh
npx --yes @jazzer.js/core fuzz/asn1-der.fuzz.js fuzz/asn1-der_seed_corpus -- -runs=0
```

## Scope

These harnesses are a dev-only tool. `fuzz/package.json` pins
`@jazzer.js/core` as a `devDependency` of the harness workspace alone —
it is never a runtime dependency of `@blamejs/pki`, which ships zero npm
runtime dependencies.
