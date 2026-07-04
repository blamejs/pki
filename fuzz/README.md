# Fuzz harnesses

Coverage-guided fuzz targets against the parser surface most likely to
crash on adversarial input — the strict DER codec and the X.509
certificate parser. Each `<name>.fuzz.js` file is a libFuzzer-compatible
harness (jazzer.js format) consumed by:

- **ClusterFuzzLite** locally on every PR + nightly batch.
- **OSS-Fuzz** upstream once the submission lands.

Both pipelines feed the same harnesses with the same seed corpora;
findings reproduce identically.

## Targets

| File                   | Target             |
| ---------------------- | ------------------ |
| `asn1-der.fuzz.js`     | `pki.asn1.decode`  |
| `x509-parse.fuzz.js`   | `pki.x509.parse`   |

Each harness exports a `fuzz(data)` function the engine drives with
mutated bytes. The contract for both targets is the same: decoding or
parsing attacker-controlled bytes may only ever succeed or throw a
`pki.errors.PkiError` (`Asn1Error` / `OidError` / `CertificateError`).
The harness catches that class and returns normally. Any other throw —
`RangeError`, a stack overflow from unbounded recursion, a bare
`TypeError`, a hang — escapes as a finding; libFuzzer records the
reproducer and persists it in the corpus so future runs catch the
regression.

Per-target seed corpora live in `fuzz/<name>_seed_corpus/`. Each file
is a single seed input; the build script zips them at compile time.
`x509-parse.fuzz.js` reuses the ASN.1 corpus — a certificate is a DER
SEQUENCE, so those seeds exercise the parser's front door. Add new
seeds whenever a real-world input class isn't covered (raw attack
payloads, regression inputs from past bug fixes, etc.).

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
