# Interop integration tests

These tests cross-check what the toolkit parses and emits against an
**independent** PKI implementation. Passing its own decoder proves
internal consistency; agreeing with a second, unrelated implementation is
what proves standards conformance.

The oracle today is the **OpenSSL** command-line tool. NSS (`certutil`) is
recognized as an optional second oracle when present on PATH.

## Running

Locally (OpenSSL on PATH):

```
node scripts/test-integration.js                     # every file
node scripts/test-integration.js x509-openssl-interop  # one file
node scripts/check-services.js                       # just the oracle probe
```

In a pinned, known-version container (bundles Node + OpenSSL + NSS):

```
docker compose -f docker-compose.test.yml run --rm interop
```

Skip the oracle probe if the toolchain is already verified:

```
node scripts/test-integration.js --skip-service-check
```

Point at a specific OpenSSL binary with `PKIJS_OPENSSL=/path/to/openssl`.

## Layout

Each file is a standalone test: it exports `run()`, prints `CHECKS <n>` on
success, and exits non-zero on failure — the same contract as the smoke
files. `scripts/test-integration.js` spawns each one in its own Node
process (so a crash or leaked handle is contained to one file) and
aggregates the check counts. These live **outside** `test/smoke.js` on
purpose: the smoke gate must run with no external toolchain and must never
skip silently, which a live-oracle dependency would force.

## Adding an oracle or a wire concern

Each file exposes a staged `_run<Concern>On<Endpoint>` function — for
example `_runX509InteropOnOpenssl(bin)`. A new cross-checker (NSS
`certutil`, a signing peer) is a **sibling staged function** driven by the
same parsed structure, not a rewrite of the assertions. A new wire concern
(CMS SignedData, a PKCS#12 bag, an OCSP response the toolkit builds) is a
new `<concern>-openssl-interop.test.js` file that parses/emits with the
toolkit and has OpenSSL validate the bytes independently.

## What `x509-openssl-interop` asserts

- `pki.x509.parse` and `openssl x509` read the **same** subject, issuer,
  serial, and validity window from the shared fixture
  (`test/fixtures/pkijs-selfsigned-ec.pem`).
- `pki.x509.pemEncode(pemDecode(pem))` reproduces the exact DER bytes, and
  OpenSSL still accepts and parses the re-encoded PEM.
