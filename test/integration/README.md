# Interop integration tests

These tests cross-check what the toolkit parses and emits against an independent
PKI implementation. Passing its own decoder proves internal consistency; agreeing
with a second, unrelated implementation is what proves standards conformance.

The oracle is the OpenSSL command-line tool. NSS (`certutil`) is recognized as an
optional second oracle when present on PATH — `scripts/check-services.js` probes
for it and reports it — but no driver in this directory invokes it yet, so every
cross-check here runs against OpenSSL. An NSS driver is a wanted contribution.

## Running

Locally, with OpenSSL on PATH:

```
node scripts/test-integration.js                       # every file
node scripts/test-integration.js x509-sign-openssl-interop   # one file
node scripts/check-services.js                         # just the oracle probe
```

In a pinned, known-version container that bundles Node and OpenSSL (the image
also installs `nss-tools`, ready for a future NSS driver):

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
success, and exits non-zero on failure, the same contract as the smoke files.
`scripts/test-integration.js` spawns each one in its own Node process, so a crash
or leaked handle is contained to one file, and aggregates the check counts.

These live outside `test/smoke.js` on purpose. The smoke gate must run with no
external toolchain and must never skip silently, which a live-oracle dependency
would force.

`_interop-ctx.js` is the shared harness: resolving the OpenSSL binary
(`opensslBin`), probing what that build supports (`opensslSupports`), running it
(`runOpenssl`), and managing temporary files (`tmpFile`, `withTmp`). A test asks
`opensslSupports` before exercising an algorithm the local build may lack, rather
than inferring availability from a failure.

## Adding a wire concern

A new wire concern — a CMS structure, a PKCS#12 bag, an OCSP response the toolkit
builds — is a new `<concern>-openssl-interop.test.js` file that parses or emits
with the toolkit and has OpenSSL validate the bytes independently. Drive the
oracle through `_interop-ctx.js` rather than spawning it directly, so the binary
resolution, the capability probe, and the temp-file cleanup stay in one place.

A second oracle for an existing concern is an added assertion inside that same
file, driven by the same parsed structure, rather than a rewrite of the existing
assertions.

## Coverage today

The suite cross-checks certificate issuance and parsing, CRL issuance and
revocation lookup, CSR, CRMF, CMP, and CMC message building, attribute
certificates, CMS countersignatures and AuthenticatedData, S/MIME header
protection, PKCS#12 in both integrity modes and both privacy modes, key
encryption, path building, ML-KEM certificates, C509 encoding including the RFC
3779 resource extensions, the ACME and EST clients against a scripted peer, the
human-readable inspector against `openssl -text`, and byte identity across
re-encode round-trips.
