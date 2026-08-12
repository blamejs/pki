# Fuzz harnesses

Coverage-guided fuzz targets against the surface most likely to misbehave on
adversarial input: the strict DER and CBOR codecs, every format parser, every
verifier, and the issuance paths. Each `<name>.fuzz.js` file is a
libFuzzer-compatible harness in jazzer.js format, run two ways:

- **CI.** jazzer.js drives every harness on each PR, 60 seconds per target, and
  on a nightly batch schedule, 30 minutes per target. See
  `.github/workflows/cflite_*.yml`.
- **OSS-Fuzz.** Continuous upstream fuzzing once the submission lands.

`.clusterfuzzlite/` is the canonical ClusterFuzzLite and OSS-Fuzz build
integration, the Dockerfile and `build.sh` an upstream submission mirrors. The
CI workflows invoke jazzer.js directly rather than through the CFLite action
wrapper, which does not support JavaScript targets.

## Targets

### Codecs

| File                       | Target                                                |
| -------------------------- | ----------------------------------------------------- |
| `asn1-der.fuzz.js`         | `pki.asn1.decode`                                     |
| `cbor-det-parse.fuzz.js`   | `pki.cbor.decode` + the `read.*` leaf readers          |
| `schema-all-parse.fuzz.js` | `pki.schema.parse`, the detect-and-route orchestrator: every format's `matches()` detector plus the BER-tolerant root decode |
| `guard-json.fuzz.js`       | the strict bounded JSON reader, differential against `JSON.parse` on every accept |
| `guard-encoding.fuzz.js`   | the strict base64url / base64 / hex decoders (a two-sided canonicality oracle), the bounded text decode, and the canonical-OID assert against the DER codec |

### Format parsers

| File                       | Target                                                |
| -------------------------- | ----------------------------------------------------- |
| `x509-parse.fuzz.js`       | `pki.schema.x509.parse`                               |
| `c509-parse.fuzz.js`       | `pki.schema.c509.parse` (draft-ietf-cose-cbor-encoded-cert) |
| `crl-parse.fuzz.js`        | `pki.schema.crl.parse`                                |
| `csr-parse.fuzz.js`        | `pki.schema.csr.parse`                                |
| `csrattrs-parse.fuzz.js`   | `pki.schema.csrattrs.parse` (RFC 8951 CsrAttrs + RFC 9908 templates) |
| `pkcs8-parse.fuzz.js`      | `pki.schema.pkcs8.parse` + `parseEncrypted`           |
| `pkcs12-parse.fuzz.js`     | `pki.schema.pkcs12.parse`                             |
| `cms-parse.fuzz.js`        | `pki.schema.cms.parse`                                |
| `ocsp-parse.fuzz.js`       | `pki.schema.ocsp.parseRequest` + `parseResponse`      |
| `tsp-parse.fuzz.js`        | `pki.schema.tsp.parse` / `parseRequest` / `parseTstInfo` / `parseToken`, plus `pki.tsp.sign` and `pki.tsp.verify` over the result |
| `attrcert-parse.fuzz.js`   | `pki.schema.attrcert.parse`                           |
| `crmf-parse.fuzz.js`       | `pki.schema.crmf.parse`                               |
| `cmp-parse.fuzz.js`        | `pki.schema.cmp.parse`                                |
| `cmc-parse.fuzz.js`        | `pki.schema.cmc.parse`                                |
| `smime-parse.fuzz.js`      | `pki.schema.smime` (RFC 5035 ESS + RFC 8551 SMIMECapabilities) |
| `pkix-ext-parse.fuzz.js`   | the RFC 5280 §4.2.1 extension-value decoders          |

### Verifiers

| File                       | Target                                                |
| -------------------------- | ----------------------------------------------------- |
| `cms-verify.fuzz.js`       | `pki.cms.verify`                                      |
| `cms-decrypt.fuzz.js`      | `pki.cms.decrypt` (EnvelopedData / AuthEnvelopedData / EncryptedData) |
| `cms-decompress.fuzz.js`   | `pki.cms.decompress` (RFC 3274 CompressedData)        |
| `smime-verify.fuzz.js`     | `pki.smime.verify`                                    |
| `smime-decrypt.fuzz.js`    | `pki.smime.decrypt`                                   |
| `ocsp-verify.fuzz.js`      | `pki.ocsp.verify`                                     |
| `composite-verify.fuzz.js` | composite ML-DSA signature verification via `pki.path.validate` |
| `ct-verify.fuzz.js`        | `pki.ct.verifySct`                                    |
| `ct-parse.fuzz.js`         | `pki.ct.parseSctList` (round-tripped through `pki.ct.encodeSctList`) |
| `ct-log-list.fuzz.js`      | `pki.ct.parseLogList` (RFC 6962 §3.2 + the log-list v3 JSON schema) |
| `ct-log-list-sig.fuzz.js`  | `pki.ct.verifyLogListSignature`                       |
| `merkle-verify.fuzz.js`    | `pki.merkle.verifyInclusion` / `verifyConsistency` + the tree hashes |
| `shbs-verify.fuzz.js`      | `pki.shbs.verify` (HSS) + `verifyLms` (LMS)           |
| `sigstore-verify.fuzz.js`  | `pki.sigstore.parseBundle` + `verifyBundle`           |
| `webauthn-parse.fuzz.js`   | `pki.webauthn.parseAttestationObject` + `verify` + `parseAuthenticatorData` + `parseClientData` + `verifyAssertion` |
| `webauthn-mds.fuzz.js`     | `pki.webauthn.verifyMetadataBlob` + `metadataFor` + `metadataAnchors` |
| `key-decrypt.fuzz.js`      | `pki.key.decrypt` (RFC 5958 / RFC 8018 EncryptedPrivateKeyInfo) |
| `hpke-open.fuzz.js`        | `pki.hpke.setupR` + `open` (RFC 9180 recipient path)  |
| `trust-certdata.fuzz.js`   | `pki.trust.parseCertdata` + `parseCcadbCsv` (NSS certdata + CCADB CSV text) |

### Issuance and producing paths

| File                       | Target                                                |
| -------------------------- | ----------------------------------------------------- |
| `x509-sign.fuzz.js`        | `pki.x509.sign`                                       |
| `c509-encode.fuzz.js`      | `pki.schema.c509.encode`                              |
| `crl-sign.fuzz.js`         | `pki.crl.sign` (RFC 5280 §5)                          |
| `csr-sign.fuzz.js`         | `pki.csr.sign`                                        |
| `cms-sign.fuzz.js`         | `pki.cms.sign`                                        |
| `tsp-sign.fuzz.js`         | `pki.tsp.sign` (RFC 3161 token creation)              |
| `attrcert-sign.fuzz.js`    | `pki.attrcert.sign` (RFC 5755)                        |
| `crmf-build.fuzz.js`       | `pki.crmf.build` (RFC 4211)                           |

### Transport and wire layers

| File                          | Target                                             |
| ----------------------------- | -------------------------------------------------- |
| `est-transfer.fuzz.js`        | `pki.est.transferDecode` + `splitMultipartMixed` (RFC 8951 base64 + RFC 2046 multipart) |
| `http-digest-challenge.fuzz.js` | the RFC 7616 `WWW-Authenticate` challenge parser, plus `answer` on a parsed result |
| `tls-cert-decompress.fuzz.js` | `pki.tls.decompressCertificate` + `parseCertificateMessage` (RFC 8879) |
| `jose-parse.fuzz.js`          | `pki.jose.parseJson` + `base64url.decode` + the JWS profile walk |
| `acme-object.fuzz.js`         | the `pki.acme` resource-object validators + `identify` + `parseAriCertId` |

### Reporting surfaces

| File                       | Target                                                |
| -------------------------- | ----------------------------------------------------- |
| `inspect-cert.fuzz.js`     | `pki.inspect.certificate`                             |
| `lint-certificate.fuzz.js` | `pki.lint.certificate`                                |

## The contract every harness holds

Each harness exports a `fuzz(data)` function the engine drives with mutated
bytes. The contract for every target is the same: decoding or parsing
attacker-controlled bytes may only succeed or throw a `pki.errors.PkiError`
(`Asn1Error`, `OidError`, `CertificateError`, and the rest of the taxonomy). The
harness catches that class and returns normally. Any other outcome escapes as a
finding — a `RangeError`, a stack overflow from unbounded recursion, a bare
`TypeError`, a hang — and libFuzzer records the reproducer and persists it in the
corpus so future runs catch the regression.

`pki.lint.certificate` is the one exception, since its data path returns a
`fatal` finding rather than throwing; its harness asserts that instead.

## Seed corpora

Per-target seed corpora live in `fuzz/<name>_seed_corpus/`. Each file is a
single seed input. The build script zips them at compile time, and the CI
workflow passes the directory to jazzer as the starting corpus. Every format
seed is also a DER SEQUENCE, so the codec target benefits from the same samples.
Add new seeds whenever a real-world input class is not covered: raw attack
payloads, regression inputs from past bug fixes, and the like.

Only these curated seeds are committed. libFuzzer writes the inputs it discovers
back into the corpus directory during a local run, and those generated entries
are not tracked, so drop new seeds in by hand.

## Run locally

Pure-Node mode, with no Docker and no coverage guidance, is useful for a sanity
check on a harness edit:

```sh
npm install                                             # once, in fuzz/
npx --yes @jazzer.js/core fuzz/asn1-der.fuzz.js -- -max_total_time=60
npx --yes @jazzer.js/core fuzz/x509-parse.fuzz.js -- -max_total_time=60
```

The seed corpus is discovered automatically when passed as a directory argument:

```sh
npx --yes @jazzer.js/core fuzz/asn1-der.fuzz.js fuzz/asn1-der_seed_corpus -- -runs=0
```

## Scope

These harnesses are a dev-only tool. `fuzz/package.json` pins `@jazzer.js/core`
as a `devDependency` of the harness workspace alone. It is never a runtime
dependency of `@blamejs/pki`, which ships zero npm runtime dependencies.
