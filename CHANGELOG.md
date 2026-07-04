# Changelog

All notable changes to `@blamejs/pki` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.2 — 2026-07-04

Fail-closed hardening across the DER codec, WebCrypto engine, and X.509 parser.

### Changed

- pki.oid gains registerFamily(base, members): register a whole OID arc family in one call by its shared base arc and each member's trailing leaf. The built-in registry is now declared this way, so a new object identifier is a data entry under its family rather than a re-spelled full path.

### Fixed

- pki.asn1.read.time rejects semantically invalid UTCTime/GeneralizedTime values (Feb 30, month 13, hour 25, second 60, day 00) instead of silently normalizing them, so a malformed certificate validity window no longer parses to a shifted instant that disagrees with a strict verifier.
- BIT STRING decoding enforces DER's requirement that unused trailing bits be zero; UniversalString and BMPString decoding reject out-of-range and lone-surrogate code points with a typed Asn1Error instead of a bare RangeError.
- HMAC verify resolves false for a wrong-length signature instead of throwing, per the Web Cryptography API.
- AES-CTR encrypt/decrypt reject a counter length other than 128 rather than silently ignoring the parameter and diverging from a conformant implementation.
- pki.x509.parse raises a typed CertificateError (not a generic TypeError) for a truncated tbsCertificate, rejects a certificate carrying duplicate extensions (RFC 5280 §4.2), and validates the certificate version against the RFC 5280 set.
- pki.oid.fromArcs rejects a negative arc instead of emitting a malformed OID string.
- pki.version, pki.C.version, and the CLI now report the installed package version — the value is single-sourced from the package manifest and can no longer drift from the published release.

### Security

- The DER decoder now builds every INTEGER and OID sub-identifier in a single linear pass and refuses any that exceed a per-value byte ceiling (C.LIMITS.DER_MAX_INTEGER_BYTES / OID sub-identifier limit), before reading them. Previously these values were accumulated a byte at a time, which is quadratic in their length: a certificate carrying an oversized serial number or OID arc — well within the overall size cap — could pin a CPU for minutes. This closes a remotely-triggerable decode denial-of-service reachable through pki.x509.parse and pki.asn1.read.*.
- pki.webcrypto.subtle.unwrapKey now enforces the 'unwrapKey' key usage on every unwrap path, including the RSA-OAEP and AES-GCM delegate paths that previously skipped it — an unwrapping key without the 'unwrapKey' usage is now rejected. deriveKey now enforces the distinct 'deriveKey' usage rather than inheriting 'deriveBits'. Both close cases where an operator-set key-usage restriction could be bypassed.

## v0.1.1 — 2026-07-04

First published release of the 0.1.x foundation.

### Changed

- First release published to npm. The toolkit surface is the 0.1.x foundation — pki.asn1 (strict DER codec), pki.oid (OID ↔ name registry), pki.x509.parse (DER/PEM certificate parsing), and pki.webcrypto (a W3C SubtleCrypto engine over node:crypto with ML-DSA/SLH-DSA signatures alongside the full classical set) — now available on npm with a SLSA provenance attestation, and served as the pkijs.com documentation container.

## v0.1.0 — 2026-07-04

Initial foundation — a PQC-first WebCrypto engine, a strict DER codec, an OID registry, and X.509 certificate parsing.

### Added

- pki.webcrypto — a zero-dependency W3C Web Cryptography API (Crypto / SubtleCrypto / CryptoKey) built on Node's native node:crypto. PQC-first without being PQC-only: ML-DSA-44/65/87 and SLH-DSA signatures sit alongside the full classical set — RSASSA-PKCS1-v1_5, RSA-PSS, RSA-OAEP, ECDSA, ECDH, Ed25519/Ed448, AES-GCM/CBC/CTR/KW, HMAC, HKDF, PBKDF2, and the SHA family (including legacy SHA-1) — plus ML-KEM key generation. Every key and signature it emits is OpenSSL/NSS-interoperable.
- pki.asn1 — a strict, fail-closed DER decoder and canonical encoder with a navigable node tree, typed readers (integer, boolean, OID, bit string, octet string, time, string), and value builders. Rejects indefinite length, non-minimal encodings, and trailing bytes, and enforces size and depth caps (X.690).
- pki.oid — a two-way OID ↔ name registry with dotted/arc conversion, seeded with RFC 5280 attribute types and extensions, the classical signature/public-key/digest algorithms, and the NIST post-quantum arcs (ML-DSA, ML-KEM, SLH-DSA).
- pki.x509.parse — parse DER or PEM X.509 certificates into structured, validated fields: version, serial, signature algorithm, issuer/subject distinguished names, validity window as Date values, subject public-key info, and the extension list, with the exact tbsCertificate bytes exposed for downstream verification.
- pki.C — functional scale constants (C.TIME.*, C.BYTES.*) and shared codec limits.
- pki.errors — a PkiError taxonomy with a defineClass factory and stable domain/reason codes.
- pki command-line front-end (version, oid, parse).

### Security

- The DER decoder is fail-closed: non-DER shapes are rejected and size/depth caps are enforced before the parser walks the input, so a hostile length prefix cannot become a decoder denial-of-service.
- The crypto engine is fail-closed: an unknown algorithm, curve, or format is rejected rather than silently downgraded, and every sign/verify path returns a real verdict or throws.
