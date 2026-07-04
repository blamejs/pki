# Changelog

All notable changes to `@blamejs/pki` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.0 — 2026-07-04

Initial foundation — a PQC-first WebCrypto engine, a strict DER codec,
an OID registry, and X.509 certificate parsing.

### Added

- **`pki.webcrypto`** — a zero-dependency W3C Web Cryptography API
  (`Crypto` / `SubtleCrypto` / `CryptoKey`) built on Node's native
  `node:crypto`. PQC-first without being PQC-only: ML-DSA-44/65/87 and
  SLH-DSA signatures sit alongside the full classical set —
  RSASSA-PKCS1-v1_5, RSA-PSS, RSA-OAEP, ECDSA, ECDH, Ed25519/Ed448,
  AES-GCM/CBC/CTR/KW, HMAC, HKDF, PBKDF2, and the SHA family (including
  legacy SHA-1) — plus ML-KEM key generation. Every key and signature it
  emits is OpenSSL/NSS-interoperable.
- **`pki.asn1`** — a strict, fail-closed DER decoder and canonical
  encoder with a navigable node tree, typed readers (integer, boolean,
  OID, bit string, octet string, time, string), and value builders. The
  decoder rejects indefinite length, non-minimal length/integer/OID
  encodings, and trailing bytes, and enforces size and depth caps.
- **`pki.oid`** — a two-way OID ↔ name registry with dotted/arc
  conversion, seeded with the RFC 5280 attribute types and extensions,
  the classical signature/public-key/digest algorithms, and the NIST
  post-quantum arcs (ML-DSA, ML-KEM, SLH-DSA).
- **`pki.x509.parse`** — parse DER or PEM X.509 certificates into
  structured, validated fields: version, serial, signature algorithm,
  issuer/subject distinguished names, validity window as `Date` values,
  subject public-key info, and the extension list. The exact
  `tbsCertificate` bytes are exposed for downstream signature
  verification.
- **`pki.C`** — functional scale constants (`C.TIME.*`, `C.BYTES.*`) and
  shared codec limits.
- **`pki.errors`** — a `PkiError` taxonomy with a `defineClass` factory
  and stable `domain/reason` codes.
- **`pki`** — a command-line front-end (`version`, `oid`, `parse`).

### Security

- The DER decoder is fail-closed: non-DER shapes are rejected and
  size/depth caps are enforced before the parser walks the input, so a
  hostile length prefix cannot become a decoder denial-of-service.
- The crypto engine is fail-closed: an unknown algorithm, curve, or
  format is rejected rather than silently downgraded, and every
  sign/verify path returns a real verdict or throws.
