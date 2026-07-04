# Changelog

All notable changes to `@blamejs/pki` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.4 — 2026-07-04

The ASN.1 codec's universal-type metadata moves to a single descriptor registry.

### Changed

- The ASN.1/DER codec's universal-type metadata is now defined once in a descriptor registry (each entry carries the type's tag and its required DER encoding form). pki.asn1.TAGS, the primitive-only set (a type DER requires primitive, encoded constructed, is rejected) and the constructed-only set (a SEQUENCE/SET encoded primitive is rejected) are all derived from it, so registering a universal type is a single data entry. This is an internal refactor: the public surface and every decode/encode result are unchanged, and it lays the groundwork for schema-driven format parsers.

## v0.1.3 — 2026-07-04

WebCrypto EC key import validates the curve against the key material.

### Security

- pki.webcrypto.subtle.importKey now derives an imported EC key's named curve from the key material and enforces it across the spki, pkcs8 and jwk formats. Previously it trusted the caller-supplied namedCurve without checking it against the key, so a key on an unsupported curve (for example secp256k1) imported as an approved curve, and a key on one curve could be labelled as another — an algorithm-confusion vector in which the CryptoKey's algorithm disagreed with its key material. A curve the framework does not support is now rejected (NotSupportedError) and a namedCurve that does not match the key is rejected (DataError); generateKey already enforced this, and import now matches it. The raw-key format was already validated against its declared curve and is unchanged.

## v0.1.2 — 2026-07-04

Fail-closed hardening across the DER codec, WebCrypto engine, and X.509 parser.

### Changed

- pki.oid gains registerFamily(base, members): register a whole OID arc family in one call by its shared base arc and each member's trailing leaf. The built-in registry is now declared this way, so a new object identifier is a data entry under its family rather than a re-spelled full path.
- Every primitive now declares the normative reference it is derived from (@spec) and, where it guards a known attack, the class it defends (@defends). The generated reference documentation links each citation to its source — RFC section anchors, NIST FIPS, ITU-T, W3C, CVE and CWE — so the surface is traceable to the standards it implements.

### Fixed

- pki.asn1.read.time rejects semantically invalid UTCTime/GeneralizedTime values (Feb 30, month 13, hour 25, second 60, day 00) instead of silently normalizing them, and preserves a four-digit GeneralizedTime year below 100 instead of remapping it a century, so a malformed or edge-case certificate validity window no longer parses to a shifted instant that disagrees with a strict verifier.
- The DER encoder is now symmetric with the decoder — no builder can emit DER the decoder would reject: build.utcTime rejects a year outside RFC 5280's 1950-2049 window rather than wrapping it a century, build.generalizedTime zero-pads the year to four digits, build.set orders its components as DER requires, build.integer/enumerated reject an empty or non-minimal content buffer, build.oid caps each sub-identifier, and build.ia5 rejects non-ASCII bytes.
- String decoding validates each restricted type: IA5String and VisibleString reject bytes outside their permitted range, PrintableString rejects characters outside its restricted set, and UTF8String rejects malformed UTF-8 instead of substituting the Unicode replacement character — closing a parser-differential on certificate name fields.
- BIT STRING decoding enforces DER's requirement that unused trailing bits be zero and rejects an empty BIT STRING that declares unused bits; UniversalString and BMPString decoding reject out-of-range and lone-surrogate code points with a typed Asn1Error instead of a bare RangeError.
- HMAC verify resolves false for a wrong-length signature instead of throwing, per the Web Cryptography API. AES-CTR encrypt/decrypt reject a counter length other than 128 rather than silently ignoring the parameter.
- pki.x509.parse raises a typed CertificateError (not a generic TypeError) for a truncated tbsCertificate, rejects a certificate carrying duplicate extensions (RFC 5280 §4.2), rejects a tbsCertificate with a repeated or out-of-order trailing field — a second extensions [3] wrapper (which would otherwise hide the first extension block and split duplicate extension OIDs across two wrappers past the per-extension check), or an out-of-order or unknown context field (RFC 5280 §4.1), rejects an empty issuer distinguished name (RFC 5280 §4.1.2.4) while still permitting an empty subject for the subjectAltName case, rejects an empty or non-SEQUENCE extensions field (RFC 5280 §4.1.2.9) with a typed error rather than a raw TypeError, validates the certificate version against the RFC 5280 set, and fails closed on a malformed string in a distinguished name (an invalid-UTF8 or out-of-range name value) instead of hex-escaping the invalid bytes away, so the decoder's strict string validation is enforced on the name path; a genuinely non-string attribute value (a primitive ANY-typed value, or a constructed non-string type such as a SEQUENCE) still renders as its RFC 4514 hex-encoded DER so the name stays representable.
- pki.oid.fromArcs rejects a negative or unsafe-integer arc instead of emitting a malformed OID string; the OID sub-identifier ceiling admits a 128-bit UUID-based arc; and the INTEGER ceiling admits a key at the magnitude cap with its DER sign octet.
- pki.version, pki.C.version, and the CLI now report the installed package version — the value is single-sourced from the package manifest and can no longer drift from the published release.

### Security

- The DER decoder now builds every INTEGER and OID sub-identifier in a single linear pass and refuses any that exceed a per-value byte ceiling (C.LIMITS.DER_MAX_INTEGER_BYTES / OID sub-identifier limit), before reading them. Previously these values were accumulated a byte at a time, which is quadratic in their length: a certificate carrying an oversized serial number or OID arc — well within the overall size cap — could pin a CPU for minutes. This closes a remotely-triggerable decode denial-of-service reachable through pki.x509.parse and pki.asn1.read.*.
- The DER decoder rejects a primitive-encoded SEQUENCE or SET (X.690 §8.9.1/§8.11.1 require these to be constructed) rather than producing a leaf node. Previously such input decoded to a leaf that pki.x509.parse dereferenced as a structured node, crashing with an uncaught TypeError on attacker-controlled bytes; it now fails closed with a typed error.
- The DER decoder also rejects the mirror violation — a constructed encoding of a universal primitive-only type (INTEGER, OBJECT IDENTIFIER, BOOLEAN, the restricted strings, UTCTime/GeneralizedTime, BIT/OCTET STRING), which is valid BER but not valid DER (X.690 §10.2). Previously a constructed string tag decoded to a childless node that a certificate distinguished name would hex-render, letting an invalid BER/DER name value parse despite the restricted-string content checks; it now fails closed at decode.
- pki.webcrypto.subtle.unwrapKey now enforces the 'unwrapKey' key usage on every unwrap path, including the RSA-OAEP and AES-GCM delegate paths that previously skipped it — an unwrapping key without the 'unwrapKey' usage is now rejected. deriveKey now enforces the distinct 'deriveKey' usage rather than inheriting 'deriveBits'. Both close cases where an operator-set key-usage restriction could be bypassed.
- pki.x509.parse now rejects a certificate whose outer signatureAlgorithm does not match the signature algorithm inside the signed tbsCertificate (RFC 5280 §4.1.1.2). Surfacing the two AlgorithmIdentifiers without enforcing their equality let a certificate claim one algorithm in the signed body and another in the outer wrapper — a signature-algorithm-substitution vector; the two fields must now be identical.

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
