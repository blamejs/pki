# Changelog

All notable changes to `@blamejs/pki` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.8 — 2026-07-05

A PKCS#10 certification-request parser joins the pki.schema family.

### Added

- pki.schema.csr.parse — a PKCS#10 CertificationRequest parser per RFC 2986. It turns a DER Buffer or a 'CERTIFICATE REQUEST' PEM string into a structured object: version, subject distinguished name, subjectPublicKeyInfo, the requested attributes (each with its type OID, resolved name, and raw-DER values), and the signatureAlgorithm / signatureValue over the CertificationRequestInfo — with the raw certificationRequestInfoBytes returned for signature verification. It composes the shared schema engine and PKIX sub-schemas (AlgorithmIdentifier, Name, SubjectPublicKeyInfo), so a certification request inherits the identical fail-closed structural rules and a malformed request throws a typed CsrError (csr/*); a leaf-level codec fault surfaces as asn1/*. The version must be v1 (INTEGER 0), the [0] IMPLICIT attributes element is mandatory, and each attribute's values SET must be non-empty. pki.schema.parse now detects and routes certification requests, and pki.schema.all() lists it alongside crl and x509. pki.schema.csr.pemDecode / pemEncode handle the PEM envelope.
- pki.asn1.read.enumerated — reads an ENUMERATED value from a decoded node (the same content rules as an INTEGER), the counterpart to the now-strict pki.asn1.read.integer.

### Security

- pki.asn1.read.integer now rejects an ENUMERATED-tagged node. INTEGER and ENUMERATED share DER content encoding, so an INTEGER-pinned field — a certificate or certification-request version, a serial number, or a cRLNumber — mis-encoded as ENUMERATED was previously decoded as though it were the INTEGER, a type confusion that let malformed DER parse where a conformant reader rejects it. read.integer is now strict on the tag, and ENUMERATED values are read with the new pki.asn1.read.enumerated. Certificate, CRL, and certification-request parsing reject these inputs fail-closed.
- SubjectPublicKeyInfo is now required to be a universal SEQUENCE across the certificate and certification-request parsers — a context-tagged or SET-tagged constructed node carrying a well-formed algorithm and key is no longer accepted as an SPKI.
- SET OF components are now required to be in ascending DER order (X.690 §11.6) wherever the schema declares a SET OF — a relative distinguished name, and a certification request's attributes and attribute values. A non-canonical, unsorted encoding is rejected fail-closed.

## v0.1.7 — 2026-07-04

A unified pki.schema family: the structure-schema engine, the X.509 parser, a new CRL parser, and a detect-and-route orchestrator.

### Added

- pki.schema.crl.parse — an X.509 CRL (CertificateList) parser per RFC 5280 §5. It turns a DER Buffer or an 'X509 CRL' PEM string into a structured object: version, issuer distinguished name, thisUpdate / nextUpdate as real Dates, the ordered list of revoked certificates (serial number + hex + revocation date + entry extensions), and the CRL extensions — with the cRLNumber, reasonCode, and invalidityDate values decoded and the raw tbsCertList bytes returned for signature verification. It composes the same schema engine and shared PKIX sub-schemas (AlgorithmIdentifier, Name, Extension) as the certificate parser, so the CertificateList inherits the identical fail-closed structural rules (bounds-checked positional reads, the signature-algorithm agreement, non-empty issuer, extension uniqueness, the v2-only version rule).
- pki.schema.parse — a detect-and-route entry point: hand it DER or PEM and it identifies which registered PKI format the bytes encode (certificate vs CRL) and routes to that member's parser. pki.schema.all() enumerates the registered formats.

### Changed

- The schema engine and the per-format parsers are reorganized under one pki.schema namespace. pki.x509.parse is now pki.schema.x509.parse (and .pemDecode / .pemEncode likewise), and the structure-schema engine pki.asn1.schema is now pki.schema.engine. pki.asn1 remains the strict DER codec (decode / encode / build / read / TAGS). This is a breaking rename with no compatibility shim; see MIGRATING. The schema engine also gained a universal-tag optional-field recognizer, which the CRL's bare version / nextUpdate / revokedCertificates fields require.

### Migration

- Replace pki.x509.parse(...) with pki.schema.x509.parse(...); pki.x509.pemDecode / pemEncode become pki.schema.x509.pemDecode / pemEncode.
- Replace pki.asn1.schema (the structure-schema engine) with pki.schema.engine. pki.asn1 is unchanged for the DER codec (pki.asn1.decode / encode / build / read / TAGS).

## v0.1.6 — 2026-07-04

A declarative ASN.1 structure-schema engine; the X.509 parser is rebuilt on it.

### Added

- pki.asn1.schema — a declarative ASN.1 structure-schema engine. A schema is plain data built from combinators (seq / field / optional / explicit / trailing / seqOf / setOf / setOfUnique / choice, plus the value leaves oidLeaf / integerLeaf / boolean / octetString / bitString / any / decode / time); pki.asn1.schema.walk(schema, node, ctx) interprets it against a decoded DER node under an error namespace, enforcing the structural rules — shape assertion, bounds-checked positional reads, optional / context-tagged fields in strictly increasing tag order, SET-OF uniqueness, and fail-closed typed errors — in one place. This is the shared base the certificate parser is built on and the forthcoming CRL / CMS parsers compose, so a new format is declared as data rather than hand-written.

### Changed

- pki.x509.parse is now built on the schema engine: the Certificate, tbsCertificate, and every sub-structure (AlgorithmIdentifier, Name, Validity, SubjectPublicKeyInfo, Extensions) are declared as schemas and walked. Every valid certificate parses to the same result as before, and every malformed certificate is still rejected — the full existing test suite passes unchanged. The certificate's structural rules (positional bounds, the trailing-field grammar, extension uniqueness, the signature-algorithm agreement) now live in one auditable place instead of a hand-written decoder, and the format is structurally incapable of the positional-read and duplicate-field bug classes. The parser now validates the full certificate structure before applying cross-field checks, so a certificate carrying more than one defect at once may be rejected with a different (still fail-closed) error than a prior release reported.

## v0.1.5 — 2026-07-04

Container healthcheck honors WIKI_PORT; release-tooling supply-chain hardening.

### Fixed

- The example wiki container's HEALTHCHECK now probes the port from WIKI_PORT (defaulting to 3009) rather than a hardcoded 3009, so overriding WIKI_PORT at runtime no longer leaves the container reporting unhealthy while the server is serving on the configured port.

### Security

- The CI secret-scan gate now fetches the gitleaks binary over authenticated requests and verifies it against the checksums file published in the same release before executing it, so a corrupted or tampered download fails closed instead of running as the gate. Tracking the latest release keeps detection rules current.
- The release-container workflow validates that the base image resolved to a well-formed sha256 digest before building against it, so a failed resolution can no longer silently produce an unpinned base — the scanned image is always the published one.
- The workflow-security audit re-runs when its own configuration file changes, so an edit that would suppress a finding is itself audited.

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
