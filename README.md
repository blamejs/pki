<div align="center">

<img src="assets/pkijs-logo.png" alt="@blamejs/pki" width="200" />

# @blamejs/pki

**A pure-JavaScript PKI toolkit that owns its stack.**

X.509, ASN.1/DER, OID, CMS, OCSP, timestamping, and PKCS formats — with an
in-house, fail-closed DER codec and a post-quantum-first algorithm registry.
No npm runtime dependencies. No TypeScript. No Web Crypto ceiling.

[![npm version](https://img.shields.io/npm/v/@blamejs/pki.svg?label=%40blamejs%2Fpki&color=2563eb)](https://www.npmjs.com/package/@blamejs/pki)
[![npm downloads](https://img.shields.io/npm/dm/@blamejs/pki.svg?color=2563eb)](https://www.npmjs.com/package/@blamejs/pki)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![node](https://img.shields.io/node/v/@blamejs/pki.svg)](https://nodejs.org)

[![CI](https://github.com/blamejs/pki/actions/workflows/ci.yml/badge.svg)](https://github.com/blamejs/pki/actions/workflows/ci.yml)
[![CodeQL](https://github.com/blamejs/pki/actions/workflows/codeql.yml/badge.svg)](https://github.com/blamejs/pki/actions/workflows/codeql.yml)
[![Fuzzing](https://github.com/blamejs/pki/actions/workflows/cflite_batch.yml/badge.svg)](https://github.com/blamejs/pki/actions/workflows/cflite_batch.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/blamejs/pki/badge)](https://scorecard.dev/viewer/?uri=github.com/blamejs/pki)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13562/badge)](https://www.bestpractices.dev/projects/13562)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/spec/v1.0/levels#build-l3)

[![Zero runtime deps](https://img.shields.io/badge/runtime%20deps-0-2ea043)](#security-posture)
[![PQC-first](https://img.shields.io/badge/crypto-PQC--first-2563eb)](#security-posture)
[![No TypeScript](https://img.shields.io/badge/TypeScript-not%20required-2ea043)](#why-this-toolkit)
[![strict DER](https://img.shields.io/badge/DER-strict%20%2F%20fail--closed-2ea043)](#security-posture)

[pkijs.com](https://pkijs.com) · [Roadmap](ROADMAP.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

</div>

---

## Why this toolkit

Most JavaScript PKI code inherits its ASN.1 parser and its algorithm coverage
from somewhere else — an external DER library with its own CVE history, or the
Web Crypto API with its limits on streaming, opaque keys, and algorithm reach.
`@blamejs/pki` owns those layers:

- **Its own DER codec.** Strict, canonical, bounded. Malformed input is rejected
  in bounded time, not walked into a stack overflow.
- **An OID-named algorithm registry.** Every algorithm, attribute, and extension
  is named through one two-way OID table (`pki.oid`), so a new signature or KEM
  algorithm — including a post-quantum one — is a registry entry, not a special
  case in `parse`. OID-driven sign/verify resolution rides the same table as the
  signing surface lands.
- **Fail-closed everywhere.** Every parse, sign, and verify path throws on
  failure. No path returns zero, a default, or partial output in place of a real
  verdict.
- **Zero dependencies in your `package.json`.** The cryptography runs on Node's
  built-in `node:crypto` — the full classical set plus post-quantum ML-DSA and
  SLH-DSA signatures via the platform OpenSSL 3.5. ML-KEM key generation is
  available today, with KEM encapsulation on the roadmap. Nothing is vendored,
  nothing is installed; `npm audit` has nothing to say because there is no
  dependency tree.

## Install

```sh
npm i @blamejs/pki
```

Requires Node.js 24.18+ (runs on the shipped runtime — no build step, no
transpilation).

```js
var pki = require("@blamejs/pki");
```

## Quickstart

### Parse an X.509 certificate

`pki.schema.x509.parse` accepts a DER `Buffer` or a PEM string/Buffer and returns a
fully-decoded, validated certificate — distinguished names rendered and
structured, the validity window as real `Date`s, algorithms and extensions
named through the OID registry, and the exact signed `tbsBytes` for a downstream
verifier.

```js
var pki = require("@blamejs/pki");
var fs  = require("node:fs");

var pem  = fs.readFileSync("cert.pem", "utf8");
var cert = pki.schema.x509.parse(pem);

cert.subject.dn;                    // "CN=example.com, O=Example Org, C=US"
cert.issuer.dn;                     // "CN=example.com, O=Example Org, C=US"
cert.serialNumberHex;              // "7057e1ebeec2e5f7…"
cert.signatureAlgorithm.name;      // "sha256WithRSAEncryption"
cert.subjectPublicKeyInfo.algorithm.name;  // "rsaEncryption"
cert.validity.notAfter;            // Date — 2027-07-04T07:16:15.000Z

cert.extensions.forEach(function (ext) {
  ext.name;      // "subjectKeyIdentifier" (or null when the OID is unknown)
  ext.critical;  // boolean
  ext.value;     // Buffer — the raw extnValue OCTET STRING contents
});
```

Malformed bytes throw a typed error rather than returning a half-parsed object:

```js
try {
  pki.schema.x509.parse(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]));
} catch (e) {
  e.constructor.name;  // "CertificateError"
  e.code;              // e.g. "x509/not-a-certificate" — stable domain/reason string
}
```

### Convert PEM ↔ DER

```js
var der = pki.schema.x509.pemDecode(pem, "CERTIFICATE");   // Buffer of DER bytes
var out = pki.schema.x509.pemEncode(der, "CERTIFICATE");   // 64-column PEM string
```

### Decode and build ASN.1 / DER directly

The codec under every structure is public. Decode returns a zero-copy node tree;
the builders emit canonical DER.

```js
// Build a canonical-DER SEQUENCE, then decode it back.
var der = pki.asn1.build.sequence([
  pki.asn1.build.oid("2.5.4.3"),          // commonName
  pki.asn1.build.utf8("example.com"),
]);

var node = pki.asn1.decode(der);
node.tagNumber === pki.asn1.TAGS.SEQUENCE;   // true
node.children.length;                        // 2
pki.asn1.read.oid(node.children[0]);         // "2.5.4.3"
pki.asn1.read.string(node.children[1]);      // "example.com"
```

The decoder is strict by construction — non-DER shapes are refused, not
tolerated:

```js
try {
  pki.asn1.decode(Buffer.from([0x30, 0x80, 0x00, 0x00]));  // indefinite length
} catch (e) {
  e.constructor.name;  // "Asn1Error"
  e.code;              // "asn1/indefinite-length"
}
```

Size and depth are bounded before a byte is walked; override the caps per call
when you need to:

```js
pki.asn1.decode(der, { maxBytes: pki.C.BYTES.mib(4), maxDepth: 32 });
```

### Resolve object identifiers

Every algorithm, attribute type, and extension is named by an OID. The registry
is a two-way map, seeded with the RFC 5280 set, the classical algorithm set, and
the NIST post-quantum arcs (ML-DSA, ML-KEM, SLH-DSA).

```js
pki.oid.name("1.2.840.113549.1.1.11");  // "sha256WithRSAEncryption"
pki.oid.byName("sha256");               // "2.16.840.1.101.3.4.2.1"
pki.oid.toArcs("2.5.4.3");              // [2, 5, 4, 3]

// Extend it with your own arc:
pki.oid.register("1.3.6.1.4.1.99999.1", "acmeCorpExtension");
```

### Sign with post-quantum ML-DSA — or any classical algorithm

`pki.webcrypto` is a standard W3C WebCrypto (`SubtleCrypto`) engine over
`node:crypto`. The post-quantum suite lives in the same API as RSA, ECDSA, and
EdDSA — pick the algorithm, the rest is identical:

```js
var subtle = pki.webcrypto.subtle;
var data   = Buffer.from("sign me");

// FIPS 204 ML-DSA-65 — a post-quantum signature.
var kp  = await subtle.generateKey({ name: "ML-DSA-65" }, true, ["sign", "verify"]);
var sig = await subtle.sign({ name: "ML-DSA-65" }, kp.privateKey, data);
var ok  = await subtle.verify({ name: "ML-DSA-65" }, kp.publicKey, sig, data); // true

// The classical set — ECDSA, RSA-PSS, Ed25519, AES-GCM, ECDH, HKDF, … — is the
// same call shape, and every key it exports is OpenSSL/NSS-interoperable.
```

## What ships today

The core codec and certificate-reading surface are here and stable. Everything
is callable today; nothing below is a stub.

| Namespace | What it does |
|---|---|
| `pki.asn1` | Strict, bounded DER codec — `decode` (zero-copy node tree), `encode`, `build.*` canonical-DER value builders, `read.*` typed readers, `TAGS`, OID-content encode/decode |
| `pki.cbor` | Strict, bounded RFC 8949 deterministic CBOR codec — `decode` (zero-copy node tree) + `read.*` typed leaf readers incl. the keyed map lookup `read.mapGet` (text or COSE-label integer key, the map's major type asserted in the accessor), fail-closed on every non-canonical shape (indefinite length, non-minimal argument, unsorted / duplicate map keys, non-shortest float, trailing bytes) |
| `pki.oid` | Two-way OID ↔ name registry — `name`, `byName`, `register`, `toArcs`/`fromArcs`, `toDER`/`fromDER`; seeded with RFC 5280 + NIST PQC arcs |
| `pki.webcrypto` | A W3C WebCrypto (`SubtleCrypto`) engine over `node:crypto` — `sign`/`verify`/`encrypt`/`decrypt`/`deriveBits`/`digest`/`generateKey`/`importKey`/`exportKey` across RSA, ECDSA, ECDH, Ed25519/Ed448, AES, HMAC, HKDF, PBKDF2, SHA — **and** post-quantum ML-DSA-44/65/87 and SLH-DSA signatures, plus ML-KEM-512/768/1024 key generation and certificate/PKCS#8 import — the RFC 9935 seed / expandedKey / both private-key CHOICE is validated fail-closed, so an OpenSSL-legacy bare-seed or an internally inconsistent key is rejected with a typed error (KEM encapsulation lands with CMS KEM-decrypt). Zero-dependency, OpenSSL-interoperable |
| `pki.schema` | The schema family — `parse` detects which PKI format DER / PEM encodes and routes to the right parser, `all` enumerates the registered formats, and the engine + per-format members are grouped here |
| `pki.schema.x509` | Parse DER / PEM certificates into structured, validated fields, with named + partly-decoded extensions — including the RFC 3739 / ETSI EN 319 412-5 qualified-certificate `qcStatements` (EU-qualified declaration, reliance limit, QSCD flag, certificate type, retention, PDS URLs, country of qualification; unknown statements preserved opaque), fail-closed — `parse`, `pemDecode`, `pemEncode` |
| `pki.schema.c509` | Parse C509 CBOR-encoded certificates (draft-ietf-cose-cbor-encoded-cert) — the compact CBOR profile of X.509, decoded fail-closed under deterministic CBOR; an explicit `parse` call (CBOR, not DER, so not auto-routed) |
| `pki.schema.crl` | Parse DER / PEM X.509 CRLs per RFC 5280 §5 — revoked serials with real-`Date` revocation times, named + partly-decoded extensions, fail-closed — `parse`, `pemDecode`, `pemEncode` |
| `pki.schema.csr` | Parse DER / PEM PKCS#10 certification requests per RFC 2986 — subject DN, public key, requested attributes, signature, fail-closed — `parse`, `pemDecode`, `pemEncode` |
| `pki.schema.pkcs8` | Parse DER / PEM PKCS#8 private keys per RFC 5208 / 5958 — algorithm, raw key bytes, attributes, optional public key, fail-closed; encrypted keys recognized (not decrypted) — `parse`, `parseEncrypted`, `pemDecode`, `pemEncode` |
| `pki.schema.cms` | Parse DER / PEM CMS per RFC 5652 / 5083 / 9629 — SignedData (§5, signer infos + raw signed-attribute bytes for external verification), EnvelopedData (§6, all five RecipientInfo kinds incl. RFC 5753 key-agreement and RFC 9629 KEM recipients with ML-KEM validation), EncryptedData (§8), AuthenticatedData (§9, MAC surface + raw `authAttrsBytes`), and AuthEnvelopedData (RFC 5083, with RFC 5084 AES-GCM/CCM parameter validation); §11 attribute placement enforced, countersignatures validated recursively, certificates / CRLs validated against the closed CHOICE sets and kept raw, every result tagged `contentTypeName`, fail-closed — `parse`, `pemDecode`, `pemEncode` |
| `pki.schema.ocsp` | Parse DER / PEM OCSP requests and responses per RFC 6960 — per-certificate status (good / revoked / unknown), responder identity, raw tbs bytes for external verification, certificates kept raw, fail-closed; non-basic response types recognized (not decoded) — `parseRequest`, `parseResponse`, `pemDecode`, `pemEncode` |
| `pki.schema.tsp` | Parse DER / PEM RFC 3161 timestamp requests, responses, and tokens — the TimeStampReq a client sends (imprint, requested policy, nonce, certReq), the TSTInfo payload (imprint, genTime with sub-second precision, serial, nonce, accuracy), the status-to-token coupling, and the token wrapper composed over CMS with the single-signer rule, fail-closed — `parse`, `parseRequest`, `parseResponse`, `parseTstInfo`, `parseToken`, `pemDecode`, `pemEncode` |
| `pki.schema.attrcert` | Parse DER / PEM RFC 5755 attribute certificates — the holder and issuer identities (validated GeneralNames), the validity window (real `Date`s), the privilege attributes (role / group / clearance) and extensions, with the raw signed region for a verifier; the obsolete v1 form is recognized and deferred, fail-closed — `parse`, `pemDecode`, `pemEncode` |
| `pki.schema.crmf` | Parse DER / PEM RFC 4211 certificate request messages (CertReqMessages — the CMP / EST enrollment body) — the requested-certificate template (subject, public key, validity, extensions), proof-of-possession, and registration controls, with the raw `CertRequest` region a POP verifier hashes; names dual-accepted (IMPLICIT and EXPLICIT), fail-closed — `parse`, `pemDecode`, `pemEncode` |
| `pki.schema.pkcs12` | Parse DER / BER / PEM RFC 7292 PKCS#12 (PFX) stores — key bags via the PKCS#8 parser, shrouded keys (algorithm surfaced, ciphertext opaque), cert / CRL / secret bags raw and byte-exact, encrypted and enveloped safes structurally via CMS, `friendlyName` / `localKeyId` decoded, and the exact MAC byte range (`macedBytes`) plus RFC 9579 PBMAC1 recognition for external verification; BER accepted exactly where §4.1 requires it, fail-closed — `parse`, `pemDecode`, `pemEncode` |
| `pki.schema.cmp` | Parse DER / PEM RFC 9810 Certificate Management Protocol messages (PKIMessage) — the header (version, sender / recipient incl. the anonymous NULL-DN, nonces, transaction id, general info), the 27-arm body (certificate requests via the CRMF parser, an encrypted certificate's EnvelopedData via CMS, response / revocation / confirmation / error / support / polling arms structural, the rest raw), and the exact `headerBytes` / `bodyBytes` slices an external verifier reconstructs the protected part from; the CMP-before-OCSP dispatch order is enforced, fail-closed — `parse`, `pemDecode`, `pemEncode` |
| `pki.schema.csrattrs` | Parse DER EST CSR Attributes (`CsrAttrs`, RFC 8951 §3.5 / RFC 9908) — the `AttrOrOID` items a server sends to shape an enrollment: bare OIDs, attributes with raw values, and decoded views of the RFC 9908 meaningful types (extension requests, EC/RSA key-type conventions, the certification-request-info template). Unknown types tolerated (surfaced raw), fail-closed on structure and the RFC 9908 semantic MUSTs — `parse` |
| `pki.est` | RFC 7030 / 8951 / 9908 Enrollment over Secure Transport — the transport-agnostic client codecs (the RFC 8951 base64 transfer codec, blind to Content-Transfer-Encoding; the `multipart/mixed` splitter), the certs-only + serverkeygen response validators layered over CMS, the enroll-attribute builders (channel-binding challengePassword, out-of-band key identifiers, SMIMECapabilities, the template-priority enroll plan), and the HTTP response classifier (202 Retry-After surfaced, never slept on; 204/404 on csrattrs a "none available" verdict). No socket, fail-closed — `transferDecode`/`transferEncode`, `parseCertsOnly`, `findIssuedCert`, `parseServerKeygenResponse`, `classifyResponse`, `paths`, and the builders |
| `pki.jose` | RFC 7515 Flattened JWS + RFC 7638 JWK thumbprints — `sign` / `verify` run a Flattened JWS against declarative profiles (ACME outer, EAB inner, keyChange inner) that carry the required/forbidden header rules as data; `base64url` is the strict RFC 4648 §5 codec (padding, non-alphabet, and non-canonical trailing bits rejected); `parseJson` is a bounded reader that refuses duplicate members at any depth; `thumbprint` is the RFC 7638 / 8037 / 9964 canonical digest. The algorithm registry binds each `alg` to its key type (ES/RS/PS/EdDSA/ML-DSA), so `alg:none`, an RS256→HS256 key confusion, and an all-zero ECDSA signature have no code path; `assertPublicJwk` refuses a JWK carrying private material so an exported private key is never published — `sign`, `verify`, `base64url`, `parseJson`, `thumbprint`, `assertPublicJwk` |
| `pki.acme` | RFC 8555 / 8737 / 8738 / 9773 ACME message layer over `pki.jose` — resource-object validators (closed status enums, conditional-required fields, unknown fields ignored), the three §7.1.6 state machines, request builders (newAccount + EAB, newOrder + `replaces`, finalize with CSR identifier-set match and account-key-reuse rejection, challenge responses, deactivation, revokeCert in both key modes, the keyChange nested JWS, POST-as-GET), the http-01 / dns-01 / tls-alpn-01 challenge computations, the dns/ip identifier validators, and the ARI certID (serial sign-padding preserved). A message layer, not an HTTP client — transport-injectable, fail-closed — `validate`, `identify`, `assertTransition`, the builders, `keyAuthorization`, `http01`, `dns01`, `tlsAlpn01Extension`, `verifyTlsAlpn01`, `ariCertId` |
| `pki.schema.smime` | Decode S/MIME ESS signed-attribute values (RFC 5035 / RFC 8551) — `parseSigningCertificate` / `parseSigningCertificateV2` bind a signature to its signing certificate (cert hash, hash algorithm, issuer `GeneralNames` + serial), `parseSmimeCapabilities` decodes the ordered capability list, and `decodeAttribute` OID-dispatches a CMS attribute (enforcing the single-value rule, recognize-and-defer for unknown types). A companion decoder for CMS signed attributes, not an auto-routed format, fail-closed — `parseSigningCertificate`, `parseSigningCertificateV2`, `parseSmimeCapabilities`, `decodeAttribute` |
| `pki.schema.engine` | The declarative ASN.1 structure-schema engine every format parser composes — `walk` / `encode` / `embeddedDer` plus the schema combinators |
| `pki.path` | RFC 5280 §6 certification-path validation — `validate` runs the §6.1 state machine (signature chaining across RSA, ECDSA, EdDSA, ML-DSA, SLH-DSA and hybrid composite ML-DSA signatures — a composite is accepted only when **both** its post-quantum and traditional components verify; validity windows, name chaining, basic constraints and path length, key usage, name constraints, the certificate-policy tree) over an ordered path and a trust anchor, returning a structured verdict with per-check reason codes, and enforces a `pki.trust` anchor's per-purpose distrust-after dates and delegator purposes via `checkPurpose`; `crlChecker` supplies CRL-based revocation — including partitioned/sharded CRLs, whose §6.3.3 Distribution Point ↔ IDP correspondence lets a corresponding full-reason shard establish non-revocation — and `ocspChecker` supplies OCSP-based revocation (RFC 6960 — CertID binding, responder authorization, signature, currency) over the same pluggable hook. Pure and re-entrant, fail-closed — `validate`, `crlChecker`, `ocspChecker` |
| `pki.cms` | RFC 5652 §5 CMS SignedData signing + signature verification — `sign(content, signers, opts)` produces a SignedData (attached or detached, one or many signers, RSA / RSASSA-PSS / ECDSA / EdDSA, the post-quantum ML-DSA-44/65/87 (RFC 9882) and SLH-DSA (all twelve FIPS 205 sets, RFC 9814), and composite ML-DSA (pairing ML-DSA with a traditional RSA / ECDSA / EdDSA — accepted only when **both** components verify — draft-ietf-lamps-cms-composite-sigs)); it builds the signed attributes (content-type, message-digest, signing-time) as canonical DER, signs the exact §5.4 preimage, and emits a DER `Buffer` or PEM. `verify(input, opts)` parses a SignedData over the strict `pki.schema.cms` codec, locates each SignerInfo's signer certificate by its issuerAndSerialNumber or subjectKeyIdentifier, and checks the signature over the exact §5.4 preimage: when signed attributes are present it confirms the message-digest attribute equals the content digest and verifies over the DER re-encoding of the SignedAttributes (the on-wire `[0]` tag replaced by a universal SET OF), otherwise directly over the content. It returns a per-signer verdict with the matched signer certificate; it does not chain that certificate to a trust anchor — that is the caller's step through `pki.path.validate`. **Content encryption** (RFC 5652/5083/5084/9629): `encrypt(content, recipients, opts)` produces an EnvelopedData, AuthEnvelopedData (AES-GCM, the authenticated default), or EncryptedData — recipients auto-dispatch off the certificate key to key-transport (RSAES-OAEP; v1.5 never emitted), key-agreement (ephemeral-static ECDH over P-256/384/521 with the X9.63 KDF, and X25519/X448 with HKDF), symmetric key-wrap, password (PBKDF2 + RFC 3211 PWRI-KEK), or the post-quantum ML-KEM KEMRecipientInfo (RFC 9629/9936) — one fresh content key wrapped for every recipient. `decrypt(input, keyMaterial, opts)` recovers the content through the matching arm and returns it with an `authenticated` flag; every secret-dependent failure collapses to one uniform `cms/decrypt-failed` verdict (Bleichenbacher / EFAIL / password-oracle freedom), and PKCS#1 v1.5 is decrypt-only under the RFC 3218 implicit-rejection countermeasure. **Compression** (RFC 3274): `compress(content, opts)` / `decompress(input, opts)` produce and consume a CompressedData (ZLIB, version 0, id-alg-zlibCompress); decompress bounds the uncompressed output at 16 MiB and stops before it is materialized, so a decompression bomb fails closed as `cms/decompress-too-large` — a size transform with no integrity/confidentiality (RFC 8551 §2.4.5). Fail-closed with typed `cms/*` errors — `sign`, `verify`, `encrypt`, `decrypt`, `compress`, `decompress` |
| `pki.smime` | RFC 8551 S/MIME message assembly, verification, encryption, and compression over the CMS layer — `sign(content, signers, opts)` wraps a MIME entity as a signed S/MIME message in either form: `multipart/signed` (clear-signed — the content stays readable in any MUA, a detached CMS SignedData rides alongside as `application/pkcs7-signature` with a matching `micalg`) or `application/pkcs7-mime; smime-type=signed-data` (opaque — the whole entity is a base64 CMS SignedData). The signed bytes are the entity's RFC 8551 §3.1.1 canonical form (CRLF line endings); `verify(message, opts)` unwraps both forms and recomputes over the same canonicalizer, so a transport that re-wraps line endings still verifies and a tampered part fails. `encrypt(content, recipients, opts)` envelopes a MIME entity as an opaque `application/pkcs7-mime` message and `decrypt(message, keyMaterial, opts)` opens one — `smime-type=authEnveloped-data` (AES-GCM, confidentiality and integrity, the default) or `smime-type=enveloped-data` (AES-CBC, confidentiality only, so `decrypt` reports `authenticated: false`, the §3.3 no-integrity caveat); the `smime-type` is derived from the CMS body, not the header, and decryption is fail-closed and oracle-free. The crypto is entirely `pki.cms.sign` / `verify` / `encrypt` / `decrypt` — any RSA / RSASSA-PSS / ECDSA / EdDSA / ML-DSA / SLH-DSA signer and any RSA-OAEP / ECDH / X25519 / X448 / AES-KW / PBKDF2 / ML-KEM recipient carries through (algorithm-agnostic). Like `cms.verify`, `verify` returns the per-signer cryptographic verdict plus the recovered content; chaining a signer to a trust anchor is the caller's `pki.path.validate` step. `compress(content, opts)` / `decompress(message, opts)` add the opaque `application/pkcs7-mime; smime-type=compressed-data; name=smime.p7z` frame (RFC 8551 §3.6, RFC 3274) — a size transform with no integrity/confidentiality (§2.4.5), decompress bounded against a bomb; the recovered content, which may itself be signed or enveloped, is returned for the caller to re-verify. Bidirectionally interoperable with `openssl smime` / `openssl cms`. Fail-closed with typed `smime/*` errors — `sign`, `verify`, `encrypt`, `decrypt`, `compress`, `decompress` |
| `pki.tsp` | RFC 3161 Time-Stamp Protocol — `sign(messageImprint, tsa, opts)` produces a TimeStampToken: a CMS SignedData (over `pki.cms.sign`) whose content is a `TSTInfo` carrying the timestamped message imprint, the TSA policy, a serial number, and `genTime` (with optional accuracy / nonce / ordering), plus the RFC 3161 §2.4.2 signing-certificate attribute binding the token to the TSA certificate (SHA-2 imprints, any `pki.cms.sign` TSA key). `request` / `parseRequest` build and parse the TimeStampReq a client sends (imprint, requested policy, nonce, certReq), `response` / `parseResponse` the TimeStampResp a TSA returns — a granted status wrapping a token, or a rejection with PKIStatus and failure info, the §2.4.2 status↔token coupling enforced in both directions. `verify(token, data, opts)` verifies a token fail-closed: the CMS signature over the exact signed bytes, the message imprint recomputed from the data, the TSTInfo content type, the ESSCertID(V2) binding to the TSA certificate, the §2.3 critical timeStamping-only extendedKeyUsage, the request nonce when used, and — with a trust anchor supplied — full certification-path validation of the TSA certificate at the token's `genTime`, returning `{ valid, genTime, serialNumber, tstInfo, … }` — `sign`, `request`, `parseRequest`, `response`, `parseResponse`, `verify` |
| `pki.ocsp` | RFC 6960 Online Certificate Status Protocol — the responder and relying-party surface. `buildRequest(query, opts)` builds an OCSPRequest for one or more `{ cert, issuer }` pairs (CertID hashed under SHA-1 by default per the RFC 5019 lightweight profile, or SHA-2; optional RFC 9654 nonce, optional requestor signature). `sign(responseData, responder, opts)` produces a signed BasicOCSPResponse over the exact `ResponseData` DER — the issuing CA directly or a delegated responder, any `pki.cms.sign` key including the post-quantum ML-DSA / SLH-DSA sets, with `good` / `revoked` (reason + time) / `unknown` per-certificate status, and `buildErrorResponse(status)` the unsigned §2.3 error (`tryLater` / `unauthorized` / …). `verify(response, opts)` verifies a response fail-closed against the same hardened gates `pki.path.ocspChecker` runs: the CertID binding, responder authorization (the issuing CA or a CA-issued delegate bearing id-kp-OCSPSigning **and** id-pkix-ocsp-nocheck, passing the full out-of-path certificate gates), the signature over `tbsResponseDataBytes`, currency (`thisUpdate`/`nextUpdate`), and the request-nonce echo — returning `{ status: "good" / "revoked" / "unknown", … }`, never a silent accept. Transport-free — `buildRequest`, `sign`, `buildErrorResponse`, `verify` |
| `pki.ct` | RFC 6962 Certificate Transparency SCTs — `parseSctList` decodes the `SignedCertificateTimestampList` a certificate or OCSP response carries in the SCT extension (a TLS-presentation-language payload inside the §3.3 double DER wrap) into per-SCT log id, exact `timestamp` (BigInt), named signature algorithm, and raw signature; `reconstructSignedData` rebuilds the exact `digitally-signed` preimage; `verifySct` verifies an SCT signature against a log's public key by reconstructing the signed data, routing an ECDSA signature through the strict DER-conformance gate, and verifying through the crypto engine — resolving true or false, and throwing a typed error on a structural fault. The producing side: `encodeSctList` builds the extension value byte-for-byte (the exact inverse of `parseSctList`) and `signSct` performs a log's signing step (rebuilding the same signed-data preimage the verifier hashes and signing it with the log's ECDSA-P-256 / RSA key). The trust surface: `parseLogList` ingests the CT log-list JSON into constraint-carrying trusted logs — recomputing each log's id as SHA-256 of its key and refusing a disagreeing id (a swapped key, §3.2), decoding the state + temporal-interval constraints — and `verifySctWithLogList` resolves the log key from an SCT's log id, enforces the state (usable/qualified/readonly trusted; retired only before retirement; pending/rejected refused) and the temporal-interval window, then delegates the signature check to `verifySct`. `verifyLogListSignature(json, signature, publicKey)` verifies the detached `log_list.sig` over the raw log-list bytes against a caller-pinned signer key (RSASSA-PKCS1-v1.5/SHA-256, EC P-256 arm; forgeable-key defenses fail closed) — cross-checked against `openssl dgst`, completing the offline log-list trust chain. Structure decoded, crypto fail-closed — `parseSctList`, `reconstructSignedData`, `verifySct`, `encodeSctList`, `signSct`, `parseLogList`, `verifySctWithLogList`, `verifyLogListSignature` |
| `pki.merkle` | RFC 6962 / RFC 9162 Merkle-tree proof verification — `leafHash` / `nodeHash` / `emptyRootHash` build the domain-separated (0x00 leaf / 0x01 node) SHA-256 tree hashes; `verifyInclusion` folds an audit proof back to a root and `verifyConsistency` reconstructs both the old and new root (the append-only guarantee), each constant-time-compared to a trusted checkpoint root. Fail-closed on bad geometry, sync hashing, transport-free — `leafHash`, `nodeHash`, `emptyRootHash`, `verifyInclusion`, `verifyConsistency` |
| `pki.trust` | Mozilla / CCADB trust-store ingestion — `parseCertdata` reads the NSS `certdata.txt` object stream and `parseCcadbCsv` the CCADB CSV export into one identical constraint-carrying anchor shape: the per-purpose trust bits (only `CKT_NSS_TRUSTED_DELEGATOR` grants) and the per-purpose distrust-after dates the bare root list omits. Certificate and trust objects pair by byte-exact issuer + serial (never adjacency) and are cross-checked against the parsed DER, so metadata can never attach to the wrong root; `anchor()` hands an entry to `pki.path.validate({ trustAnchor, checkPurpose })`. Offline, fail-closed, bounded — `parseCertdata`, `parseCcadbCsv`, `anchor` |
| `pki.shbs` | Stateful hash-based signature **verification** — HSS/LMS (RFC 8554), carried in X.509 by RFC 9802 and CMS by RFC 9708, profiled by NIST SP 800-208 (CNSA 2.0 firmware signing). `verify` checks an HSS signature (every level must pass) and `verifyLms` a single-tree LMS, over the raw public-key / signature blobs the parsers already surface. Pure public-input SHA-256 / SHAKE256 hashing, a data-driven typecode registry, bounds-before-slice reads; a malformed blob throws a typed `ShbsError`, a well-formed-but-wrong signature returns `false`. **Verify only by design** — stateful signing needs atomic one-time-key state that belongs in an HSM — `verify`, `verifyLms` |
| `pki.hpke` | Hybrid Public Key Encryption (RFC 9180) — the encrypt-to-a-public-key primitive behind TLS ECH, MLS, and OHTTP. `setupS`/`setupR` establish a sender/recipient context (KEM encapsulation + HKDF key schedule); the context's `seal`/`open` AEAD-encrypt with a sequence-counter nonce and `export` derives further secrets; `seal`/`open` are single-shot wrappers. DHKEM (P-256, P-521, X25519, X448) × HKDF-SHA256/SHA512 × AES-GCM/ChaCha20Poly1305/export-only × all four modes, proven against the RFC 9180 Appendix A vectors. DHKEM(P-384) and HKDF-SHA384 are RFC-registered but Appendix A ships no vector for them, so they fail closed until an authoritative KAT exists. Pure composition over `node:crypto`; ML-KEM / X-Wing are a registry data-row extension pending stable drafts — `suites`, `setupS`, `setupR`, `seal`, `open` |
| `pki.sigstore` | Offline verifier for a Sigstore bundle — the exact artifact `npm publish --provenance` produces and the registry serves. `verifyBundle` composes five fail-closed legs against caller-pinned trust (Fulcio CA roots + Rekor log keys, never trusted from the bundle): the DSSE signature over its PAE preimage under the Fulcio leaf key; the ephemeral Fulcio certificate chain, validated as of the Rekor log time; the RFC 9162 inclusion proof folded to a Rekor-signed tree root; the log entry bound to this exact signature; and the in-toto SLSA subject digest the caller confirms against the published artifact. Zero runtime deps — reuses the X.509 parser, RFC 5280 path validator, and Merkle verifier; the net-new codecs are the DSSE PAE byte-builder and a fail-closed JSON reader. `pae`, `parseBundle`, `verifyBundle` |
| `pki.inspect` | Human-readable certificate inspection — the pure-JS equivalent of `openssl x509 -text`. `certificate(pem \| der \| parsed)` renders a familiar OpenSSL-style report: version, serial, signature algorithm, issuer/subject distinguished names, validity, public-key details (curve or modulus size + the raw point/modulus), every decoded extension with its critical flag, and the signature. Built over the strict parser and the two-way OID registry, so it names extension and algorithm OIDs an OpenSSL build shows only as raw bytes. No OpenSSL dependency; the format is stable and OpenSSL-familiar rather than pinned to one OpenSSL version; a malformed extension falls back to a hex dump rather than throwing — `certificate` |
| `pki.webauthn` | WebAuthn / passkey attestation verification — offline trust evaluation of a W3C WebAuthn (Level 3) attestation. `parseAttestationObject(bytes)` decodes the CBOR attestation object + authenticatorData + COSE credential key over the strict `pki.cbor` codec; `verify(attestationObject, clientDataHash, opts)` checks the attestation-statement signature and each format's structural bindings for **packed / tpm / android-key / apple / fido-u2f / none** — the x5c leaf key, the apple nonce, the tpm `certInfo` Name/`extraData` over the `pubArea`, the android `KeyDescription`, the fido-u2f `verificationData` — binding the credential public key to each attestation (via the signed authenticatorData for packed/fido-u2f, or a cert/`pubArea`-key equality check for android-key/apple/tpm) and enforcing each leaf's certificate requirements. The credential-key check covers the full WebAuthn COSE algorithm set — ES256/384/512, RS256/384/512, PS256, EdDSA (Ed25519), and the RFC 9864 fully-specified identifiers **ESP256/384/512, Ed25519, and Ed448** — validating the public-key point on its curve, rejecting the compressed EC point form, and enforcing a minimally-encoded DER ECDSA signature. A verifier, not a ceremony client; fail-closed with typed `webauthn/*` errors. Chaining the returned trust path to a pinned root (and aaguid→root via FIDO MDS) is the caller's step through `pki.path.validate` — `parseAttestationObject`, `verify` |
| `pki.lint` | Certificate linting — the zlint / pkilint of JavaScript. `certificate(pem \| der \| parsed, opts)` walks a parsed certificate and emits graded, advisory findings — each with a stable id, a severity (`fatal` > `error` > `warn` > `notice`), a source, a spec-clause citation, and a message — against the RFC 5280 profile plus a representative CA/Browser Forum TLS BR subset (serial sign/size, validity ordering + the the SC081v3 reducing validity schedule, keyCertSign coherence, unknown critical extensions, empty-subject SAN, SKI/AKI presence, SAN required + CN-in-SAN, dNSName syntax, serverAuth EKU, weak keys). Unlike every other entry the DATA path never throws: hostile bytes return a `fatal` `lint/unparseable` finding (with the strict parser's code) so a whole directory lints without a try/catch; only config-time misuse throws a typed `LintError`. `certificate`, `rules`, `profiles` |
| `pki.C` / `pki.constants` | Version-stable constants — functional scale helpers (`C.TIME.*`, `C.BYTES.*`), codec `LIMITS`, `version` |
| `pki.errors` | The `PkiError` taxonomy — `defineClass` plus `ConstantsError` / `Asn1Error` / `OidError` / `PemError` / `CertificateError` / `CrlError` / `CsrError` / `Pkcs8Error` / `CmsError` / `OcspError` / `TspError` / `AttrCertError` / `CrmfError` / `Pkcs12Error` / `CmpError` / `PathError` / `CtError` / `JoseError` / `AcmeError` / `WebauthnError` / `LintError`, each carrying a stable `code` in `domain/reason` form |
| `pki` CLI | `pki version`, `pki oid <dotted\|name>`, `pki parse <cert>`, `pki inspect <cert>`, `pki lint <cert>`, `pki convert <file> --to der\|pem`, `pki verify <cert>... --anchor <cert>`, `pki sign <file> --cert <c> --key <k>` |

### CLI

```sh
pki version                              # the installed @blamejs/pki version
pki oid 1.2.840.113549.1.1.11           # sha256WithRSAEncryption
pki oid sha256                           # 2.16.840.1.101.3.4.2.1
pki parse cert.pem                       # structured JSON summary of a certificate
pki inspect cert.pem                     # openssl x509 -text style report (pki.inspect)
pki lint cert.pem                        # graded conformance findings; exit 1 on an error
pki lint cert.pem --json --profile cabf-tls
pki convert cert.pem --to der > cert.der # transcode between PEM and DER (round-trips)
pki verify leaf.pem --anchor root.pem --time 2026-01-01T00:00:00Z   # RFC 5280 path validation
pki sign msg.txt --cert signer.pem --key signer-key.pem --out msg.p7s   # CMS SignedData (pki.cms.sign)
pki sign msg.txt --cert signer.pem --key signer-key.pem --detached --pem # detached, PEM to stdout
```

`inspect`/`lint`/`convert`/`verify`/`sign` are thin front-ends over `pki.inspect`, `pki.lint`, the
per-format PEM codecs, `pki.path.validate`, and `pki.cms.sign` — the CLI never does anything the
library API can't. `lint` exits non-zero when any `error`/`fatal` finding is present; `verify`
exits non-zero when the path does not validate; `sign` reads a PKCS#8 DER/PEM private key and its
certificate and writes a DER (or `--pem`) SignedData to `--out` or stdout.

### What's coming

Certificate build/sign/verify, CMS AuthenticatedData /
AuthEnvelopedData, PKCS#8 decryption (PBES2) / SPKI, PKCS#12 MAC verification
and bag decryption, and the post-quantum certificate and CMS surface (ML-DSA /
ML-KEM / SLH-DSA and hybrid composites) are on the roadmap and ride this same
core. See
[ROADMAP.md](ROADMAP.md) for the full plan and current status of each area, and
[CHANGELOG.md](CHANGELOG.md) for what has landed.

## Architecture

Every PKI format is a thin, declarative schema over one shared engine. A parser
declares the ASN.1 structure as data and hands it to `walk`; it never advances a
child cursor, re-checks a tag, or re-rolls PEM handling by hand. So each
structural rule — bounds-checked positional reads, optional / context-tagged
field ordering, SET-OF ascending-order and uniqueness, arity, and fail-closed
typed errors — is written **once** in the engine, and no new format can
reintroduce the bug class it prevents. Adding a format is a schema declaration
plus a documentation comment block, not new parse logic.

```
┌─ Detect + route ─────────────────────────────────────────────────────────┐
│ pki.schema.parse — inspect the DER root, route to the matching sibling   │
└──────────────────────────────────────────────────────────────────────────┘
                                     │
 ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
 │  x509  │ │  crl   │ │  csr   │ │ pkcs8  │
 └────────┘ └────────┘ └────────┘ └────────┘
 ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
 │  cms   │ │  ocsp  │ │  tsp   │ │  crmf  │
 └────────┘ └────────┘ └────────┘ └────────┘
 ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
 │ pkcs12 │ │  cmp   │ │ smime  │ │attrcert│
 └────────┘ └────────┘ └────────┘ └────────┘
                                     │  routed DER format parsers (siblings)
┌─ Protocols · trust · supply chain  (reached by explicit call) ───────────┐
│ pki.path RFC 5280 · pki.trust anchors · pki.ct SCTs · pki.hpke RFC 9180  │
│ pki.shbs HSS/LMS · pki.merkle RFC 9162 · pki.sigstore npm provenance     │
│ pki.jose · pki.acme · pki.est — compose the layers below directly.       │
└──────────────────────────────────────────────────────────────────────────┘
                                     │  every module composes ↓
┌─ Shared structure ───────────────────────────────────────────────────────┐
│ pki.schema.engine — walk + combinators (positional reads, tag order,     │
│ SET-OF uniqueness, typed errors) · the PKIX sub-schemas · and the        │
│ guard family (guard-*) — one fail-closed choke point per CVE class.      │
└──────────────────────────────────────────────────────────────────────────┘
                                     │  built on ↓
┌─ Foundation ─────────────────────────────────────────────────────────────┐
│ pki.asn1 — strict bounded DER codec · pki.cbor — deterministic CBOR ·    │
│ pki.oid — two-way PQC-seeded registry · pki.errors — PkiError taxonomy   │
│ · pki.C — version-stable LIMITS + scale constants.                       │
└──────────────────────────────────────────────────────────────────────────┘

┌─ Crypto ─────────────────────────────────────────────────────────────────┐
│ pki.webcrypto ─▶ node:crypto — a W3C SubtleCrypto engine: the            │
│ classical set + post-quantum ML-DSA / SLH-DSA + ML-KEM key generation.   │
└──────────────────────────────────────────────────────────────────────────┘
```

**Foundation.** The strict, bounded DER codec (`pki.asn1`), the two-way OID
registry (`pki.oid`), the `PkiError` taxonomy (`pki.errors`), and the
version-stable constants (`pki.C`). These have no PKI knowledge; they are the
bytes-and-names layer everything else stands on.

**Shared structure.** The declarative schema engine (`pki.schema.engine`) and the
PKIX sub-schemas it is fed — `AlgorithmIdentifier`, `Name`, `Extension`, the
bounded version reader, and the single coerce → decode → walk parse-entry that
every format's `parse` is bound to. Because input coercion, the PEM size cap, and
the DER-decode wrapping live here once, a format cannot diverge on a guard.

**Format parsers.** `x509`, `crl`, `csr`, `pkcs8`, `cms`, `ocsp`, `tsp`, `attrcert`,
`crmf`, `pkcs12`, `cmp`, `smime`, and `csrattrs` are siblings: each is a schema
declaration composed from the shared pieces, emitting its own typed
`domain/reason` error codes. `pki.schema.parse` inspects a decoded root and
detect-and-routes to the matching sibling; the detectors are mutually exclusive by
construction, so routing is unambiguous regardless of registration order.

**Protocols, trust, and supply chain.** Above the format parsers sit the domain
modules reached by explicit call rather than DER routing: `pki.path` (RFC 5280
path validation), `pki.trust` (trust anchors), `pki.ct` (Certificate Transparency
SCTs), `pki.hpke` (RFC 9180), `pki.shbs` (HSS/LMS stateful hash signatures),
`pki.merkle` (RFC 9162 transparency proofs), `pki.sigstore` (offline npm-provenance
verification), `pki.webauthn` (WebAuthn / passkey attestation verification),
`pki.cms` (RFC 5652 SignedData signing + signature verification), `pki.tsp` (RFC 3161
timestamping — requests, responses, token creation and verification), and the
`jose` / `acme` / `est` enrollment surfaces. Each composes
the shared structure, foundation, and crypto layers directly. Alongside the schema
engine, the fail-closed **guard family** (`guard-*`) centralizes each CVE-class
defense — detached-buffer re-view, resource caps, constant-time compares,
canonical-DN comparison — as one choke point a format cannot re-inline.

**Crypto.** `pki.webcrypto` is a W3C `SubtleCrypto` engine over `node:crypto`,
carrying the classical suite plus post-quantum ML-DSA / SLH-DSA signatures and
ML-KEM key generation. Sign/verify resolves algorithms through the same OID
registry the parsers read, so the signing surface and the parsing surface share
one algorithm vocabulary.

## Security posture

- **Zero npm runtime dependencies, nothing vendored.** The cryptography runs on
  Node's built-in `node:crypto`; the toolkit vendors no third-party code — a
  platform built-in ships zero bytes and stays OpenSSL-interoperable by
  construction. There is no dependency tree, transitive or vendored, to
  compromise or keep current.
- **Fail-closed DER.** The decoder rejects every non-canonical shape — indefinite
  length, non-minimal length or tag encodings, trailing bytes, over-long or
  over-deep input — with a typed `Asn1Error` before it walks the structure. Size
  and depth caps are enforced up front, so adversarial input is bounded work, not
  a stack overflow.
- **Fail-closed verification.** Every verify path throws on failure. A default
  that accepts-on-error is treated as a bug, not an ergonomic.
- **PQC-first crypto.** Post-quantum ML-DSA and SLH-DSA signatures run in the
  WebCrypto engine (`pki.webcrypto`) alongside the classical set today, and
  ML-KEM key generation is available with KEM encapsulation on the roadmap.
  Every algorithm is named in the OID registry (`pki.oid`); OID-driven
  sign/verify resolution rides that registry as the signing surface lands, and
  there is no classical-only default where a post-quantum option exists.
- **Signed releases.** Release tags are annotated and SSH-signed; published
  tarballs carry provenance and an SBOM. See
  [SECURITY.md → Verifying release authenticity](SECURITY.md#verifying-release-authenticity).

Report a vulnerability privately — see [SECURITY.md](SECURITY.md). For usage
questions and support channels, see [SUPPORT.md](SUPPORT.md).

## Documentation

Full primitive-by-primitive reference lives at [pkijs.com](https://pkijs.com),
generated from the source comment blocks so it cannot drift from the shipped API.

## License

[Apache-2.0](LICENSE). Third-party attribution — currently none, since the
toolkit vendors nothing — is tracked in [NOTICE](NOTICE).
