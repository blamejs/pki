# Roadmap

`@blamejs/pki` is a pure-JavaScript (CommonJS) PKI toolkit: X.509, CMS, OCSP, timestamping, PKCS enrollment and certificate formats, built post-quantum-first with no npm runtime dependencies and security defaults that are wired in rather than opt-in. It reimplements the standards surface of the classical PKI.js toolkit while owning its own ASN.1 codec and crypto layer, so correctness, denial-of-service resistance, and algorithm agility are in-tree rather than inherited from external parsers or the Web Crypto ceiling.

This document tracks capability areas and the standards they target, in rough delivery order. Every item is marked **Shipped** (available in the current release), **Targeted** (committed for a near-term release), **Planned** (accepted, scheduled later), or **Under design** (shape still being settled). Status changes as capabilities ship; consult the changelog for what is released today.

## Foundations

The parser and algorithm layers are the load-bearing decisions the rest of the library rides on.

- **Strict, validating DER/BER codec** — *Shipped.* An in-house, purpose-built ASN.1 encoder/decoder with a hard depth and size bound so malformed or deeply nested input is rejected in bounded time instead of exhausting the stack. DER is canonical on encode; the decoder rejects non-canonical structures by default and accepts BER only where a specific standard permits it. A single structure definition drives both encode and decode so context-tag (EXPLICIT/IMPLICIT) handling cannot diverge between the two directions.
- **Data-driven algorithm registry** — *Targeted.* The OID registry (`pki.oid`) names every algorithm, attribute, and extension in both directions today; the resolution table that maps an OID to its parameters, key importer, signer, and verifier lands with the signing surface, so new signature and KEM algorithms — including post-quantum ones — are registry entries, not special cases.
- **Node-native crypto engine** — *Shipped.* Cryptographic operations run over Node's native `node:crypto` through the W3C WebCrypto engine (`pki.webcrypto`), which removes the Web Crypto limits on streaming, opaque (non-extractable) key handles, and algorithm coverage. It ships the full classical set plus post-quantum ML-DSA and SLH-DSA signatures; ML-KEM key generation is available, with KEM encapsulation on the roadmap.
- **Fail-closed operation** — *Shipped.* Every decode and (as they land) encrypt, sign, and verify path throws on failure through the typed `PkiError` taxonomy. No path emits zero, default, or partial output in place of a real result.

## X.509 certificates and CRLs — RFC 5280

- **Certificate parse / build / sign / verify** — *Targeted.* Full v3 certificate model with the complete standard extension set (basic constraints, key usage and extended key usage, authority and subject key identifiers, certificate policies and policy constraints/mappings, name constraints, CRL distribution points, authority/subject information access, private key usage period, issuing distribution point, subject directory attributes, alternative names).
- **Distinguished names as ordered RDN collections** — *Targeted.* Names are modeled as an ordered sequence of relative distinguished names, each an unordered set of type/value pairs, so multi-valued RDNs encode correctly from the first release.
- **CRLs** — *Targeted.* Certificate revocation lists: parse, build, sign, verify, and revoked-certificate lookup.
- **Qualified certificate statements** — *Planned.* eIDAS/EU qualified-certificate statements. RFC 3739 / ETSI EN 319 412.
- **Microsoft enterprise CA extensions** — *Planned.* Certificate template and CA version structures. [MS-WCCE] / [MS-CRTD].

## Certification requests — RFC 2986 (PKCS#10)

- **CSR parse / build / sign / verify** — *Targeted.* Certification requests with first-class attribute and extension helpers (subject alternative names, challenge password, requested extensions) so common requests do not require hand-assembling ASN.1.

## Certification path validation — RFC 5280

- **Path validation engine** — *Shipped.* `pki.path.validate` runs the RFC 5280 §6.1 validation algorithm over an ordered path and a trust anchor: signature chaining, validity windows, name chaining, key usage, basic constraints and path length, name constraints, and the certificate-policy tree. Trust anchors may be roots or intermediates. **Path building** — constructing the ordered path from a certificate pool and trust store — is *Targeted*; the validator takes the ordered path as input, so signer certificates supplied out of band are validated today.
- **Structured results** — *Shipped.* Validation returns the complete path plus a per-check reason code for every step. Validity-window enforcement is always on, with the check date an explicit input. Validation is pure and re-entrant — input certificate state is never mutated, so a chain can be validated repeatedly.
- **Revocation checking** — *Shipped (CRL); OCSP Targeted.* A pluggable revocation hook is integrated into the path result; `pki.path.crlChecker` ships CRL consultation (signature, issuer authorization, distribution-point scope, currency). An OCSP checker satisfies the same interface and lands next.
- **Adversarial conformance corpus** — *Targeted.* Name-constraint and path-validation behavior is gated against a public adversarial corpus.

## Cryptographic Message Syntax — RFC 5652

- **SignedData** — *Targeted.* Sign and verify, detached and attached, single- and multi-signer, with signed and unsigned attributes. Signed attributes are canonical-DER encoded before hashing. Verification derives each parameter from the correct structure — the content digest, the signer's digest algorithm, and the key's own algorithm identifier are kept distinct — and validates algorithm-identifier parameters strictly per OID.
- **EnvelopedData with a first-class recipient model** — *Targeted.* Encrypt and decrypt with key-transport, key-agreement, pre-shared-key, and password recipients. Recipient identification is pluggable: issuer-and-serial, subject key identifier, and recipient key identifier for cases with no X.509 certificate. Key agreement follows RFC 5753 for the ECC profile.
- **EncryptedData** — *Targeted.* Password- and predefined-key symmetric content protection.
- **AuthenticatedData** — *Targeted.* MAC-protected content.
- **AuthEnvelopedData** — *Planned.* The correct CMS wrapper for AEAD content encryption, with spec-correct AEAD parameter encoding. RFC 5083 / RFC 5084.
- **KEMRecipientInfo** — *Planned.* The recipient type that carries KEM-encapsulated content-encryption keys, enabling post-quantum CMS encryption. RFC 9629.
- **Streaming CMS** — *Planned.* Streaming sign/verify and encrypt/decrypt for large payloads, enabled by the in-house crypto engine.

## Keys and credential stores

- **PKCS#8 private keys and SPKI public keys** — *Targeted.* Import/export of private-key and public-key info, including encrypted private keys. RFC 5958 / RFC 5280.
- **Password-based encryption** — *Targeted.* PBES2 and PBKDF2 parameter handling with UTF-8 password encoding (correct for non-ASCII passwords) and tunable, standards-compliant salt and iteration counts. RFC 8018.
- **PKCS#12 (PFX)** — *Shipped (parse).* Parse key-and-certificate stores: authenticated safe, cert/CRL/key/secret bags, shrouded key bags (algorithm surfaced, ciphertext opaque), nested safe contents, `friendlyName` / `localKeyId` attributes, and MAC integrity surfaced with the exact MACed byte range — RFC 9579 PBMAC1 recognized. BER content regions (indefinite lengths, constructed octet strings) accepted exactly where §4.1 requires them; interoperability with OpenSSL is a release acceptance gate. Building, MAC verification, and bag decryption ride the PBES2 work above. RFC 7292.

## Post-quantum and hybrid cryptography

The clearest differentiator: the classical toolkit this library replaces has no post-quantum surface at all. PQC algorithms are registry entries alongside classical ones, not bolt-ons.

- **ML-KEM in X.509** — *Targeted.* ML-KEM public keys in certificates and SPKI. draft-ietf-lamps-kyber-certificates.
- **ML-DSA in X.509** — *Targeted.* ML-DSA certificate signing and verification, tracking the LAMPS certificate specification through publication. draft-ietf-lamps-dilithium-certificates.
- **SLH-DSA** — *Planned.* Stateless hash-based signatures in X.509 and CMS. RFC 9814 (CMS) and the SLH-DSA X.509 work.
- **ML-KEM in CMS** — *Planned.* KEM-based content-encryption-key transport via KEMRecipientInfo. RFC 9629.
- **ML-DSA in CMS** — *Planned.* draft-ietf-lamps-cms-ml-dsa.
- **Composite (hybrid) signatures and KEMs** — *Under design.* Dual-algorithm certificates and CMS pairing a post-quantum algorithm with a classical one for the transition period. draft-ietf-lamps-pq-composite-sigs and draft-ietf-lamps-pq-composite-kem.
- **EdDSA** — *Planned.* Ed25519/Ed448 signing and verification and X25519/X448 key agreement. RFC 8410 / RFC 8032.

## Revocation and transparency

- **OCSP** — *Targeted.* Request and response, basic OCSP response, per-certificate status: create, parse, sign, verify. RFC 6960.
- **Certificate Transparency SCTs** — *Planned.* Signed certificate timestamp list encode/decode and signature verification, with correct padding and immutable verification. RFC 6962.
- **CT log client** — *Under design.* add-chain / add-pre-chain submission and signed-tree-head, inclusion, and consistency-proof verification. RFC 6962.

## Timestamping — RFC 3161

- **Time-Stamp Protocol** — *Targeted.* Timestamp request and response, timestamp token (TSTInfo), accuracy and status: create, parse, sign, verify.

## Attribute certificates — RFC 5755

- **Attribute certificates** — *Planned.* v2 attribute certificates for authorization and privilege management, and the legacy v1 profile.

## Enrollment and lifecycle protocols

Certificate lifecycle management is absent from the toolkit this library replaces; it is a first-class goal here.

- **ACME** — *Planned.* Account, order, authorization, challenge, and JWS flow for automated Web PKI issuance. RFC 8555.
- **EST** — *Planned.* Enrollment over Secure Transport for device and IoT enrollment. RFC 7030.
- **Certificate request messages (CRMF)** — *Shipped (parse).* `pki.schema.crmf.parse` decodes an RFC 4211 CertReqMessages — the request body CMP and EST enrollment carry — into the requested-certificate template, proof-of-possession, and registration controls, surfacing the raw CertRequest bytes a proof-of-possession verifier hashes. Building CertReqMessages, and the CMP message envelope around them, are *Planned*.
- **CMP** — *Planned.* Certificate Management Protocol including HTTP transfer and the lightweight profile, composing the CRMF request messages above. RFC 4210 / RFC 9480 / RFC 9483.
- **SCEP** — *Under design.* Simple Certificate Enrollment Protocol for MDM and network-device enrollment. RFC 8894.
- **CMC** — *Under design.* Certificate Management over CMS, for federal/PIV ecosystems. RFC 5272 / 5273 / 5274.

## High-level builder API

- **Safe-by-default builders** — *Targeted.* Ergonomic certificate, CSR, and CMS builders that accept strings and plain objects, with first-class PEM input and output and sensible extension helpers. The natural, easy path is the safe and correct one. Low-level ASN.1 structures remain available but are opt-in, and every public API member is public — no legitimate use is blocked by visibility.

## Messaging

- **S/MIME** — *Under design.* A native S/MIME assembly layer over the CMS building blocks so operators are not left wiring MIME by hand. RFC 8551.

## Assurance and interoperability

- **Interoperability gates** — *Targeted.* Cross-tool round-trip and parse checks (OpenSSL, and for PKCS#12 also Windows CAPI, macOS Keychain, and NSS) run as acceptance gates, not aspirations.
- **Fuzzing** — *Targeted.* An adversarial fuzz corpus against the ASN.1 codec and every parse path, run continuously.
- **Independent security review** — *Planned.* A published security assessment of the parser and every crypto path as a release deliverable.

## Documentation

- **Source-generated reference and runnable examples** — *Targeted.* API documentation is generated from source, and every example is executed in continuous integration on the shipped runtime so it cannot drift or break across Node versions. Coverage prioritizes the common tasks — signing with your own CA, parsing a certificate, building a CSR with a SAN, PEM conversion — that otherwise generate repeated questions.

## Standards & security references

### RFC & specification reference

The toolkit targets the standards surface below. Status is given for post-quantum work items because several are still Internet-Drafts (I-D) whose numbers are not yet assigned; those are tracked as forward-watch and cited by draft name until publication.

**ASN.1 & encoding**

| Identifier | Title | Part the toolkit uses |
|---|---|---|
| ITU-T X.680 | Abstract Syntax Notation One (ASN.1) — basic notation | Type model the codec compiles against (SEQUENCE/SET/CHOICE/tagging) |
| ITU-T X.690 | BER / CER / **DER** encoding rules | The in-house DER encoder/decoder; DER is the canonical wire form |
| RFC 5280 §4 | Certificate/CRL ASN.1 profile | Which fields/extensions are mandatory, their DER constraints |

**X.509 & PKIX**

| Identifier | Title | Part the toolkit uses |
|---|---|---|
| RFC 5280 | Internet X.509 PKI Certificate & CRL Profile | Core cert/CRL structure, extensions, validity |
| RFC 6818 | Updates to RFC 5280 | Clarifications folded into the profile |
| RFC 8398 | Internationalized Email Addresses in X.509 Certificates | `SmtpUTF8Mailbox` SAN handling |
| RFC 8399 | Internationalization Updates to RFC 5280 | UTF-8/IDN handling in names |
| RFC 4514 | LDAP: String Representation of Distinguished Names | DN parse/format (round-trip) |
| RFC 4519 | LDAP: Schema for User Applications | Standard DN attribute types/OIDs |
| RFC 5755 | Attribute Certificate Profile for Authorization | Attribute-certificate structure |
| RFC 3739 | Qualified Certificates Profile | QC statements / qualified-cert fields |
| RFC 6962 | Certificate Transparency | SCT extension parse/verify (Merkle log proofs) |

**Certificate validation & revocation**

| Identifier | Title | Part the toolkit uses |
|---|---|---|
| RFC 5280 §6 | Certification Path Validation algorithm | Chain building, policy tree, name constraints |
| RFC 6960 | Online Certificate Status Protocol (OCSP) | OCSP request/response build & verify |
| RFC 5019 | Lightweight OCSP Profile (high-volume) | GET/precomputed-response profile |
| RFC 6961 | TLS Multiple Certificate Status Request (multi-stapling) | Stapled multi-status parsing |
| RFC 9654 | OCSP Nonce Extension (obsoletes RFC 8954) | Nonce up to 128 octets for replay binding |

**CMS & messaging**

| Identifier | Title | Part the toolkit uses |
|---|---|---|
| RFC 5652 | Cryptographic Message Syntax (CMS) | SignedData / EnvelopedData / DigestedData |
| RFC 5083 | CMS AuthEnvelopedData | AEAD-protected content type |
| RFC 5084 | AES-GCM / AES-CCM in CMS | Authenticated content encryption |
| RFC 5753 | Use of ECC Algorithms in CMS | ECDH/ECDSA recipient/signer info |
| RFC 3565 | Use of AES in CMS | AES key-wrap / content encryption |
| RFC 8551 | S/MIME 4.0 Message Specification | S/MIME layering over CMS |
| RFC 9629 | Using KEM Algorithms in CMS (`KEMRecipientInfo`) | KEM-based recipient info (PQC transport) |

**Keys, stores & textual encoding**

| Identifier | Title | Part the toolkit uses |
|---|---|---|
| RFC 5958 | Asymmetric Key Packages (PKCS#8 v2 / OneAsymmetricKey) | Private-key container |
| RFC 5208 | PKCS#8 Private-Key Information Syntax (original) | Legacy PKCS#8 read |
| RFC 7292 | PKCS#12 Personal Information Exchange | `.p12`/`.pfx` bag parsing & MAC |
| RFC 8018 | PKCS#5 v2.1 — PBKDF2 / PBES2 | Password-based key derivation/encryption |
| RFC 2986 | PKCS#10 Certification Request (CSR) | CSR build & verify |
| RFC 3279 | Algorithms & Identifiers for PKIX | Classical signature/key OIDs |
| RFC 5480 | ECC Subject Public Key Information | EC public-key encoding/curve OIDs |
| RFC 4055 | Additional RSA Algorithms for PKIX (RSA-PSS/OAEP) | PSS/OAEP `AlgorithmIdentifier` parameters |
| RFC 7468 | Textual Encodings of PKIX/PKCS/CMS (PEM) | PEM label/base64 parse & emit |

**Enrollment & lifecycle**

| Identifier | Title | Part the toolkit uses |
|---|---|---|
| RFC 8555 | ACME | Automated issuance client/challenges |
| RFC 7030 | Enrollment over Secure Transport (EST) | Simple/re-enrol, CA certs, CSR attrs |
| RFC 4210 | Certificate Management Protocol (CMP) | PKI message envelope / cert requests |
| RFC 9480 | CMP Updates | Current CMP message conventions/algorithms |
| RFC 9483 | Lightweight CMP Profile | Constrained-deployment CMP subset |
| RFC 5272 | Certificate Management over CMS (CMC) | CMC full/simple enrolment |
| RFC 5273 | CMC: Transport Protocols | CMC over HTTP/mail |
| RFC 5274 | CMC: Compliance Requirements | Conformance behavior |
| RFC 8894 | Simple Certificate Enrolment Protocol (SCEP) | SCEP `PKIOperation` messaging |

**Timestamping**

| Identifier | Title | Part the toolkit uses |
|---|---|---|
| RFC 3161 | Time-Stamp Protocol (TSP) | TimeStampReq/Resp, TSTInfo |
| RFC 5816 | ESSCertIDv2 update to RFC 3161 | SHA-2 signer-cert binding in tokens |

**Algorithms — classical**

| Identifier | Title | Part the toolkit uses |
|---|---|---|
| RFC 8017 | PKCS#1 v2.2 (RSA: RSASSA-PSS, RSASSA-PKCS1-v1_5, OAEP) | RSA sign/verify/encrypt primitives |
| RFC 3447 | PKCS#1 v2.1 (RSA) | Legacy parameter/OID compatibility |
| RFC 8032 | EdDSA (Ed25519, Ed448) | Edwards-curve signatures |
| RFC 8410 | Ed25519/Ed448 & X25519/X448 Identifiers in PKIX | Curve OIDs in certs/keys |
| RFC 6979 | Deterministic (EC)DSA | Deterministic-nonce signing option |
| RFC 5915 | Elliptic Curve Private Key Structure | `ECPrivateKey` encoding |
| RFC 8422 | ECC Named Curves & Point Formats | Curve identifiers/point encoding |

**Algorithms — post-quantum** (NIST FIPS + IETF LAMPS)

| Identifier | Title / status | Part the toolkit uses |
|---|---|---|
| FIPS 203 | ML-KEM (Module-Lattice KEM) | KEM key-gen/encaps/decaps engine |
| FIPS 204 | ML-DSA (Module-Lattice Signature) | Lattice signature engine |
| FIPS 205 | SLH-DSA (Stateless Hash-Based Signature) | Hash-based signature engine |
| **RFC 9882** | Use of ML-DSA in CMS *(published Oct 2025)* | ML-DSA SignerInfo/SignedData |
| **RFC 9814** | Use of SLH-DSA in CMS *(published Jul 2025)* | SLH-DSA SignerInfo (pure mode, empty context) |
| **RFC 9629** | KEM algorithms in CMS (`KEMRecipientInfo`) | Framework for ML-KEM recipient info |
| draft-ietf-lamps-dilithium-certificates | Algorithm Identifiers for ML-DSA in X.509 *(I-D, active)* | ML-DSA cert/CRL public-key & signature OIDs |
| draft-ietf-lamps-kyber-certificates | Algorithm Identifiers for ML-KEM in X.509 *(I-D, active)* | ML-KEM subject-public-key in certs |
| draft-ietf-lamps-x509-slhdsa | Algorithm Identifiers for SLH-DSA in X.509 *(I-D, active)* | SLH-DSA cert/CRL identifiers |
| draft-ietf-lamps-cms-kyber | Use of ML-KEM in CMS *(I-D, at IESG)* | ML-KEM `KEMRecipientInfo` conventions over RFC 9629 |
| draft-ietf-lamps-pq-composite-sigs | Composite ML-DSA for X.509 *(I-D, active)* | Hybrid ML-DSA + RSA/ECDSA/EdDSA cert signatures |
| draft-ietf-lamps-pq-composite-kem | Composite ML-KEM for X.509 *(I-D, active)* | Hybrid ML-KEM + RSA-OAEP/ECDH/X25519 keys |
| draft-ietf-lamps-cms-composite-sigs | Composite ML-DSA in CMS *(I-D, active)* | Composite-signature SignerInfo |
| draft-ietf-lamps-cms-composite-kem | Composite ML-KEM in CMS *(I-D, active)* | Composite-KEM recipient info |
| draft-turner-lamps-cms-fn-dsa | Use of FN-DSA (FALCON) in CMS *(individual I-D, forward-watch)* | FN-DSA signer info once standardized |

**WebCrypto engine**

| Identifier | Title / status | Part the toolkit uses |
|---|---|---|
| W3C Web Cryptography API | Web Cryptography API | `SubtleCrypto` surface for classical sign/verify/derive/digest |
| WICG PQC additions | ML-KEM / ML-DSA & modern-curve additions to WebCrypto *(proposal-stage, not yet a finalized extension)* | Target surface for browser-native PQC; polyfilled until shipped |

### Vulnerability classes & CVEs to defend against

CVSS is quoted from NVD with the scoring version noted; where the maintainer's own advisory rates lower/higher, the split is flagged. CISA-KEV status was checked against the live catalog: **none of the CVEs below are KEV-listed** (all are DoS-class, side-channel, or research findings without confirmed mass in-the-wild exploitation).

**1. ASN.1 / DER parser DoS & memory-safety**

| CVE | What it is | CVSS | KEV | Exploitation | Design mitigation |
|---|---|---|---|---|---|
| CVE-2022-0778 | OpenSSL `BN_mod_sqrt()` infinite loop parsing crafted explicit EC params (before signature check) | 7.5 High (v3.1) | No | Public PoC / trivial crash | Loop/step bounds on every decode path; require named curves, reject explicit EC parameters; parse stays bounded and pre-verify-safe |
| CVE-2021-3712 | ASN.1 `STRING` read over-read — code assumes NUL-termination not guaranteed; can leak process memory | 7.4 High (v3.1); OpenSSL/distros: Moderate | No | Theoretical, no public exploit | Length-delimited string handling — slice by declared length, never scan for NUL |
| CVE-2016-2108 | ASN.1 negative-zero / ANY mishandling → memory corruption on re-serialization | 9.8 Critical (v3.0); OpenSSL: High | No | No reliable public RCE | Canonical-DER only: reject non-minimal INTEGER, negative zero, redundant encodings |
| CVE-2025-66031 | node-forge `asn1.fromDer` unbounded recursion → V8 stack exhaustion from deeply nested TLVs | 8.7 High (v4.0) | No | Public PoC / DoS | Hard nesting-depth cap with an iterative (non-recursive) TLV walk; fail-closed on depth/size limits |
| CVE-2025-12816 | node-forge ASN.1 validator desynchronization — malformed OPTIONAL reinterpreted as the next mandatory field | 8.6 High | No | Disclosed; validation bypass | Strict OPTIONAL/DEFAULT boundary tracking; single-pass tag-length validation that cannot re-seat field boundaries |

**2. Certification-path / policy-constraint DoS & bypass**

| CVE | What it is | CVSS | KEV | Exploitation | Design mitigation |
|---|---|---|---|---|---|
| CVE-2023-0464 | X.509 policy-constraints exponential resource use in path validation | 7.5 High (v3.1); OpenSSL: Low; Red Hat: 5.3 | No | Theoretical (policy checking off by default) | Iterative policy tree with a hard node/expansion cap; fail-closed at the cap |
| CVE-2023-0465 | Invalid certificate policies silently ignored → downstream policy checks skipped | 5.3 Medium (v3.1); OpenSSL: Low | No | Theoretical; needs malicious CA-signed cert | Invalid policy OIDs are surfaced/rejected, never silently dropped |
| CVE-2023-0466 | `X509_VERIFY_PARAM_add0_policy()` documented to enable policy check but does not | 5.3 Medium (v3.1); OpenSSL: Low | No | Theoretical | Policy enforcement is explicit and actually runs when requested — no advertised-but-skipped check |
| CVE-2021-3450 | `X509_V_FLAG_X509_STRICT` overwrites the valid-CA check → non-CA accepted as issuer | 7.4 High (v3.1) | No | No confirmed public PoC | Single authoritative `basicConstraints` CA gate that no later check can overwrite |
| CVE-2022-3602 / CVE-2022-3786 ("SpookySSL") | Stack buffer overflow decoding punycode email during name-constraint checking (3602: 4 controllable bytes, pre-announced Critical→downgraded High; 3786: `.`-only overflow, crash) | 7.5 High each (v3.1) | No | Public crash PoCs; no in-the-wild IoCs | Memory-safe pure-JS name decoding (no fixed-size buffers), bounded punycode, strict name-constraint parsing |

**3. Name-constraint / SAN / name-confusion bypass**

| CVE | What it is | CVSS | KEV | Exploitation | Design mitigation |
|---|---|---|---|---|---|
| CVE-2009-2408 | NSS accepts embedded NUL in CN (`paypal.com\0.evil.com`) → cert-name confusion / MITM (canonical NUL-prefix class; the pattern recurs across TLS stacks) | v2-era, score unverified here | No | Public exploit (Kaminsky/Marlinspike, Black Hat 2009) | Compare names by declared length; reject embedded NUL/control bytes and non-canonical IA5/UTF8 in DN/SAN; SAN-only matching with no CN fallback |
| (see also 2022-3602/3786) | Name-constraint parsing overflow | — | — | — | Memory-safe, bounded name-constraint evaluation |

**4. Signature-verification bypass / forgery**

| CVE | What it is | CVSS | KEV | Exploitation | Design mitigation |
|---|---|---|---|---|---|
| CVE-2006-4340 | NSS RSA e=3 Bleichenbacher signature forgery — extra data after PKCS#1 v1.5 hash accepted | 4.0 Medium (v2.0; no v3) | No | Public technique / PoC | Full PKCS#1 v1.5 structural check (every padding byte, zero trailing data); prefer RSA-PSS |
| CVE-2022-21449 ("Psychic Signatures") | Java ECDSA accepts `r=0, s=0` → any signature validates | 7.5 High (v3.1) | No | Public PoC (JWT/TLS) | Reject ECDSA signatures with `r` or `s` outside `[1, n−1]` (no zero/out-of-range components) |
| CVE-2015-9235 | `jsonwebtoken` algorithm confusion — `alg` from the token trusted (RS256↔HS256, `alg:none`) → auth bypass | 9.8 Critical (v3.0) | No | Weaponized (standard pentest technique) | Verify `AlgorithmIdentifier` against the expected key type; the message never selects the verification algorithm; reject `none` and unexpected/omitted parameters strictly per OID |

**5. Padding oracles / CMS decryption**

| CVE | What it is | CVSS | KEV | Exploitation | Design mitigation |
|---|---|---|---|---|---|
| CVE-2019-1563 | OpenSSL CMS/PKCS7 Bleichenbacher padding oracle when decrypt success/failure is observable | 3.7 Low (v3.1); 4.3 Medium (v2) | No | Theoretical (needs automated oracle) | Constant-time PKCS#1 v1.5 with implicit rejection and uniform error behavior; prefer RSA-OAEP / `KEMRecipientInfo` |
| CVE-2017-6168 (ROBOT, representative) | RSA PKCS#1 v1.5 adaptive chosen-ciphertext oracle (F5 BIG-IP; ROBOT is a multi-vendor family) | 9.1 Critical (v3.0) | No | Public scanning tooling; broad exposure at disclosure | No distinguishable padding-error behavior; prefer KEM/OAEP transport over RSA PKCS#1 v1.5 |

**6. PEM / PKCS#12 parsing memory-safety**

| CVE | What it is | CVSS | KEV | Exploitation | Design mitigation |
|---|---|---|---|---|---|
| CVE-2024-0727 | OpenSSL PKCS12 NULL-pointer dereference on a crafted `.p12` (optional ContentInfo fields may be NULL) | 5.5 Medium (v3.1); OpenSSL: Low | No | Trivial public PoC (DoS) | Null-check every optional ContentInfo/MAC field; fail-closed on malformed PKCS#12 (memory-safe JS — no deref) |
| CVE-2023-0215 | OpenSSL `BIO_new_NDEF` use-after-free in streaming ASN.1 (PEM/SMIME/CMS write paths) | 7.5 High (v3.1); OpenSSL: Moderate | No | DoS; no weaponized PoC | Memory-safe streaming decode (GC-managed, no manual free) with robust cleanup on decode failure |

**7. Post-quantum-specific pitfalls** (design-class; implementation hazards, not all with a single clean CVE)

| Hazard | Representative real-world finding | Design mitigation |
|---|---|---|
| KEM decapsulation failure handling | Fujisaki–Okamoto implicit-rejection requirement (FIPS 203) | ML-KEM decapsulation always runs the re-encryption check and returns the implicit-rejection secret on mismatch — never branches on decapsulation success/failure |
| Secret-dependent timing | **KyberSlash 1/2** (secret-dependent division timing in Kyber/ML-KEM decaps, 2024); **Clangover** (CVE-2024-37880 — compiler turned constant-time source into variable-time binary; CVSS unverified) | No secret-dependent division/branch/memory access; assert constant-time survives the JIT/optimizer; avoid table lookups on secret indices |
| ML-DSA context-string handling | Domain-separation context omission / pure-vs-pre-hash confusion | Always bind the context string; reject context > 255 bytes; keep pure and pre-hash modes distinct and explicit |
| Hybrid / composite downgrade | Accepting a composite signature/KEM when only the classical (or only the PQC) component verifies | Composite verification requires **all** component signatures/KEMs to pass; no negotiation down to a single component |
