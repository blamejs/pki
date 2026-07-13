# Changelog

All notable changes to `@blamejs/pki` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.2.8 — 2026-07-13

pki.webcrypto rejects an AES key of invalid length at import instead of deferring the failure to first use.

### Fixed

- pki.webcrypto.subtle.importKey now rejects a raw or JWK AES key whose length is not 128, 192, or 256 bits as a webcrypto/data DataError at import, rather than returning a CryptoKey that only fails at first use. Covers AES-GCM, AES-CBC, AES-CTR, and AES-KW; HMAC, HKDF, and PBKDF2 keys are unaffected.
- The README capability table and the documentation site render the certificate-inspection entry correctly: an inline code span containing pipe characters no longer breaks the surrounding table into misaligned columns.

## v0.2.7 — 2026-07-13

pki.webcrypto rejects an imported key whose type disagrees with its algorithm, and reports every cipher fault as a typed error.

### Changed

- The pkijs.com documentation site is regenerated with content-hashed CSS/JS under a strict Content-Security-Policy, an in-memory search endpoint, a browsable reference of every error class and code, symbol autocomplete, and concept guides. Documentation only -- the published package is unchanged.

### Fixed

- pki.webcrypto.subtle.importKey now validates that an imported asymmetric key's actual type matches the requested algorithm (an RSA key imported under an Ed25519, ECDSA, or RSA-PSS name is rejected as webcrypto/data), closing an algorithm-confusion path where a mislabeled CryptoKey could later be used under the wrong signature scheme. The EC import path already derived and checked the curve; this extends the same key-is-authority rule to RSA and the Edwards/Montgomery curves.
- pki.webcrypto AES cipher faults now fail closed with a typed webcrypto/operation error instead of a raw Node exception: a decrypt of a tampered AES-GCM ciphertext (failed authentication tag), bad AES-CBC padding, a non-8-byte-multiple AES-KW wrap/unwrap length, and a malformed cipher parameter all surface as a WebCryptoError, so a caller catching pki.errors.PkiError sees a typed verdict rather than a bare Node error crossing the API boundary.

## v0.2.6 — 2026-07-12

WebAuthn attestation verification covers Ed448 and the RFC 9864 fully-specified COSE algorithms, and hardens credential-key conformance.

### Added

- pki.webauthn now verifies the RFC 9864 fully-specified COSE algorithm identifiers a WebAuthn relying party may receive: ESP256 (-9), ESP384 (-51), ESP512 (-52), Ed25519 (-19), and Ed448 (-53). Ed448 (-53) is the only WebAuthn path to Ed448, so an Ed448 credential now verifies rather than erroring as an unsupported algorithm.
- The verifier is now checked against the official W3C WebAuthn Level 3 test-vector suite -- every published vector across ES256 / ES384 / ES512 / RS256 / Ed25519 / Ed448 and the packed / self / tpm / apple / fido-u2f / none formats -- as an independent cross-implementation oracle.

### Changed

- A WebAuthn credential key with COSE alg -8 (EdDSA) now requires curve Ed25519 (crv 6), matching the WebAuthn algorithm-identifier profile; an -8 key claiming Ed448 (crv 7) is rejected -- Ed448 is carried under the fully-specified identifier -53 instead.
- An EC2 credential key must use the uncompressed point form; the compressed sign-bit y encoding is rejected for WebAuthn credential keys.

### Fixed

- The WebAuthn credential public-key point is now validated on its curve, so an off-curve or identity EC/Edwards point fails closed at decode rather than being carried into a later verify step.
- An ECDSA attestation signature is now enforced as a minimally-encoded DER ECDSA-Sig-Value (X.690): a non-minimal, negative, zero, or over-size r/s coordinate is rejected as malformed instead of being stripped and accepted.

## v0.2.5 — 2026-07-12

WebAuthn / passkey attestation verification joins the toolkit as pki.webauthn.

### Added

- pki.webauthn.parseAttestationObject(bytes) structurally decodes a WebAuthn attestation object (the CBOR { fmt, attStmt, authData }) and its authenticatorData over the strict pki.cbor codec, returning the format id, the decoded rpIdHash / flags / signCount, the attested credential data (aaguid, credentialId, and the decoded COSE credentialPublicKey), and the raw authenticatorData bytes a signature covers. Malformed input throws webauthn/bad-attestation-object. W3C WebAuthn Level 3.
- pki.webauthn.verify(attestationObject, clientDataHash, opts) verifies a WebAuthn attestation statement -- packed, tpm, android-key, apple, fido-u2f, or none -- checking the attestation signature over authenticatorData || clientDataHash and each format's structural bindings (the x5c leaf key, the apple nonce, the tpm certInfo Name / extraData over the pubArea, the android KeyDescription, the fido-u2f verificationData), binding each attestation certificate key to the credential public key, and enforcing each format's certificate requirements (a packed leaf's Authenticator Attestation subject and non-CA basic constraints, a tpm AIK's empty subject and non-CA constraints). It resolves the attestation type and trust path or throws a typed webauthn/* error; a signature that does not verify is a webauthn/verify-failed verdict, never a silent pass. The error taxonomy gains WebauthnError (webauthn/*). W3C WebAuthn Level 3, RFC 9052.
- The OID registry gains the FIDO id-fido-gen-ce-aaguid, Android key-attestation, Apple anonymous-attestation, and TCG TPM (AIK key purpose, tpmManufacturer / tpmModel / tpmVersion) arcs that WebAuthn attestation certificates carry.

### Changed

- The bounded big-endian byte cursor under pki.ct's TLS-vector decoding is extracted to a shared engine primitive so the packed big-endian TPM structures in pki.webauthn read through the same bounds-before-slice cursor -- one definition of the length-checked read, carrying each caller's typed error domain.

## v0.2.4 — 2026-07-12

Human-readable certificate inspection joins the toolkit as pki.inspect.

### Added

- pki.inspect.certificate(input) renders a certificate (a PEM string, a DER Buffer, or a pki.schema.x509.parse result) as a human-readable OpenSSL-x509-text-style report, composed over the strict X.509 parser, the shared RFC 5280 extension decoders, and the two-way OID registry. Standard extensions (basic constraints, key usage, extended key usage with purpose names, subject/issuer alternative names, subject and authority key identifiers, and more) decode to their content; an extension with no decoder is named from the registry and shown as its string or a hex dump. A value that is not a certificate, DER, or PEM throws inspect/bad-input; malformed certificate bytes throw inspect/bad-certificate; a malformed single extension never sinks the report. The error taxonomy gains InspectError (inspect/*). RFC 5280.

## v0.2.3 — 2026-07-12

Offline Sigstore bundle verification joins the toolkit as pki.sigstore.

### Added

- pki.sigstore.verifyBundle(bundle, opts) verifies a Sigstore bundle offline against caller-supplied trust material (opts.fulcioRoots, the Fulcio CA certificates; opts.rekorKeys, the Rekor log public keys, each with an optional validFor window honored against the log time so a rotated-out key is not used; optional opts.identity policy and opts.time). It returns { verified: true, payload, statement, subjects, predicateType, predicate, identity, integratedTime } on success -- payload being the raw verified envelope bytes, never a re-serialization -- and throws a typed sigstore/* error on any leg's failure. The transparency-log entry is bound to both the bundle signature and its leaf certificate, and only the v0.1-v0.3 bundle versions this release verifies are accepted (a newer version is recognized and deferred). pki.sigstore.parseBundle(input) decodes and structurally validates a bundle (object, JSON string, or Buffer) fail-closed. pki.sigstore.pae(payloadType, payloadBytes) builds the DSSE Pre-Authentication Encoding a signature covers. DSSE / Sigstore bundle v0.3 / RFC 9162 / SLSA provenance v1.
- The OID registry gains the Fulcio (Sigstore) certificate-extension arc 1.3.6.1.4.1.57264.1.* (the OIDC issuer, build-signer and source-repository identity claims), honoring the raw-string-vs-DER-UTF8String encoding split by member. The error taxonomy gains SigstoreError (sigstore/*): a malformed or oversize bundle (sigstore/bad-bundle), an unknown media type (sigstore/bad-bundle-version), an unsupported content arm (sigstore/unsupported-content), a DSSE signature that does not verify under the Fulcio leaf key (sigstore/dsse-verify-failed), an inclusion proof that does not reconstruct the tree root (sigstore/inclusion-proof-mismatch) or is malformed (sigstore/bad-inclusion-proof), a tree root not attested by the Rekor key (sigstore/unsigned-root), a log time not attested by the Rekor SET that signs it (sigstore/unattested-time, so an attacker cannot backdate the ephemeral Fulcio certificate into validity), a Fulcio chain that does not terminate at a caller-supplied trust anchor (sigstore/chain-incomplete) or fails validation as of the log time (sigstore/chain-invalid), an undecodable certificate identity (sigstore/bad-certificate), a malformed transparency-log entry (sigstore/bad-tlog-entry), a log entry that does not bind this signature (sigstore/entry-mismatch), an identity that fails the caller policy (sigstore/identity-mismatch), a payload that is not the expected in-toto statement (sigstore/bad-statement), and a predicateType that does not match a caller-pinned one (sigstore/predicate-mismatch). Fulcio CA anchors and Rekor keys honor their trusted-root validity windows so a rotated-out key or CA is not used, and every anchor sharing a subject DN is tried.

## v0.2.2 — 2026-07-11

Hybrid Public Key Encryption (RFC 9180) joins the toolkit as pki.hpke.

### Added

- pki.hpke.setupS(suiteIds, recipientPublicKey, opts) / pki.hpke.setupR(suiteIds, enc, recipientPrivateKey, opts) establish a sender / recipient HPKE context (RFC 9180 sec. 5.1); the returned context exposes seal(aad, pt) / open(aad, ct) with the sequence-counter nonce and a message-limit guard, and export(exporterContext, L) for the secret-export interface. pki.hpke.seal / pki.hpke.open are the single-shot wrappers (sec. 6). pki.hpke.suites carries the RFC 9180 sec. 7 KEM / KDF / AEAD / MODE code points. Keys are node KeyObjects or serialized bytes; the offered suites are DHKEM P-256, P-521, X25519, and X448, HKDF-SHA256 / HKDF-SHA512, the three AEADs plus export-only, and all four modes. RFC 9180.
- The error taxonomy gains HpkeError (hpke/*): a malformed, low-order, or otherwise invalid encapsulated or KEM key (hpke/bad-key, so a Diffie-Hellman that fails during derivation surfaces as a typed error, never a raw fault), an unknown or unsupported ciphersuite code point (hpke/unknown-suite, never a silent default), an unsupported mode (hpke/unknown-mode, so an out-of-registry mode is rejected rather than key-scheduled), an authenticated mode invoked without the sender's key (hpke/auth-key-required), inconsistent PSK inputs (hpke/inconsistent-psk), an AEAD tag that does not verify (hpke/open-failed, returning no plaintext), a sequence-number overflow (hpke/message-limit, before any nonce reuse), a seal/open against an export-only suite (hpke/export-only), and a wrong-direction context call (hpke/wrong-role, so a recipient context cannot seal nor a sender context open -- they share a key and base nonce).

## v0.2.1 — 2026-07-11

Stateful hash-based signature verification (HSS/LMS) joins the toolkit as pki.shbs.

### Added

- pki.shbs.verify(publicKey, message, signature) verifies an HSS (Hierarchical Signature System) signature -- the wire form RFC 9802 (X.509) and RFC 9708 (CMS) carry for id-alg-hss-lms-hashsig -- returning true only if every level of the hierarchy verifies. pki.shbs.verifyLms(publicKey, message, signature) verifies a single-tree LMS signature (the component HSS composes, and a standalone algorithm). Both take the raw octet blobs the parsers surface (a certificate's subjectPublicKeyInfo.publicKey.bytes, tbsBytes, and signatureValue.bytes); a malformed blob -- bad length, an unknown or unapproved typecode, truncation, a typecode the public key does not commit to -- throws a typed ShbsError, and a well-formed but wrong signature returns false. RFC 8554 / RFC 9802 / RFC 9708 / NIST SP 800-208.
- The OID registry gains id-alg-hss-lms-hashsig (1.2.840.113549.1.9.16.3.17), id-alg-xmss-hashsig, and id-alg-xmssmt-hashsig, all with parameters MUST be absent (RFC 9802 sec. 4) -- a stateful-hash-signature AlgorithmIdentifier carrying any parameters now fails closed at the shared algorithm-identifier gate, inherited by every format the toolkit parses. The error taxonomy gains ShbsError (shbs/*).

### Changed

- XMSS / XMSS^MT verification and automatic HSS/LMS verification inside pki.path.validate are not in this release -- see the roadmap. The former awaits an authoritative interoperability test vector (RFC 8391 ships none and NIST ACVP does not yet cover XMSS); the latter awaits a real HSS-signed certificate to prove the certification-path wiring end to end. Operators verify today by handing the raw certificate / CMS blobs to pki.shbs.verify directly.

## v0.2.0 — 2026-07-11

Trust-store ingestion, sharded-CRL revocation, and a hardened input-guard layer.

### Added

- pki.trust.parseCertdata(text) and pki.trust.parseCcadbCsv(text) parse the Mozilla/NSS certdata.txt object stream and the CCADB All Certificate Records CSV into one Anchor shape carrying the exact { name, publicKey, algorithm, parameters } fields pki.path.validate consumes, plus per-purpose distrustAfter dates, delegator purposes (only CKT_NSS_TRUSTED_DELEGATOR grants a purpose), subjectDer, label, and mozillaCaPolicy. Certificate and trust objects are paired by byte-exact issuer + serial (never adjacency) and cross-checked against the parsed DER, so metadata can never attach to the wrong root. pki.trust.anchor(entry, { purpose }) hands the anchor to validate, failing fast when the entry does not delegate the purpose. Malformed octal, an oversized block or file, an unrecognized trust value, an undecodable distrust date, or a mispaired object throws a typed trust/* error. Offline and pure: the caller supplies the text; nothing fetches.
- pki.path.validate gains opts.checkPurpose plus trust-anchor constraint enforcement: with an anchor carrying distrustAfter / purposes metadata, a leaf whose notBefore is strictly after the anchor's distrust date for the checked purpose fails with path/distrusted-after (the boundary instant stays trusted, matching Mozilla's enforcement), and a purpose the anchor does not delegate fails with path/purpose-not-trusted. Anchors without the metadata validate exactly as before.
- cRLDistributionPoints and freshestCRL certificate-extension decoders, and RFC 5280 sec. 6.3.3 distribution-point correspondence in pki.path.crlChecker: a partitioned CRL whose critical issuing-distribution-point shares an identically-encoded name with one of the certificate's distribution points, carries no reason restriction on either side, is current, and verifies now establishes a good status for its shard. A non-corresponding, reason-restricted, non-critical-IDP, delta, or unverifiable shard keeps failing closed to undetermined -- and a listed serial still reports revoked regardless of correspondence.
- pki.asn1.decode and pki.cbor.decode accept a maxItems option (default C.LIMITS.DER_MAX_ITEMS) capping the total decoded elements, so a small dense input cannot fan out into an unbounded node tree (asn1/too-many-items). OCSP responses are capped at C.LIMITS.OCSP_MAX_CERTS embedded certificates (ocsp/too-many-certs), bounding the pre-authentication signature work an attacker-supplied response can demand.
- Strict JWK oct key-material decoding: importKey / unwrapKey reject a JWK oct key whose k member is missing, empty, padded, or non-canonical base64url instead of importing a wrong or empty key, and JSON key unwrap rejects duplicate members at every depth so a smuggled second parameter can no longer resolve last-wins. Unwrapped JWK text is bounded (size, nesting depth, strict UTF-8).

### Changed

- OID string handling is canonical everywhere: pki.asn1.build.oid and pki.oid.toDER reject a leading-zero arc (previously accepted and silently encoded as a DIFFERENT OID -- "2.05.29.15" emitted the DER of 2.5.29.15), and pki.oid.toArcs / register now enforce the X.660 arc bounds on the string form (a root above 2, or a second arc above 39 under roots 0 and 1, can never be DER-encoded and now throws oid/bad-arc). Error codes consolidated with the canonical form: a one-arc or non-numeric-arc string throws oid/bad-input (previously oid/too-short and oid/bad-arc; oid/too-short is removed).
- pki.jose and WebCrypto JWK unwrap JSON limits are enforced through one shared bounded reader; an unwrapped-key JSON parse failure reports the typed webcrypto/data error without a nested SyntaxError cause.

### Fixed

- Signing via pki.jose over a payload backed by a detached ArrayBuffer now fails closed with a typed error instead of silently signing an empty payload; PEM encoding and EST transfer encoding reject a detached or non-buffer input the same way.
- EST server-side key generation rejects an EnvelopedData whose encryptedContent is present but zero-length (est/bad-key-part); previously only the fully absent form was rejected, so an empty ciphertext could reach the caller's decrypt step. The same shared check now backs the CRMF encrypted-key proof-of-possession and PKCS#12 paths.
- An attribute certificate whose objectDigestInfo digest is not octet-aligned is rejected at parse (attrcert/bad-object-digest-info) instead of surfacing a bit-truncated digest.
- A malformed content-type attribute value inside AuthEnvelopedData authenticated attributes surfaces cms/bad-content-type-attr instead of a raw asn1/* codec error.
- pki.path.validate rejects fractional maxPathCerts / maxPolicyNodes values (path/bad-input) instead of silently tolerating them, and validates requiredEku / userInitialPolicySet entries as canonical OID strings at the entry point -- a leading-zero or out-of-bounds key could never match decoder output and now fails at boot instead of silently never matching.

## v0.1.32 — 2026-07-11

OCSP-backed revocation checking joins certification-path validation.

### Added

- pki.path.ocspChecker(responses) -> RevocationChecker builds an OCSP-backed revocation checker for pki.path.validate's revocationChecker option from a set of pre-fetched OCSP responses (DER Buffer, PEM string, or already-parsed). It matches the full CertID triple against the certificate under whichever hash algorithm the CertID declares, authorizes the responder (issuing CA or a CA-issued id-kp-OCSPSigning delegate), verifies the response signature over tbsResponseData, and enforces thisUpdate/nextUpdate currency, reporting good, revoked (with revocationReason), or unknown. A wrong-issuer CertID, an unauthorized responder, a stale, not-yet-valid, or nextUpdate-less response, a non-successful responseStatus, or any verification failure yields unknown, which the validator fails closed unless softFail is set. RFC 6960.

## v0.1.31 — 2026-07-11

The DER format cohort and the JOSE surface graduate to stable.

### Changed

- pki.schema.pkcs12 / attrcert / crmf / cmp / csrattrs (parse, pemDecode, pemEncode), pki.schema.all and pki.schema.parse, and the pki.jose signing / verification / thumbprint / base64url / JSON surface graduate from experimental to stable.
- The LTS-CALENDAR graduation criterion now states that a settled, well-tested format no mainstream tool implements graduates on the toolkit's own conformance-vector round-trip plus coverage-guided fuzzing, rather than on a harness oracle that does not exist.

## v0.1.30 — 2026-07-11

Fail-closed hardening of the byte-input and text-decode boundaries.

### Changed

- A detached-backed BufferSource (a transferred / structuredClone'd view) passed to any DER format parser -- pki.schema.x509 / crl / csr / pkcs8 / cms / pkcs12 -- fails closed with the format's typed bad-input error at the shared parse-input boundary rather than being decoded as an empty buffer.

### Fixed

- The EST transfer and multipart-mixed decoders enforce their size cap on the raw byte length before decoding the payload to a string, and an HTTP error response body is decoded only up to the prefix shown in the message -- closing a single-input string-allocation amplification where an oversized body was materialized in full before the cap rejected it.
- pki.oid.fromDER rejects a non-Buffer or detached-backed input with a typed oid/bad-input error instead of a raw TypeError.

## v0.1.29 — 2026-07-10

A detached-backed BufferSource now fails closed with a typed error at every byte-input boundary.

### Fixed

- pki.webcrypto digest / sign / verify no longer silently process a detached-backed Buffer as EMPTY input (a fail-open where a transferred backing ArrayBuffer left the view zero-length); a detached BufferSource is now rejected with a typed webcrypto/data error, as is getRandomValues.
- pki.asn1.decode, pki.cbor.decode, and pki.ct.parseSctList reject a detached-backed Buffer or view with a typed error (asn1/not-buffer, cbor/not-buffer, ct/bad-input) instead of a raw TypeError or a misleading truncated-input verdict. The underlying byte-view failure is threaded as the error cause.

## v0.1.28 — 2026-07-10

Merkle transparency proof verification joins the toolkit as pki.merkle.

### Added

- pki.merkle.leafHash / nodeHash / emptyRootHash -- the RFC 6962 / RFC 9162 tree hashes: a leaf is SHA-256(0x00 || entry), an interior node is SHA-256(0x01 || left || right), the empty tree is SHA-256(""). The domain-separation prefixes are applied unconditionally.
- pki.merkle.verifyInclusion({ leafIndex, treeSize, leafHash, proof, rootHash }) -- verify an RFC 6962 / RFC 9162 audit proof by folding the leaf up the audit path and constant-time-comparing the reconstructed root to a trusted root. Returns true only when the proof binds the leaf to the root.
- pki.merkle.verifyConsistency({ oldSize, newSize, oldRoot, newRoot, proof }) -- verify an append-only consistency proof by reconstructing BOTH the old and the new root and constant-time-comparing each; the append-only guarantee lives in the old-root leg.
- The error taxonomy gains MerkleError (merkle/*). A node-count ceiling (C.LIMITS.MERKLE_MAX_PROOF_NODES) rejects a pathologically long proof before any hashing; the precise per-proof guard is the geometry check in each verifier.
- Fuzz target merkle-verify (both fold algorithms and the hash producers over adversarial coordinates, hashes, and proofs) joins the per-PR and nightly fuzz matrices with a seed corpus.

## v0.1.27 — 2026-07-10

A strict deterministic-CBOR codec joins the toolkit as pki.cbor.

### Added

- pki.cbor.decode -- the RFC 8949 core-deterministic CBOR decoder. It returns a node carrying the major type, the argument (a lossless BigInt), zero-copy content / bytes views (the raw ranges an external verifier hashes), and children (array elements, ordered map key/value pairs, or a tag's one inner item). Every non-canonical shape fails closed with a stable cbor/* code; maxBytes, maxDepth, maxItems, and a per-bignum byte cap bound the work before allocation (so a container declaring millions of tiny elements fails closed rather than exhausting memory); allowTrailing decodes the first item of a CBOR Sequence.
- The read.* leaf readers over a decoded node: read.uint / read.nint / read.int (uniform BigInt), read.byteString (zero-copy Buffer), read.textString (strict UTF-8), read.array, read.map (ordered key/value node pairs), read.boolean / read.nullValue / read.undefinedValue, read.float (half / single / double), and the tagged forms read.biguint (RFC 8949 tag 2 unsigned bignum, minimality and byte cap enforced), read.time (RFC 8949 tag 1 epoch time, bounded to the valid Date range), and read.oid (RFC 9090 tag 111, decoded through the shared OID-content codec so a malformed body surfaces the existing oid/* codes).
- The error taxonomy gains CborError (cbor/*). The decoder is profile-parameterized, so a future CTAP2 canonical profile is a data addition rather than a new code path.
- Fuzz target cbor-det-parse (the decode head-well-formedness and minimal-argument checks, the map ordering / uniqueness verify, the shortest-float rule, the strict-UTF-8 gate, and the size / depth / bignum caps, in both whole-buffer and CBOR-Sequence modes) joins the per-PR and nightly fuzz matrices with a seed corpus.

### Changed

- pki.oid.paramsMustBeAbsent graduated from experimental to stable: its dotted-OID-to-boolean surface has been unchanged since 0.1.21 and is exercised end-to-end by the algorithm-identifier decoder every format shares.

## v0.1.26 — 2026-07-10

Test-coverage measurement and the OpenSSF Best Practices badge.

### Added

- npm run coverage measures statement and branch coverage over the full test suite with c8. It is a development dependency only — the published package still declares zero runtime dependencies.

### Changed

- The README badge row now includes the OpenSSF Best Practices badge.

## v0.1.25 — 2026-07-10

ACME joins the toolkit: an RFC 8555 message layer over a new RFC 7515 JOSE surface.

### Added

- pki.jose — the RFC 7515 Flattened JWS and RFC 7638 JWK-thumbprint layer. jose.sign / jose.verify produce and check a Flattened JWS against one of three declarative profiles (ACME outer, EAB inner, keyChange inner) that carry the required and forbidden header rules as data, so sign and verify cannot diverge; jose.base64url is the strict RFC 4648 section 5 codec (a trailing '=', a '+' or '/', whitespace, or non-canonical trailing bits are rejected); jose.parseJson is a bounded recursive-descent reader that throws on a duplicate member at any nesting depth, on invalid UTF-8, and past the size or depth caps; jose.thumbprint is the RFC 7638 canonical SHA-256 thumbprint (RSA, EC, oct, OKP, and AKP member templates, optional members excluded).
- pki.acme — the RFC 8555 / 8737 / 8738 / 9773 ACME message layer over pki.jose. acme.validate checks a directory, account, order, authorization, challenge, or renewalInfo object against its spec (closed status enums, conditional-required fields such as a pending order's expires, URL and RFC 3339 shapes, non-empty arrays; unknown fields are ignored, never reflected); acme.validateProblem checks an RFC 7807 problem document and its subproblems (a top-level identifier is rejected); acme.assertTransition enforces the three section 7.1.6 state machines; acme.identify classifies an object into exactly one kind.
- ACME request builders: acme.newAccount (with a fail-closed mailto contact check) and acme.externalAccountBinding (an HMAC-only inner JWS over the account key); acme.newOrder (identifier validation with one leading wildcard label permitted for dns, and the RFC 9773 replaces field); acme.finalize, which parses the CSR with pki.schema.csr, requires its requested identifier set (SAN plus CN) to equal the order identifiers, and rejects a CSR whose public key is the account key (RFC 8555 section 11.1); acme.challengeResponse, acme.deactivate, acme.revokeCert (account-key or certificate-key signed, CRLReason range-checked), acme.keyChange (the section 7.3.5 nested JWS), and acme.postAsGet (an empty payload, distinct from an empty object).
- ACME challenge computations: acme.keyAuthorization (token plus the account-key thumbprint), acme.http01, acme.dns01 (the _acme-challenge record with one wildcard label stripped), and the tls-alpn-01 pair acme.tlsAlpn01Extension / acme.verifyTlsAlpn01, which build and check the critical id-pe-acmeIdentifier extension (a 32-octet Authorization equal to the SHA-256 of the key authorization) together with a single-entry SubjectAltName.
- ARI (RFC 9773): acme.ariCertId builds a certificate's renewal identifier from its authorityKeyIdentifier and serial content octets — the serial's leading sign-padding byte is preserved, so the identifier matches what a CA computes; acme.parseAriCertId decodes one back to its two halves; acme.validateRenewalInfo checks a suggestedWindow and rejects an inverted or zero-width window.
- The error taxonomy gains JoseError (jose/*) and AcmeError (acme/*); the OID registry gains id-pe-acmeIdentifier (RFC 8737).
- pkix.pemDecodeAll decodes an RFC 7468 multi-block PEM chain (CERTIFICATE label, no explanatory text between blocks, at least one block) beside the existing single-block pemDecode.
- Fuzz targets jose-parse (the base64url and JSON codecs and the JWS profile walk) and acme-object (the resource validators, identify, and the ARI certID parser) join the per-PR and nightly fuzz matrices with seed corpora.

## v0.1.24 — 2026-07-10

EST enrollment joins the toolkit: the RFC 8951 CSR-attributes parser and an RFC 7030 client-codec surface.

### Added

- pki.schema.csrattrs.parse(der) — decode EST CSR Attributes (CsrAttrs ::= SEQUENCE OF AttrOrOID, RFC 8951 section 3.5) into { items }. Each item is { kind, oid, name } — kind 'oid' for a bare OBJECT IDENTIFIER or 'attribute' for an Attribute, which adds raw values plus, for the RFC 9908 meaningful types, a decoded view: extensions (id-ExtensionReq), curve / keySize (the EC / RSA key-type conventions), or template (the CertificationRequestInfoTemplate). An empty SEQUENCE is a complete valid document. Unknown OIDs / attribute types are tolerated (surfaced raw); the RFC 9908 semantic MUSTs fail closed with a typed CsrattrsError (at most one id-ExtensionReq whose value is a single Extensions, template version v1(0), a template carrying at most one id-aa-extensionReqTemplate and never both extension-request kinds). Registered in the format orchestrator (pki.schema.parse routes a CsrAttrs, including the empty SEQUENCE, to csrattrs).
- pki.est — the transport-agnostic RFC 7030 / 8951 / 9908 EST client surface. transferDecode / transferEncode are the RFC 8951 base64 transfer codec (RFC 4648, blind to any Content-Transfer-Encoding header, bounded before and after decoding). splitMultipartMixed splits the /serverkeygen multipart/mixed body (terminal boundary required, nested/extra parts rejected). parseCertsOnly validates a certs-only Simple PKI Response (RFC 5272 section 4.1) over cms.parse output — empty signerInfos, no eContent, plain X.509 certificates only — surfacing certificates raw and in as-received order. findIssuedCert picks the issued certificate by a public-key match (never a positional guess). parseServerKeygenResponse dispatches the two-part key + certificate response and enforces the request-to-response recipient-arm coherence. classifyResponse is the HTTP status / content-type / Retry-After state machine (a 202 surfaces retryAfterSeconds, never slept on; 204/404 on /csrattrs is a 'none available' verdict). paths builds the RFC 7030 operation URLs with the optional CA-label guard. The builders assemble the CSR attributes EST adds: challengePasswordFromTlsUnique (channel binding, 255-octet cap), decryptKeyIdentifierAttr / asymmetricDecryptKeyIdentifierAttr, smimeCapabilitiesAttr, buildEnrollAttributes (the RFC 9908 template-priority enroll plan), and reenrollGuard.
- The error taxonomy gains CsrattrsError (csrattrs/*) and EstError (est/*).
- The OID registry gains the RFC 4108 / RFC 7030 / RFC 9908 attribute identifiers: id-aa-decryptKeyID, id-aa-asymmDecryptKeyID, id-aa-certificationRequestInfoTemplate, and id-aa-extensionReqTemplate.
- Fuzz targets csrattrs-parse and est-transfer (the base64 + multipart codecs) join the per-PR and nightly fuzz matrices with seed corpora.

## v0.1.23 — 2026-07-09

CMS grows authenticated content: RFC 5652 AuthenticatedData, RFC 5083 AuthEnvelopedData, and RFC 9629 KEM recipients (ML-KEM ready) — plus a toolkit-wide hardening pass.

### Added

- pki.schema.cms.parse decodes id-ct-authData (RFC 5652 section 9 AuthenticatedData): { version, originatorInfo, recipientInfos, macAlgorithm, digestAlgorithm, encapContentInfo, authAttrs, authAttrsBytes, mac, unauthAttrs }. The section 9.1 version rule is computed from originatorInfo contents (recipient kinds never influence it); digestAlgorithm and authAttrs are enforced as a biconditional; authAttrs are required for a non-id-data content type and must carry content-type (matching the eContentType) and message-digest; authAttrsBytes is the raw on-wire [2] TLV for the section 9.2 MAC re-tag.
- pki.schema.cms.parse decodes id-ct-authEnvelopedData (RFC 5083): { version, originatorInfo, recipientInfos, encryptedContentInfo, aead, authAttrs, authAttrsBytes, mac, unauthAttrs }. A recognized AES-GCM/CCM content-encryption algorithm gets its RFC 5084 parameters validated (present, nonce bounds — CCM 7..13 octets, ICV length from the allowed set and equal to the mac length, DEFAULT-omitted per X.690 11.5) and surfaced as aead: { kind, nonce, icvLen }; an unrecognized algorithm surfaces raw parameters with aead null.
- KEMRecipientInfo (RFC 9629) parsed under the OtherRecipientInfo id-ori-kem arm: { version, rid, ridType, kem, kemct, kdf, kekLength, ukm, wrap, encryptedKey } as kemri alongside the raw oriValue. version must be 0; kekLength must be 1..65535 and match a recognized AES key-wrap's KEK size; a recognized ML-KEM kem pins the exact FIPS 203 ciphertext length. An unrecognized oriType still surfaces raw (the ORI extension point); a recognized one is validated by content, never accepted on the type OID alone.
- The parameters-absent registry (pki.oid.paramsMustBeAbsent) gains ML-KEM-512/768/1024 (RFC 9936) and the three HKDF identifiers (RFC 8619), enforced once in the shared AlgorithmIdentifier schema so certificates, CMS, and every other format inherit the rule.
- RFC 5652 section 11 attribute placement rules, enforced everywhere attribute sets are parsed: content-type / message-digest / signing-time must not appear in unsigned, unauthenticated, or unprotected attribute sets; countersignature only in unsigned attributes. signing-time values are validated as single-valued Time; every countersignature value is validated as a SignerInfo whose signedAttrs carry message-digest and no content-type (RFC 5652 section 11.4), recursively.
- Every pki.schema.cms.parse result carries contentType (the dotted OID) and contentTypeName, naming which of the five content types was dispatched — no more duck-typing the result shape.
- pemEncode lands on every remaining format: pki.schema.ocsp.pemEncode (default label OCSP RESPONSE), pki.schema.attrcert.pemEncode (ATTRIBUTE CERTIFICATE), pki.schema.crl.pemEncode (X509 CRL), and label-required pki.schema.tsp.pemEncode / pki.schema.crmf.pemEncode (no standard PEM label exists for those formats, so the operator names the envelope explicitly).
- New fuzz targets with seed corpora: crl-parse, csr-parse, pkcs8-parse, and schema-all-parse (the orchestrator front door), plus authenticated-content and KEM-recipient seeds for cms-parse; all wired into the per-PR and nightly fuzz matrices.
- pki.oid.register / registerFamily validate X.660 encodability at registration: root arc 0..2, second arc 0..39 under roots 0 and 1, at least two arcs, and no leading-zero components — a typo fails at config time instead of minting an unmatchable registry key.

### Changed

- SignedData and OriginatorInfo certificates/crls buckets validate the closed CertificateChoices / RevocationInfoChoice tag sets (RFC 5652 sections 10.2.1-10.2.2): elements are still surfaced raw, but a tag outside the CHOICE — or a primitive encoding — is rejected instead of silently feeding the version computation.
- Signed and authenticated attribute sets must be DER encoded even when the enclosing structure is BER (RFC 5652 sections 5.3/9.1, RFC 5083 section 2.1) — an indefinite-length attribute set reaching the PKCS#12 public-key-integrity path is now rejected instead of surfacing re-tag bytes a verifier would hash incorrectly.
- Validity, TBSCertificate, and AttributeTypeAndValue assert their SEQUENCE tag (RFC 5280 section 4.1): a SET-tagged body no longer parses through pki.schema.x509.parse while the format orchestrator rejects the same bytes.
- issuerUniqueID / subjectUniqueID are decoded as the [n] IMPLICIT BIT STRING RFC 5280 section 4.1.2.8 defines — an EXPLICIT-wrapped or malformed unique identifier is rejected.
- The IssuingDistributionPoint decoder enforces the DER field grammar (strictly ascending tags, each at most once, DER BOOLEAN values, no encoded DEFAULT FALSE); a CRL whose IDP violates it has unknown scope and is unusable for revocation decisions.
- An empty embedded SEQUENCE is rejected wherever a Certificate / CertificateList is expected (OCSP certs lists, CMP, CRMF); CRMF encryptedKey proof-of-possession and PKCS#12 encrypted safes reject a zero-length ciphertext the same way as a missing one.
- RecipientEncryptedKey surfaces ridType (rKeyId | issuerAndSerialNumber) so a key-agreement consumer no longer duck-types the recipient-matching form.
- The pki.schema.cms.parse reference documentation describes all five decoded content types and their return shapes.

### Fixed

- Crypto engine: deriveKey implements the W3C get-key-length rules (AES lengths limited to 128/192/256, HMAC defaulting to the hash block size); deriveBits rejects over-length, zero, and non-multiple-of-8 requests against the actual shared-secret size; unwrapKey surfaces a typed error instead of a bare JSON.parse SyntaxError; an RSA publicExponent is bounds-checked before numeric narrowing.
- Path validation: an unreadable basicConstraints or issuer key-usage extension now fails the check that consulted it instead of being silently swallowed; name-constraint inputs are validated at the entry point; the policy-tree node budget is a documented constant (LIMITS.PATH_MAX_POLICY_NODES).
- ASN.1 codec: the constructed encodings of GeneralString, NumericString, and ObjectDescriptor are rejected in DER mode; the byte caps passed to asn1.decode are validated as finite non-negative integers.
- Publish pipeline: the npm tarball and SBOM are re-hashed against the attested SLSA subjects and verified with slsa-verifier before anything is signed, released, or published; eslint is lockfile-pinned and runs isolated from the pack workspace; gitleaks is version+checksum pinned; the OpenSSF Scorecard threshold gate fails closed when a score cannot be extracted.
- Every behavioral fix above ships with a conformance vector driving the public parse/validate surface on the malformed input.

## v0.1.22 — 2026-07-09

An RFC 5035 / RFC 8551 S/MIME ESS signed-attribute decoder joins the schema family.

### Added

- pki.schema.smime.parseSigningCertificate(der) / parseSigningCertificateV2(der) — decode the RFC 5035 ESS SigningCertificate (v1) and SigningCertificateV2 (v2) signed-attribute values into { certs, policies }. Each certs entry is { certHash, hashAlgorithm, issuerSerial } in wire order: certHash raw; hashAlgorithm the implied SHA-1 for v1, or the decoded algorithm (or the id-sha256 default, flagged defaulted) for v2; issuerSerial (or null) the issuer GeneralNames (each CHOICE arm validated, surfaced raw) plus serialNumber as a BigInt and serialNumberHex. certs is non-empty and order-preserving; a v2 hashAlgorithm encoded byte-equal to its DEFAULT is rejected smime/non-canonical-default (X.690 §11.5). Malformed input fails closed with a typed smime/* (or leaf asn1/*) code.
- pki.schema.smime.parseSmimeCapabilities(der) — decode an RFC 8551 SMIMECapabilities value into { capabilities }, an ordered list (preference order preserved, never sorted) of { capabilityID, name, parameters } with parameters the raw ANY-DEFINED-BY bytes.
- pki.schema.smime.decodeAttribute(attr) — an OID-dispatch convenience over the three decoders for a CMS-shaped { type, values } attribute (the shape cms.parse surfaces on signerInfos[i].signedAttrs). It enforces the single-AttributeValue rule (a values length other than one is rejected smime/multi-valued-attribute), routes on the attribute OID, and recognize-and-defers an unknown type as smime/unsupported-attribute carrying the type, registry name, and raw values.
- The error taxonomy gains SmimeError, carrying a stable smime/* code.
- The OID registry gains the smimeCapabilities attribute identifier and the RFC 2634 ESS attribute names (receiptRequest through contentReference), so a CMS signed attribute of one of those types resolves to a name in an unsupported-attribute diagnostic.

## v0.1.21 — 2026-07-09

SLH-DSA signatures verify in certification-path validation, and the post-quantum / EdDSA parameters-absent rule is enforced across every format.

### Added

- SLH-DSA signature verification in pki.path.validate — all twelve FIPS 205 parameter sets (id-slh-dsa-sha2-{128,192,256}{s,f} and the SHAKE sets). A certificate or CRL signed with SLH-DSA now verifies by importing the issuer's SLH-DSA public key and checking the one-shot signature over the raw signed region; the same rows serve both the certificate signature check and the CRL revocation checker. ML-DSA and the classical RSA / ECDSA / EdDSA set were already wired.
- pki.oid.paramsMustBeAbsent(oid) — a predicate that reports whether an AlgorithmIdentifier bearing the given OID must encode its parameters field as absent (the ML-DSA and SLH-DSA families and the RFC 8410 Edwards / Montgomery curves). It is the single source the shared AlgorithmIdentifier decoder consults.
- The OID registry now names the twelve pre-hash HashSLH-DSA identifiers (id-hash-slh-dsa-*, RFC 9909 §3), so a certificate or CRL that carries a HashSLH-DSA algorithm resolves to a name and is covered by the parameters-absent rule.

### Fixed

- The shared AlgorithmIdentifier decoder now rejects a present parameters field on the algorithms whose parameters MUST be absent — ML-DSA, SLH-DSA, Ed25519, Ed448, X25519, and X448 (RFC 9909 §3, RFC 9814 §4, RFC 9881 §2, RFC 8410 §3) — failing closed with a <format>/bad-algorithm-parameters code. Previously a stray explicit NULL or arbitrary bytes in that field were surfaced raw. The rule is enforced once in the shared decoder, so every format that names an algorithm inherits it; a conforming identifier, which omits the field, is unaffected.
- Certification-path validation now enforces issuer-key / signature-algorithm consistency for the one-shot families whose public-key OID equals the signature OID — EdDSA, ML-DSA, and SLH-DSA — rejecting a mismatch with a path/algorithm-mismatch reason (RFC 9814 §4). Because the underlying WebCrypto import binds a public key of a different type to the requested algorithm name and verifies with the real key, a certificate or CRL signed by one key type but labelling its signatureAlgorithm as another one-shot type could otherwise validate; the check closes that algorithm-confusion path for both the certificate signature and the CRL revocation checker.

## v0.1.20 — 2026-07-09

An RFC 6962 Certificate Transparency SCT-list parser joins the toolkit.

### Added

- pki.ct.parseSctList(extValue) — RFC 6962 SCT-list parsing. It decodes the SignedCertificateTimestampList extension value (the raw extnValue content an x509 or OCSP extension surfaces) into { scts, unknownScts }. Each scts entry is a fully decoded v1 SCT: version (0), logId (32-byte Buffer) plus logIdHex, timestamp (exact BigInt) plus timestampMs (a Number, or null above 2^53) plus timestampDate, extensions (raw Buffer), the hashAlg / sigAlg code points plus a named signatureAlgorithm, the raw signature, and rawSct (the full SerializedSCT body). A SerializedSCT whose version is not v1 is preserved opaque in unknownScts as { version, rawSct } rather than failing the list (RFC 6962 §3.3 gives each SerializedSCT its own length so unknown versions are skippable). The extension value is the §3.3 double DER OCTET STRING wrap over a TLS-encoded list, decoded with a bounded reader that validates the list and per-SCT framing and every internal length, and asserts a per-list byte and count cap before it iterates. The signature is never verified and the log id never recomputed. Malformed input fails closed with a typed ct/* (or leaf asn1/*) code.
- pki.ct.reconstructSignedData(entry, sct) — rebuilds the exact digitally-signed preimage a verifier hashes to check an SCT's signature (RFC 6962 §3.2), for a decoded v1 SCT. entry selects the log-entry form: { entryType: 0, leafCert } for an SCT delivered over TLS or OCSP (signed over the leaf certificate), or { entryType: 1, tbsCertificate, issuerKeyHash } for an SCT embedded in a certificate (signed over the issuer key hash and the precertificate TBS). The preimage reuses the parsed SCT's raw extensions byte-for-byte; a verifier hashes the returned bytes and checks the signature with the log's public key.
- The certificate-extension value registry gains the SCT-list decoder and the precertificate-poison decoder (the poison value is content-validated as ASN.1 NULL, not merely tag-checked).
- The OID registry gains the Certificate Transparency arc — the SCT-list, precertificate-poison, precertificate-signing-certificate, and OCSP SCT-list identifiers — so those extension OIDs resolve to names.
- The error taxonomy gains CtError, carrying a stable ct/* code.

## v0.1.19 — 2026-07-09

An RFC 9810 Certificate Management Protocol message parser joins the pki.schema family.

### Added

- pki.schema.cmp.parse(input) — RFC 9810 PKIMessage parsing. It decodes a DER Buffer or PEM into { header, headerBytes, body, bodyBytes, protection, extraCerts }. The header carries pvno (1..3), validated sender / recipient GeneralNames (the anonymous NULL-DN accepted), and the optional messageTime (GeneralizedTime only), protectionAlg, senderKID / recipKID, transactionID, senderNonce / recipNonce, freeText, and generalInfo (recognized id-it values are syntax-checked). The body is { arm, tag, bytes, decoded? }: ir / cr / kur / krr / ccr decode through the CRMF parser; ip / cp / kup / ccp decode to a certificate-response structure (an encrypted certificate's EnvelopedData decodes through the CMS parser; the deprecated EncryptedValue arm and caPubs surface raw, conferring no trust); krp decodes to a key-recovery structure ({ status, newSigCert, caCerts, keyPairHist }); rr / rp, genm / genp, error, certConf (an empty confirmation is the legal reject-all), and pollReq / pollRep decode structurally; pkiconf decodes to null; every other defined arm — p10cr, the challenge-response and announcement arms, and nested (never auto-recursed) — surfaces raw. certReqId values are big integers and accept the protocol's -1 sentinel. The two cross-field coherence rules (protection bits and protectionAlg present together or absent together; a certConf hashAlg requires version cmp2021) are enforced. Protection is surfaced, not verified: headerBytes and bodyBytes are the exact wire slices, so a verifier reconstructs the protected part as a DER SEQUENCE wrapping them and checks the MAC or signature. Malformed input fails closed with a typed cmp/* or asn1/* code.
- pki.schema.cmp.pemDecode(text, label?) / pemEncode(der, label?) — PEM handling for messages that transit text channels (default label CMP).
- pki.schema.crmf.parse now surfaces every CertTemplate field, including serialNumber and the issuer/subject unique identifiers. RFC 4211's rule that a certificate request must omit the CA-assigned fields (serialNumber, signingAlg) and the deprecated unique identifiers moved from the shared CertTemplate structure to the request layer, so a request that sets them still fails closed while the same structure can identify an existing certificate — serialNumber and issuer present — inside a CMP revocation.
- The OID registry gains the CMP id-it information types and the message-protection MAC algorithm identifiers (passwordBasedMac, dhBasedMac, kemBasedMac), so a parsed message's info types and protection algorithm resolve to names.
- The error taxonomy gains CmpError, carrying a stable cmp/* code.

### Changed

- pki.schema.tsp parsing (parse, parseTstInfo, parseToken, pemDecode) is now stable.
- The npm-publish vulnerability scan reads the committed lockfiles (the dev and build toolchain that runs during a publish) instead of the runtime SBOM, which is empty by construction because the package ships zero runtime dependencies.

### Fixed

- Certification-path validation bounds the BasicConstraints pathLenConstraint and the PolicyConstraints / InhibitAnyPolicy skip counts before narrowing them to a number, so a certificate carrying a value past the safe-integer range is rejected rather than having the counter round silently to the wrong value (the same exact-or-rejected rule the RSASSA-PSS salt length and PKCS#12 iteration count follow).
- Certification-path validation rejects a non-empty DER NULL in an RSASSA-PSS hash AlgorithmIdentifier's parameters — a NULL must carry empty content (X.690 8.8.2), so the previous tag-only check accepted a malformed encoding it now fails closed.

## v0.1.18 — 2026-07-08

An RFC 7292 PKCS#12 (PFX) store parser joins the pki.schema family.

### Added

- pki.schema.pkcs12.parse(input) — RFC 7292 PFX parsing. It decodes a DER / BER Buffer or PEM into { version, integrityMode, mac, macedBytes, authSafeSigned, safeBags, encryptedSafes }. Password-integrity stores surface { kind, hashOid, hashName, hashParameters, pbmac1, macValue, macSalt, iterations } plus macedBytes — the exact value octets the HMAC covers, excluding the octet-string header, so an external verifier hashes the correct region. The RFC 9579 PBMAC1 arm is validated, not just recognized: its parameters must be present, the key-derivation function must be PBKDF2 with a keyLength, and the decoded KDF (salt, iteration count, key length, PRF) and MAC scheme surface on pbmac1. The X.690 DEFAULT rule is enforced (an explicitly encoded iterations = 1 is non-canonical and rejects). Public-key-integrity stores surface the CMS SignedData and must carry at least one signer (the signature itself is verified externally). Each safeBag carries its type, friendlyName / localKeyId (decoded, single-value and single-instance rules enforced), and all attributes: keyBags delegate to pki.schema.pkcs8.parse, shrouded key bags to parseEncrypted (algorithm surfaced, ciphertext opaque), cert / CRL / secret values stay raw and byte-exact, and safeContentsBags recurse under a depth ceiling. Encrypted and enveloped safes are validated structurally by the CMS module with ciphertext kept raw, and must declare id-data (a SafeContents) as their encrypted content type. The version-3 rule, the contradictory MacData-alongside-SignedData combination, the closed bag-type and cert/CRL-type sets, and per-list element caps all fail closed with typed pkcs12/* codes; a MacData-less id-data store is legal syntax and parses as integrityMode "none".
- pki.schema.pkcs12.pemDecode(text, label?) / pemEncode(der, label?) — PEM handling for stores that transit text channels (default label PKCS12).
- pki.asn1.decode gains an opt-in ber option accepting exactly two shapes — an indefinite length on a constructed value and a constructed OCTET STRING, whose segments reassemble into one primitive content — for formats whose content is normatively BER. The default remains strict DER; minimal-length, minimal-integer, trailing-byte, and size / depth verdicts are unchanged in both modes, an indefinite length on a primitive value still rejects, a foreign-type segment inside a constructed string rejects, and constructed-string nesting is capped (each level re-copies its payload, so deep nesting is memory amplification, not data).
- pki.schema.engine.embeddedDer(schema, bytes, ctx, opts) — the named form of the re-decode idiom: decode a fresh DER / BER blob carried inside an already-decoded value and walk it against a schema, wrapping codec failures in the caller's typed code. A shared budget option bounds how many nested blobs one parse may unwrap, so a container that chains encodings across octet-string boundaries cannot restart the depth caps from zero. The timestamp, OCSP, and certificate-request parsers now route their embedded-structure decodes through it.
- SEQUENCE OF / SET OF schemas can declare an element-count ceiling (max), so a container listing a great many tiny elements fails typed instead of amplifying memory through per-element parse products; a single attribute's value list is now capped this way across every format.
- The OID registry gains the PKCS#12 bag types, the PKCS#12 password-based encryption identifiers, the PKCS#9 certTypes / crlTypes / friendlyName / localKeyId entries, PKCS#5 PBKDF2 / PBES2 / PBMAC1, the NIST AES content-encryption arc, and the HMAC-with-SHA identifiers, so a store's algorithms resolve to names.
- The error taxonomy gains Pkcs12Error, carrying a stable pkcs12/* code.

### Changed

- The npm-publish workflow's vulnerability scan now scans the SBOM unconditionally and the vendored-bundle directory only when it holds a real bundle, so the scan is exact in both states instead of warning on the empty directory.

### Fixed

- Certification-path validation bounds the RSASSA-PSS saltLength and trailerField before numeric conversion, so an oversized value rejects with path/unsupported-algorithm instead of rounding silently on its way to the verifier — the same exact-or-rejected rule the PKCS#12 MAC parameters follow.

## v0.1.17 — 2026-07-06

An RFC 4211 certificate-request-message parser joins the pki.schema family.

### Added

- pki.schema.crmf.parse(input) — RFC 4211 CertReqMessages parsing. It decodes a DER Buffer or PEM into { messages: [ { certReq, popo, regInfo } ] }, where each certReq is { certReqId, certReqIdHex, certTemplate, controls, certReqBytes } and certTemplate carries the requestable fields version, issuer, validity, subject, publicKey, and extensions (each null when absent). The fields RFC 4211 §5 requires a request to omit — serialNumber and signingAlg (assigned by the CA) and issuerUID and subjectUID (deprecated) — are rejected, not returned, so a requester cannot dictate a CA-assigned value. issuer and subject Names are accepted in both the EXPLICIT and the IMPLICIT wire encodings; the OptionalValidity times are EXPLICIT UTCTime or GeneralizedTime; a supplied CertTemplate version must be 2; certReqId is an unbounded signed integer. popo is null, a raVerified marker, a decoded signature proof (with its poposkInput and signature surfaced raw), or a raw key-encipherment / key-agreement arm; for a signature proof, poposkInput's presence is checked against the template per §4.1. certReqBytes is the exact CertRequest byte range a proof-of-possession verifier hashes. Malformed input fails closed with a typed crmf/* or asn1/* code.
- pki.schema.crmf.pemDecode(text, label?) — extract the DER bytes from a PEM block (the first block unless a label is given).
- The OID registry gains the RFC 4211 registration-control (id-regCtrl) and registration-info (id-regInfo) identifiers on the id-pkip arc, so a parsed control or info entry resolves to its name (oldCertID, pkiArchiveOptions, utf8Pairs, and the rest).
- The error taxonomy gains CrmfError, carrying a stable crmf/* code.
- pki.schema.engine.encode(schema, value) — the constructor direction of the schema engine. A single declarative schema now drives both decode (walk, bytes to value) and encode (canonical DER, value to bytes): every leaf carries a read and a write, and EXPLICIT wrapping and IMPLICIT context-tag retagging are applied in one place, so an encoder can no longer emit a different tag than the decoder reads. A round-trip test proves walk(decode(encode(value))) recovers the value across universal, IMPLICIT, EXPLICIT, and SET-OF-ordered shapes, and the CRMF request format is proven to round-trip end to end.

### Changed

- pki.schema.ocsp request and response parsing (parseRequest, parseResponse, pemDecode) is now stable.
- An experimental primitive is surfaced for a graduation review once it has been experimental for a fixed number of releases; the review is recorded as a graduation to stable or a dated keep-experimental decision, so the experimental-to-stable-to-deprecated transition is driven on a schedule (see LTS-CALENDAR.md).

## v0.1.16 — 2026-07-06

Certification path validation joins the toolkit — RFC 5280 section 6, as a pure re-entrant algorithm.

### Added

- pki.path.validate(path, opts) — RFC 5280 section 6 certification-path validation. It validates an ordered array of pki.schema.x509.parse certificates (or DER/PEM it parses) against a trust anchor, running the section 6.1 state machine: section 6.1.3(a)(1) signature chaining, the always-on section 6.1.3(a)(2) validity window with the check date an explicit input, section 6.1.3(a)(4) name chaining, section 6.1.3(b,c)/6.1.4(g) name constraints (directoryName, dNSName, rfc822Name including an emailAddress carried in the subject DN, uniformResourceIdentifier, and iPAddress with the address-and-mask subtree form), section 6.1.4(k) basic constraints as the single authoritative CA gate, section 6.1.4(l,m) path length, section 6.1.4(n) keyUsage keyCertSign, and the section 6.1.3(d)/6.1.4(a,b,i,j)/6.1.5 certificate-policy tree with its explicit-policy, policy-mapping, and inhibit-any-policy counters. It returns { valid, path, results, workingPublicKey, workingPublicKeyAlgorithm, workingPublicKeyParameters, validPolicyTree } where results[i].checks carries a stable path/* reason code per check. Validation is pure and re-entrant. An unrecognized critical extension, an undetermined revocation status, or a structural fault fails the path with a typed code.
- pki.path.crlChecker(crls) — a CRL-backed revocation checker for the validate revocationChecker option, composing pki.schema.crl.parse. For each certificate it consults every CRL issued by the certificate's issuer (so a clean CRL cannot shadow a revoking one), verifies each CRL signature over its tbsBytes, honors the issuing-distribution-point scope and reason coverage, checks thisUpdate/nextUpdate currency, and requires the CRL signer to assert keyUsage cRLSign; a certificate listed in any authoritative in-scope CRL is revoked, and an issuer with no authoritative in-scope CRL yields an undetermined status, which the validator fails closed unless softFail is set. An OCSP checker satisfies the same interface.
- pki.schema.pkix gains the ns-parameterized RFC 5280 section 4.2.1 extension-value decoders (pkix.certExtensionDecoders) — basicConstraints, keyUsage, nameConstraints, certificatePolicies, policyMappings, policyConstraints, inhibitAnyPolicy, subjectAltName / issuerAltName, extKeyUsage, and authorityKeyIdentifier / subjectKeyIdentifier — each turning a raw extension value into a validated structure or a typed error, fail-closed. The shared GeneralName validator gains a decoded-value mode (surfacing the IA5 text, the IP octets, or the directoryName as a structured name alongside the raw bytes) and an address-and-mask subtree-base mode for name-constraint bases; both are opt-in, so the existing callers are byte-identical.
- The OID registry gains the RFC 5280 policy and wildcard extension identifiers used by path validation: policyMappings, policyConstraints, and inhibitAnyPolicy, plus the anyPolicy and anyExtendedKeyUsage special-OID leaves.
- The error taxonomy gains PathError, carrying the per-check reason in its stable path/* code.

## v0.1.15 — 2026-07-06

CMS EnvelopedData and EncryptedData join the parser, and every documentation example is now executed as a test.

### Added

- pki.schema.cms.parse now decodes CMS EnvelopedData (RFC 5652 §6) and EncryptedData (§8). An EnvelopedData returns { version, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs } with all five RecipientInfo kinds decoded — KeyTransRecipientInfo (§6.2.1, with the issuerAndSerialNumber/subjectKeyIdentifier version coupling enforced), KeyAgreeRecipientInfo (§6.2.2 + RFC 5753 §3.1), KEKRecipientInfo (§6.2.3), PasswordRecipientInfo (§6.2.4), and OtherRecipientInfo (§6.2.5). An EncryptedData returns { version, encryptedContentInfo, unprotectedAttrs }. The wrapped keys, the ciphertext, and all AlgorithmIdentifier parameters are surfaced raw — every recipient carries the keyEncryptionAlgorithm its encryptedKey must be unwrapped with, and a kekid / rKeyId OtherKeyAttribute is surfaced as raw DER — decryption and key-unwrap are a separate layer. The CMSVersion is recomputed and enforced per structure and per recipient, recipientInfos is required non-empty, and the encryptedContent [0] IMPLICIT OCTET STRING is read as the ciphertext directly.
- The schema engine gains an implicitTag option on pki.schema.engine.seq() and on pki.schema.pkix.algorithmIdentifier(ns, { implicitTag }) — a [tag] IMPLICIT SEQUENCE / AlgorithmIdentifier reader (used by the PasswordRecipientInfo keyDerivationAlgorithm [0]). A call with no option is byte-identical to before.
- Every @example in the documentation comment blocks is now executed end-to-end as a test (test/layer-0-primitives/doc-examples.test.js, in the smoke gate), not merely parse-checked: an example must run to completion or throw a typed PkiError, and every documented @primitive path must resolve to a real export — so a documented example can no longer drift from the shipped API. A new @originated comment tag records a callable's original availability version when its documented path is later corrected, enforced alongside the @since version gate.

### Changed

- The W3C WebCrypto constructor classes (CryptoKey, Crypto, SubtleCrypto, WebCryptoError) are now reachable under pki.webcrypto (e.g. pki.webcrypto.CryptoKey) alongside the ready Crypto instance, matching their documented path; the previously-separate pki.WebCrypto holder is removed.
- Repository tooling now installs npm packages exclusively through integrity-verified lockfiles: the fuzz build installs the jazzer.js engine via npm ci against the committed fuzz/package-lock.json, and the vendoring script resolves a package to an integrity-pinned lockfile in an isolated staging workspace — no install script runs and the repo's own node_modules is never touched — before bundling. Tooling child processes that need a shell (the Windows npm shim) now receive one explicitly-quoted command string instead of an unescaped argument array.

### Fixed

- Two documented API paths that did not resolve at runtime are corrected: pki.webcrypto.CryptoKey (previously reachable only via pki.WebCrypto.CryptoKey) and pki.asn1.read.oid (its comment block labeled the path pki.asn1.readOid, which never existed). Both are now reachable at the documented path.
- A documentation example for pki.webcrypto.subtle.exportKey referenced an undefined variable; it now generates the key pair it exports.

## v0.1.14 — 2026-07-05

An RFC 5755 attribute-certificate parser joins the pki.schema family.

### Added

- pki.schema.attrcert — an RFC 5755 attribute-certificate parser. pki.schema.attrcert.parse turns a DER Buffer or PEM into a structured v2 attribute certificate ({ version, holder, issuer, signatureAlgorithm, serialNumber, serialNumberHex, validity, attributes, issuerUniqueID, extensions, tbsBytes, signatureValue }). The holder (baseCertificateID / entityName / objectDigestInfo) and issuer (v1Form / v2Form) identities come back as validated GeneralNames; the validity window is real Dates; the privilege attributes (id-at-role, id-aca-group, id-at-clearance, and any others) resolve by name where the registry knows them. The outer-equals-inner signatureAlgorithm agreement (RFC 5755 4.2.4), the positive-and-at-most-20-octet serialNumber (4.2.5), the GeneralizedTime-only validity (4.2.6), the non-empty unique-typed attribute list (4.2.7), and the digestedObjectType enumeration are all enforced fail-closed. pki.schema.parse detect-and-routes an attribute certificate; the obsolete v1 form is recognized and deferred with a precise attrcert/legacy-v1-not-supported.
- pki.schema.pkix gains a shared GeneralNames validator that the attribute-certificate parser composes for its four GeneralNames-bearing fields — validating every element as a well-formed GeneralName (rejecting a bad tag, a wrong primitive/constructed form, a non-IA5 string, or a mis-sized iPAddress) rather than surfacing the sequence as opaque bytes. It handles both a bare universal SEQUENCE OF GeneralName and a context-tagged IMPLICIT GeneralNames.
- The OID registry gains the RFC 5755 attribute-certificate object identifiers: the id-aca attribute-type family (authenticationInfo / accessIdentity / chargingIdentity / group), id-at-role and id-at-clearance, the id-ce-targetInformation and id-ce-noRevAvail extensions, and the id-pe-ac-auditIdentity / id-pe-aaControls / id-pe-ac-proxying private extensions — so a parsed attribute certificate's attributes and extensions resolve by name.

## v0.1.13 — 2026-07-05

An RFC 3161 timestamp parser joins the pki.schema family.

### Added

- pki.schema.tsp — an RFC 3161 timestamp parser. pki.schema.tsp.parse turns a DER Buffer or PEM into a TimeStampResp ({ status, statusString, failInfo, timeStampToken }) with the granted-carries-token / rejected-carries-none coupling enforced (tsp/missing-token, tsp/unexpected-token) and the PKIFailureInfo named bits decoded. pki.schema.tsp.parseToken parses a TimeStampToken by composing pki.schema.cms.parse and asserting the id-ct-TSTInfo content type (tsp/wrong-econtent-type), attached content (tsp/detached-token), and the single (TSA) signer (tsp/multi-signer), returning the decoded TSTInfo plus the signer material. pki.schema.tsp.parseTstInfo decodes a bare TSTInfo. The TSTInfo mandatory version-1, the GeneralizedTime-only genTime, the accuracy 1..999 range, the ordering DEFAULT FALSE omission, and the PKIStatus 0..5 range are all enforced fail-closed. pki.schema.parse detect-and-routes a TimeStampResp.
- The codec and schema engine gain three composable primitives that TSP required: pki.asn1.read.integerImplicit / pki.schema.engine.implicitInteger(tag) (a context-tagged IMPLICIT INTEGER, for the Accuracy millis / micros fields); pki.schema.engine.implicitSeqOf(tag, item) (an order-preserving IMPLICIT SEQUENCE OF, the sibling of implicitSetOf without the SET ordering rule, for the extensions field); and RFC 3161 / X.690 §11.7 fractional-seconds GeneralizedTime support in pki.asn1.read.time (a '.'-separated, trailing-zero-free, Z-terminated fraction, surfaced at millisecond precision).
- The OID registry gains the id-kp extended-key-purpose family (including id-kp-timeStamping) and the id-aa S/MIME authenticated-attribute family (signingCertificate / signingCertificateV2 / timeStampToken), so a parsed TSA certificate's key purpose and a signer's ESS binding attribute resolve by name.

## v0.1.12 — 2026-07-05

SLH-DSA object identifiers corrected and completed to all twelve FIPS 205 parameter sets.

### Fixed

- SLH-DSA OID resolution — id-slh-dsa-shake-128s and id-slh-dsa-shake-256s were mapped to the arcs of id-slh-dsa-sha2-256s (.24) and id-slh-dsa-shake-128f (.27), so pki.oid.name / pki.oid.byName resolved them incorrectly. All twelve Pure SLH-DSA parameter sets (sha2-128s/128f/192s/192f/256s/256f and shake-128s/128f/192s/192f/256s/256f) are now registered at their correct arcs .20 through .31 per RFC 9909 §3; the previously-absent nine sets now resolve as well. WebCrypto SLH-DSA sign/verify was unaffected — it selects by algorithm name, not through the OID registry.

## v0.1.11 — 2026-07-05

An OCSP request and response parser joins the pki.schema family.

### Added

- pki.schema.ocsp.parseRequest and pki.schema.ocsp.parseResponse — an OCSP request / response parser per RFC 6960 (§4.1 OCSPRequest, §4.2 OCSPResponse). parseRequest turns a DER Buffer or an 'OCSP REQUEST' PEM string into { tbsRequestBytes, version, requestorName, requestList, requestExtensions, optionalSignature }, each requestList entry carrying its CertID with the two issuer hashes raw. parseResponse turns a DER Buffer or an 'OCSP RESPONSE' PEM string into { responseStatus, responseBytes, basicResponse }; for a successful basic response, basicResponse carries { tbsResponseDataBytes, responderID, producedAt, responses, signatureAlgorithm, signature, certs } and each responses[i].certStatus is { type: 'good' | 'revoked' | 'unknown' } (a revoked entry adds its revocationTime and revocationReason). A malformed structure throws a typed OcspError (ocsp/*), an unsupported responseType throws ocsp/unsupported-response-type, and a leaf-level codec fault surfaces as asn1/*. pki.schema.ocsp.pemDecode handles the PEM envelope, and pki.schema.parse detect-and-routes both OCSP shapes.
- pki.asn1.read.nullImplicit and the pki.schema.engine.implicitNull(tag) leaf — read a context-tagged IMPLICIT NULL (the shape the OCSP CertStatus good [0] and unknown [2] arms take), the primitive-leaf sibling of implicitBitString and implicitOctetString. It rejects a constructed or non-empty context node fail-closed.
- An ocsp-parse coverage-guided fuzz harness joins the CI fuzzing matrix (jazzer.js + libFuzzer, per pull request and nightly), driving both OCSP entry points on mutated input.

## v0.1.10 — 2026-07-05

A CMS SignedData parser joins the pki.schema family; coverage-guided fuzzing now runs in CI.

### Added

- pki.schema.cms.parse — a CMS SignedData parser per RFC 5652 (§3 ContentInfo + §5 SignedData). It turns a DER Buffer or a 'CMS' PEM string into { version, digestAlgorithms, encapContentInfo, certificates, crls, signerInfos }. encapContentInfo.eContent is the raw content (or null when the signature is detached); each SignerInfo carries its raw signature and, when signed attributes are present, the on-wire signedAttrsBytes for external verification. The signer identifier is an issuerAndSerialNumber or a subjectKeyIdentifier, with the version-to-identifier rule (RFC 5652 §5.3) enforced, and a degenerate certificates-only SignedData (empty digest algorithms and signer infos) is accepted. A ContentInfo whose content type is not id-signedData throws cms/unsupported-content-type (a recognized PKCS#7 type) or cms/unknown-content-type; a malformed structure throws a typed CmsError (cms/*) and a leaf-level codec fault surfaces as asn1/*. pki.schema.cms.pemDecode / pemEncode handle the PEM envelope, and pki.schema.parse detect-and-routes a CMS message.
- pki.asn1.read.octetStringImplicit and the pki.schema.engine.implicitOctetString(tag) leaf — read a context-tagged IMPLICIT OCTET STRING (the shape the CMS SignerIdentifier subjectKeyIdentifier [0] takes), the primitive-leaf sibling of implicitBitString.
- Coverage-guided fuzzing in CI — a ClusterFuzzLite integration (.clusterfuzzlite/) plus pull-request and nightly-batch workflows run jazzer.js + libFuzzer against the pki.asn1.decode, pki.schema.x509.parse and pki.schema.cms.parse harnesses. A finding fails the run with the reproducer inline and uploads the crash input as an artifact. The integration is detectable by OpenSSF Scorecard's Fuzzing check.

### Fixed

- The OpenSSL interop runner counted a cross-check the oracle could not perform (for example, an OpenSSL predating ML-DSA) as a pass. Such a cross-check is now recorded as a skip and reported separately, so the interop pass count is not inflated by checks that never executed.

## v0.1.9 — 2026-07-05

A PKCS#8 private-key parser joins the pki.schema family.

### Added

- pki.schema.pkcs8.parse — a PKCS#8 PrivateKeyInfo / OneAsymmetricKey parser per RFC 5208 §5 and RFC 5958 §2. It turns a DER Buffer or a 'PRIVATE KEY' PEM string into { version, privateKeyAlgorithm, privateKey, attributes, publicKey }, where privateKey is the raw OCTET STRING content (the inner RSA/EC/curve key, decoded by the caller via privateKeyAlgorithm.oid) and publicKey is present only for a v2 key. The version must be v1 (0) or v2 (1), and a [1] public key is permitted only in a v2 key (both directions enforced). A malformed key throws a typed Pkcs8Error (pkcs8/*); a leaf-level codec fault surfaces as asn1/*. pki.schema.pkcs8.pemDecode / pemEncode handle the PEM envelope.
- pki.schema.pkcs8.parseEncrypted — recognizes an EncryptedPrivateKeyInfo ('ENCRYPTED PRIVATE KEY') and surfaces its encryptionAlgorithm and raw encryptedData. Decryption (PBES2/PBKDF2 + a passphrase) is a separate concern and is not performed here. This is an explicit call — an EncryptedPrivateKeyInfo shares its SEQUENCE{SEQUENCE, OCTET STRING} shape with a PKCS#1 DigestInfo, so pki.schema.parse does not auto-route it (structure alone cannot classify it without a validated encryption-algorithm discriminator).
- pki.asn1.read.enumerated's sibling pki.asn1.read.bitStringImplicit and the pki.schema.engine.implicitBitString(tag) leaf — read a context-tagged IMPLICIT BIT STRING (the shape a PKCS#8 OneAsymmetricKey public key [1] takes).

## v0.1.8 — 2026-07-04

A PKCS#10 certification-request parser joins the pki.schema family.

### Added

- pki.schema.csr.parse — a PKCS#10 CertificationRequest parser per RFC 2986. It turns a DER Buffer or a 'CERTIFICATE REQUEST' PEM string into a structured object: version, subject distinguished name, subjectPublicKeyInfo, the requested attributes (each with its type OID, resolved name, and raw-DER values), and the signatureAlgorithm / signatureValue over the CertificationRequestInfo — with the raw certificationRequestInfoBytes returned for signature verification. It composes the shared schema engine and PKIX sub-schemas (AlgorithmIdentifier, Name, SubjectPublicKeyInfo), so a certification request inherits the identical fail-closed structural rules and a malformed request throws a typed CsrError (csr/*); a leaf-level codec fault surfaces as asn1/*. The version must be v1 (INTEGER 0), the [0] IMPLICIT attributes element is mandatory, and each attribute's values SET must be non-empty. pki.schema.parse now detects and routes certification requests, and pki.schema.all() lists it alongside crl and x509. pki.schema.csr.pemDecode / pemEncode handle the PEM envelope.
- pki.asn1.read.enumerated — reads an ENUMERATED value from a decoded node (the same content rules as an INTEGER), the counterpart to the now-strict pki.asn1.read.integer.

### Changed

- C.TIME.ms is renamed to C.TIME.milliseconds, so every C.TIME duration helper now reads as a full word (milliseconds, seconds, minutes, hours, days, weeks). The behaviour is unchanged — it still returns an integer millisecond count.

### Security

- pki.asn1.read.integer now rejects an ENUMERATED-tagged node. INTEGER and ENUMERATED share DER content encoding, so an INTEGER-pinned field — a certificate or certification-request version, a serial number, or a cRLNumber — mis-encoded as ENUMERATED was previously decoded as though it were the INTEGER, a type confusion that let malformed DER parse where a conformant reader rejects it. read.integer is now strict on the tag, and ENUMERATED values are read with the new pki.asn1.read.enumerated. Certificate, CRL, and certification-request parsing reject these inputs fail-closed.
- SubjectPublicKeyInfo is now required to be a universal SEQUENCE across the certificate and certification-request parsers — a context-tagged or SET-tagged constructed node carrying a well-formed algorithm and key is no longer accepted as an SPKI.
- SET OF components are now required to be in ascending DER order (X.690 §11.6) wherever the schema declares a SET OF — a relative distinguished name, and a certification request's attributes and attribute values. A non-canonical, unsorted encoding is rejected fail-closed.

### Migration

- Replace C.TIME.ms(n) with C.TIME.milliseconds(n). The other C.TIME and C.BYTES helpers are unchanged.

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
