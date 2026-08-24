# Security Policy

`@blamejs/pki` is a security-first PKI toolkit. Its defaults are fail-closed: the
DER decoder rejects every non-canonical shape, every verify path throws on
failure, and post-quantum algorithms are first-class registry entries rather than
bolt-ons. This document covers how to report a vulnerability, which versions are
supported, how an operator hardens a deployment that embeds the toolkit, and how
to verify that a release is authentic.

---

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Report privately through GitHub's **["Report a vulnerability"](https://github.com/blamejs/pki/security/advisories/new)**
private advisory form on the repository's Security tab. This opens a private
channel with the maintainers.

Include:

- Affected version (`v0.X.Y` tag, or the `main` `<sha>` you tested)
- A description of the issue and the impact you observed
- A minimal reproducer: the smallest certificate, DER blob, message, or code
  snippet that triggers the behavior
- Whether you have discussed this with anyone else, and any coordinated-
  disclosure timeline you are working to

The toolkit's dominant attack surface is parsing untrusted bytes, so a reproducer
that is a raw DER, PEM, or message blob is the most useful thing you can send.
Attach it, base64 or hex, rather than describing it in prose.

### Response targets

| Severity | First response | Triage / acknowledgment | Fix released |
|---|---|---|---|
| Critical (parser memory-safety, signature-verification bypass, algorithm-substitution accepted) | within 72 h | within 7 d | next patch (≤ 14 d) |
| High (fail-closed guarantee broken, path-validation bypass, canonicalization mismatch) | within 7 d | within 14 d | next patch (≤ 30 d) |
| Medium (unbounded work / DoS on adversarial input, information leak in an error) | within 14 d | within 30 d | next patch |
| Low (defense-in-depth gaps) | within 30 d | as scheduled | next minor |

We coordinate disclosure with the reporter. A typical embargo is 14 days after a
fix is released, to give operators time to upgrade. Reporter credit appears in
the release notes unless anonymity is requested.

---

## Supported versions

Pre-1.0, the supported version is the most-recent published patch on the
most-recent minor. Older minors do not receive security backports unless the
issue is critical and the operator base on the older minor is non-trivial.

Once 1.0 ships, an LTS calendar takes effect: each major gets 24 months of
security-only patches after the next major releases.

| Version range | Security patches |
|---|---|
| Latest `v0.x` minor — current patch line | yes |
| Older `v0.x` patch lines | no |

---

## What the toolkit defends, by design

### Parsing untrusted bytes

- **Adversarial DER or PEM crashing the parser.** The decoder enforces size and
  depth caps before it walks a structure, and rejects every non-canonical shape
  with a typed `Asn1Error`: indefinite length, non-minimal length or tag
  encodings, constructed strings where DER forbids them, and trailing bytes after
  the top-level value. Malformed input costs bounded work and gets a permanent
  verdict, rather than producing a stack overflow or a half-parsed object.
- **Adversarial CBOR crashing the parser.** The `pki.cbor` decoder applies the
  same posture to RFC 8949 core-deterministic CBOR: size, depth, and per-bignum
  byte caps before the walk, and a typed `CborError` on every non-canonical
  shape — an indefinite length, a non-minimal (preferred) argument, out-of-order
  or duplicate map keys, a non-shortest or non-canonical-NaN float, ill-formed
  UTF-8, or trailing bytes. No lenient mode exists.
- **Single-input string-allocation amplification.** Every boundary that decodes
  untrusted bytes to a string — PEM armor, a JOSE or ACME JSON document, an EST
  transfer or multipart body — enforces its size cap on the raw byte length
  before materializing the string. An oversized input is rejected before it
  allocates a full-size string, and a body above Node's maximum string length
  fails typed rather than escaping as an untyped `ERR_STRING_TOO_LONG`. A
  detached-backed input, such as a transferred or structuredClone'd view whose
  bytes are gone and which therefore reads as zero-length, fails closed with a
  typed error at the byte boundary instead of being processed as empty.
- **Decode-fanout and verify-fanout amplification.** A decoded input's element
  count is capped independently of its byte size (`asn1/too-many-items`,
  `cbor/*`, per-list PKCS#12 caps), and an OCSP response is capped in embedded
  certificates before any pre-authentication signature work. A small hostile
  input cannot fan out into unbounded allocations or unbounded asymmetric-verify
  work.
- **Decompression bombs (CWE-409).** Every decompression in the toolkit runs
  through one bounded primitive, so the defense cannot be picked up by one caller
  and missed by the next. The output is capped at the decompressor itself (Node's
  `maxOutputLength`), which stops at the bound before the output is materialized,
  so a tiny stream that would expand to gigabytes is refused rather than
  allocated. `pki.cms.decompress` (RFC 3274 CompressedData, RFC 1950 ZLIB) caps
  at `C.LIMITS.COMPRESS_MAX_BYTES` (16 MiB, tightened downward via
  `opts.maxOutputBytes`) and throws `cms/decompress-too-large`.
  `pki.tls.decompressCertificate` (RFC 8879) caps at the message's own declared
  `uncompressed_length`, so an attacker's declaration is its own ceiling, bounded
  in turn by the RFC 8446 §4 handshake framing limit
  `C.LIMITS.TLS_CERT_MSG_MAX_BYTES` (2^24-1) and by any tighter caller cap, and
  throws `tls/too-large`. Every other malformed, truncated, or corrupt stream
  collapses to a uniform per-domain code, with no per-errno telemetry.
- **Compressed-stream malleability (CWE-20).** A decompressor stops at the end of
  the first complete frame and silently ignores anything after it. Appended
  bytes, or a whole second frame, would recover identical content and give one
  content unboundedly many encodings, breaking any digest taken over the
  compressed object. The shared primitive requires the whole input to be exactly
  one frame: the consumed input length must equal the input length, or the stream
  is refused (`cms/decompress-failed`, `tls/decompress-failed`). This is the same
  rule the DER layer applies when it rejects trailing bytes.
- **Silent frame truncation (CWE-354).** A decompressor must fault on a frame it
  could not finish. Some runtimes instead return a short result and report the
  whole input as consumed, so neither the output nor a consumed-length check can
  see that the frame was cut: a peer strips a frame's tail and the receiver
  processes a prefix as though it were the whole message. The shared primitive
  probes each algorithm once at startup and drops any whose decompressor behaves
  that way, so it is neither advertised nor accepted. On the current LTS Node
  this drops zstd from `pki.tls`, leaving zlib and brotli; it returns on a runtime
  that faults.
- **Unbounded certificate-entry allocation (CWE-770).** A TLS Certificate
  message's byte ceiling does not bound how many `CertificateEntry` elements it
  declares. The smallest legal entry is 6 bytes, so a message well inside the
  framing limit can declare hundreds of thousands, each costing far more heap
  than wire. `pki.tls.parseCertificateMessage` caps the count at
  `C.LIMITS.TLS_CERT_MAX_ENTRIES` (100, matching `PATH_MAX_CERTS`, since a chain
  longer than the path validator accepts has nothing to offer), and at exactly
  one under a negotiated RawPublicKey type, which RFC 8446 §4.4.2 requires.
- **Compressed certificate length agreement (RFC 8879 §5).**
  `pki.tls.decompressCertificate` enforces the bound on both sides: the cap above
  catches output larger than declared, and an explicit comparison catches output
  smaller than declared (`tls/length-mismatch`), which is the direction no cap can
  see. An algorithm outside the RFC 8879 registry, one the runtime cannot
  decompress, or one the receiver never advertised is refused before any
  decompressor is handed the bytes.
- **Compression is not protection.** CMS CompressedData carries no integrity,
  confidentiality, or authentication (RFC 8551 §2.4.5). The decompress verdict
  has no `authenticated` or `valid` field, so a caller cannot mistake size
  reduction for protection; sign or encrypt the result if you need it. The same
  holds for a decompressed certificate message: it is structure, not trust, so
  path-validate the certificates it carries.
- **Container nesting and amplification (PKCS#12).** A PFX chains fresh encoded
  blobs inside octet strings, where every re-decode would restart the depth cap
  from zero. The PKCS#12 parser carries one cross-decode budget over all of them
  and caps element counts at each list, so a crafted store fails typed
  (`pkcs12/too-deep`, `pkcs12/too-many-elements`) instead of exhausting the stack
  or memory. Its BER acceptance is scoped to exactly the two shapes RFC 7292 §4.1
  requires, indefinite lengths and constructed octet strings, and only for that
  format. Every other format and every other DER strictness verdict is unchanged.
- **Encoding malleability.** Every textual encoding an operator hands the toolkit
  is decoded strictly against its one canonical form: base64url (JOSE and JWK key
  material), base64 (PEM bodies, EST transfer), hex, a JSON document, and a
  dotted-decimal OID string. A padded or non-canonical base64url `k`, a JSON
  document with a duplicate member at any depth, or an OID string with a
  leading-zero arc (which encodes a different OID than the string names) fails
  typed instead of aliasing a second spelling of the same value past a verifier.
  JSON parsing is bounded in size and nesting and assigns `__proto__` as an own
  property, never a prototype mutation.
- **A value that answers differently on the second read.** Where a verb takes an
  object, the toolkit reads its state through the language rather than through
  the object: a `Date` gives up its instant through the intrinsic `getTime` and
  is compared as a number, so neither an overriding subclass nor a
  `Symbol.toPrimitive` decides the moment a certificate is checked at; a byte
  view's contents are read through the intrinsic accessors that reach its buffer,
  so a lying `byteLength` cannot shorten what gets hashed; and the kind of a
  value is settled from its internal slot, which admits an equivalent built from
  another realm and refuses a lookalike carrying only the prototype. Arguments
  that outlive a promise turn are deep-copied at entry, and a field supplied
  through an accessor is refused there rather than read once and stored, since a
  value that can differ between the check and the use is not one the check
  covered. The same rule governs the OPERATIONS a decision is made with, not
  only the values it reads: a check written as `key.usages.indexOf(usage)` asks
  the runtime, at the moment of the call, which function `indexOf` is, so one
  replaced afterwards reports every usage present and the refusal is never
  raised. The crypto engine, the JWS signer, the format decoders and every guard
  therefore take what they decide with at load and invoke it without reading a
  property of the captured function, so a permission check, a canonical
  serialization, or the split between a ciphertext and its authentication tag
  concludes the same thing whenever it runs. Asking whether a registry carries a
  name has the same shape, since written out it reads a membership test and the
  call that applies it, and either answering the wrong way admits a name the
  registry never held: an undefined OCSP response status, a reserved CRL reason
  code, a trust bit no root program granted. Those questions are asked through a
  captured operation as well. The boundary is the process: code that loads before this
  package can replace the built-ins it captures, and nothing inside a library can
  defend against that. Two doors into that class stay shut for the same reason.
  Each guard module freezes what it exports, because a boundary reaches its check
  as a property of the guard object at the moment of the call and every module is
  handed the same object, so one assignment would otherwise replace a
  constant-time comparison, a size cap or a secret wipe everywhere at once. And a
  table asked a question by a key the wire supplies -- which GeneralName
  alternative a context tag selects, which string types are DisplayText, which
  decoder an extension OID resolves to, whether a policy OID has already been
  seen -- carries no prototype, so a name planted on `Object.prototype` cannot
  answer for an entry nothing registered.
- **One signature covering several encodings.** A type-3 C509 certificate is a
  re-encoding of an X.509 certificate, and the X.509 signature covers the bytes
  it rebuilds rather than the C509 bytes themselves. Where the specification
  fixes which spelling a value takes, this decoder accepts only that spelling, so
  a certificate has one C509 encoding rather than several that rebuild it
  identically. Otherwise code identifying, caching, or deduplicating a
  certificate by its C509 bytes would see distinct byte strings for one
  certificate, each carrying a signature that verifies. The encoder walks the
  same rules, so what it emits is what it accepts. One redundancy the
  specification itself permits remains, in that a registered algorithm may ride
  as its registry integer or as its object identifier, so identify a certificate
  by the X.509 bytes it reconstructs rather than by its C509 bytes.
- **A misspelled authoring field silently omitted from a signed artifact.** Every
  producing verb refuses a field it does not read, on each caller-owned argument,
  before any of them is used. Without that door the artifact is built, signed and
  returned while simply not carrying what was asked for, and nothing in the
  result says so. The cases were not hypothetical: `extension` in place of
  `extensions` on `pki.x509.sign` produced a signed certificate with NO
  extensions, so an intended CA shipped without `basicConstraints` and an
  intended constrained certificate without `keyUsage`; `revokedCertificates` in
  place of `revoked` on `pki.crl.sign` produced a correctly signed, structurally
  valid CRL asserting that NOTHING is revoked; and an issuer nested inside the
  spec rather than passed as the second argument produced a self-signed
  certificate. Each permitted-field table is derived from what the verb actually
  reads, including through the helpers it delegates to, because a table naming a
  field nothing reads reopens the same hole. A NESTED descriptor carries its own
  table, because the level above cannot see its fields: a PKCS#12 `safeContents`
  entry holds the privacy directive for everything inside it, and a misspelled
  `encrypt` there was neither present nor falsy, so it passed the check that
  rejects a present-but-falsy directive and the safe was emitted as plaintext
  `id-data` -- an unshrouded private-key bag in the clear, inside a PFX whose
  MAC still verified and which opened without complaint. A bag is checked
  against the fields ITS OWN TYPE reads, because a union admits a field the
  chosen type never looks at: `encrypt` on a plaintext key bag was accepted and
  ignored, emitting the key unencrypted. The rule covers every caller-owned
  argument without exception, including one that carries only required fields:
  a misspelling of those is refused for what it leaves missing, but a name
  belonging on a DIFFERENT argument, written there instead, is read by nothing
  and dropped in silence -- `ordering` placed on the TSA argument of
  `pki.tsp.sign` emitted a token the size of one that never requested it. Where
  an argument has mutually exclusive FORMS, the table is the one the selected
  form reads, because a union admits what the chosen branch never looks at: an
  issuing certificate supplied alongside an explicit issuer name signed under the
  certificate's own distinguished name; `recipientCerts` under the PKCS#12
  `safeContents` form selected no privacy at all and the private key went out in
  the clear; and `pss` under CMP MAC protection emitted a message byte for byte
  identical to one that never named it.
- **Round-trip drift on signed bytes.** `pki.schema.x509.parse` returns the exact
  `tbsBytes` byte range that was signed, so a downstream verifier hashes the
  bytes that were actually signed rather than re-encoding and hoping for
  round-trip fidelity. The same discipline covers the CMP message-protection
  input: `pki.schema.cmp.parse` surfaces the exact `headerBytes` and `bodyBytes`
  wire slices so a verifier reconstructs the protected part from the bytes that
  were actually protected, never a re-encoding. CMP `caPubs` are surfaced as raw certificates
  conferring no trust, so a client cannot be steered into installing a trust
  anchor from an unauthenticated response. `pki.ct.parseSctList` follows the same
  rule for Certificate Transparency: it decodes the SCT-list structure but never
  verifies a signature or recomputes a log id, and
  `pki.ct.reconstructSignedData` rebuilds the exact RFC 6962 digitally-signed
  preimage from the parsed bytes so the log-signature check runs on what was
  actually signed. The TLS-encoded list itself is decoded with a bounded reader
  that validates every framing length and caps the per-list byte size and SCT
  count before iterating, so a crafted SCT extension is bounded work with a typed
  `ct/*` verdict. The CT log-list trust surface (`pki.ct.parseLogList`) binds
  identity to the key rather than a label: it recomputes each log's id as SHA-256
  of its DER SubjectPublicKeyInfo and refuses a stated `log_id` that disagrees
  (`ct/log-id-mismatch`, RFC 6962 §3.2), so a tampered list cannot swap a log's
  key while keeping its id or point an id at an attacker key.
  `pki.ct.verifySctWithLogList` then enforces trust before any crypto: a
  `pending` or `rejected` log, or a `retired` log for an SCT timestamped at or
  after its retirement, is `ct/log-untrusted`, and a certificate whose `notAfter`
  is outside the resolved log's temporal-interval window, or unresolvable for a
  windowed log, is `ct/temporal-interval`. Neither constraint is silently
  skipped, and only then does it delegate the signature check to `verifySct`. The
  log-list JSON is decoded through the bounded, duplicate-member-rejecting reader
  with byte and depth caps and `__proto__` safety.
  `pki.ct.verifyLogListSignature` verifies the detached `log_list.sig` over the
  raw log-list bytes, byte for byte and never re-serialized, against a
  caller-pinned signer key; no key is baked in. It pins the scheme to
  RSASSA-PKCS1-v1.5/SHA-256, rejecting a PSS signature, and fails closed before
  any verification on a forgeable key: an RSA public exponent below 3 (a PKCS#1
  v1.5 `e = 1` "signature" is just the DigestInfo) or an even exponent, a
  sub-2048-bit RSA key, and, on the EC arm, a non-conformant ECDSA DER Sig-Value
  defeating the CVE-2022-21449 `r = s = 0` shape are all typed throws rather than
  a `true`. Its verdict is cross-checked against `openssl dgst -verify`.
  `pki.schema.smime` decodes the ESS signing-certificate attributes the same way:
  it surfaces the certificate hash, the implied or decoded hash algorithm, and
  the issuer and serial reference raw, so a verifier recomputes the hash and
  matches the binding against the actual signing certificate. It never recomputes
  a hash or trusts a certificate, and it rejects a `SigningCertificateV2` hash
  algorithm encoded equal to its DEFAULT as non-canonical DER, closing an
  encode ambiguity a signature check would otherwise have to tolerate.

### Keys, secrets, and the crypto engine

- **Untyped faults escaping the key boundary.** A `CryptoKey` is opaque, and one
  created by a different WebCrypto implementation is indistinguishable from one
  of this engine's by type, algorithm, and usages while holding its material
  somewhere this engine cannot read. Every entry point that takes a key decides
  which of the two it has before using it. The `pki.*` verbs export a foreign key
  through whichever implementation holds its material — the platform's
  WebCrypto, or a separately installed copy of this toolkit, whose handle this
  process can read — and re-import it; a key whose implementation keeps its
  material beyond reach is refused rather than guessed at. An `extractable:
  false` key is refused on every one of those paths, including the one that could
  read its handle directly, because that flag is a promise the key carries with
  it. `pki.webcrypto.subtle`, where the specification leaves
  cross-implementation use undefined, refuses such a key with a typed fault
  naming where it came from. Neither path lets a bare type error naming an
  internal property escape from inside the crypto library, and neither ever
  substitutes a different key: a key created non-extractable is reachable by no
  other implementation, and is refused with that as the reason.
- **WebCrypto import algorithm confusion and raw cipher faults.**
  `pki.webcrypto` derives an imported asymmetric key's type from the key material
  rather than the caller's claim, so an RSA key imported under an Ed25519,
  ECDSA, or RSA-PSS name is a `webcrypto/data` reject and a mislabeled
  `CryptoKey` cannot later sign or verify under the wrong scheme. Every AES
  cipher fault fails closed with a typed `webcrypto/operation` — a tampered
  AES-GCM authentication tag, bad AES-CBC padding, a non-conforming AES-KW wrap
  length — rather than leaking a raw Node exception across the API boundary. A
  raw or JWK AES key of an invalid length (not 128, 192, or 256 bits) is rejected
  as a `webcrypto/data` DataError at import, closing the gap where the failure
  was deferred to first use.
- **Algorithm-parameter confusion.** For the algorithms whose `parameters` field
  must be absent — ML-DSA, SLH-DSA, the RFC 8410 Edwards and Montgomery curves,
  ML-KEM (RFC 9936), and the HKDF identifiers (RFC 8619) — the single shared
  AlgorithmIdentifier decoder rejects a present parameters field, whether an
  explicit NULL or arbitrary bytes, with a `<format>/bad-algorithm-parameters`
  code (RFC 9909 §3, RFC 9814 §4, RFC 9881 §2, RFC 8410 §3). The check lives in
  the one decoder every format composes, so a certificate, CMS message, OCSP
  response, timestamp, CRL, CSR, or key cannot smuggle unauthenticated bytes past
  a parser through that field, and no format can drift out of the rule.
- **ML-KEM key misuse (RFC 9935 / FIPS 203).** An ML-KEM public key establishes
  keys; it cannot sign or agree. `pki.path.validate` enforces the RFC 9935 §5
  rule that an ML-KEM certificate's keyUsage, if present, asserts
  `keyEncipherment` and nothing else. A leaf presented for signing
  (`digitalSignature`), an ML-KEM "CA" (`keyCertSign`), a `keyAgreement` or
  `dataEncipherment` misuse, and an extra reserved bit alongside
  `keyEncipherment` all fail closed with `path/kem-key-usage`. `pki.lint` mirrors
  the rule and adds an encapsulation-key-size check keyed to the algorithm OID,
  which is the sole authority for the parameter set rather than the length. On
  import, `pki.webcrypto.subtle.importKey("pkcs8", ...)` validates the RFC 9935 §6
  `seed` / `expandedKey` / `both` private-key CHOICE by its DER tag before the
  engine sees it, so the OpenSSL-legacy bare-seed layout the engine would
  otherwise accept is rejected, and an internally inconsistent seed or expanded
  key (FIPS 203 §7.3) is a typed `webcrypto/data` verdict rather than a raw
  engine error.
- **Key-establishment secret lifetime (CWE-226 / CWE-244).** Every secret the
  toolkit allocates during key establishment is wiped as soon as it stops being
  needed (NIST SP 800-227 RS5 / §4.2, RFC 9629 §7): a KEM shared secret and the
  key-encryption key derived from it, the raw ECDH / X25519 / X448 agreement
  secret, the copy a KDF makes of its input keying material, the password-derived
  key-encryption key, and the AES content-encryption key exported on every
  encrypt and decrypt. The wipe runs in a `finally`, so a failing decryption
  clears the same buffers a succeeding one does. A wrong key or a tampered
  ciphertext is the case an attacker can force, so a success-only wipe would
  preserve the secret exactly when it matters. A message's content key is shared
  by all its recipients, so it is cleared once the message is complete rather
  than per recipient. Only buffers the toolkit allocated are cleared; a caller's
  key, password, KEK, or supplied content key, and the returned plaintext, are
  never written to. This is best effort: the runtime copies a shared secret where
  no JS can reach it and may relocate a backing store, so the window in which a
  secret is readable is shortened rather than eliminated. Separately, the FIPS
  203 §7.3 ciphertext-length check runs at the crypto engine so a direct
  `decapsulateBits` caller inherits it. It checks length only, because a
  correct-length tampered ciphertext must still implicit-reject to a pseudo-random
  secret rather than throw: a throw there would be a decryption oracle, and the
  CMS uniform verdict depends on it not being one.
- **Recovered plaintext after a failed integrity check (RFC 5083 §1).** A cipher
  produces the whole recovered plaintext before the step that decides whether the
  message was authentic, so on a forged AEAD message the plaintext exists in full
  and is then abandoned. Withholding it from the caller is not destroying it, and
  RFC 5083 §1 requires a receiver whose integrity check fails to destroy it. Every
  cipher the toolkit runs — CMS content decryption and the RFC 3211 password
  recipient unwrap, PBES2, HPKE `open`, PKCS#12 safe decryption, and the AES-GCM,
  AES-CBC, AES-CTR and AES-KW paths of the crypto engine — goes through one place
  that clears both halves on both exits. The success path is cleared for the same
  reason: joining the halves copies them, so the first buffer would otherwise
  remain as a second complete copy of the plaintext that the caller never receives
  and nothing else would clear. The same best-effort limits stated above apply:
  this shortens the window in which the plaintext is readable rather than
  guaranteeing no copy survives.
- **PBES2 private-key decryption is not a padding oracle (CWE-208).**
  `pki.key.decrypt` (RFC 5958 EncryptedPrivateKeyInfo under RFC 8018 PBES2) reads
  the attacker-controlled PBKDF2 salt and iteration count, and validates the
  parameter structure and IV length, before any key derivation. An over-cap salt
  or iteration count (`opts.maxIterations` lowers the cap and never raises it), a
  malformed parameter set, or a wrong-length IV is a distinct typed reject with
  no derivation work performed. Because a MAC-less PBES2-CBC decrypt has no
  integrity tag, every secret-dependent failure — a wrong password, and a valid
  PKCS#7 pad whose plaintext is not a `PrivateKeyInfo` — collapses to the single
  uniform `key/decrypt-failed` (RFC 8018 §8), so an attacker cannot distinguish
  the two. PBES1, PBMAC1, and scrypt are refused rather than silently accepted.
- **PKCS#12 MAC integrity (CWE-347 / CWE-208).** `pki.pkcs12.verifyMac`
  recomputes a store's classic Appendix B HMAC or RFC 9579 PBMAC1 over the exact
  AuthenticatedSafe byte range (`macedBytes`, excluding the OCTET STRING header,
  which is the canonical off-by-the-header MAC trap) and compares it in constant
  time through `guard.crypto.constantTimeEqual`, so a wrong password leaks no
  timing or length signal. It throws a typed error on a MAC-less or
  public-key-integrity store rather than returning a falsy verdict.
  `pki.pkcs12.build` encodes every password the PKCS#12 way (BMPString+NULL for
  the Appendix B KDF, UTF-8 for the PBES2 bags and PBMAC1) so the output is not
  silently unopenable elsewhere, refuses a ≤160-bit PBMAC1 digest (RFC 9579), and
  never emits a non-canonical DEFAULT-1 MacData iterations. An omitted password
  is refused rather than encoded as the empty one, and `opts.integrity.mode` is
  validated against the one value it selects: a misspelled option is the input
  that reads as an omission rather than as a value, so before this a store could
  be built under the empty password, or MACed when the caller asked for a
  signature, with nothing said either way. The empty password is still available
  as an explicit `""`. `pki.pkcs12.open`
  verifies that MAC before it decrypts any bag (RFC 7292 §5.1): a store whose
  password MAC fails returns nothing, and the wrong-password verdict is the MAC
  gate (`pkcs12/mac-mismatch`) rather than a per-bag decrypt error that could
  leak which bag or which byte differed. It refuses a MAC-less store unless the
  caller explicitly opts in (`allowUnauthenticated`, surfaced as `macVerified:
  false`), and because a PBES2 bag decrypt after a valid MAC is still MAC-less at
  the cipher layer, it collapses every post-integrity decrypt failure into the
  uniform `pkcs12/decrypt-failed`. The bag KDF iteration and salt work factors
  are bounded before derivation (`opts.maxIterations` lowers the cap), and one
  aggregate budget spans the whole call for both the Appendix C and the PBES2
  schemes — a per-bag cap resets on every bag, so without it a store repeating a
  costly bag up to the element limit multiplies the cap by that limit in blocking
  key-derivation work. For a
  public-key-integrity store (an `id-signedData` authSafe, RFC 7292 §4) `open`
  verifies the CMS SignedData signature over the AuthenticatedSafe first and
  returns nothing on a failure (`pkcs12/signature-invalid`), exactly as the MAC
  gate does for password mode. The signer is surfaced as a per-signer verdict in
  `signers` but is not chained to a trust anchor: a valid signature authenticates
  the store's integrity, not the signer's identity, and anchoring
  `signers[i].cert` is the caller's `pki.path.validate` step, the out-of-path
  signer contract shared with CMS, TSP, and OCSP-delegate verification. For
  public-key privacy (an `id-envelopedData` safe encrypting the SafeContents to a
  recipient public key, RFC 7292 §3.1) `open` decrypts only after the integrity
  gate. The MAC or SignedData covers the whole AuthenticatedSafe, including the
  enveloped element, so a tamper is caught by integrity first and the recipient
  decrypt is never reached. Every recipient-side fault — a wrong `recipientKey`,
  a tampered envelope, a CBC unpad failure, a decrypt that yields non-SafeContents
  bytes — collapses into the uniform `pkcs12/decrypt-failed`, exposing no
  padding, recipient, or structure oracle. The recipient private key is a privacy
  credential only, never a MAC key, a signature-verification input, or a PBES2
  password, and the recipient certificate is not trust-chained.
- **CMS decryption oracles (Bleichenbacher / EFAIL / password-guessing).**
  `pki.cms.decrypt` is oracle-free by construction. Recipient selection fails
  with a distinct typed code, but every secret-dependent failure past that point
  collapses to the single uniform `cms/decrypt-failed` verdict — same code, same
  message, no cause chaining — so an attacker measuring the error has no
  distinguishable signal (RFC 3218, EFAIL). That covers a PKCS#1 v1.5 or
  RSAES-OAEP unwrap fault, an AES-KW integrity-check (A6A6…) mismatch, an RFC
  3211 PWRI check-byte mismatch, a CBC padding fault, an AES-GCM tag mismatch,
  and a content-key length mismatch. The PKCS#1 v1.5 arm is decrypt-only and
  applies the RFC 3218 §2.3.2 implicit-rejection countermeasure: on any v1.5
  fault it substitutes a fresh random content-encryption key and proceeds, so the
  failure surfaces later and uniformly, exactly like every other bad key. v1.5 is
  never emitted. Integrity is verified before any plaintext is released, and a
  CBC EnvelopedData (unauthenticated content) surfaces `authenticated: false` in
  the verdict rather than silently, with AES-GCM AuthEnvelopedData the encrypt
  default. The declared content cipher's mode is bound to the container carrying
  it before any key is used: an EnvelopedData must name a CBC cipher and an
  AuthEnvelopedData an AEAD one (RFC 5083 §2.1, RFC 5084 §3). A message whose
  algorithm identifier has been switched to the same-key-length cipher of the
  other mode is refused rather than opened in the mode it was not encrypted under
  and reported under the algorithm it falsely declared. The mode is resolved from
  the identifier rather than from the display name that identifier resolves to,
  so a caller-registered name cannot widen what is admitted. A password
  recipient's PBKDF2 iteration count is capped (`cms/iteration-limit`, a
  caller-lowerable bound) so an attacker-inflated count cannot force unbounded
  work. `pki.smime.decrypt` (RFC 8551) inherits every one of these properties
  unchanged: it only propagates the uniform `cms/decrypt-failed` verdict, adds no
  secret-dependent branch of its own, and derives the `smime-type` from the CMS
  body rather than the attacker-controlled MIME header, so a mislabeled header
  cannot misrepresent what was encrypted. An enveloped-only (CBC) message has no
  integrity (RFC 8551 §3.3), so its recovered plaintext is returned marked
  `authenticated: false`. The caller gets an explicit unauthenticated verdict
  alongside the content, rather than a bare result that looks trustworthy, and
  can reject it. Callers that require integrity should check `authenticated`, or
  send AES-GCM AuthEnvelopedData, the encrypt default.
- **AEAD-parameter tampering (CMS AuthEnvelopedData).** A recognized AES-GCM or
  AES-CCM content-encryption algorithm must carry its RFC 5084 parameters: the
  nonce is bounds-checked (CCM 7..13 octets), the ICV length must come from the
  RFC's allowed set and equal the length of the `mac` field, and an ICV length
  encoded equal to its DEFAULT is rejected as non-canonical DER (X.690 §11.5). A
  message therefore cannot shrink its own integrity tag, or desynchronize the tag
  length a verifier checks from the one the structure claims.
- **Stateful-signature key reuse and downgrade.** `pki.shbs` verifies HSS/LMS
  signatures (RFC 8554) and deliberately never signs. Stateful hash-based signing
  requires a one-time-key index whose state must advance atomically across every
  signature and every restart, and a single reuse can leak enough material to
  forge, so SP 800-208 confines signing to hardware. Verification is pure
  public-input hashing, with no secret and no side channel; the public key is the
  sole authority for every parameter set, so a signature whose typecode disagrees
  with the key cannot verify against it, which is the downgrade defense. An HSS
  hierarchy accepts only if every level verifies, and every field length is
  bounds-checked before it is read. An unapproved or unknown typecode, a
  truncated blob, or a hostile level count fails closed with a typed error rather
  than an unbounded loop or an out-of-bounds read.
- **Composite (hybrid) signature downgrade.** `pki.path.validate` (certificates,
  CRLs, OCSP responses) and `pki.cms.verify` (CMS `SignerInfo`,
  draft-ietf-lamps-cms-composite-sigs) verify composite ML-DSA signatures
  (draft-ietf-lamps-pq-composite-sigs), a post-quantum ML-DSA paired with a
  traditional RSA, ECDSA, or EdDSA key, by reconstructing the domain-separated
  message representative and verifying the two components independently. Both
  must pass. A single-component accept would be the exact downgrade the
  construction exists to prevent: it would let an adversary who breaks either the
  post-quantum or the classical primitive forge a signature the other component
  should still reject. The public-key algorithm OID is bound to the signature OID
  as an algorithm-confusion defense, the AlgorithmIdentifier parameters must be
  absent, and an arm whose curve or pre-hash the crypto engine cannot reach fails
  closed to a typed reason code rather than silently skipping its check. In CMS
  the SignerInfo `digestAlgorithm` must equal the arm's pre-hash (draft §3.4), and
  a mismatch fails closed, taking the §5 SHOULD-reject, so the message-digest
  attribute cannot be computed under a different digest than the one the
  composite signature covers. `pki.cms.sign` produces a composite `SignerInfo`
  from the two component keys (`{ mldsa, trad }`) and never emits a
  single-component signature.
- **Algorithm substitution.** Every algorithm, attribute, and extension is named
  in an OID registry (`pki.oid`), so a structure's algorithm identifiers resolve
  to a known name rather than being trusted blindly. OID-driven sign and verify
  resolution — deriving the verification algorithm from the trusted key and the
  expected `AlgorithmIdentifier`, so a structure cannot smuggle in a weaker or
  unexpected algorithm by naming a different OID — rides this registry and lands
  with the signing surface.
- **Silent verification failure.** Every verify and parse path throws on failure.
  No path returns zero, a default, or partial output in place of a real result,
  so a caller cannot mistake an error for a pass.

### Path validation, revocation, and signed messages

- **Certification-path validation bypass.** `pki.path.validate` enforces the RFC
  5280 §6 algorithm fail-closed. The basic-constraints CA check is the single
  authoritative gate that no later check can overwrite (CVE-2021-3450). The
  signature algorithm is derived from the certificate and the issuer key, never a
  message-selected field (CVE-2015-9235). ECDSA signatures with a component
  outside `[1, n−1]`, including the all-zero forgery, are rejected
  (CVE-2022-21449). An EdDSA (Ed25519/Ed448) issuer or revocation-responder key
  is validated on-curve and full-order before verification, so a low-order key —
  for example the identity point, which the platform imports without complaint
  and which verifies a forged signature for every message — cannot certify a
  forged chain or forge a CRL or OCSP response. The certificate-policy tree
  carries a hard node cap and fails closed at it (CVE-2023-0464), and an invalid
  policy OID is surfaced rather than silently dropped (CVE-2023-0465). Name
  comparison rejects embedded NUL and control bytes so a truncated name cannot
  compare equal (CVE-2009-2408), and it refuses input it cannot compare rather
  than answering that two names matched: the one place a distinguished-name
  identity is decided never returns a match it did not establish. An unknown critical extension, or an undetermined
  revocation status, terminates the path with a typed reason code rather than
  passing — the latter unless the caller sets `softFail`, which is exactly the
  option that converts "revocation could not be determined" into a pass, and
  which is off unless asked for. Revocation is also only checked when a
  `revocationChecker` is supplied: a path validated without one is a path whose
  revocation status was never asked about, which is a different claim from
  `revoked: false`. Post-quantum SLH-DSA signatures (all twelve FIPS 205
  parameter sets) verify on this path over the exact signed bytes, alongside
  ML-DSA and the classical set.
- **Trust-anchor misuse and revocation-scope confusion.** A `pki.trust` anchor
  carries the root program's own constraints, and `pki.path.validate` enforces
  them when the caller names the purpose being validated for. Pass `checkPurpose:
  "serverAuth"`, or whichever purpose you are actually validating for, and a leaf
  issued after that root's per-purpose distrust date, or a purpose the root was
  never a trusted delegator for, fails closed. Both constraints are per-purpose,
  so without that option there is no purpose to judge them against — and an
  anchor that carries such metadata while no purpose is named is refused as a
  configuration fault rather than validated as though it carried none. Before,
  a root distrusted for TLS validated a TLS leaf and the verdict said nothing.
  An anchor set parsed from a root program carries these constraints because the
  program means them to bind, so `checkPurpose` is a requirement rather than
  optional hardening, and the verdict's `anchorConstraints` reports which purpose
  was judged and which of the two constraints applied. A verb with a single key
  purpose names it: `pki.tsp.verify` judges its anchors under `timeStamping`,
  the same key purpose it already requires of the TSA certificate.
  Trust metadata pairs to its certificate by byte-exact issuer and
  serial and is cross-checked against the parsed DER, so a crafted store cannot
  attach one root's permissions to another. A partitioned CRL establishes
  non-revocation only for the shard whose issuing-distribution-point name
  corresponds byte-identically to the certificate's own distribution point with
  no reason restriction. A non-corresponding, reason-scoped, non-critical-IDP, or
  delta shard stays revocation-only, and a listed serial reports revoked
  regardless. The scope flags that decide this are IMPLICIT BOOLEANs, read under
  the DER rules that define them — one content octet of `0x00` or `0xFF` — in
  both the validator and the standalone `pki.crl` verbs, since a byte test would
  read an empty flag as absent and an unreadable scope as a license to answer.
  That correspondence needs the certificate, so `pki.crl.isRevoked`, which is
  given a serial and nothing else, refuses any scoped CRL instead of answering
  from one: an absent serial on a CRL covering some other partition, certificate
  kind, or revocation reason is not an unrevoked certificate. A CRL also speaks
  for a span, and the same reasoning applies to it: told the instant a question is
  asked at, `pki.crl.isRevoked` refuses a list whose `nextUpdate` has passed,
  whose `thisUpdate` is later, or which states no `nextUpdate` at all and so
  cannot be told from a replayed copy. Told no instant it answers structurally
  and says so, and a serial's absence then means it is not on that list rather
  than that the certificate is unrevoked.
- **Malformed or hostile trust-anchor objects.** `pki.path.validate` seeds the
  certification path from `opts.trustAnchor`, passed as a `{ name, publicKey,
  algorithm }` tuple or a parsed certificate. The anchor is normalized and
  shape-checked at the door: a tuple missing a field, or one whose declared
  `algorithm` disagrees with its `publicKey`, is refused with `path/bad-input`
  rather than seeding an undefined working key that a self-describing key
  algorithm could still validate against — a soft verdict answering a different
  question than the caller asked. The key's own SubjectPublicKeyInfo is
  authoritative for its algorithm and parameters, so a declared curve that
  disagrees with the key cannot be promoted and inherited by an intermediate that
  omits its own. A parsed certificate is recognized as a certificate before any
  tuple field is read, so a value reached through `Object.prototype` cannot
  reclassify it as a hand-built tuple and bind a substituted key. An anchor
  supplied as a `Proxy` — or one whose `purposes` or `distrustAfter` constraint
  map is a `Proxy` — is refused: reflection traps could answer a field
  inconsistently or report a field absent while forwarding the rest, hiding a
  restriction the caller attached. A plain tuple, a parsed certificate, or an
  object inheriting from one, with plain-object constraint maps, is the normal,
  unaffected form.
- **OCSP response forgery.** `pki.path.ocspChecker` treats a response as
  authoritative only when an authorized responder signed it: the issuing CA
  directly, or a certificate that same CA issued bearing id-kp-OCSPSigning in its
  extendedKeyUsage (RFC 6960 §4.2.2.2). An ordinary leaf the CA issued, an
  `anyExtendedKeyUsage` certificate, a certificate from a different CA, an expired
  responder, and one whose keyUsage forbids digitalSignature all cannot sign a
  status. A delegated responder must also carry id-pkix-ocsp-nocheck (RFC 6960
  §4.2.2.2.1), the CA's statement that it vouches for the responder for its
  certificate lifetime, and any critical extension on the responder certificate
  must be recognized and well-formed. Otherwise the checker cannot confirm the
  responder itself is unrevoked and fails closed, so a revoked responder cannot
  keep signing. The response must also bind to the certificate under test through
  the full CertID triple, with `issuerNameHash` and `issuerKeyHash` recomputed
  under the CertID's own hash algorithm, so a `good` for one issuer's serial
  cannot be replayed to answer for another issuer's same serial. A missing or
  passed `nextUpdate`, an unauthorized responder, or any signature-verification
  failure yields an undetermined status that fails the path closed.
  `pki.ocsp.verify`, the standalone relying-party entry, and
  `pki.path.verifyOcspResponse`, its lower-level primitive, run this exact
  responder-authorization, signature, CertID, and currency core; there is no
  weaker second OCSP verify path. Request-nonce binding is not part of that
  shared core: it lives in `pki.ocsp.verify` alone, which compares the RFC 9654
  nonce in constant time and downgrades a `good` to `unknown` when the response
  omits or does not echo a nonce the client sent. `pki.path.verifyOcspResponse`
  takes no request nonce, so a caller reaching for the lower-level primitive
  gets no replay binding and must compare the nonce itself. A `revoked`
  verdict is reported as `revoked` either way, with `nonceMatched: false` saying
  the response was not bound to this request: revocation does not go stale the way
  non-revocation does, so discarding a signed, current, authorized `revoked`
  because it was replayed would hand a soft-failing caller the very certificate
  the responder refused. Because the standalone entry does not assume the caller
  pre-chained the certificate, it first binds the supplied issuer certificate to
  the target: the target's issuer DN must equal the issuer's subject DN, and the
  target's signature must verify under the issuer's key. A rogue certificate
  sharing the issuer's subject DN but a different key therefore cannot recompute
  a matching CertID and authorize a `good` response for a certificate that CA
  never issued. On the producing side, `pki.ocsp.sign` embeds the responder
  certificate verbatim from caller-supplied DER rather than re-encoding a parsed
  certificate, so the bytes a relying party verifies are the exact bytes the CA
  issued.
- **Timestamp-token forgery (TSA impersonation).** `pki.tsp.verify` trusts a
  timestamp token only when its signer is demonstrably a time-stamping authority.
  The TSA signing certificate is an out-of-path signer: it signs the token but
  sits on no certification path the caller has already validated. It receives
  full certification-path validation to the caller's trust anchor at the token's
  own `genTime` — issuer signatures, the validity window at signing time,
  critical-extension handling, optional revocation — when the caller supplies
  `opts.trustAnchor`. With no anchor there is nothing to chain to, and a `valid:
  true` verdict then means the token's signature and its bindings hold under a
  certificate whose issuer was never established; any certificate carrying the
  EKU below would do. Supply the anchor for any verdict you intend to act on. RFC
  3161 §2.3 is enforced on top: the certificate's extendedKeyUsage extension must
  be present, be critical, and contain exactly id-kp-timeStamping, so a
  general-purpose certificate the same CA issued (a TLS leaf, an
  `anyExtendedKeyUsage` holder) cannot mint a token that verifies. The token is
  bound to that exact certificate through its ESSCertID(V2) signing-certificate
  attribute (RFC 5816): the certificate hash is recomputed and compared, so a
  valid signature cannot be re-paired with a substituted certificate. The message
  imprint is recomputed from the presented data, the encapsulated content must be
  a TSTInfo, and the token must echo a request nonce. Every checked field
  is read from the verified encapsulated content rather than a caller-supplied
  parsed object, and a well-formed token failing any check is a fail-closed
  `{ valid: false }` verdict with a typed reason code, never a silent pass.
  What the verdict establishes is reported in the same three parts the rest of
  the toolkit uses: `valid` for the signature and the structural bindings,
  `trusted` for chaining to an anchor the caller named, and `revocationChecked`
  for whether the authority's revocation status was ever established. Revocation
  runs only when a `revocationChecker` is supplied, so without that third field a
  timestamp whose authority was never checked against a CRL or an OCSP responder
  read exactly like one established un-revoked — and a timestamp is archived
  precisely to be re-read years later, when nobody remembers which it was. An
  undetermined status leaves the authority untrusted rather than trusted-
  unchecked; this verb has no `softFail`, so "the responder could not be reached"
  cannot become a trusted timestamp.
- **Merkle proof forgery.** `pki.merkle` verifies RFC 6962 / RFC 9162 inclusion
  and consistency proofs fail-closed. The leaf (`0x00`) and node (`0x01`)
  domain-separation prefixes stop the second-preimage swap, a proof whose node
  count does not match the tree geometry is a typed reject rather than a
  best-effort fold, consistency reconstructs both roots so a rewritten history is
  caught on the old-root leg, and the root comparison is constant-time. The only
  Boolean `false` is an honest root non-match; every malformed input throws.
- **CMS SignedData preimage substitution.** `pki.cms.verify` checks a SignedData
  signature over the exact bytes RFC 5652 §5.4 defines, never a re-derived copy.
  When signed attributes are present, the message-digest attribute must equal the
  digest of the content, and the signature is verified over the DER re-encoding
  of the SignedAttributes, with the on-wire `[0]` implicit tag replaced by the
  universal SET OF the standard requires. An attacker can therefore neither swap
  the content out from under a set of signed attributes, nor strip the attributes
  and present a signature made over them as one made over the content — see the
  next entry, which is what makes the second half of that true. Each
  parameter comes from the structure that owns it — the content digest from the
  digestAlgorithm, the signature scheme from the signer's own key algorithm — so
  a signer cannot claim one algorithm while the key implies another. Those signed
  attributes are decoded from the exact bytes the signature covers rather than
  from a parsed representation a caller could mutate independently, so a supplied
  parsed object cannot desynchronize the checked attributes from the verified
  preimage. A parsed SignedData is re-derived from the bytes its parser recorded
  before any of this runs, and one that carries no such record — an object
  assembled or rebuilt rather than parsed — is refused, so a caller cannot hand
  this verb a structure whose parts describe different messages.
  An EdDSA signer key is validated on-curve and full-order before
  verification, so a low-order Ed25519 or Ed448 point, which `node:crypto`
  imports without complaint and which can verify a forged signature, is rejected.
  A false verdict or an unresolved parameter is a fail-closed `cms/*` outcome,
  never a silent pass.
- **CMS signed-attribute stripping (the SignedData EUF-CMA gap).** A CMS
  signature does not commit to *whether* signed attributes were present, so a
  signature made over a SignedAttributes block can be re-presented as one made
  over content: take a message the signer really signed with attributes, drop the
  `signedAttrs` field, and set the encapsulated content to the DER of those same
  attributes. RFC 5652 §5.4 then says the signature is over the content itself,
  which is exactly what it covers, and with no attributes there is no
  message-digest or content-type attribute left to disagree. This is Attack Type
  1 of `draft-vangeest-lamps-cms-euf-cma-signeddata`, it needs no access to the
  signer, and it is expressible entirely in DER — `openssl cms -verify` accepts
  such a message and writes the attribute block out as verified content. The
  standards fixes are protocol changes (signing under a context string naming the
  mode) that no verifier can apply on its own.
  `pki.cms.verify` refuses the shape instead. Every message the attack produces
  has, as its content, the encoded SignedAttributes of a real message — which
  §5.3 requires to carry both a content-type and a message-digest attribute — so
  a `SignerInfo` with no signed attributes whose content parses as exactly that
  is `cms/ambiguous-content`, fail-closed, rather than a signature the verifier
  pretends to understand. The condition is necessary to the attack rather than a
  guess: ordinary content does not have that shape, and a set of attributes
  missing either mandatory member is not refused. `pki.cms.sign` closes the other
  direction (Attack Type 2) by refusing to sign attribute-shaped content with
  `signedAttributes: false`, since that signature could afterwards be promoted
  into an attributes-present message. The cost is that content which genuinely is
  an encoded SignedAttributes block must be signed WITH signed attributes, which
  makes it unambiguous again.
  The verdict also carries `eContentType` and a per-signer
  `signedAttributesPresent`, so a caller whose profile requires attributes — RFC
  8551 S/MIME does — or a particular content type can enforce it from the verdict
  rather than parsing the message a second time.
  What the signature establishes and who signed remain separate questions, and
  the verdict answers them separately. A SignedData carries its own
  certificates, so `valid` says only that the signature is sound under one of
  them, which anyone able to mint a certificate can arrange. `trusted` says
  every signer chained to a root named in `opts.trustAnchors`, validated through
  the same RFC 5280 path engine `pki.path.validate` uses rather than a second
  one. Supply no anchors and `trusted` is `false` — there was nothing to chain
  to, which is an answer rather than an omission. Anchors that cannot be read
  are a configuration fault and throw, because absorbing them into `trusted:
  false` would report a verdict about the message for a check that never ran.
  `pki.smime.verify` carries both through unchanged. The
  producing side (`pki.cms.sign`, and `pki.tsp.sign` over it) emits exactly the
  shapes the verifier checks: canonical DER signed attributes, the same
  algorithm-parameter forms (NULL for RSA, absent for ECDSA and EdDSA, the
  RSASSA-PSS params), and ECDSA signatures re-encoded to canonical DER through
  the shared `validator.sig` gate. A token this toolkit signs therefore cannot
  desynchronize from what it, or OpenSSL, verifies, and the signer's private key
  is only ever handed to the WebCrypto sign call, never logged or embedded.
  Post-quantum ML-DSA (ML-DSA-44/65/87, RFC 9882) signs and verifies over the
  same preimage in pure mode with the empty context. What a signing verb signs is
  also fixed at the moment it is called. Every byte argument is re-viewed on entry,
  so an input whose backing store has been transferred away — a `structuredClone`
  with `transfer`, a worker hand-off, a stream that adopted the buffer — is refused
  with the calling module's own `bad-input` code instead of reading as zero-length
  and yielding a sound signature over nothing. Every argument is also copied whole
  at entry, at every depth, and each copy is cleared when the call settles — so a
  caller that keeps a reference and edits it while the signature is in flight
  cannot change what gets signed after the checks that govern it have run, and a
  password or key the copy duplicated does not outlive the call. The same holds for
  the other producing verbs — `pki.x509.sign`, `pki.csr.sign`, `pki.crl.sign`,
  `pki.attrcert.sign`, `pki.crmf.build`, `pki.cmc.build`, `pki.cmp.build`,
  `pki.ocsp.buildRequest`, `pki.ocsp.sign`, `pki.tsp.sign`, and `pki.pkcs12.build`
  — each of which runs that copy at the call rather than a promise turn later.
  Every part of that is load-bearing. An empty read would have produced a key
  identifier over no bytes or a PKCS#12 file keyed to a password the caller never
  held; a late read would have encoded an extension the checks never saw; a copy
  that stopped at the first level would have left a MAC secret nested inside an
  options object still rewritable across the turn. A parsed structure passed inside
  a spec is left alone rather than copied, because the provenance a verb requires
  is keyed to that object's identity, and a `CryptoKey` is used rather than cloned.
  The message-digest algorithm
  is held to each parameter set's security strength on both sign and verify, so a
  below-strength digest — the weaker link that would cap the signature's
  collision resistance — is refused, and the signer certificate's public-key
  parameter set must agree with the SignerInfo signatureAlgorithm. SLH-DSA (the
  twelve FIPS 205 pure sets, RFC 9814) signs and verifies the same way, with the
  message digest pinned per set.

### WebAuthn and passkeys

- **WebAuthn credential-key confusion.** `pki.webauthn` binds a credential COSE
  key to its declared algorithm and curve, so an EdDSA key claiming ES256, or the
  legacy `-8` identifier carrying Ed448 rather than Ed25519, is rejected. It
  validates the public-key point on its curve, so an off-curve or identity point
  fails closed at decode instead of reaching a verify step where an invalid-curve
  attack could apply. The EC point must be uncompressed, the COSE key exactly its
  canonical CTAP2 parameter set, and an ECDSA attestation signature a minimally
  encoded DER `ECDSA-Sig-Value`; a non-minimal, negative, zero, or over-size `r`
  or `s` is a typed reject rather than being normalized and accepted.
- **Attestation-key substitution.** `pki.webauthn.verify` binds every attestation
  to the credential being registered, by the mechanism each format defines. For
  packed and fido-u2f the attestation signature covers the `authenticatorData`,
  and fido-u2f's signed `verificationData` embeds the credential key explicitly,
  so a signature that verifies is a signature over that exact credential key. For
  android-key, apple, and tpm the attestation certificate's public key — or, for
  tpm, the `pubArea`'s — is additionally required to equal the credential public
  key: an unsigned-integer comparison for EC and RSA coordinates, so a
  leading-zero re-encoding cannot desynchronize it, and a byte-exact comparison
  for a fixed-width Ed25519 key, with the tpm `pubArea` key also bound to the
  `certInfo` TPM Name it certifies. The apple nonce must equal the SHA-256 over
  `authenticatorData || clientDataHash`, and the android attestation-challenge
  must equal the `clientDataHash`, so an attacker cannot pair a valid attestation
  over one key with a different credential. The strict `pki.cbor` codec decodes
  the attestation object and COSE keys, a bounds-before-slice reader decodes the
  TPM structures, and every failed check throws a typed `webauthn/*`
  error: a signature that does not verify is a thrown verdict, never a silent
  pass. RS1 (SHA-1) is accepted for verifying the legacy TPM authenticators that
  emit it, never for signing.
- **A verified signature read as a verified ceremony.** The attestation and
  assertion procedures establish that a signature is sound. What makes a response
  acceptable is the ceremony binding, and most of that depends on state only the
  relying party holds: the challenge it issued, the origin the browser reported,
  the RP ID it operates under, and the user-presence policy it requires. An
  attestation naming another origin's RP ID, with user presence clear, is a
  perfectly sound statement about a credential that must not be registered. The
  verdict fields are therefore `attestationVerified` and `signatureVerified`
  rather than a bare `verified`: a caller writing `if (res.verified)` gets
  `undefined` instead of a pass for a question it did not ask. The bindings this
  layer can check are offered by name — `expectedRpId`, `requireUserPresence`,
  `requireUserVerification`, `allowedAlgorithms`, and for `clientDataJSON` the
  ceremony type, challenge, and origin — and every verdict reports in
  `bindingChecked` which of them ran, so a check that passed is distinguishable
  from one that never happened. Both `pki.webauthn.verify` and
  `pki.webauthn.verifyAssertion` check the ceremony type unconditionally whenever
  they are given the JSON, because which ceremony a response belongs to is fixed
  by the specification rather than chosen by the caller, and a response from one
  ceremony replayed into the other is exactly what that stops. In a cross-origin
  ceremony the framed document's origin and the top-level origin that framed it
  are separate values and both can be compared, so a framing policy is not left
  resting on the one a nested page controls. Where a stored `previousSignCount`
  is supplied, a counter that fails to advance is refused as the cloned
  authenticator it signals.
- **Metadata-catalogue forgery and rollback (FIDO MDS).** A metadata BLOB decides
  which roots an authenticator model is allowed to chain to and whether that
  model is still trusted, so a reader that parses before it verifies hands an
  attacker the trust decision. `pki.webauthn.verifyMetadataBlob` establishes the
  JWS signature and chains the BLOB's own signing certificate to an
  operator-supplied FIDO root before a single byte of the payload is read: a BLOB
  that does not verify never reaches the JSON reader, the entry walk, or any
  per-entry certificate decode. No FIDO root is bundled and there is no
  trust-on-first-use, because which metadata authority to trust is the operator's
  decision, exactly as a root store is for path validation. A replayed older
  catalogue, one whose sequence number does not exceed the number the caller
  already holds, is refused as a rollback, and one past its `nextUpdate` is
  refused as stale; both are fail-closed and both are opt-outable only by the
  caller. Byte, entry-count, and per-entry anchor-count ceilings bound the decode
  and the per-entry certificate parsing, since a byte ceiling alone does not
  bound how many items are declared inside it. When a verified catalogue is
  supplied to `verify`, the attestation trust path must fully validate to a root
  that authenticator's own model registered — the same path validation any chain
  gets, rather than a name comparison against the top of the path, which is a
  value an attacker controls — and a model carrying a disqualifying status report
  is refused, so a revoked authenticator cannot present an otherwise well-formed
  attestation and be reported as verified. The status gate is on the anchors
  themselves, not only inside that verb: `pki.webauthn.metadataAnchors` refuses to
  hand back the attestation roots of a model the catalogue has disqualified, so a
  caller anchoring the trust path with `pki.path.validate` cannot reach a weaker
  verdict than one who passed the catalogue to `verify`. It reads the reports the
  same way given the same catalogue, instant and presented certificate, and
  applies the strictest reading of whichever of those is not supplied. An
  authenticator that declares no
  model identity is looked up by the key identifiers of its attestation
  certificates rather than being silently exempt from any of this. Which
  identifier is allowed to select the entry depends on what the attestation
  signature actually covers: the fido-u2f signature is computed over named fields
  (`0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F`) and does
  not include the AAGUID, so for that format those bytes are attacker-editable
  and never select the entry; the attestation certificate does. Without that
  rule, setting the AAGUID to a listed model that shares the vendor's registered
  root would resolve to that model's entry and skip the real one's status
  reports, letting a revoked authenticator present itself as its healthy sibling.
  A note for relying parties: `res.aaguid` is reported as the authenticator
  presented it, and for a fido-u2f attestation it is not signature-bound. Use
  `res.metadata.aaguid`, which names the entry that was actually matched.

### Enrollment and messaging protocols

- **Enrollment-response replay and unauthenticated verdicts (CMC).**
  `pki.cmc.verify` binds a Full PKI Response to the request that provoked it
  before it reports anything. The Transaction Identifier, the Sender and
  Recipient Nonce echo, and the Data Return echo each apply once the client sent
  that half, and an absent or differing echo is then a refusal rather than a
  missing optional field, so a response captured from one exchange cannot be
  replayed into another. The conditional is literal: a request that carried none
  of those controls has nothing for the response to echo, so a client that sends
  no binding gets no replay defense, and `pki.cmc.verify` cannot enforce one the
  request never asked for. `pki.cmc.build` emits all three from named spec fields
  for that reason, and `pki.est.fullcmc` reads them back out of the request bytes
  rather than taking the caller's word for what was sent. The nonce is compared
  in constant time and by full value, so a truncated echo cannot match on a
  prefix. Where several status controls are present the worst governs, so a
  rejection cannot hide behind an earlier success. The carrier's own signature is
  not assumed: RFC 5272 §3.2.1.3.4 requires it. A conforming response carries its
  own signer certificate and is checked against it with nothing asked of the
  caller. Where the signer is found nowhere, verification is fail-closed with a
  named opt-out (`allowUnverified`, which reports `signatureVerified: false`)
  rather than a silent default, so no caller receives a verdict believing a check
  ran that did not. That opt-out covers only "could not check": a signature that
  is present and wrong is always a refusal, and a carrier bearing no signer at
  all is refused. Nothing in the response is trusted, so the certificate bag and
  any Publish Trust Anchors control are surfaced as data for
  `pki.path.validate` rather than added to a store.
- **EST enrollment-response confusion.** The `pki.est` client codecs are
  fail-closed over hostile server output. The RFC 8951 base64 transfer decode is
  bounded before and after decoding and never reads a Content-Transfer-Encoding
  header, which is the class of errata 5904 and 5107. The `multipart/mixed`
  splitter requires the terminal boundary and rejects nested or extra parts. The
  certs-only validator rejects any response that is not an empty-signerInfos,
  no-eContent SignedData of plain X.509 certificates, and the serverkeygen
  validator enforces the request-to-response recipient-arm coherence. The issued
  certificate comes from a public-key match (`findIssuedCert`) rather than a
  positional guess, which RFC 5272 forbids assuming.
- **EST transport is fail-closed on the wire (CWE-295 / CWE-319 / CWE-770 /
  CWE-522).** The `pki.est` network verbs run over `pki.transport`, the toolkit's
  single socket choke point, and there is no code path that disables TLS server
  authentication: `rejectUnauthorized` is always on, an explicit trust anchor (or
  a deliberate system-store opt-in) is required, so a request with neither fails
  closed rather than trusting an unpinned server, and TLS is floored at 1.2. A
  request URL, and every redirect target, must be `https`. A scheme downgrade is
  refused, a cross-origin redirect on an enroll POST needs an explicit opt-in,
  and the redirect chain is bounded. The origin-specific identity is dropped on a
  cross-origin redirect and never carried to another origin: HTTP Basic
  credentials (answered only after the server is authenticated), the mTLS client
  certificate and key, and the pinned `servername` (SNI, which selects the
  enrollment host's certificate), dropped even when no client certificate is set.
  A caller's `checkServerIdentity` pin is retained and re-evaluated against the
  redirected host, so a certificate or SPKI pin keeps applying rather than being
  silently bypassed. The response body is bounded while it streams, aborted the
  instant it crosses the cap and before it reaches a decoder, a stalled socket
  times out, and a 202 Retry-After is surfaced to the caller rather than slept
  on.
- **EST HTTP Digest is security-on-by-default (CWE-327 / CWE-757).** HTTP Digest
  access authentication (RFC 7616), the alternative to HTTP Basic on every EST
  verb, answers only SHA-256 and SHA-512-256 challenges. MD5 (and MD5-sess) and
  the legacy no-qop RFC 2069 mode are refused unless the caller explicitly opts
  in, an unsupported or unusable challenge fails closed rather than downgrading,
  the most secure offered algorithm is chosen, a server `stale` re-challenge is
  bounded, and there is no `scheme: "auto"`, so a Digest challenge is never
  silently answered with Basic. The untrusted `WWW-Authenticate` challenge is
  parsed with a quoted-string-honoring tokenizer bounded before the copy, so a
  comma or scheme name inside a quoted value is never mistaken for a delimiter.
  The credential, like Basic, is answered only on the authenticated origin and
  never sent to a redirected server.
- **EST server-generated key confidentiality (CWE-311 / CWE-319).**
  `pki.est.serverkeygen` binds the delivered key's encryption to the request:
  whether the key part must be a CMS `EnvelopedData`, and to which recipient, is
  derived from the CSR's own DecryptKeyIdentifier or
  AsymmetricDecryptKeyIdentifier attribute, so a cleartext key cannot silently
  substitute for the encrypted key the request asked for. The channel is asserted
  to negotiate a confidentiality-bearing cipher — a NULL, anonymous, or EXPORT
  suite is refused — before the key is surfaced. The verb never decrypts the key
  part, so it is not a decryption oracle.
- **CMP transaction verify-before-read (CWE-345 / CWE-294 / CWE-770).** The
  `pki.cmp.session` orchestrator confers protection trust the transfer
  layer does not: a response is protection-verified — a signature chained to the
  supplied anchors, or a PBMAC1 MAC under the shared secret — and bound to this
  exchange before any field of its body is read. Cryptographic validity alone is
  not accepted; the signer must also be trusted, chaining to a supplied trust
  anchor with the RFC 9483 keyUsage gate, or matching the shared secret. A
  valid-but-untrusted response, whose signer an attacker on the transport can
  supply via the message's own unsigned extraCerts, is a hard stop, and the
  signature flavor therefore requires a trust anchor at construction rather than
  silently trusting an unpinned signer. A meddler who flips the HTTP response
  cannot forge a granted status or a poisoned poll delay, because the session
  throws on a failed or untrusted verify rather than reading a certificate off
  it. Each request carries a fresh `senderNonce` and echoes the peer's last
  `senderNonce` as `recipNonce` under one stable `transactionID`, so a response
  cannot be replayed or interleaved from another exchange (RFC 9810 §5.1.1). A
  `waiting` status is polled under a loop bounded by both a poll count and a
  total-wait budget with an injectable sleeper, so a CA cannot hold the client
  open indefinitely. A verified rejection or error, and an exhausted poll budget,
  are terminal typed verdicts (`outcome: rejected`, `poll-timeout`); a tampered,
  unverifiable, or nonce-desynchronized response is a hard-stop `CmpError` rather
  than a value the caller can misread as an issued certificate. Revocation and
  the support messages run under that same shell, with two rules of their own.
  A session revokes its own certificate: the signature over an `rr` is the proof
  of authorization to revoke (RFC 9483 §4.2), so the certificate named in the
  request must be the one the session protects with, compared by serial number
  and by the RFC 5280 §7.1 canonical name rule, and a PBMAC1 session is refused
  because a shared secret says nothing about which certificate its holder may
  revoke. And a value a verdict hands back is held to being the structure its
  operation names: certificates delivered for chain construction or a root key
  update are parsed as X.509 certificates, and a CRL delivered by either a
  revocation response or a CRL request is parsed as a `CertificateList`, so a
  responder cannot answer with any well-formed SEQUENCE and have it read as one.
  A CRL request is also bound to the source it named (§4.3.4 returns the latest
  CRL from the referenced source, not any CRL): by the §7.1 canonical rule when
  it named an issuer, and against the CRL's own `issuingDistributionPoint` when
  it named a distribution point, under the RFC 5280 §6.3.3 correspondence rule
  the path validator applies to a shard CRL. A CRL stating no scope is claiming
  to be its issuer's complete list, which a distribution point cannot bind, so
  the issuer is required alongside one: the message carries the distribution
  point, since only one `CRLSource` alternative can go on the wire, and the
  issuer names the CA whose CRL the caller will accept.
  A root CA key update is held to more than that, because its three certificates
  are only useful in the relationships §4.3.2 names: `newWithOld` must carry the
  new root key, name the same subject as `newWithNew`, and be issued and signed
  by the old root the request named; `oldWithNew`, when sent, must carry the old
  root key, name the old root, and be issued and signed by the new one. Binding
  the keys alone would not do it — a certification authority that has ever issued
  an ordinary certificate for the new key satisfies key equality and signature
  validity, and its holder could pair it with a self-signed certificate of their
  own choosing and have the result read as the authority's rollover — so the
  names are bound too, under the RFC 5280 §7.1 canonical comparison. Each of the
  three must also hold the authority the update transfers: `basicConstraints`
  with `cA` TRUE, and a `keyUsage`, where one is present, that allows
  `keyCertSign`. An ordinary end-entity certificate for the same subject and key
  clears the name, key, and signature rules while being able to certify nothing.
  The signatures are checked by the same certification-path engine that verifies a
  message's protection, so a responder cannot deliver three unrelated
  certificates and have the update reported as one an entity can act on.
  A certificate-request template's `keySpec` is held to RFC 9483 §4.3.3: an
  `id-regCtrl-algId` element must name an algorithm other than RSA, since an RSA
  key length is stated with `id-regCtrl-rsaKeyLen` instead. Whether an algId names
  RSA is decided by OID family rather than a fixed list, so a standardized RSA
  identifier the registry has not enumerated is still recognized from the arc it
  sits under — including the ISO/IEC 9796-2 RSA signatures giving message recovery,
  on the TeleTrusT signatureScheme arc — and such a requirement is refused with
  `cmp/bad-info-value` rather than surfaced to the caller as a non-RSA algorithm.
- **JWS algorithm confusion and JSON smuggling (ACME).** The `pki.jose` layer
  binds every `alg` to its key type in a registry, so the classic JWS attacks
  have no code path: there is no `none` row (CVE-2015-9235), the HMAC algorithms
  exist only in the External Account Binding profile so an `RS256`→`HS256` key
  confusion cannot resolve (CVE-2016-10555), signature lengths are pinned before
  any crypto call, and an all-zero ECDSA signature is refused (CVE-2022-21449).
  An OKP (Ed25519/Ed448) verification key is validated on-curve and full-order
  before use, so a low-order key, which the platform imports without complaint
  and which verifies a forged signature, cannot verify a forged JWS. The
  base64url codec rejects padding, non-alphabet bytes, and non-canonical trailing
  bits (RFC 8555 §6.1), and the JSON reader rejects a duplicate member at any
  nesting depth, the parser-differential smuggling class (CVE-2017-12635), under
  hard size and depth caps. `pki.acme` carries the protocol MUSTs fail-closed: a
  finalize CSR whose public key is the account key is rejected (RFC 8555 §11.1),
  a `mailto` contact with header fields or multiple addresses is refused rather
  than guessed, a tls-alpn-01 validation certificate must carry a critical
  `id-pe-acmeIdentifier` with a 32-octet Authorization and a single-entry
  SubjectAltName (RFC 8737), a wildcard is one leading label on a `dns`
  identifier only, and the ARI certID preserves the serial's DER sign-padding
  byte so it matches what the CA computes (RFC 9773).
- **ACME issued-certificate binding (CWE-345).** RFC 8555 states nothing about
  what the certificate resource may answer with, so the certificate an ACME
  client installs is bound to the order it placed by the client rather than by
  the wire. `downloadCertificate` checks the returned end-entity certificate
  against the order in both respects: it must certify the public key that order's
  CSR asked to have certified, and its identifier set must equal the order's
  identifiers. At least one of the two is required by default, since a caller
  holding only the order or only the CSR can still bind what it has; a download
  supplying neither is refused rather than returned unchecked. The result reports
  which of the two ran, so a binding that was not performed cannot read as one
  that was, and neither can a waived one. The check covers whichever chain is
  returned, an alternate chosen through `selectChain` included.

  A certificate's identifier set is its dNSName and iPAddress subject alternative
  names; its subject common name is read only where it asserts none. Where an
  alternative name is present the common name is not an additional identity —
  name matching has read the alternative names and ignored the common name for
  many years, and CABF TLS BR 7.1.4.2.2 requires any common name to appear among
  them anyway — and an address in a common name is never an IP identity, because
  address matching does not fall back to it. The outbound CSR check deliberately
  parts from that and reads every common name the request carries, alternative
  names present or not: the two sides answer different questions. The issued
  certificate's set says what that certificate authenticates. The CSR's says what
  the request is asking to have certified, and a CA may carry a common name
  through into the certificate it issues, so a request naming the order's
  identifier in an alternative name and an unauthorized one in its subject is a
  request for a name the order does not cover.

  A name that maps to no ACME order identifier is refused rather than dropped, on
  both sides: an order identifier of a registered type other than `dns` or `ip`,
  a `subjectAltName` that is neither a dNSName nor an iPAddress, and a subject
  common name that is neither a dns name nor a canonical IP address. Dropping one
  would let a set report as checked after leaving part of it out — a subject may
  carry several common names, and dropping the unmappable one while another
  supplies the match reports the set as bound while the certificate still names
  something the order never covered. Names are folded with ASCII case rules
  rather than the Unicode mapping, so a character whose Unicode lowercase is
  ASCII is not read as the ASCII name it would fold to.
- **ACME client transport is fail-closed on the wire (CWE-295 / CWE-319 /
  CWE-770 / CWE-294).** `pki.acme.client` drives a live directory over the same
  `pki.transport` socket choke point, with no path that disables TLS server
  authentication: `rejectUnauthorized` is always on, an explicit trust anchor (or
  a system-store opt-in) is required, and TLS is floored at 1.2. The directory
  URL and every server-returned URL — account, order, authorization, challenge,
  finalize, certificate, and the ARI path — must be `https`, so an `http` URL
  from a compromised or downgraded directory is refused rather than fetched.
  Every such URL must also be canonical. A spelling the WHATWG URL parser would
  silently rewrite is refused: a path or query the transport would normalize, a
  fragment, or a host in an IPv4-address form (hex, octal, decimal, shorthand)
  the parser coerces to a different and often loopback or internal address. The
  account-key-signed JWS `url` (RFC 8555 §6.4) therefore always names the exact
  authority the request is directed to and cannot be steered to an unintended
  host. Every authenticated request carries a fresh single-use anti-replay nonce
  bound to that URL, harvested only from a validated `Replay-Nonce`, with a
  bounded `badNonce` retry so a nonce-replay error cannot loop. Reads are
  POST-as-GET, a poll count and a total-wait budget bound the poll loop, which
  sleeps on a `Retry-After` through an injectable sleeper, so the delay is
  bounded rather than attacker-unbounded, and every response body is size-capped
  before it reaches a JSON or PEM decoder. When `downloadCertificate` selects
  among alternate issuance chains, the `Link` response header is parsed strictly
  (RFC 8288: `rel="alternate"` matched as a whole token, a malformed header or a
  non-`https` target refused). Because an alternate is fetched with the
  account-key-signed POST-as-GET, an alternate target is confined to the
  certificate download's own origin, so an untrusted, TLS-delivered but unsigned
  `Link` header cannot steer that authenticated request to another host (SSRF).
  The extra signed fetches are bounded by `maxAlternates` (default 8) so a header
  advertising many alternates cannot amplify into unbounded requests, resolved
  URLs are de-duplicated, and an alternate whose end-entity certificate differs
  from the primary's is rejected rather than substituted (RFC 8555 §7.4.2).
  `renewalWindow` refuses before any request for a certificate already past its
  `notAfter` or one the caller marks replaced, spreads the renewal instant with a
  uniform random draw inside the CA's suggested window, and clamps the ARI
  `Retry-After` to [60 s, 24 h] so a hostile or absent value can neither hammer
  the CA nor defer the next check indefinitely (RFC 9773 §4.2/4.3).
- **S/MIME header protection: injection, downgrade, and outer-header trust
  (CWE-93 / CWE-345).** `pki.smime` header protection (RFC 9788) inlines the
  protected headers on the Cryptographic Payload so the CMS signature or
  encryption covers them. Every header field a composer emits routes through one
  fail-closed guard: a CR, LF, or NUL in a field value, or a field name outside
  RFC 5322 ftext, is rejected (`smime/bad-header`), so a caller-supplied Subject
  cannot inject a Bcc, split the message, or forge a multipart boundary. On
  receive, the authenticated inner headers are surfaced distinctly in
  `protectedHeaders` from the untrusted outer display headers and never silently
  merged, so a transport that rewrites an outer header cannot change the verified
  set, and an outer From that disagrees is flagged `fromMismatch`. A payload
  whose declared `hp` marker is malformed, invalid, or contradicts the
  cryptographic envelope — a signed message claiming `hp="cipher"` — fails closed
  with `smime/bad-header-protection` rather than being treated as unprotected;
  there is no silent downgrade path. For an encrypted message the Header
  Confidentiality Policy keeps the real header values (Subject, Comments,
  Keywords) only inside the ciphertext, never in the outer section, and the
  authenticated `HP-Outer` records (RFC 9788 §2.2) inside the ciphertext document
  which fields were left visible. `decrypt` therefore derives the
  end-to-end-confidential set (`headerProtection.confidential`) from signed or
  encrypted data alone, letting a caller reply or forward without leaking a
  confidential header (§6.1). Inbound detection of the legacy RFC 8551
  `message/rfc822` wrap (RFC 9788 §4.10) is opt-in
  (`opts.legacyHeaderProtection`) and safe by default. A legacy RFC8551HP message
  is structurally indistinguishable from an ordinary forwarded `message/rfc822`,
  and RFC 9788 §4.10.2 states the inference is "not based on any strong
  end-to-end guarantees", so the toolkit never conflates the two: a legacy
  inference is surfaced only under `headerProtection.legacy`, in its own
  `{ headers, mode, fromMismatch, confidential }` object, never in
  `protectedHeaders`, and never setting `present: true`. A consumer that keys
  trust off `present` or `protectedHeaders`, the authenticated and
  cryptographically declared (`hp=`) set, therefore cannot be tricked into
  treating a forwarded attachment's From or Subject as this message's own
  headers. Consuming the inferred set is an explicit choice — read
  `headerProtection.legacy.headers` — and comes with `legacy.fromMismatch`, which
  flags a forwarded message whose inner sender differs from the outer one.
  Detection applies only after the signature or AEAD verdict succeeds and
  requires all four §4.10.1 conditions; a nested crypto layer, an `hp=` on the
  inner message, a non-`message/rfc822` payload, or a duplicate Content-Type on
  either part reports `legacy: null`.

### Network fetches that could widen trust

- **CT log-list fetch verifies before it parses (CWE-345 / CWE-347 / CWE-295 /
  CWE-770).** `pki.ct.fetchLogList` fetches the `log_list.json` and its detached
  `log_list.sig` over the same fail-closed `pki.transport` (`rejectUnauthorized`
  always on, an explicit anchor or system-store opt-in required, TLS floored at
  1.2), then verifies the detached signature over the raw fetched bytes against a
  caller-pinned distributor key before it parses. `pki.ct.parseLogList` runs only
  on a valid signature, over the same buffer that was verified, so an unverified
  or tampered document is never parsed, read, cached, or surfaced; a one-byte
  change to a validly structured list fails closed as `ct/log-list-untrusted`, a
  verdict distinct from every parse-domain code. The signer key is pinned
  out-of-band, never trust-on-first-use and never fetched from the list's own
  origin, and no vendor URL or key is baked in. The fetch is HTTPS-only even
  across an injected transport, and the detached signature must share the
  log-list origin, so the log-list endpoint's origin-bound credentials (an
  `Authorization` or `Cookie` header, the mTLS client certificate) can never
  reach a different signature host. Each response is size-capped before the trust
  chain, and the surfaced `timestamp` lets a caller police freshness without a
  hidden clock.
- **AIA caIssuers fetching is SSRF-bounded and trust-preserving (CWE-918 /
  CWE-770 / CWE-295).** `pki.path.build` fetches a missing intermediate from a
  certificate's Authority Information Access `caIssuers` URL only when the caller
  opts in (`opts.fetchAia: true`; the default build is fully offline), and only
  as a lazy fallback after the local candidate pool is exhausted (RFC 4158 §7.2
  local-before-remote, so a build the static pool can complete never touches the
  network). The fetch URL comes from an untrusted certificate, so the surface is
  bounded against server-side request forgery and amplification. Only an `https:`
  `uniformResourceIdentifier` accessLocation is fetched: an `http`, `ldap`,
  `ftp`, `file`, or `mailto` URL, or a non-URI GeneralName, is skipped before any
  socket. A non-globally-routable destination is refused, whether it is such an
  address literal or a hostname that resolves to one, with the resolved address
  pinned for the connection to close the rebinding window. The classifier blocks
  the complete IANA special-purpose set: for IPv4 the private, loopback, CGNAT,
  link-local (`169.254.0.0/16` cloud-metadata), benchmarking, TEST-NET,
  6to4-relay, multicast, and reserved ranges (RFC 6890); for IPv6 everything
  outside global unicast `2000::/3`, plus the special-use carve-outs within it —
  `2001::/23` (IETF protocol), `2002::/16` (6to4), `2001:db8::/32` and
  `3fff::/20` (documentation), and IPv4-mapped. An untrusted certificate
  therefore cannot drive an authenticated GET to an internal service by IP
  literal or by hostname. Only the `id-ad-caIssuers` access method is used, never
  `id-ad-ocsp`. A build-wide total fetch budget is enforced as a silent cap: on
  reaching it the builder stops fetching rather than throwing, so a fetch bound
  can never deny a path the static pool could build. A per-certificate URL cap
  also applies, alongside a build-wide URL dedupe on the normalized URL so a
  mesh pointing many certs at one URL fetches once, a streaming response-size cap
  plus a per-response certificate-count cap so a bundle cannot force tens of
  thousands of parses, and no redirect following, so only a `200` with an in-cap
  body is a certificate source. Every fetch fault — a transport error, a non-200,
  an oversize or non-certificate body — is a silent skip, and the search
  continues over the pool rather than failing the build. The fetch runs over the
  same fail-closed `pki.transport` (`rejectUnauthorized` always on; an explicit
  anchor or system-store opt-in required), and its TLS trust (`opts.tls`) is
  distinct from `opts.trustAnchors`, so the web-PKI trust for the HTTPS
  connection is never conflated with the PKI trust store the built path validates
  against. Most important, a fetched certificate is untrusted pool material: it
  is scored, deduped, and accepted through the exact same `pki.path.validate`
  §6.1 gate as any candidate, and is never added to the trust anchors, so a
  fetched self-signed or anchor-looking certificate can never complete a chain by
  itself (RFC 4158 §6.6).

### Supply chain

- **Compromise through transitive dependencies.** There are zero npm runtime
  dependencies and nothing is vendored. The cryptography runs on Node's built-in
  `node:crypto`, so there is no third-party runtime code, transitive or bundled,
  to compromise. If a library is ever vendored under `lib/vendor/`, which happens
  only when a required operation is confirmed missing from the Node floor, it is
  pinned by SHA-256 in `MANIFEST.json` and a tampered artifact is detectable by
  re-verifying the manifest. The acquisition path is verified too: repository
  tooling (the fuzz build, the vendoring flow) installs npm packages only through
  integrity-pinned lockfiles (`npm ci`, install scripts disabled), so a
  registry-served substitute fails the integrity check before a byte of it runs.

## Operator hardening checklist

The toolkit fails closed by default. The items below are what an operator
embedding it is responsible for.

- [ ] **Treat every input as untrusted.** Parse certificates, messages, and keys
      that arrive from the network or from users through the shipped `pki.*`
      parse entry points, never by hand-walking a node tree past the codec's
      checks.
- [ ] **Keep the size and depth caps sane for your context.** The defaults
      (`C.LIMITS.DER_MAX_BYTES`, `C.LIMITS.DER_MAX_DEPTH`) bound adversarial
      input. If you raise them for a legitimately large structure, raise them
      only for the call that needs it rather than lifting the ceiling globally.
- [ ] **Enforce the validity window.** When you evaluate a certificate, check
      `validity.notBefore` and `validity.notAfter` against your check time. A
      parsed certificate is not a valid one.
- [ ] **Pin your trust anchors explicitly.** Validate chains only against a trust
      anchor set you control. Never treat a certificate's own asserted issuer,
      self-signature, or embedded chain as trust.
- [ ] **Compare the signed bytes, not a re-derived copy.** When verifying a
      signature, hash the `tbsBytes` the parser returns. Do not re-encode the
      parsed fields and sign or verify over the re-encoding.
- [ ] **Fail closed on unknown critical extensions.** When you build certificate
      handling on top of the parser, refuse a certificate whose `extensions` list
      carries a `critical: true` extension you do not understand.
- [ ] **Prefer the post-quantum or hybrid option** where your peers support it.
      Post-quantum ML-DSA and SLH-DSA signatures are available today alongside
      the classical set, with ML-KEM key generation shipped and KEM encapsulation
      on the roadmap. Choose them rather than defaulting to classical-only.
- [ ] **Verify release authenticity before deploying** (below), and re-verify the
      vendored `MANIFEST.json` if you fork or re-package the toolkit.

## What the toolkit does not defend against (operator responsibility)

- **Trust-policy decisions.** Which roots you trust, which key usages you
  require, which name constraints you enforce, and how you handle revocation are
  policy. The toolkit gives you the primitives; it does not choose them for you.
- **Private-key storage.** Protecting private-key material at rest and in memory
  (HSM, OS keystore, sealed storage) is out of scope. The toolkit reads and
  writes key structures; it does not custody your keys.
- **Clock integrity.** Validity-window and timestamp checks are only as
  trustworthy as the clock you pass in. Sourcing a trusted time is the operator's
  job.
- **Randomness quality for key generation.** Key and nonce generation draw on the
  host's CSPRNG; a compromised host RNG is out of scope.
- **Application-layer misuse.** Calling a parse entry point and then ignoring the
  thrown error, or trusting a field the toolkit surfaced but the operator never
  validated, defeats the fail-closed design.

---

## Verifying release authenticity

Release tags are annotated and SSH-signed, and published tarballs carry
provenance and an SBOM. Verify before deploying.

### Signed tags

```sh
git fetch --tags
git tag -v vX.Y.Z          # must print a Good "git" signature for the maintainer key
```

<!--
  MAINTAINER SIGNING KEY — PLACEHOLDER.
  The maintainer SSH signing-key fingerprint is published here and registered as
  a GitHub SSH signing key at the first signed release. Until that release lands,
  this table intentionally carries no fingerprint — do not trust any value that
  claims to be it before it is filled in here in a signed commit.
-->

| Field | Value |
|---|---|
| Algorithm | Ed25519 (SSH signing key) |
| Fingerprint (SHA-256) | _set at the first signed release — placeholder until then_ |
| Public key file | published at the first signed release |
| Registered as | GitHub SSH signing key on the maintainer account |

To verify without trusting GitHub's UI, fetch the maintainer's public key from a
trusted channel, write your own `allowed_signers` file, and run
`git -c gpg.ssh.allowedSignersFile=<file> tag -v vX.Y.Z`.

### npm provenance

The published npm package carries provenance linking the tarball to the exact
workflow run and commit that built it:

```sh
npm view @blamejs/pki@X.Y.Z --json | jq .dist        # integrity hash + provenance
npm audit signatures                                  # verifies registry signatures + provenance
```

Provenance binds the tarball bytes to a build; it does not by itself prove the
source is clean. Pair it with the signed-tag check above so both the source side
and the build side are covered.

The same provenance bundle can be verified offline with the toolkit itself.
`pki.sigstore.verifyBundle` checks the DSSE signature, the Fulcio chain as of the
Rekor log time, the RFC 9162 inclusion proof against a Rekor-signed root, and the
in-toto SLSA subject digest, against trust material you pin: the Fulcio CA roots
and Rekor log keys. It has no dependency tree of its own. An Ed25519 or Ed448
Fulcio leaf key is validated on-curve and full-order at the raw
signature-verification sink rather than only at key parsing, so a low-order key
that would verify a forged EdDSA signature is refused. That is the same gate
every EdDSA verification path in the toolkit routes through.

Two things that verification does **not** establish on its own, and both matter:

- **Who signed it.** Those legs prove the bundle is internally consistent and
  anchored to the Fulcio and Rekor material you pinned. They do not say the
  signer was this project: anyone who can obtain a Fulcio certificate can produce
  a bundle that passes all of them for an artifact of their own. Pass `identity`
  and the certificate's SAN, OIDC issuer, and source-repository URI are compared
  to what you expect; omit it and no identity check runs. The verdict says which
  of the two happened: `identityChecked` carries a boolean per field, so a signer
  that was checked is distinguishable from one that never was. An `identity`
  naming none of those three fields is refused rather than treated as satisfied,
  and so is a field name that is not one of them — either would accept every
  signer while reading as a policy in force. No default identity exists,
  because which repository is allowed to sign is the relying party's to state.
- **Which artifact it covers.** Confirm a returned `subjects[].digest` matches
  the tarball you install. The signer chooses that digest, so it binds the bundle
  to an artifact only once you have compared it to the bytes in your hand.

### SBOM

Each release ships a CycloneDX SBOM (`sbom.cdx.json`). Because the toolkit
vendors nothing today, the component set is empty by design. Match it against the
shipped `lib/vendor/MANIFEST.json`, an empty `packages` map, to confirm the
release adds no third-party runtime code. If a library is ever vendored, it
appears in both.

---

## Coordinated disclosure

We follow coordinated vulnerability disclosure. If you are a downstream
distributor and need embargoed advance notice of a fix, say so in your private
report and we will coordinate a shared timeline.
