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
  verdict, rather than producing a stack overflow or a half-parsed object. It also
  refuses an element carrying a universal tag X.680 Table 1 reserves and assigns to
  no type: tag 0, which is the end-of-contents encoding, tag 15, and every tag from
  37 up. A child nothing refuses is a child a format detector may count, so
  `pki.schema.parse` and `pki.schema.detectFormat` never see one. The rule is the
  table's reserved rows, not the set of types this codec has readers for, which is
  smaller: an assigned type with no reader here still decodes, since one can arrive
  inside an `ANY`, and `pki.asn1.reservedUniversalTag` answers which is which.
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
- **A size limit read after the copy it bounds (CWE-770).** A boundary that
  copies its input before comparing it against a limit pays an allocation the
  size of a hostile value to reject it. Every caller byte input to `pki.ct`
  entered through one door that copies, and the limits sat past it: a 64 MiB
  value against the 4 MiB certificate-transparency log-list cap allocated 64 MiB
  and then refused, and the fixed-width fields had no limit before their copy at
  all, so a 32 MiB value handed as a 32-byte tree head hash allocated 32 MiB and
  one handed as its signature allocated 64 MiB across the two reads. The same
  order was wrong on HPKE's raw key material and encapsulated keys, where a value
  handed in place of a 32-byte key was copied in full before the width check
  refused it. Each of those doors now reads the input's authoritative byte length
  first and copies only a value within the limit, and the shared one carries the
  toolkit's DER ceiling as its default so a route added later is bounded without
  being bounded by hand. A string is measured as the UTF-8 it will encode to,
  which is the number the conversion allocates and is not its code-unit count.
  One residual: a value between a field's own fixed width and that ceiling is
  still copied before the check that names the width refuses it. Bounding each
  field tighter would preempt the format's own refusal and replace its error code
  with a generic one, so the bound stays where the allocation is unbounded rather
  than where it is merely larger than the field.
- **Decode-fanout and verify-fanout amplification.** A decoded input's element
  count is capped independently of its byte size (`asn1/too-many-items`,
  `cbor/*`, per-list PKCS#12 caps), and an OCSP response is capped in embedded
  certificates before any pre-authentication signature work. A small hostile
  input cannot fan out into unbounded allocations or unbounded asymmetric-verify
  work.
- **Unbounded transparency-log entry fanout (CWE-834).** A Sigstore bundle's
  entry list was bounded only by the 1 MiB bundle byte budget. An entry is tried
  until one passes every check that depends on which entry it is, and those
  checks include a certification-path validation whose instant comes from the
  entry itself unless the caller pins `opts.time`, so each additional entry buys
  another path validation. A measured entry is about 6.7 KB, which leaves room
  for roughly 155 in a budget-sized bundle, while every bundle in the Sigstore
  conformance corpus carries exactly one. `pki.sigstore.verifyBundle` caps the
  count at `C.LIMITS.TLOG_MAX_COUNT` (32) and refuses before reading any entry.
  The ceiling is a local resource bound, not a rule the bundle specification
  states. Within that ceiling the artifact is read once per digest algorithm. The
  comparison against the digest an entry records runs per attempt, and an attempt
  that failed it sent the next one over the same bytes again, so a 100 MB artifact
  was hashed 32 times; the same bytes under the same algorithm are the same digest.
  The comparison against the `messageDigest` the bundle itself carries reads
  through the same answer, that claim naming its own algorithm and an attempt
  having already hashed the artifact under it.
- **Repeated-identifier work amplification in TUF metadata (CWE-834).** A root
  states a key list per role and a document carries a signature list, and both
  were walked per occurrence rather than per distinct member. Each repetition of
  one key identifier canonicalized and hashed the whole key, imported it, and
  derived its material identity again; in the signature list each repetition of
  one failing signature re-ran the signature check as well, because an identifier
  is skipped only once a signature under it has succeeded. A document that meets
  no threshold is therefore the most expensive case rather than the cheapest.
  A verify's own role is a third list of the same kind: its identifiers were
  resolved to keys one occurrence at a time, each resolution deep-copying the key
  and hashing its canonical form. Measured, a 588 KB candidate repeating one
  identifier 2000 times per role spent 12.6 seconds inside the role walk, 1000
  repetitions of a single all-zero signature over a 414 KB body cost 2000 key
  imports, 1000 signature checks and 1.6 seconds, and 7500 repetitions of one
  identifier in a role beside a 500 KB key spent 10.2 seconds resolving it, all
  inside the metadata size cap and all before anything had authenticated the
  document. Memos alone left the document choosing how much work it asked for.
  Distinct signatures for one authorized key share no memo, and each hashes the
  whole signed body, so a 500 KB body under 2400 signatures made with a key
  nobody authorized bought 2400 checks and about a second, synchronously, in a
  1,013,726-byte document. `pki.tuf.verifySignatures` reads the keys the ROLE
  names and looks up the one signature each is listed with, so the signature list
  decides which signature each key offers and no longer how many checks run: 1000
  distinct signatures under one key cost one check, and 40 keys the role names cost
  40. The work follows the document's own size rather than the product of its body
  and its signature list. The role is the caller's argument, and a root rotation
  verifies a candidate against the root role it states itself as well as against
  the trusted one, that being the check the specification requires of a new root,
  so the count of that one call is the candidate's to state.
  `pki.tuf.updateRoot` decides each identifier once per walk.
  The same documents answer in 11, 36, 5 and 6 milliseconds. A key is
  also imported once per identifier rather than once for the identity a threshold
  counts it under and again for the signature check, which both halves the work
  and makes the key counted and the key verified with the same key.
  A key identifier listed more than once is where the two authorities differ, and
  the first signature it carries is the one asked. The specification caps the
  count at one verified signature from a key identifier and leaves the document
  readable; the reference implementation refuses the document. A second entry
  cannot raise a count already capped at one, so what it could do is cost another
  pass over the body. A document listing a wrong signature for a key ahead of a
  right one therefore reads as that key not having signed.
- **A DSSE envelope signature the verdict never covered.** The Sigstore bundle
  specification states that an envelope in a bundle carries exactly one
  signature, and that a verifier rejects an envelope whose signature count is
  not one. Only `signatures[0]` was ever read, so an envelope carrying a second
  was accepted and its verdict described a check that had not been run against
  the rest of what the envelope carried. The count is now enforced at the bundle
  door as `sigstore/bad-dsse`.
- **A work bound answered with a value that is not a number (CWE-834).**
  `opts.maxIterations` lowers the key-derivation work a PKCS#12 store is allowed
  to demand. The option was read once for each part of its shape check and again
  for the comparison that applies it, so an option supplied through an accessor
  could return a valid integer to every check and a non-numeric value to the
  comparison. The cap became NaN, and no count is above NaN, so the comparison
  stopped refusing anything. `pki.pkcs12.open` and `pki.pkcs12.verifyMac` read
  the option once and every use reads that one value. The same read-once shape is
  applied to the PBES2 and CMP iteration caps.
- **A check turned off by the value that asked for it (CWE-20).** An option whose
  `true` value turns a validation requirement on was compared against `true`, so a
  value outside the documented domain selected the off branch and the call ran with
  the requirement disabled. A `"true"` read out of a config file is such a value, and
  a boundary testing truthiness instead has the mirror fault, turning a requirement
  on for `"false"` and `0`. `requireAlgorithmProtection` on `pki.cms.verify` and
  `pki.cms.decrypt`, `requireRevocation` and the RFC 5280 sec. 6.1.1 policy inputs
  `initialExplicitPolicy`, `initialAnyPolicyInhibit` and `initialPolicyMappingInhibit`
  on `pki.path.validate`, `requireJsonContentType` on `pki.ct.fetchLogList`, and
  `expectSCEPStandard` and `requireStrongProfile` on `pki.scep.getCACaps` take `true`,
  `false`, `null` or an absent option, and refuse anything else with the module's
  `bad-input` code before the check they govern runs and before any request goes out.
  A trust anchor's own copies of those three policy flags were already typed where
  they are copied, and a caller's values are compared against them. `pki.path.build`
  types the four it forwards at its own door, because a build reaches an AIA fetch
  before it reaches `pki.path.validate` and a build that assembles no path never
  calls it, so the request went out while the malformed switch rode along unread. On
  both verbs the value that passed the door is the value the check uses: normalizing
  a trust anchor reads its name, key and algorithm, and those reads run caller code
  when the anchor carries accessors, so an options object the caller still holds
  could answer the typing and the use differently and the policy state was built from
  the second answer. `pki.path.build` also refuses a requirement asked for together
  with `validate: false`, which returns the ordered path without applying any of them.
  `pki.cms.decrypt` refuses `requireAlgorithmProtection` on a content type that
  cannot carry the attribute at all: RFC 8933 sec. 6 gives it a place in an
  `AuthenticatedData` alone, and the plaintext of an `EnvelopedData` came back
  before with the requirement neither applied nor reported.
- **A verdict describing a check that ran on a different value (CWE-367).** A
  verify verb reads one option to decide whether a rule applies and reads it again
  for the value the rule uses, so an option supplied through an accessor can
  answer those reads differently and the verdict then reports a check that never
  ran against what the caller supplied. `pki.jose.verify` read `opts.key` seven
  times, among them the RFC 7638 thumbprint comparison against the jwk a JWS
  embeds and the key the signature is verified under, so the key compared need not
  have been the key used and a JWS naming an unpinned signer returned a verdict
  instead of `jose/key-mismatch`. `pki.webauthn.parseClientData` read each
  `expected*` option once to decide whether to compare and once for the value
  compared, so `checked.challenge`, `checked.origin` and `checked.type` could
  report a comparison against a value the caller never supplied. Both take each
  named option once, at entry, before any of it is examined, as do the `pki.smime`
  verbs and the `pki.hpke` setup verbs (whose `mode` was read at the default and
  again at the use, so an accessor answering auth then base got a base setup).

  The same rule now covers what a verify verb is given as well as how it is
  configured, because a verification that awaits gives a caller a window in which to
  change what it still holds. `pki.tlog.verifyNote`, `pki.tlog.verifyCheckpoint`,
  `pki.tuf.verifySignatures`, `pki.tuf.updateRoot`, `pki.ct.verifySct`,
  `pki.ct.getSth`, `pki.ct.addChain`, `pki.ct.getProofByHash`,
  `pki.ct.getSthConsistency`, `pki.ct.fetchLogList` and `pki.jose.verify` each take
  the document, the keys, the pinned trust inputs and the validation instant ONCE, at
  entry, and every check and every verification below reads those copies. Held as
  views across a key import or a network fetch, the bytes verified need not have been
  the bytes reported: a TUF role's threshold could be met by key material nobody
  authorized, a note's signature line attributed to a signer whose key never signed
  it, a tree head checked under a log that was not the one pinned, and an expired
  root accepted by moving the `Date` supplied to it. None of that requires the
  caller to be hostile, only to reuse a buffer while a verification is pending.
  `pki.webauthn.verify` and `pki.webauthn.verifyAssertion` already copied their
  inputs.
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
  in turn by the RFC 8446 §4 handshake framing limit (TLS 1.3 is now RFC 9846)
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
  probes each algorithm once at startup, handing it a frame with the last two
  bytes cut, and drops any decompressor that returns anything at all rather than
  faulting, so that algorithm is neither offered nor accepted. At the Node 24.21
  engine floor zlib, brotli and zstd all fault on a cut frame, so all three are
  offered; on a runtime where one returns instead, that algorithm is dropped.
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
  raised. The crypto engine, the JWS signer, the format decoders, every guard,
  the key import and export verbs and the Sigstore bundle verifier therefore
  take what they decide with at load and invoke it without reading a property
  of the captured function, so a permission check, a canonical serialization,
  the binding of a transparency-log entry to a bundle's signature, or the split
  between a ciphertext and its authentication tag concludes the same thing
  whenever it runs. Every SIGNATURE CHECK is held the same way: certification
  path validation, `pki.ct`'s signed tree heads, log lists and SCTs, all five
  signature families in `pki.cms.verify`, both key routes in `pki.jose.verify`,
  WebAuthn assertions and attestations, the FIDO metadata BLOB, each half of a
  composite signature and the AuthenticatedData MAC take the WebCrypto verify
  and the key import they use at load. Held as a method on an object instead,
  one replaced afterwards decides the verdict: reproduced on a signed tree head,
  where it turned another log's signature from refused into accepted. The
  comparator that orders a DER SET OF and answers whether two byte strings are
  equal is captured for the same reason, since it decides emitted bytes at one
  end and a verdict at the other. Asking whether a registry carries a
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
  answer for an entry nothing registered. What a verify verb hands back is closed
  the same way: every field of a verdict is defined on the verdict rather than
  assigned onto it, so an inherited setter cannot take the write and answer the
  read from its own getter, and the verdict carries a `then` of its own, so
  resolving it does not hand an inherited accessor the verdict as a receiver on
  its way to the caller. A list a verb returns is appended to by defining the
  entry, so a setter at that index cannot substitute what the caller reads.
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
  skipped, and only then does it delegate the signature check to `verifySct`.
  `pki.ct.verifySctList` applies those same per-SCT trust gates across every SCT a
  certificate carries and renders a certificate-level verdict, recording each
  SCT's outcome so one untrusted or forged SCT cannot sink the result and the
  caller decides a CT policy (a minimum count of valid SCTs from a minimum number
  of distinct trusted operators) from the surfaced counts. `pki.path.validate`
  runs that verification as an opt-in gate (`ctLogList` / `ctPolicy`): a
  certificate that declares a CT policy but carries no SCT-list extension fails
  closed (`path/ct-required`), and the embedded SCTs are checked against the
  precertificate entry `pki.ct.x509CertEntry` reconstructs by removing the SCT
  extension from the certificate's TBSCertificate as byte surgery, never a
  re-encoding. An SCT dated after the validation time is rejected and never
  counted toward the policy (RFC 6962 sec. 5.2, a client rejects a future-dated
  SCT), so a postdated attestation cannot satisfy a CT threshold before its
  claimed issuance time. The
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
- **A PKCS #11 URI that names a module or a PIN the operator did not intend.** A
  `pkcs11:` URI arrives as a command-line argument, a config field or an
  environment variable, so `pki.pkcs11.parseUri` reads the RFC 7512 sec. 2.3 and
  sec. 2.4 grammar rather than a general URI reader. A character a component
  admits only percent-encoded, a truncated or non-hexadecimal escape, a value
  that is not valid UTF-8, an empty attribute between two delimiters, and an
  attribute repeated where the RFC admits it once are each a typed `pkcs11/*`
  refusal. Two more are the refusals sec. 2.4 asks a consumer for: a URI
  carrying both `pin-source` and `pin-value` leaves which PIN applies
  undecided, and a `module-path` that is not absolute lets the shared object a
  process loads depend on the directory it is started from. An attribute name
  and a `type` value are folded with the ASCII fold the grammar is written in,
  so a name carrying a character Unicode folds onto an ASCII letter, such as
  the Kelvin sign onto `k`, is refused rather than read as the standard
  attribute it resembles and then held to none of that attribute's rules.
  `pki.pkcs11.formatUri` is held to the same rules and reads each component
  once before it writes anything, and a vendor attribute name is held to the
  vendor grammar and refused when a standard attribute owns it, so a name
  carrying a delimiter cannot put an attribute into the URI that the caller
  never named. Nothing here loads a PKCS #11 module or talks to a token.

### Keys, secrets, and the crypto engine

- **A copied byte argument is out of the caller's reach once taken (CWE-367 /
  CWE-471).** Every verb copies the byte arguments it is given at its entry, so
  that what it validates is what it then uses. The copy is taken into storage of
  its own rather than through `Buffer.from`, which for a small result allocates
  out of a shared pool: a caller whose own value came from that pool holds a view
  of the whole store, the copy lands inside it, and the caller could find and
  overwrite it while the verb was awaiting something. A shared-memory input
  (`SharedArrayBuffer`) is refused outright rather than copied, and a detached
  backing buffer is refused rather than read. This covers the pinned keys,
  hashes, trust anchors and signed bytes each verb copies.
- **A key written out by the tool used to look at it (CWE-532).** A report goes
  somewhere: a terminal with scrollback, a log, a ticket, a screenshot. A PKCS#8
  file and a PKCS#12 store both carry a private key, so a renderer that wrote the
  key bytes into its report would make an inspection tool a way of copying a key
  out of a file somebody opened only to read its metadata. `pki.inspect.pkcs8` and
  `pki.inspect.pkcs12` name the key algorithm, the public half where the structure
  carries one, and that a private key is present with its length, and never its
  bytes. A PKCS#12's encrypted safes are named rather than decrypted, because
  these verbs take no password. The rule is measured rather than asserted: the
  conformance vectors search each rendered report for byte runs of the key in hex,
  base64 and colon-hex, so a renderer that started printing one would fail.
  `pki.inspect.asn1` is the one verb outside that rule, and it says so where it is
  documented: a structural dump exists to show the bytes, so it withholds no value
  and prints private key material like any other. Its `maxValueBytes` cap bounds how
  much of a value it renders rather than whether it renders one, so it is a report
  size control and not a disclosure control. `pki.inspect.any` never routes to it, so
  the guarantee above holds for a report reached by format detection.
- **A key the tool wrote where anyone could read it.** `pki keygen` is the first
  verb in this toolkit that puts a private key on disk, and the decisions it makes
  are inherited by whoever runs it. The key goes to the file `--out` names and
  never to stdout, because a terminal's scrollback is a copy of the key and so is
  the shell history of the pipeline it ran in. An existing file is never written
  over, since a key written over another destroys the only copy of the first; the
  refusal names the file in the way. The file is created with owner-only
  permissions in the call that creates it rather than chmod'd afterwards, which
  would leave a window where it is readable. On Windows Node does not apply the
  mode argument, measured: a file created with `0600` reports `0666`. The help
  text says so rather than implying a guarantee the platform does not give, and
  the conformance vector asserts the claim against what the platform does. The
  public half goes to a separate `--pub`, so sending a public key does not mean
  handing over the file that holds the private one. A key path on a command line
  is visible in the process table to every user on the machine while the process
  runs; the help text says that too, since a reader who does not know it cannot
  work around it. `--out` and `--pub` naming one file is refused before a key is
  generated, since the private key would go where the public half was asked for.
  A run that fails after creating a file removes only the files it created, and it
  identifies them by what the creating descriptor reported rather than by what the
  path holds once that descriptor has closed. The identity is recorded before any
  content, so a run whose write failed can still tell its own file from one that
  replaced it; recorded only on a completed write, such a record had no identity
  at all and the path was cleared of whatever occupied it. A file that replaced the
  one this run created, changed since, or gained a second link to its content, is
  left where it is and named on stderr, as is one the platform cannot identify
  after a failed write and one the cleanup could not examine at all. The link test
  asks what is on disk rather than comparing against a recorded count, a name
  added before the record was taken and removed afterwards having made the count
  fall. A report naming a path keeps to one line, a newline in a name having ended
  the line early and put what followed it where the tool's own output is read.
  Every file the CLI writes is covered, not only the keys: `csr`, `issue`, `fetch`
  and `sign` with `--out` create a path that does not exist through an exclusive
  descriptor and remove it if the write fails, while a path that already exists is
  overwritten as those verbs have always done and is never one the run removes.
  That overwrite opens the path without permission to create, so a path that stops
  existing between the two calls is retried as the exclusive create it has become
  rather than written by name into a file nothing is tracking.
  Two residuals: where a filesystem reports no inode, a replacement whose size and
  timestamp match the original cannot be told from it, and the path is removed by
  name, so a replacement arriving between the comparison and the unlink is
  removed. Node offers no unlink by descriptor to close that.
- **A certificate issued carrying less, or more, than the request asked for.** A
  certification request asks for extensions through the RFC 2985 section 5.4.2
  extensionRequest attribute, and that clause leaves to the issuing CA which of
  them to honor. Both answers are unsafe taken by default. Copying what a request
  asks for lets the requester write its own names, and its own basic constraints,
  into the certificate. Dropping them issues a certificate that does not carry
  what was asked for while reporting success: `pki issue --csr` built its
  extensions from `--san` alone, so a request carrying a subjectAltName produced a
  leaf with none, which matches no host name. `pki issue` now refuses a request
  that asks for extensions until the operator says what to do with them, naming
  what was asked. `--copy-requested-san` writes the requested subjectAltName,
  converting each name through the same builder that validates one given on the
  command line, so a name the builder refuses stops the issuance. A requested name
  of a form that copy does not write is named and refuses the issuance rather than
  being left out of it. `--ignore-requested-extensions` issues without what the
  request asked for. Nothing else a request asks for is copied, so a request
  asking to be certified as a CA is refused rather than honored.
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
- **Signing-key form and bare-name classification are fail-closed.** Every
  signing verb routes its key through one import gate. A WebCrypto `CryptoKey`
  is detected structurally, not by an `instanceof` a cross-realm or
  separately-installed copy would fail, and a public or secret `CryptoKey`, or a
  `node:crypto` KeyObject rather than a WebCrypto `CryptoKey`, is refused with a
  typed fault naming the specific problem rather than a generic one — none of
  these can reach the signer. A `subjectAltName`, or any `GeneralName`, supplied
  as a bare string is classified into exactly one form only when it is
  unambiguous: a string that could be read as more than one form, or as none, is
  refused with a typed `bad-input` rather than guessed into a name the caller did
  not intend, and the explicit object form is always the escape.
- **HPKE keys are bound to the suite they are used under.** `pki.hpke` accepts a
  serialized private key as `{ skm, pkm }` for every KEM through one door: `skm`
  must be exactly the suite's private-key length (an EC scalar additionally in
  `[1, n-1]`, an ML-KEM private key the 64-byte seed), the public key is derived
  from it, and a supplied `pkm` must equal that derivation or the call is refused
  with `hpke/bad-key`. A `node:crypto` KeyObject is checked to be of the suite's
  curve or ML-KEM parameter set, and a public KeyObject where a private one is due
  is refused rather than tried. An ML-KEM encapsulation key is held to the FIPS 203
  sec. 7.2 check at import (length and modulus), an encapsulated key to the
  sec. 7.3 length check before decapsulation, and the auth modes, which the ML-KEM
  KEMs do not define, are refused with `hpke/auth-unsupported` at both ends.
- **A PQ/T hybrid KEM binds both components into one secret.** The MLKEM768-P256,
  MLKEM1024-P384 and MLKEM768-X25519 suites derive the HPKE shared secret from the
  ML-KEM secret and the nominal-group secret together, through the CFRG C2PRI
  combiner, so neither component alone determines it and a break of one does not
  yield the secret. A hybrid private key is the 32-byte seed both component keys
  expand from, and a public key or encapsulated key is the two components
  concatenated at the exact component widths, which differ between the two
  directions: ML-KEM-768 has a 1184-byte encapsulation key and a 1088-byte
  ciphertext. A seed of any other length, a concatenation of any other total
  length, a `pkm` that is not the derivation of the supplied seed, and on
  MLKEM768-P256 and MLKEM1024-P384 a traditional half that is not a point on the
  curve, are each refused with `hpke/bad-key` before any decapsulation runs. On
  MLKEM768-X25519 every 32-byte string is a valid X25519 public key (RFC 7748
  sec. 5), so there is no point check to make; a half that drives the agreement to
  the all-zero output is refused with `hpke/bad-key`. The auth modes are refused
  with `hpke/auth-unsupported` at both ends for the same reason they are for
  ML-KEM. There is no negotiation to a single component and no path that returns a
  secret derived from one of the two.
- **A single-stage HPKE key schedule refuses an input it cannot length-prefix.** The
  SHAKE128 and SHAKE256 KDFs run the one-stage schedule of draft-ietf-hpke-hpke
  sec. 5.1, which feeds `psk`, `psk_id` and `info` to the derive behind a two-byte
  length. Each is therefore capped at 65535 bytes and a longer one is refused with
  `hpke/input-length`, as is an export longer than 65535 with `hpke/export-length`
  (sec. 7.2.1 states the first as a MUST). Truncating a length instead would let a
  sender and a recipient derive different keys from inputs each accepted.
  TurboSHAKE128 and TurboSHAKE256 are registered in the same table and are not
  offered, because no released OpenSSL exposes either XOF; a request for one is
  refused with `hpke/unknown-suite` rather than key-scheduled as if it were HKDF.
- **A width check reads the bytes that will be used, not a length the caller
  states.** A Buffer can carry an own `length` property that differs from its real
  byte count, so `pki.hpke` snapshots every key, seed, encapsulated key, `info`,
  `psk`, `psk_id`, aad and ciphertext a caller supplies before any width or limit
  is read. A value wider than the suite's width is refused with `hpke/bad-key` and
  one over a single-stage KDF's 65535-byte bound with `hpke/input-length`,
  whichever length the caller's object reports. The snapshot also means the bytes
  verified are the bytes used: a caller holding a reference cannot change them
  after the check.
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
  ML-KEM (RFC 9936), the HKDF identifiers (RFC 8619), the ECDSA and DSA signature
  identifiers (RFC 3279 §2.2.2 and §2.2.3, RFC 5758 §3.2), and the SHAKE digests
  and RSASSA-PSS-SHAKE signatures (RFC 8702 §2, §3.1, §3.2) — the single shared
  AlgorithmIdentifier decoder rejects a present parameters field, whether an
  explicit NULL or arbitrary bytes, with a `<format>/bad-algorithm-parameters`
  code (RFC 9909 §3, RFC 9814 §4, RFC 9881 §2, RFC 8410 §3). The check lives in
  the one decoder every format composes, so a certificate, CMS message, OCSP
  response, timestamp, CRL, CSR, or key cannot smuggle unauthenticated bytes past
  a parser through that field, and no format can drift out of the rule. An
  identifier whose specification requires the field PRESENT and NULL, which is
  `rsaEncryption` and every `*WithRSAEncryption` under RFC 4055, is not in the set:
  declaring one there would refuse conforming certificates.
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
  cipher the toolkit runs — CMS content decryption and the password
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
  recomputes a store's classic Appendix B HMAC or PBMAC1 (RFC 9579, obsoleted by
  RFC 9879) over the exact
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
  RSAES-OAEP unwrap fault, an AES-KW integrity-check (A6A6…) mismatch, a PWRI
  check-byte mismatch (RFC 3211, carried forward by RFC 3370), a CBC padding
  fault, an AES-GCM tag mismatch,
  and a content-key length mismatch. The PKCS#1 v1.5 arm is decrypt-only and
  applies the RFC 3218 §2.3.2 implicit-rejection countermeasure: on any v1.5
  fault it substitutes a fresh random content-encryption key and proceeds, so the
  failure surfaces later and uniformly, exactly like every other bad key. v1.5 is
  never emitted. **A candidate the implicit rejection substituted for never
  becomes the answer.** The substitute exists to make the failure cost the same
  work and the same time as a success, not to decide the recipient, so the
  decrypt runs and its result is then discarded. Before this, the content decrypt
  decided it, and a random substitute key leaves a final CBC block that is valid
  PKCS#7 padding about one time in 256, so a known-bad recipient won that often
  and the verb returned the wrong plaintext while naming that recipient as the
  one it used. Padding is the only check a non-AEAD content offers, which is the
  argument for the AEAD default: AES-GCM rejects a wrong content key on the tag,
  at a probability no attacker can ride.

  **RSAES-PKCS1-v1_5 over a content with no integrity tag is refused, and the
  refusal is why the two paragraphs above do not contradict each other.** Those
  two requirements cannot both hold for that combination: discarding a
  substituted candidate's result keeps the plaintext correct and makes acceptance
  depend on whether the unwrap conformed, while letting it stand keeps the arms
  indistinguishable and can return the wrong plaintext. Measured against an
  `openssl cms -encrypt -aes-256-cbc` message, 256 chosen ciphertexts per arm,
  the first gives one acceptance where the unwrap conformed and none where it did
  not. So `pki.cms.decrypt` and `pki.smime.decrypt` refuse the combination with
  `cms/unauthenticated-rsa-v15` **before the unwrap**, which leaves no decision
  for it to influence: zero acceptances on both arms. `allowUnauthenticatedRsa15`
  accepts it knowingly, and reading an `openssl cms -encrypt` or
  `openssl smime -encrypt` message needs that option, since OpenSSL emits exactly
  this combination when no algorithm is named and reports
  `ossl_cipher_unpadblock: bad decrypt` on a wrong key, leaking the same signal
  more loudly. An AEAD content or an RSAES-OAEP recipient needs no option, each
  carrying its own integrity check. Re-encrypting to `aes-256-gcm` removes the
  question. Integrity is verified before any plaintext is released, and a
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
- **Composite (hybrid) KEM.** `pki.kem.encapsulate` and `pki.kem.decapsulate`
  establish a shared secret with a composite ML-KEM key
  (draft-ietf-lamps-pq-composite-kem): a post-quantum ML-KEM paired with a
  traditional RSA-OAEP, ECDH, X25519, or X448. The two component shared secrets
  are mixed through the draft's SHA3-256 combiner, which also binds the
  traditional ciphertext, the traditional public key, and a per-algorithm label,
  so the established secret stays secret as long as EITHER component is unbroken,
  and a ciphertext cannot be re-bound to a different composite algorithm. The
  per-algorithm label bytes are stored as the draft's authoritative values rather
  than derived from the algorithm name, since one label is a non-mnemonic byte
  string. The AlgorithmIdentifier parameters must be absent, an RSA component
  whose modulus does not match the algorithm OID is refused, and a malformed key
  or ciphertext, an unsupported algorithm, or a component decapsulation failure
  fails closed to a typed reason code. The intermediate component secrets and the
  combiner preimage are cleared once the composite secret is derived (draft §3.5).
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

- **An artifact that is signed before anyone asks whether it conforms
  (CWE-1021).** A certificate, request or CRL that violates a MUST of the
  profile it is written to is a misissuance the moment a key touches it, and
  checking afterwards does not undo the signature, the audit-log entry, or the
  hardware token's use counter. `pki.x509.sign`, `pki.csr.sign` and
  `pki.crl.sign` lint the artifact the spec describes against RFC 5280, RFC 2986
  and the RFC 5280 §5 profile respectively, and refuse an error-severity finding
  with a `/profile-violation` code naming the rule and its clause, before the
  signing key is reached. A CRL with no `cRLNumber` cannot be ordered against a
  successor, and one with no `nextUpdate` states no window a replayed copy can be
  told from; both are refused. `opts.profile` names a further profile to hold the
  artifact to at build time, and `opts.profile: "none"` runs no rules, which is
  how a deliberately non-conforming artifact is produced for a test corpus.
- **A name constraint a relying party may ignore (CWE-693).** RFC 5280 fixes the
  criticality of nine certificate extensions, and `nameConstraints` is one it
  requires critical. A verifier that does not recognize an extension marked
  non-critical may ignore it, so a sub-CA issued with a non-critical
  `nameConstraints` is unconstrained in the hands of that verifier.
  `pki.x509.sign` and `pki.csr.sign` refuse a pre-encoded extension carrying a
  criticality the RFC does not permit, in both directions: the six it requires
  non-critical (`authorityKeyIdentifier`, `subjectKeyIdentifier`,
  `subjectDirectoryAttributes`, `freshestCRL`, `authorityInfoAccess`,
  `subjectInfoAccess`) and the three it requires critical (`nameConstraints`,
  `policyConstraints`, `inhibitAnyPolicy`). The CRL and attribute-certificate
  signers hold the same line for the criticality their own profiles fix.
- **A wildcard name escaping an excluded subtree (CWE-295).** An excluded
  `dNSName` subtree states the names a certificate must not present. A wildcard
  subject alternative name is not one name: it stands for every name one label
  below its parent. Compared as literal text, `*.example.com` is not the string
  `bar.example.com`, so an exclusion of `bar.example.com` admitted a certificate
  that presents that very name. The comparison asks whether a wildcard reaches
  into an excluded subtree and refuses it when it does. The permitted direction
  keeps asking the containment question and is not widened, so a permitted base
  must still cover the whole of a wildcard. A wildcard reaches exactly one label,
  so an excluded name below that depth remains out of its reach.
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
  forged chain or forge a CRL or OCSP response. Certificate policies are
  processed as the RFC 9618 `valid_policy_graph`, whose size is linear in the
  policies and mappings on the path where RFC 5280 §6.1's tree was exponential
  in the path length (CVE-2023-0464); the node cap remains and still fails
  closed, now bounding the number of policies a path names rather than growing
  with its length. An invalid
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
- **Signature-timestamp substitution.** A CAdES signature timestamp lives in
  `unsignedAttrs`, which no signature covers, so an attacker reaches it without
  touching a signature. `pki.cms.verify` recomputes the imprint from the signature
  octets it just verified for that signer. A token stamping other bytes (a
  different signer of the same message, an earlier version of it, a signature from
  elsewhere) is a fail-closed row verdict rather than a time the message gets to
  claim. The row carries the authority's trust state separately from the signer's:
  `timestampTrustAnchors` is what makes a timestamp's `trusted` answerable, and
  without it the row reports `valid` with `trusted: false`, which is not evidence
  of when anything happened. Two incoherences are refused as well, both decided
  from the signature the attribute hangs on rather than from the token alone: a
  `genTime` earlier than the `signing-time` the signature itself asserts, and one
  later than the signing certificate's `notAfter`, which is the half of ETSI EN 319
  122-1 clause 6.3 requirement m that certificate bytes can decide. A `genTime`
  that is not a usable instant is refused rather than compared, since an ordering
  test against one answers false in both directions and would pass both rules by
  being uncomparable. A weak-digest imprint is refused by default at both ends, so
  `pki.cms.attachTimestamp` will not write an attribute whose row the verifier
  would then refuse, and the archived-token opt-in is needed at each.
  What a `valid: true` row establishes is narrower than it looks: the token was
  issued over the signature octets that SignerInfo carries. Whether that signature
  is sound is `signers[i].ok`, and the rows are reported beside a failed signature
  rather than withheld, so acting on a timestamp means reading both. The imprint
  names signature octets rather than a signer, which is what clause 5.3 specifies:
  two certificates holding one key produce one signature value over one content,
  and a token over that value answers for either of them.
- **CMS algorithm substitution.** The algorithm identifiers a CMS message names are
  protected only indirectly, and on an authenticated-data message not at all. RFC
  5652 sec. 9.2 makes the MAC input the DER encoding of `authAttrs` alone, so
  `AuthenticatedData.digestAlgorithm` and `macAlgorithm` sit outside it: an attacker
  rewrites the digest algorithm, touches nothing else, and the MAC still verifies
  while the recipient recomputes the content digest under the algorithm the attacker
  chose. That attack needs no key. On a signature the exposure is the parameters: RFC
  8933 sec. 6 notes that RSASSA-PKCS1-v1_5 pins the digest identifier inside the
  signature while RSASSA-PSS does not, and ECDSA, EdDSA, ML-DSA and SLH-DSA carry no
  such identifier either, so the hash, mask generator, salt length and trailer field
  are attacker-selectable fields. `pki.cms.sign`, `pki.cms.countersign` and
  `pki.cms.authenticate` emit the RFC 6211 `CMSAlgorithmProtection` attribute on
  request, which places a copy of those identifiers inside the signed or
  authenticated attributes, and `pki.cms.verify` and `pki.cms.decrypt` compare every
  copy they find against the fields it protects. A disagreement is a refusal with
  `cms/algorithm-protection-mismatch`, never a flag on a verdict, and there is no
  option to turn the comparison off: RFC 6211 sec. 3.1 makes it a MUST for any
  verifier that reads the attribute. Both identifiers the attribute is assigned are
  read, the one RFC 6211 states and the one the IANA registry gives it, because a
  verifier recognizing a single spelling checks nothing on a message that uses the
  other. Emission is off by default and absence is not a failure, since RFC 8933
  sec. 4.1 makes including it a SHOULD and most CMS in the field carries none;
  `requireAlgorithmProtection` makes absence a failure for a profile that needs one.
  A caller-supplied copy that contradicts the identifiers being emitted is refused at
  the signing door, so this toolkit cannot produce a message its own verifier rejects.
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
  not assumed: RFC 5272 §3.2.1.3.4 requires it (that document is obsoleted by
  RFC 10002, which the shipped surface predates). A conforming response carries its
  own signer certificate and is checked against it with nothing asked of the
  caller. Where the signer is found nowhere, verification is fail-closed with a
  named opt-out (`allowUnverified`, which reports `signatureVerified: false`)
  rather than a silent default, so no caller receives a verdict believing a check
  ran that did not. That opt-out covers only "could not check": a signature that
  is present and wrong is always a refusal, and a carrier bearing no signer at
  all is refused. Nothing in the response is trusted, so the certificate bag and
  any Publish Trust Anchors control are surfaced as data for
  `pki.path.validate` rather than added to a store.
- **Forged and unauthenticated SCEP responses.** `pki.scep.parse` verifies the
  outer SignedData signature before it reads a single transaction attribute, and
  refuses a pkiMessage whose signature does not verify (`scep/bad-signature`).
  The transaction state a SCEP client acts on, the messageType, the pkiStatus and
  failInfo of a CertRep, and the sender and recipient nonces, is therefore read
  only from a signer whose signature checked, never surfaced alongside a false
  verdict a caller could mistake for a verified one. The underlying CMS verifier
  returns a per-signer verdict rather than throwing on a bad signature, so the
  refusal is an explicit gate in the SCEP layer rather than an inherited side
  effect. A valid signature is not an authenticated signer, however: it proves
  only that the message is self-consistent with the certificate it embeds, so an
  attacker could mint a certificate and sign a forged CertRep that echoes an
  observed nonce. A client authenticates a CA response against the CA certificate
  it already holds by passing `opts.signerCert`, which refuses a signer whose
  public key does not match (`scep/untrusted-signer`) and reports
  `signerAuthenticated: true`; a caller that omits it receives a crypto-only
  verdict (`signerAuthenticated: false`) and must authenticate the surfaced
  `signerCert` itself before acting on the transaction state. A message carrying
  more than one signer is refused, and passing `expectedSenderNonce` refuses a
  recipientNonce that does not echo the nonce sent (RFC 8894 §3.1, §3.2.1).
  `pki.scep.getNextCACert` authenticates the CA rollover exchange the same way: it
  verifies the response SignedData signature, requires exactly one signer, and
  pins that signer to the current CA certificate the caller passes
  (`caCertificate`), refusing a response signed by any other key
  (`scep/untrusted-signer`). The current CA certificate is required, so the next
  CA certificate a client installs when the current one expires, and would then
  trust as a certification authority, is never returned unless the current CA
  signed for it (RFC 8894 §4.7.1).
- **Enrolling an unprovable request (SCEP).** `pki.scep.build` verifies that the
  PKCS#10 `messageData` is a well-formed CertificationRequest whose self-signature
  is a valid proof-of-possession before it encrypts it, through the same inbound
  check `pki.csr.verify` runs. Arbitrary bytes or a request whose signature does
  not verify under its own subject public key is refused (`scep/bad-input` or
  `scep/bad-popo`) rather than enveloped into a message the CA would reject, the
  same discipline `pki.cmc.build` and `pki.cmp.build` apply to their embedded
  requests (RFC 8894 §3.3.1). The pkcsPKIEnvelope transports the content key
  under RSAES-OAEP, not the Bleichenbacher-vulnerable RSAES-PKCS1-v1_5 that
  legacy SCEP servers historically expect; RFC 8894 does not pin the key-transport
  algorithm, and the toolkit does not emit PKCS1-v1_5 anywhere, so a SCEP CA must
  support OAEP key transport to decrypt a request this builder produces.
- **SCEP CA discovery is fingerprint-pinned and downgrade-resistant.**
  `pki.scep.getCACert` retrieves the CA certificate in the clear, so its only
  authentication is an out-of-band fingerprint. Pass `expectedFingerprint` and a
  returned certificate must hash to it or the response is refused
  (`scep/fingerprint-mismatch`, RFC 8894 §2.2); omitting it returns the certificate
  unauthenticated for the caller to verify. `pki.scep.getCACaps` reports the CA's
  advertised capabilities without lowering the client's algorithm choice on them,
  because the GetCACaps response is unauthenticated (RFC 8894 §7.5); passing
  `expectSCEPStandard` treats the absence of the strong profile as the downgrade
  signal it is and fails closed. `pki.scep.enroll` and `pki.scep.renew` authenticate
  the CA's CertRep against the CA certificate, require its recipientNonce to echo the
  request's fresh senderNonce, and select the issued certificate by public-key match
  rather than by position. The shared-secret authenticator for a first enrollment is
  the `challengePassword` the caller places in the PKCS#10; its strength is the
  operator's to guarantee, and the toolkit neither generates nor stores it.
- **Embedded-request proof-of-possession on the build side (CMC / CMP).** A
  `tcr` request in `pki.cmc.build` and a `p10cr` request in `pki.cmp.build` each
  carry a PKCS#10 CertificationRequest whose self-signature under its own subject
  public key is that request's proof-of-possession (RFC 5272 §6.3; RFC 9810
  §5.3.3, over the PKCS#10 structure of RFC 2986). Both verbs verify that
  signature, through the same inbound check `pki.csr.verify` runs, before the
  enrollment message is signed or protected. A request whose signature does not
  verify is refused with a typed `cmc/bad-popo` or `cmp/bad-popo` error, so a
  caller cannot sign and send a message embedding a request a CA would reject.
  The verdict is awaited through the native promise job rather than a replaceable
  prototype method, so a co-resident cannot force the check to report success.
- **Admissions decided through captured string operations.** A check that lets
  something through decides on the operations this toolkit captured when it
  loaded, not the ones a caller can reassign. That covers the name-constraint
  comparisons behind `pki.path.validate`, the android-safetynet hostname
  requirement in `pki.webauthn.verify`, the private-address classification
  `pki.transport.https` applies under `blockPrivateAddresses` for both address
  families, and the Trust Bits lookup in `pki.trust.parseCcadbCsv` that grants an
  anchor its purposes. Each is tested by replacing the operation it reads and
  asserting the refusal still holds; the replacement in each test is narrowed to
  the one value under test, because replacing an operation for every string stops
  an earlier step and the check never reaches the gate.
- **Signed OCSP request verification (responder side).** `pki.ocsp.verifyRequest`
  lets a responder authenticate a client's signed request (RFC 6960 §4.1.1)
  through the same certification-path signature engine `pki.ocsp.verify` uses for
  a response. The signer is found by verifying, not by assuming a position in the
  request's unordered certificate field, so a chain certificate placed before the
  signer cannot make a valid request read as invalid, and no certificate that did
  not sign is reported as a signer. Every certificate whose key verified is
  surfaced in `signerCerts` (a key may appear under an expired certificate beside
  its renewal), so the responder's trust decision does not depend on ordering.
  `signatureValid` speaks only to the cryptographic check: those certificates are
  surfaced raw for the responder to path-validate, confirm authorized to sign (a
  `keyUsage`, where present, must assert `digitalSignature`, RFC 5280 sec. 4.2.1.3),
  and whose subjects it compares against the identity expected, rather than trusted
  by the verb. The request bytes are snapshotted at entry, so a caller mutating the
  buffer across the asynchronous check is judged on the bytes the parser read, and
  an unsigned request is reported (`signed: false`) rather than refused, since
  RFC 6960 makes the signature optional.
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
  The drop is an explicit override, so a credential configured as a default on the
  transport is suppressed on the cross-origin hop.
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
- **Unauthorized key generation authority (CWE-863).** A CA that generates an end
  entity's key pair centrally delivers it signed by a Key Generation Authority,
  and RFC 9483 §4.1.6 requires that authority's certificate to carry the
  `id-kp-cmKGA` extended key usage "in order to be accepted by the EE as a
  legitimate key generation authority". `pki.cmp.openKeyPackage` reads that as the
  assertion it is. Under RFC 5280 §4.2.1.12 a certificate is constrained by its
  `extendedKeyUsage` only when the extension is present, so a certificate carrying
  none permits every purpose and satisfies a `requiredEku` path constraint while
  saying nothing about key generation; treating the purpose as a path constraint
  alone would let such a certificate deliver a private key. The assertion is
  therefore checked on the signer certificate itself, and the chain is still held
  to `requiredEku` so an issuer whose own extended key usage excludes the purpose
  cannot authorize a leaf that claims it. Both run before any key material is
  returned, as does the signature check and the §4.1.6 shape profile: exactly one
  `RecipientInfo`, so a second party cannot open a key generated for this entity,
  and an `id-ct-KP-aKeyPackage` signed content type, so a `SignedData` the
  authority made over anything else cannot be replayed as a key package. The
  recipient count is read past the `RecipientInfo`: a `KeyAgreeRecipientInfo`
  wraps the content-encryption key once per entry in its `recipientEncryptedKeys`,
  each for a different recipient (RFC 5652 §6.2.2), so one of those carrying two
  entries is two parties and is refused as well. The one
  exemption is the section's own, for an entity that protected its request with a
  shared secret and authorizes by that secret; it is stated explicitly with
  `opts.authorizedBySharedSecret`, applies only to a container opened with that
  secret, and reports `trusted: false`. `pki.cmp.session` refuses a
  server-generated key outright unless `opts.acceptCentralKeyGeneration` is set.
- **Unpaired centrally generated key (CWE-345).** An authority's signature over a
  delivered key package says the package is authentic, and says nothing about
  which certificate the key inside belongs with. A session that accepted the two
  independently would confirm an enrollment whose certificate certifies a key the
  entity does not hold, and would send the `certConf` that accepts it. So
  `pki.cmp.session` holds the delivered private key and the granted certificate to
  each other BEFORE the confirmation leg; a mismatch is `cmp/bad-key-package` and
  the transaction stops. The pair is proven by USING it,
  not by deriving the public half and comparing. A key structure states its own
  public half and the key engine reads what it is told: RFC 5958 §2 gives a
  `OneAsymmetricKey` an optional `publicKey`, an EC key's RFC 5915 `ECPrivateKey`
  carries its own public point, and an RSA private key carries the modulus and
  public exponent outright, so a structure whose private components were replaced
  while its stored public ones were left alone derives to exactly the public key
  planted in it. Instead the two halves perform whichever operation the key type
  can: a signature the public half verifies, a Diffie-Hellman agreement reached
  from both sides, or a key encapsulation the private half decapsulates. The delivered key is what binds
  the grant for such a transaction, in place of the requested public key an
  ordinary enrollment is held to, and the resume token records which of the two
  applies, so a restart cannot drop to neither. The session also requires the
  package to carry exactly one key, the sequence of one §4.1.6 profiles RFC 5958's
  `SIZE (1..MAX)` down to: one grant certifies one key, so a package carrying more
  would hand the entity keys the issued certificate says nothing about.
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

- **A related-certificate proof answers one question, and only that one
  (CWE-347).** RFC 9763 §3.1 signs the DER `IssuerAndSerialNumber` and the DER
  `BinaryTime`, and nothing more. `locationInfo` rides in the same attribute and is
  outside the signature, so a `true` from `pki.relatedCert.verifyRequest` says the
  requester holds the certificate `certID` names and says nothing about the URIs
  beside it: a caller that fetches from `locationInfo` on the strength of that
  verdict is fetching from an unauthenticated field. The verb's vectors assert this
  scope in both directions, that altering `requestTime` breaks the proof and that
  altering `locationInfo` does not. Handing the verb a certificate other than the
  one `certID` names throws rather than returning `false`, because a proof checked
  against an unnamed certificate answers a different question than the one asked.
  The three issuer-side checks §4.1 requires beyond the signature — retrieving and
  path-validating the referenced certificate, judging `requestTime` freshness, and
  confirming the key usages being asserted are present on the related certificate —
  need a fetch and a freshness policy, so they remain the caller's, and
  `pki.path.validate` is the route for the first.

- **A possession statement moves the proof to another key, and says so
  (CWE-347).** RFC 9883 lets a certification request for a key-establishment key be
  signed by a different key, one the requester already holds a certificate for. That
  is a real weakening of what a proof of possession demonstrates, and the toolkit is
  explicit about it rather than quiet. `pki.crmf.verifyPop` reports
  `subjectBound: false` whenever the control is present, however complete the
  template is: the proof demonstrates possession of the SIGNATURE key, and nothing in
  the message demonstrates possession of the requested key, because that key cannot
  sign. What the statement buys a CA is a signature it can attribute to the same
  entity, which is why RFC 9883 §4 then makes path validation of the signature
  certificate a MUST. `pki.possession.verifyRequest` requires `trustAnchors` and
  throws without them rather than returning a verdict that skipped that MUST.
  Accepting a signing key that is not the subject's, and a subject key that cannot
  sign, is scoped to a request that declares the statement; a request without one is
  still held to signing with the key it asks to have certified, and vectors assert
  both refusals still stand.
- **A possession statement's two halves must name one certificate (CWE-347).** The
  statement carries an issuer-and-serial and, optionally, the certificate itself.
  Those could name different certificates, and therefore different keys, while only
  one of them signed the request. `pki.possession.parse` refuses that, on the way in
  and on the way out, so a statement this toolkit emits is one it would accept; the
  builders construct the statement and then read it back through the same reader
  rather than re-checking with a second copy of the rule. A caller supplying the
  certificate for a compact statement is held to the same rule. The two name
  comparisons RFC 9883 states as SHOULDs are deliberately NOT enforced: each ends in
  "the certificate policy MUST describe how the CA can determine that the two subject
  names identify the same entity", so the comparison is reported and `valid` is
  `false` with a reason naming the policy decision. A library that answered that
  question would be inventing a policy the operator owns.
- **An alternative signature is rebuilt from original bytes, not re-serialized
  (CWE-347).** ITU-T X.509 (2019) clause 7.2.2 requires a verifier to reconstruct
  an encoding that never appears on the wire, "re-DER-encoded" after the signature
  component and the `altSignatureValue` extension are removed. The structure it
  names is the `PreTBSCertificate` of
  `draft-truskovsky-lamps-pq-hybrid-x509` section 4, the `tbsCertificate` without
  its `signature` field, and the `PreTBSCertList` of section 5 for a CRL.
  Everywhere else this toolkit surfaces a raw byte range
  rather than rebuilding what it parsed, because rebuilding is how a verifier comes
  to accept something altered in a byte it did not reproduce. Here the specification
  leaves no choice, so `pki.altSig.signedData` keeps the bytes of every component it
  retains and recomputes only the two SEQUENCE headers whose lengths change.
  Nothing is written out of a decoded model: a model that normalized any byte would
  either fail every verification, or accept an encoding the issuer never signed. The
  vectors compare the result against bytes built independently of the implementation,
  field by field, and assert that the extensions block loses that one extension and
  no other.
- **Two signatures, and the native one still covers both (CWE-347).** Clause 7.2.2
  fixes an order: the alternative signature is generated over the structure without
  it, and the native signature is then generated over the structure with it.
  Reversing that leaves a native signature that does not cover the alternative
  signature or the alternative key, so a party reading only the native signature
  would accept a certificate whose alternative half had been substituted.
  `pki.x509.sign` and `pki.crl.sign` perform both passes, so the order is not the
  caller's to arrange, and `altSignatureValue` is computed rather than accepted as an
  option. `pki.altSig.verify` answers one question, whether the issuer's alternative
  key signed the structure; it does not validate a path or read the native signature,
  which `pki.path.validate` does.
- **A certificate identity is not bound with SHA-1 (CWE-328).** The
  `relatedCertificate` extension names a certificate by a digest of the whole
  certificate, which makes that digest an identity to compare against. `sha1` is
  refused by `pki.relatedCert.certificateHash` and `matchesCertificate` even where
  it is what the related certificate's own signature OID indicates, a chosen-prefix
  collision on a certificate being a demonstrated attack rather than a theoretical
  one. A certificate whose signature OID indicates no hash at all, such as one
  signed with Ed25519 or ML-DSA, throws `relatedcert/no-digest` rather than falling
  back to a default the document does not name. A value naming an algorithm this
  build cannot compute, or carrying a digest of the wrong length for the algorithm
  it names, throws rather than reporting no match: a `false` from a comparison
  nobody made reads as a certificate that does not match.

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
- **The destination and the trust material are settled before anything else the
  caller passed is read (CWE-20 / CWE-295 / CWE-367 / CWE-441).** Reading a value
  out of an options object can run the caller's own code, and that code can
  rewrite the options not yet read. Every `pki.ct` verb therefore takes its
  transport, URL and TLS configuration at its entry, before it reads a signed
  tree head's fields, a certificate chain's elements or a header name, and sends
  the request and checks the signature from what it took. Two shapes are refused
  rather than ordered around: `opts.url` must be a string, since asking an object
  for its text form runs the caller's code, and `opts.tls` may not carry an
  accessor, since reading its members has to be inert. Both draw
  `ct/bad-input`. The trust anchors, the client certificate, the client key and
  the pinned log key are copied by value where they are taken, so overwriting the
  bytes a caller still holds does not change what the connection is made under or
  what a tree head is verified against. The parts of a parsed destination, its
  scheme, host, port, path and query, are read through accessors captured at load,
  and the transport reads the scheme once and decides from that one string whether
  the request is allowed, whether a trust anchor is required and which port it
  defaults to.

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
- **Hostname matching against a subject `commonName`.** Name constraints apply to
  the name forms a certificate actually carries, plus the one synthesis RFC 5280
  section 4.2.1.10 requires: an `rfc822Name` constraint applies to an
  `emailAddress` attribute in the subject when the certificate has no subject
  alternative name. A `dNSName` constraint does not apply to a subject
  `commonName`. RFC 9525 section 2 forbids reading a service identity from the
  `commonName` or from any other relative distinguished name, and
  `pki.identity.match` reads neither: it compares your reference identities
  against the subject alternative name and nothing else. Pass the same reference
  identities to `pki.path.validate` as `opts.identity` to have the path verdict
  carry the result.
- **Integrity of state the caller stores between calls.** A `pki.cmp.session`
  `resumeToken` carries no secret, and a resumed poll still verifies, nonce-binds
  and key-binds every response. Its fields are what the resumed exchange is held
  to, so someone who can rewrite the stored token can widen what the resumed
  session accepts, as far as that session's trust anchors and the authority's
  protection allow and no further. Store it where the enrollment's own state is
  stored.

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
and Rekor log keys. It has no dependency tree of its own. The checkpoint carrying
that root is verified under the key the entry names in `logId.keyId`, so with more
than one log pinned a signed tree root from one of them cannot satisfy an entry
claiming another, and the tree size and root the proof folds against are read from
the verified checkpoint rather than from the `inclusionProof` fields no signature
covers. An Ed25519 or Ed448
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
