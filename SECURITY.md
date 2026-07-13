# Security Policy

`@blamejs/pki` is a security-first PKI toolkit. Its defaults are fail-closed: the
DER decoder rejects every non-canonical shape, every verify path throws on
failure, and post-quantum algorithms are first-class registry entries rather than
bolt-ons. This document describes how to report a vulnerability, which versions
are supported, how an operator hardens a deployment that embeds the toolkit, and
how to verify that a release is authentic.

---

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Report privately through GitHub's **["Report a vulnerability"](https://github.com/blamejs/pki/security/advisories/new)**
private advisory form on the repository's Security tab. This opens a private
channel with the maintainers.

Please include:

- Affected version (`v0.X.Y` tag, or the `main` `<sha>` you tested)
- A description of the issue and the impact you observed
- A minimal reproducer — the smallest certificate, DER blob, message, or code
  snippet that triggers the behavior
- Whether you have discussed this with anyone else, and any coordinated-
  disclosure timeline you are working to

Because the toolkit's dominant attack surface is **parsing untrusted bytes**,
reproducers that are raw DER / PEM / message blobs are especially valuable —
attach them (base64 or hex is fine) rather than describing them in prose.

### Response targets

| Severity | First response | Triage / acknowledgment | Fix released |
|---|---|---|---|
| Critical (parser memory-safety, signature-verification bypass, algorithm-substitution accepted) | within 72 h | within 7 d | next patch (≤ 14 d) |
| High (fail-closed guarantee broken, path-validation bypass, canonicalization mismatch) | within 7 d | within 14 d | next patch (≤ 30 d) |
| Medium (unbounded work / DoS on adversarial input, information leak in an error) | within 14 d | within 30 d | next patch |
| Low (defense-in-depth gaps) | within 30 d | as scheduled | next minor |

We coordinate disclosure with the reporter — a typical embargo is 14 days after a
fix is released, to give operators time to upgrade. Reporter credit appears in the
release notes unless anonymity is requested.

---

## Supported versions

Pre-1.0, the supported version is the most-recent published patch on the
most-recent minor. Older minors do not receive security backports unless the issue
is critical and the operator base on the older minor is non-trivial.

Once 1.0 ships, an LTS calendar takes effect: each major gets 24 months of
security-only patches after the next major releases.

| Version range | Security patches |
|---|---|
| Latest `v0.x` minor — current patch line | yes |
| Older `v0.x` patch lines | no |

---

## What the toolkit defends, by design

- **Adversarial DER / PEM crashing the parser.** The decoder enforces size and
  depth caps before it walks a structure, and rejects every non-canonical shape —
  indefinite length, non-minimal length or tag encodings, constructed strings
  where DER forbids them, and trailing bytes after the top-level value — with a
  typed `Asn1Error`. Malformed input is bounded work with a permanent verdict, not
  a stack overflow or a half-parsed object.
- **Adversarial CBOR crashing the parser.** The `pki.cbor` decoder applies the
  same posture to RFC 8949 core-deterministic CBOR: size, depth, and per-bignum
  byte caps before the walk, and a typed `CborError` on every non-canonical shape
  — an indefinite length, a non-minimal (preferred) argument, out-of-order or
  duplicate map keys, a non-shortest or non-canonical-NaN float, ill-formed UTF-8,
  or trailing bytes. There is no lenient mode.
- **Single-input string-allocation amplification.** Every boundary that decodes
  untrusted bytes to a string — PEM armor, a JOSE / ACME JSON document, an EST
  transfer or multipart body — enforces its size cap on the raw byte length
  BEFORE materializing the string, so an oversized input is rejected before it
  allocates a full-size string (and a body above Node's maximum string length
  fails typed rather than escaping as an untyped `ERR_STRING_TOO_LONG`). A
  detached-backed input (a transferred / structuredClone'd view whose bytes are
  gone, so it reads as zero-length) fails closed with a typed error at the byte
  boundary instead of being processed as empty.
- **Encoding malleability.** Every textual encoding an operator hands the
  toolkit — base64url (JOSE / JWK key material), base64 (PEM bodies, EST
  transfer), hex, a JSON document, a dotted-decimal OID string — is decoded
  strictly against its one canonical form: a padded or non-canonical base64url
  `k`, a JSON document with a duplicate member at any depth, or an OID string
  with a leading-zero arc (which encodes a DIFFERENT OID than the string names)
  fails typed instead of aliasing a second spelling of the same value past a
  verifier. JSON parsing is bounded in size and nesting and assigns `__proto__`
  as an own property, never a prototype mutation.
- **Decode-fanout and verify-fanout amplification.** A decoded input's element
  count is capped independently of its byte size (`asn1/too-many-items`,
  `cbor/*`, per-list PKCS#12 caps), and an OCSP response is capped in embedded
  certificates before any pre-authentication signature work, so a small hostile
  input cannot fan out into unbounded allocations or unbounded asymmetric-verify
  work.
- **Stateful-signature key reuse and downgrade.** `pki.shbs` verifies HSS/LMS
  signatures (RFC 8554) but deliberately NEVER signs: stateful hash-based signing
  requires a one-time-key index whose state must advance atomically across every
  signature and every restart, and a single reuse can leak enough material to
  forge, so SP 800-208 confines signing to hardware. Verification is pure
  public-input hashing (no secret, no side-channel), the public key is the sole
  authority for every parameter set (a signature whose typecode disagrees with
  the key cannot verify against it -- a downgrade defense), an HSS hierarchy
  accepts only if EVERY level verifies, and every field length is bounds-checked
  before it is read; an unapproved or unknown typecode, a truncated blob, or a
  hostile level count fails closed with a typed error rather than an unbounded
  loop or an out-of-bounds read.
- **Composite (hybrid) signature downgrade.** `pki.path.validate` verifies
  composite ML-DSA signatures (draft-ietf-lamps-pq-composite-sigs) — a post-quantum
  ML-DSA paired with a traditional RSA / ECDSA / EdDSA — by reconstructing the
  domain-separated message representative and verifying the two components
  independently, accepting the certificate (or CRL / OCSP response) ONLY when
  **both** pass. A single-component accept would be the exact downgrade the
  construction exists to prevent: it would let an adversary who breaks either the
  post-quantum or the classical primitive forge a signature the other component
  should still reject. The public-key algorithm OID is bound to the signature OID
  (algorithm-confusion defense), the AlgorithmIdentifier parameters MUST be absent,
  and an arm whose curve or pre-hash the crypto engine cannot reach fails closed to
  a typed reason code rather than silently skipping its check.
- **Merkle proof forgery.** `pki.merkle` verifies RFC 6962 / RFC 9162 inclusion
  and consistency proofs fail-closed: the leaf (`0x00`) and node (`0x01`)
  domain-separation prefixes stop the second-preimage swap, a proof whose node
  count does not match the tree geometry is a typed reject (never a best-effort
  fold), consistency reconstructs BOTH roots so a rewritten history is caught on
  the old-root leg, and the root comparison is constant-time. The only Boolean
  `false` is an honest root non-match; every malformed input throws.
- **WebAuthn credential-key confusion.** `pki.webauthn` binds a credential COSE
  key to its declared algorithm and curve (an EdDSA key claiming ES256, or the
  legacy `-8` identifier carrying Ed448 rather than Ed25519, is rejected), and
  validates the public-key point on its curve so an off-curve or identity point
  fails closed at decode instead of reaching a verify step where an invalid-curve
  attack could apply. The EC point must be uncompressed, the COSE key exactly its
  canonical CTAP2 parameter set, and an ECDSA attestation signature a
  minimally-encoded DER `ECDSA-Sig-Value` — a non-minimal, negative, zero, or
  over-size `r`/`s` is a typed reject, never normalized-and-accepted.
- **WebCrypto import algorithm confusion + raw cipher faults.** `pki.webcrypto`
  derives an imported asymmetric key's type from the key material, not the
  caller's claim: an RSA key imported under an Ed25519 / ECDSA / RSA-PSS name is a
  `webcrypto/data` reject, so a mislabeled `CryptoKey` cannot later sign or verify
  under the wrong scheme. Every AES cipher fault fails closed with a typed
  `webcrypto/operation` — a tampered AES-GCM authentication tag, bad AES-CBC
  padding, a non-conforming AES-KW wrap length — rather than leaking a raw Node
  exception across the API boundary. A raw or JWK AES key of an invalid length
  (not 128, 192, or 256 bits) is rejected as a `webcrypto/data` DataError at
  import, closing the gap where the failure was deferred to first use.
- **Trust-anchor misuse and revocation-scope confusion.** A `pki.trust` anchor
  carries the root program's own constraints and `pki.path.validate` enforces
  them: a leaf issued after the root's per-purpose distrust date, or a purpose
  the root was never a trusted delegator for, fails closed. Trust metadata pairs
  to its certificate by byte-exact issuer + serial and is cross-checked against
  the parsed DER, so a crafted store cannot attach one root's permissions to
  another. A partitioned CRL establishes non-revocation ONLY for the shard whose
  issuing-distribution-point name corresponds byte-identically to the
  certificate's own distribution point with no reason restriction — a
  non-corresponding, reason-scoped, non-critical-IDP, or delta shard stays
  revocation-only, and a listed serial reports revoked regardless.
- **Container nesting and amplification (PKCS#12).** A PFX chains fresh encoded
  blobs inside octet strings, where every re-decode would restart the depth cap
  from zero; the PKCS#12 parser carries one cross-decode budget over all of them
  and caps element counts at each list, so a crafted store fails typed
  (`pkcs12/too-deep`, `pkcs12/too-many-elements`) instead of exhausting the
  stack or memory. Its BER acceptance is scoped to exactly the two shapes
  RFC 7292 §4.1 requires (indefinite lengths, constructed octet strings) and
  only for that format — every other format and every other DER strictness
  verdict is unchanged.
- **Algorithm-substitution.** Every algorithm, attribute, and extension is named
  in an OID registry (`pki.oid`), so a structure's algorithm identifiers resolve
  to a known name rather than being trusted blindly. OID-driven sign/verify
  resolution — deriving the verification algorithm from the trusted key and the
  expected `AlgorithmIdentifier` so a structure cannot smuggle in a weaker or
  unexpected algorithm by naming a different OID — rides this registry and lands
  with the signing surface.
- **Silent verification failure.** Every verify and parse path throws on failure.
  No path returns zero, a default, or partial output in place of a real result, so
  a caller cannot mistake an error for a pass.
- **Certification-path validation bypass.** `pki.path.validate` enforces the
  RFC 5280 §6 algorithm fail-closed: the basic-constraints CA check is the single
  authoritative gate that no later check can overwrite (CVE-2021-3450); the
  signature algorithm is derived from the certificate and the issuer key, never a
  message-selected field (CVE-2015-9235); ECDSA signatures with a component
  outside `[1, n−1]` — including the all-zero forgery — are rejected
  (CVE-2022-21449); the certificate-policy tree carries a hard node cap and fails
  closed at it (CVE-2023-0464), and an invalid policy OID is surfaced, never
  silently dropped (CVE-2023-0465); name comparison rejects embedded NUL and
  control bytes so a truncated name cannot compare equal (CVE-2009-2408); and an
  unknown critical extension or an undetermined revocation status terminates the
  path with a typed reason code rather than passing. Post-quantum SLH-DSA
  signatures (all twelve FIPS 205 parameter sets) verify on this path over the
  exact signed bytes, alongside ML-DSA and the classical set.
- **OCSP response forgery.** `pki.path.ocspChecker` treats a response as
  authoritative only when it is signed by an authorized responder — the issuing
  CA directly, or a certificate that same CA issued bearing id-kp-OCSPSigning in
  its extendedKeyUsage (RFC 6960 §4.2.2.2). An ordinary leaf the CA issued, an
  `anyExtendedKeyUsage` certificate, a certificate from a different CA, an expired
  responder, or one whose keyUsage forbids digitalSignature cannot sign a status.
  A delegated responder must also carry id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1)
  — the CA's statement that it vouches for the responder for its certificate
  lifetime — and any critical extension on the responder certificate must be
  recognized and well-formed; otherwise the checker cannot confirm the responder
  itself is unrevoked and fails closed, so a revoked responder cannot keep signing. The response must also bind to the
  certificate under test through the full CertID triple, with `issuerNameHash`
  and `issuerKeyHash` recomputed under the CertID's own hash algorithm, so a
  `good` for one issuer's serial cannot be replayed to answer for another
  issuer's same serial. A missing or passed `nextUpdate`, an unauthorized
  responder, or any signature-verification failure yields an undetermined status
  that fails the path closed.
- **Algorithm-parameter confusion.** For the algorithms whose `parameters` field
  MUST be absent — ML-DSA, SLH-DSA, the RFC 8410 Edwards/Montgomery curves,
  ML-KEM (RFC 9936), and the HKDF identifiers (RFC 8619) — the single shared
  AlgorithmIdentifier decoder rejects a present parameters field (an explicit
  NULL or arbitrary bytes) fail-closed with a
  `<format>/bad-algorithm-parameters` code (RFC 9909 §3, RFC 9814 §4, RFC 9881
  §2, RFC 8410 §3). The check lives in the one decoder every format composes, so
  a certificate, CMS message, OCSP response, timestamp, CRL, CSR, or key cannot
  smuggle unauthenticated bytes past a parser through that field, and no format
  can drift out of the rule.
- **EST enrollment-response confusion.** The `pki.est` client codecs are
  fail-closed over hostile server output: the RFC 8951 base64 transfer decode is
  bounded before and after decoding and never reads a Content-Transfer-Encoding
  header (the class of errata 5904/5107); the `multipart/mixed` splitter requires
  the terminal boundary and rejects nested/extra parts; the certs-only validator
  rejects any response that is not an empty-signerInfos, no-eContent SignedData
  of plain X.509 certificates, and the serverkeygen validator enforces the
  request-to-response recipient-arm coherence. The issued certificate is picked
  by a public-key match (`findIssuedCert`), never a positional guess (RFC 5272
  forbids assuming an order).
- **JWS algorithm confusion and JSON smuggling (ACME).** The `pki.jose` layer
  binds every `alg` to its key type in a registry, so the classic JWS attacks
  have no code path: there is no `none` row (CVE-2015-9235), the HMAC algorithms
  exist only in the External Account Binding profile so an `RS256`→`HS256` key
  confusion cannot resolve (CVE-2016-10555), signature lengths are pinned before
  any crypto call, and an all-zero ECDSA signature is refused (CVE-2022-21449).
  The base64url codec rejects padding, non-alphabet bytes, and non-canonical
  trailing bits (RFC 8555 §6.1), and the JSON reader rejects a duplicate member
  at any nesting depth (the parser-differential smuggling class, CVE-2017-12635)
  under hard size and depth caps. `pki.acme` carries the protocol MUSTs
  fail-closed: a finalize CSR whose public key is the account key is rejected
  (RFC 8555 §11.1), a `mailto` contact with header fields or multiple addresses
  is refused rather than guessed, a tls-alpn-01 validation certificate must carry
  a critical `id-pe-acmeIdentifier` with a 32-octet Authorization and a
  single-entry SubjectAltName (RFC 8737), a wildcard is one leading label on a
  `dns` identifier only, and the ARI certID preserves the serial's DER
  sign-padding byte so it matches what the CA computes (RFC 9773).
- **AEAD-parameter tampering (CMS AuthEnvelopedData).** A recognized AES-GCM/CCM
  content-encryption algorithm must carry its RFC 5084 parameters: the nonce is
  bounds-checked (CCM 7..13 octets), the ICV length must come from the RFC's
  allowed set and equal the length of the `mac` field, and an ICV length encoded
  equal to its DEFAULT is rejected as non-canonical DER (X.690 §11.5) — so a
  message cannot shrink its own integrity tag or desynchronize the tag length a
  verifier checks from the one the structure claims.
- **Round-trip drift on signed bytes.** `pki.schema.x509.parse` returns the exact
  `tbsBytes` byte range that was signed, so a downstream verifier hashes the bytes
  that were actually signed rather than re-encoding and hoping for round-trip
  fidelity. The same discipline covers the CMP message-protection input:
  `pki.schema.cmp.parse` surfaces the exact `headerBytes` and `bodyBytes` wire
  slices so a verifier reconstructs the protected part from the bytes that were
  actually protected, never a re-encoding; and CMP `caPubs` are surfaced as raw
  certificates conferring no trust, so a client cannot be steered into installing
  a trust anchor from an unauthenticated response. `pki.ct.parseSctList` follows
  the same rule for Certificate Transparency: it decodes the SCT-list structure
  but never verifies a signature or recomputes a log id, and
  `pki.ct.reconstructSignedData` rebuilds the exact RFC 6962 digitally-signed
  preimage from the parsed bytes so the log-signature check runs on what was
  actually signed. The TLS-encoded list itself is decoded with a bounded reader
  that validates every framing length and caps the per-list byte size and SCT
  count before iterating, so a crafted SCT extension is bounded work with a typed
  `ct/*` verdict rather than unbounded work inside a certificate extension.
  `pki.schema.smime` decodes the ESS signing-certificate attributes the same way:
  it surfaces the certificate hash, the (implied or decoded) hash algorithm, and
  the issuer/serial reference raw so a verifier recomputes the hash and matches
  the binding against the actual signing certificate — it never recomputes a hash
  or trusts a certificate — and it rejects a `SigningCertificateV2` hash algorithm
  encoded equal to its DEFAULT as non-canonical DER, closing an
  encode-ambiguity a signature check would otherwise have to tolerate.
- **Attestation-key substitution (WebAuthn).** `pki.webauthn.verify` binds every
  attestation to the credential being registered, by the mechanism each format
  defines. For **packed** and **fido-u2f** the attestation signature covers the
  `authenticatorData` (fido-u2f's signed `verificationData` embeds the credential
  key explicitly), so a signature that verifies is a signature over that exact
  credential key. For **android-key**, **apple**, and **tpm** the attestation
  certificate — or, for tpm, the `pubArea` — public key is additionally required to
  equal the credential public key: an unsigned-integer comparison for EC and RSA
  coordinates (so a leading-zero re-encoding cannot desynchronize it) and a
  byte-exact comparison for a fixed-width Ed25519 key, with the tpm `pubArea` key
  also bound to the `certInfo` TPM Name it certifies. The apple nonce must equal the
  SHA-256 over `authenticatorData || clientDataHash`, and the android
  attestation-challenge must equal the `clientDataHash` — so an attacker cannot pair
  a valid attestation over one key with a different credential. The attestation
  object and COSE keys are decoded by the strict `pki.cbor` codec and the TPM
  structures by a bounds-before-slice reader, and every failed check throws a typed
  `webauthn/*` error — a signature that does not verify is a verdict, never a silent
  pass. RS1 (SHA-1) is accepted for verifying the legacy TPM authenticators that emit it, never
  for signing.
- **CMS SignedData preimage substitution.** `pki.cms.verify` checks a SignedData
  signature over the exact bytes RFC 5652 §5.4 defines, never a re-derived copy. When
  signed attributes are present, the message-digest attribute must equal the digest of
  the content *and* the signature is verified over the DER re-encoding of the
  SignedAttributes (the on-wire `[0]` implicit tag replaced by the universal SET OF the
  standard requires) — so an attacker can neither swap the content out from under a set
  of signed attributes nor strip the attributes and present a signature made over them
  as one made over the content. Each parameter comes from the structure that owns it —
  the content digest from the digestAlgorithm, the signature scheme from the signer's
  own key algorithm — so a signer cannot claim one algorithm while the key implies
  another. Those signed attributes are decoded from the exact bytes the signature covers,
  not from a parsed representation a caller could mutate independently, so a supplied
  parsed object cannot desynchronize the checked attributes from the verified preimage.
  An EdDSA signer key is validated on-curve and full-order before verification — a
  low-order Ed25519/Ed448 point, which `node:crypto` imports without complaint and which
  can verify a forged signature, is rejected. A false verdict or an unresolved parameter
  is a fail-closed `cms/*` outcome, never a silent pass; the signer certificate is located
  but deliberately not chained to a trust anchor, which remains the caller's explicit
  `pki.path.validate` step.
- **Supply-chain compromise via transitive deps.** There are zero npm runtime
  dependencies and nothing is vendored — the cryptography runs on Node's built-in
  `node:crypto`, so there is no third-party runtime code, transitive or bundled,
  to compromise. If a library is ever vendored under `lib/vendor/` (only when a
  required operation is confirmed missing from the Node floor), it is pinned by
  SHA-256 in `MANIFEST.json` and a tampered artifact is detectable by
  re-verifying the manifest. The acquisition path is verified too: repository
  tooling (the fuzz build, the vendoring flow) installs npm packages only
  through integrity-pinned lockfiles (`npm ci`, install scripts disabled), so
  a registry-served substitute fails the integrity check before a byte of it
  runs.

## Operator hardening checklist

The toolkit fails closed by default; the items below are what an operator embedding
it is responsible for.

- [ ] **Treat every input as untrusted.** Parse certificates, messages, and keys
      that arrive from the network or from users through the shipped `pki.*` parse
      entry points — never by hand-walking a node tree past the codec's checks.
- [ ] **Keep the size and depth caps sane for your context.** The defaults
      (`C.LIMITS.DER_MAX_BYTES`, `C.LIMITS.DER_MAX_DEPTH`) bound adversarial input.
      If you raise them for a legitimately large structure, raise them only for the
      call that needs it — do not lift the ceiling globally.
- [ ] **Enforce the validity window.** When you evaluate a certificate, check
      `validity.notBefore` / `validity.notAfter` against your check time. A parsed
      certificate is not a valid one.
- [ ] **Pin your trust anchors explicitly.** Validate chains only against a trust
      anchor set you control. Never treat a certificate's own asserted issuer,
      self-signature, or embedded chain as trust.
- [ ] **Compare the signed bytes, not a re-derived copy.** When verifying a
      signature, hash the `tbsBytes` the parser returns — do not re-encode the
      parsed fields and sign/verify over the re-encoding.
- [ ] **Fail closed on unknown critical extensions.** When you build certificate
      handling on top of the parser, refuse a certificate whose `extensions` list
      carries a `critical: true` extension you do not understand.
- [ ] **Prefer the post-quantum or hybrid option** where your peers support it.
      Post-quantum ML-DSA and SLH-DSA signatures are available today alongside
      the classical set (with ML-KEM key generation shipped and KEM
      encapsulation on the roadmap); choose them rather than defaulting to
      classical-only.
- [ ] **Verify release authenticity before deploying** (below), and re-verify the
      vendored `MANIFEST.json` if you fork or re-package the toolkit.

## What the toolkit does not defend against (operator responsibility)

- **Trust-policy decisions.** Which roots you trust, which key usages you require,
  which name constraints you enforce, and how you handle revocation are policy the
  toolkit gives you the primitives for — it does not choose them for you.
- **Private-key storage.** Protecting private-key material at rest and in memory
  (HSM, OS keystore, sealed storage) is out of scope. The toolkit reads and writes
  key structures; it does not custody your keys.
- **Clock integrity.** Validity-window and timestamp checks are only as trustworthy
  as the clock you pass in. Sourcing a trusted time is the operator's job.
- **Randomness quality for key generation.** Key and nonce generation draw on the
  host's CSPRNG; a compromised host RNG is out of scope.
- **Application-layer misuse.** Calling a parse entry point and then ignoring the
  thrown error, or trusting a field the toolkit surfaced but the operator never
  validated, defeats the fail-closed design.

---

## Verifying release authenticity

Release tags are annotated and SSH-signed, and published tarballs carry provenance
and an SBOM. Verify before deploying.

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

The same provenance bundle can be verified offline with the toolkit itself —
`pki.sigstore.verifyBundle` checks the DSSE signature, the Fulcio chain as of the
Rekor log time, the RFC 9162 inclusion proof against a Rekor-signed root, and the
in-toto SLSA subject digest, against trust material you pin (the Fulcio CA roots
and Rekor log keys), with no dependency tree of its own. Confirm a returned
`subjects[].digest` matches the tarball you install.

### SBOM

Each release ships a CycloneDX SBOM (`sbom.cdx.json`). Because the toolkit
vendors nothing today, the component set is empty by design; match it against the
shipped `lib/vendor/MANIFEST.json` (an empty `packages` map) to confirm the
release adds no third-party runtime code. If a library is ever vendored, it
appears in both.

---

## Coordinated disclosure

We follow coordinated vulnerability disclosure. If you are a downstream
distributor and need embargoed advance notice of a fix, say so in your private
report and we will coordinate a shared timeline.
