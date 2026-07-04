# Threat model

`@blamejs/pki` parses and produces the data structures at the center of
trust decisions — certificates, revocation lists, signed and encrypted
messages, keys. Almost all of its input is **attacker-influenced**: a
certificate arrives from a peer, a signed message from an untrusted
sender, a `.p12` from a user upload. This document states what the
toolkit defends, where the trust boundaries are, the threat classes it is
designed against, and what is explicitly out of scope. It is written for
operators deciding whether and how to rely on the toolkit; the specific
CVEs behind each threat class, with mitigations, are enumerated in
[`ROADMAP.md` → Standards & security references](ROADMAP.md#standards--security-references).

## Assets

- **Verification integrity** — a "valid" verdict (signature, chain,
  revocation status) must be sound. A forged or malformed input must
  never be reported as valid.
- **Availability of the parser** — parsing hostile bytes must terminate
  in bounded time and memory. A crafted input must not hang, exhaust the
  stack, or exhaust memory.
- **Confidentiality of key material** — private keys and derived secrets
  must not leak through error text, timing, or serialization.
- **Supply-chain integrity** — the bytes an operator installs are the
  bytes that were reviewed.

## Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| DER / PEM certificates, CRLs, CSRs, OCSP, CMS, PKCS#12 from the network, disk, or a user | **Untrusted** | Fail-closed parse; strict, canonical decoding; bounded time/memory |
| Trust anchors, verification keys, policy, the check-time clock | **Operator-provided (trusted)** | Taken as configuration; the toolkit never infers trust from the message |
| Node's `node:crypto` / OpenSSL | **Trusted runtime** | The cryptographic engine; the toolkit adds no crypto of its own |
| `@blamejs/pki` package contents | **Trusted after verification** | SSH-signed tags, npm provenance, SBOM (see `SECURITY.md`) |

The governing rule at every boundary: **the message never chooses how it
is verified.** The algorithm, the trust anchor, the policy, and the clock
come from the operator — a certificate cannot nominate its own issuer,
and a signed message cannot nominate its own verification algorithm.

## Threat classes and design response

1. **Parser denial-of-service and memory-safety.** Deeply nested or
   oversized structures, non-canonical lengths, unbounded recursion.
   → The DER decoder enforces hard depth and size caps *before* it walks
   the input, is iterative rather than recursively unbounded, rejects
   indefinite length and non-minimal encodings, and — being memory-safe
   JavaScript — has no buffer overflow or use-after-free surface.

2. **Certification-path and policy bypass / blow-up.** Exponential policy
   trees, a non-CA accepted as an issuer, an advertised check that
   silently does not run. → Path validation (a targeted capability) uses
   a bounded, iterative policy tree; a single authoritative
   `basicConstraints` CA gate that no later step can overwrite; and
   validity-window enforcement that is always on, with the check date an
   explicit input.

3. **Name-constraint / name-confusion bypass.** Embedded NUL or control
   bytes in a name, non-canonical string encodings, CN/SAN confusion.
   → Names are compared by declared length (never NUL-terminated scans),
   non-canonical and control bytes are rejected, and matching is
   SAN-based without a CN fallback.

4. **Signature-verification bypass / forgery.** Bleichenbacher
   PKCS#1 v1.5 forgery, zero/out-of-range ECDSA components ("psychic
   signatures"), algorithm confusion. → Signature verification (a targeted
   capability) applies full structural PKCS#1 v1.5 checks (or PSS by
   preference); rejects ECDSA `r`/`s` outside `[1, n−1]`; and derives the
   verification algorithm from the trusted key and expected
   `AlgorithmIdentifier`, with parameters validated strictly per OID —
   never taken from the message.

5. **Padding oracles.** Observable success/failure of PKCS#1 v1.5
   decryption. → CMS decryption (a targeted capability) uses constant-time
   PKCS#1 v1.5 with implicit rejection and uniform error behavior; RSA-OAEP
   and KEM-based transport preferred.

6. **Post-quantum pitfalls.** KEM decapsulation branching, secret-
   dependent timing, context-string omission, hybrid downgrade. → ML-KEM
   decapsulation (a targeted capability) always runs the re-encryption
   check and returns the implicit-rejection secret on mismatch; PQC
   operations run on the platform's constant-time implementation; ML-DSA
   context binding is explicit; composite verification requires **all**
   components to pass.

7. **Supply-chain.** A compromised dependency or altered release. → Zero
   npm runtime dependencies; a native-first crypto engine that vendors
   nothing (see `lib/vendor/README.md`); SSH-signed release tags, npm
   provenance, and a signed SBOM (see `SECURITY.md`).

## Out of scope

- **Key storage and lifecycle.** The toolkit reads and writes key
  material; it does not manage an HSM, a KMS, or key rotation. Operators
  wire those.
- **Trust-anchor curation.** The set of trusted roots/intermediates and
  the acceptance policy are operator inputs; the toolkit enforces them
  but does not decide them.
- **Transport security.** TLS/network protection of PKI messages in
  flight is the operator's responsibility.
- **Perfect side-channel resistance in a JIT.** Cryptographic operations
  run on the platform (`node:crypto` / OpenSSL); constant-time behavior
  is inherited from the runtime. Timing resistance of the toolkit's own
  non-secret parsing code is best-effort, not a guarantee against a local
  co-resident attacker.
- **Physical and fault attacks.**

## Reporting

Security issues are reported privately — see `SECURITY.md` for the
disclosure process and for verifying release authenticity.
