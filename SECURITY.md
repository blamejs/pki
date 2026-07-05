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
- **Round-trip drift on signed bytes.** `pki.schema.x509.parse` returns the exact
  `tbsBytes` byte range that was signed, so a downstream verifier hashes the bytes
  that were actually signed rather than re-encoding and hoping for round-trip
  fidelity.
- **Supply-chain compromise via transitive deps.** There are zero npm runtime
  dependencies and nothing is vendored — the cryptography runs on Node's built-in
  `node:crypto`, so there is no third-party runtime code, transitive or bundled,
  to compromise. If a library is ever vendored under `lib/vendor/` (only when a
  required operation is confirmed missing from the Node floor), it is pinned by
  SHA-256 in `MANIFEST.json` and a tampered artifact is detectable by
  re-verifying the manifest.

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
