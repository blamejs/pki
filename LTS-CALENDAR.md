# LTS calendar

`@blamejs/pki` ships on a published major cadence. Each major receives **24 months of security-only patches** starting the day the next major is published. Feature backports are not promised.

| Version          | First release | Security patches through   | Node minimum | Signature posture                       |
|------------------|---------------|----------------------------|--------------|-----------------------------------------|
| `v0.x` (pre-1.0) | 2026          | until v1.0 ships           | 24.18        | ML-DSA / SLH-DSA + classical (RSA/ECDSA/EdDSA) signatures via the WebCrypto engine |
| `v1.x`           | TBD           | first release + 24 months  | current LTS  | ML-DSA / SLH-DSA + classical signatures via the WebCrypto engine |

## What "security patches" means

- Critical and high-severity vulnerabilities in the toolkit's own code — parser denial-of-service, verification bypass, a structure that mis-encodes in a way that misrepresents a certificate or message.
- Vendored-dep CVE refreshes (the SECURITY.md commitment applies on the LTS line too).
- Algorithm-registry updates required by NIST / IETF deprecations of an algorithm the toolkit resolves.
- **Not** included: feature backports, performance improvements, or non-security bug fixes. Consumers who want those upgrade to the current major.

## Algorithm posture

The toolkit is post-quantum-first: ML-DSA and SLH-DSA signatures run in the WebCrypto engine alongside the classical RSA / ECDSA / EdDSA set, and every algorithm — classical or post-quantum — is named in the OID registry (`pki.oid`) so a new algorithm is a registry entry rather than a special case. As the structure layer lands, algorithms will resolve by the OID carried in each certificate or message so signatures verify under the identifier in the bytes rather than a single active default; that OID-driven sign/verify dispatch is on the roadmap. When an algorithm is added or deprecated, the change ships as a minor on the current major and this row is updated in the same commit.

## Node minimum policy

The "Node minimum" column is the lowest Node major the toolkit supports for that line. It tracks Node's own active-LTS schedule: a new major adopts whatever Node major is currently the active LTS. Once on the LTS line, the Node minimum is frozen for that major's security-patch window — consumers on the LTS line are not forced onto a newer Node mid-window. Nothing is transpiled, so the supported Node version is exactly the version the source runs on.

## Pre-1.0 caveat

`v0.x` has no LTS commitment. Every release may change something consumers depend on; the algorithm posture and the surface are intentionally evolving. Read [CHANGELOG.md](CHANGELOG.md) before upgrading across more than a few patches at a time. The LTS calendar takes effect at v1.0.

## Experimental primitives are exempt

Primitives documented `@status experimental` (shown as "experimental" on each wiki page) are **not** covered by the stability contract or the LTS window. They may change signature, behavior, or wire format — or be removed — in any minor, without the deprecation cycle that stable primitives get. This applies on the LTS line too. The exemption exists so the toolkit can ship primitives that track in-flight standards (draft RFCs, pre-IANA codepoints, newly published algorithm identifiers) without freezing an unsettled format for a major's full support window. A primitive graduates to stable by dropping the `@status experimental` marker in a release whose notes call out the graduation.

## The status lifecycle is driven, not left to drift

`experimental → stable → deprecated → removed` is enforced by a release gate so a primitive can't sit `experimental` forever by inertia:

- **Graduation criterion.** A primitive becomes `stable` once its governing standard is settled **and** its correctness is proven — through the integration harness against an independent implementation where one exists, or, for a format no mainstream tool implements (RFC 5755 attribute certificates, RFC 4211 CRMF, RFC 9810 CMP, RFC 8951 CsrAttrs), through the toolkit's own conformance-vector round-trip plus coverage-guided fuzzing, since an external harness oracle is unavailable. Requiring a harness oracle that does not exist would keep a settled, well-tested niche format experimental forever. The graduation basis is stated in the release notes. It is not a timer.
- **The timer forces the decision.** After a primitive has shipped `experimental` for several releases, the gate requires an explicit call: either graduate it to `stable`, or record a dated `keep-experimental` decision (with a reason and a future re-review version) in `lifecycle-reviews.json`. Silence fails the release. This is the driver — a conscious decision is recorded every cycle.
- **Deprecation is bounded.** A `deprecated` primitive must declare `@deprecated <remove-by-version>`; the gate fails once that version ships, so a deprecation is actually removed rather than lingering (Hard Rule #6: deprecation warnings ship ≥1 minor before removal).

The gate is `node scripts/check-status-lifecycle.js`, run in the static-gate set on every release.
