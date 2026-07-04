# Contributing to @blamejs/pki

Thanks for considering a contribution. `@blamejs/pki` is a pure-JavaScript PKI toolkit with strong stylistic and architectural defaults — this doc is the guide to making your patch land cleanly. The public site is [pkijs.com](https://pkijs.com).

## Quick links

- **Found a bug?** Open an issue with the bug-report template. For security bugs, **don't** open a public issue — see [SECURITY.md](SECURITY.md).
- **Have a feature idea?** Open a feature-request issue first to discuss the design before writing code. See "Ship complete, not incremental" below for why this matters, and check [ROADMAP.md](ROADMAP.md) for what is already targeted.
- **Want to ship a fix?** Read [Development setup](#development-setup), [House rules](#house-rules), and [The PR loop](#the-pr-loop) below.

## Development setup

```bash
# 1. Clone + install (zero npm runtime deps; this only fetches dev tools)
git clone https://github.com/blamejs/pki.git
cd pki
npm install --no-package-lock

# 2. Run the full test suite
node test/smoke.js

# 3. Run the wiki example app's e2e (boots the docs site on an ephemeral port)
cd examples/wiki && rm -rf data data-e2e && node test/e2e.js && cd ../..

# 4. Run the static gates (CI runs all of them)
npx eslint@latest --max-warnings 0 .
node test/layer-0-primitives/codebase-patterns.test.js
node scripts/validate-source-comment-blocks.js
node scripts/check-api-snapshot.js
shellcheck $(git ls-files '*.sh')

# 5. Interop integration — bring up the cross-tool fixture stack and validate
#    against independent implementations (OpenSSL / NSS and, for PKCS#12,
#    Windows CAPI / macOS Keychain). Required when a wire format changes.
docker compose -f docker-compose.test.yml up -d --wait
node scripts/test-integration.js
docker compose -f docker-compose.test.yml down -v
```

**Requirements:** Node.js 24.18 or newer. The toolkit runs on Node's crypto primitives as shipped and targets recent built-ins; older runtimes are out of scope. Nothing is transpiled — what ships is what runs.

## House rules

These are the project's hard rules. Patches that violate them get bounced regardless of how clean the code is.

### Zero npm runtime dependencies

The toolkit ships zero npm runtime dependencies and currently vendors nothing — the cryptography runs on Node's built-in `node:crypto` (classical and FIPS post-quantum). Any library that ever becomes a runtime dependency is vendored under `lib/vendor/` with a `MANIFEST.json` pinning version + license + SHA-256, so consumers audit from the manifest, not from `node_modules`.

If you think you need a new external library:

1. **First, check if you really need it.** The toolkit reaches for stdlib + Node's `node:crypto` first — which already covers the full classical and post-quantum algorithm set. A dependency is the last resort.
2. If the answer is yes, vendor it (bundle, copy to `lib/vendor/`, pin in the manifest, remove the npm package itself). Document why in the commit message. Reviewers will push back hard.

### Post-quantum-first crypto

Algorithms resolve through the OID-keyed registry (OID → parameters → key import → sign/verify), never a hardcoded switch. ML-DSA / ML-KEM / SLH-DSA are registry entries alongside the classical set — not bolt-ons. Don't introduce a classical-only default where a post-quantum or hybrid option exists. A new signature or KEM algorithm is a data row plus a signer, not a special case in a parser.

### Fail closed

The DER decoder rejects every non-DER shape — indefinite length, non-minimal encodings, trailing bytes, constructed strings — and enforces size and depth caps before it walks a byte. Every verify path throws on failure; no path returns zero, a default, or partial output in place of a real verdict. Malformed untrusted input surfaces as a typed `PkiError` carrying a stable `domain/reason` code. A default that accepts-on-error is a bug, not an ergonomic.

### Standards are the contract

Every structure maps to a named RFC. Encode is canonical DER; decode is strict; a valid input round-trips to identical bytes. A single structure definition drives both encode and decode so EXPLICIT/IMPLICIT context-tag handling can't diverge between the two directions — don't hand-roll a decoder and a separate encoder for the same structure.

### Code style

- **CommonJS only.** `require()` / `module.exports`. No ES module syntax in `lib/`. (The eslint config and workflow files are the documented exceptions — `.mjs` / `.yml`.)
- **`var` declarations.** Not `let` / `const`. Consistent with the rest of the codebase.
- **No TypeScript, no transpilation.** What ships is what runs. Consumers read the same source the runtime executes. This is the explicit design separator from upstream PKI.js.
- **Every `.js` file starts exactly** with the SPDX line, the copyright line, and `"use strict";` — in that order.
- **Top-of-file `require()`s.** Inline requires only for documented circular-dependency cases, with a comment explaining why.
- **Use toolkit primitives over raw literals.** `C.TIME.*` / `C.BYTES.*` and the shared bounds in `lib/constants.js`, not open-coded arithmetic. Constant-time comparison for anything security-sensitive, never `a === b`.
- **Source files are pure ASCII.** No attack characters or non-ASCII literals in `lib/`.

### Ship complete, not incremental

Every primitive is designed for completion from the start — not "minimum viable" with key features deferred to a follow-up. Before submitting a feature PR, list the full surface in the issue's design discussion, re-deriving it from the governing RFC: every algorithm the RFC lists, every recipient / signer variant, every documented failure mode. What's in, what's out, and why each "out" is a complete decision rather than a deferred bullet.

If a slice genuinely shouldn't be in the first release (real ROI question, escape hatch exists, no demand), say so explicitly. "Defer with re-open conditions" is a complete answer; "future patch" is not.

### Interop is a coverage axis, not an afterthought

A structure the toolkit emits must round-trip through an independent implementation — OpenSSL or NSS, and for PKCS#12 also Windows CAPI and macOS Keychain — not just through our own decoder. A parser that only satisfies our own encoder is only half-tested. New wire format → the interop harness gains a case in the same PR.

### Test coverage

The test suite is layered; the smoke runner walks every layer in dependency order (primitives first, consumers last):

- `test/layer-0-primitives/` — pure-function primitives: the codec, the OID registry, the certificate model, error types. No network, no external tools.
- Higher layers — structure composition and end-to-end parse/build/sign/verify flows.
- `test/smoke.js` — the single entry point; prints `CHECKS <n>` on success, exits non-zero on any failure.
- `examples/wiki/test/e2e.js` — the docs site exercised over real HTTP.

A new primitive lands with at least layer-0 tests. Each test file exports `run()` (sync or async), has a CLI entry that prints `CHECKS <n>` on success and exits `1` on failure, and requires `../helpers` for `check` / `waitUntil` / `vectors` rather than rolling its own mocks. Follow the shape in `test/layer-0-primitives/asn1-der.test.js`.

New behavior lands with a test that **reproduces the failure first** (red on the current tree, green on the fix), driving the real consumer path (`pki.x509.parse(pem)`, not a hand-decoded node tree) with the adversarial or malformed input that triggers it. Root-cause the whole class the bug samples, not just the one input.

## Developer Certificate of Origin (DCO)

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/). By adding a `Signed-off-by` line to each commit you certify that you wrote the patch — or otherwise have the right to submit it — under the project's Apache-2.0 license. Sign off with `git commit -s` (which appends `Signed-off-by: Your Name <you@example.com>`); the sign-off must match the commit author.

## The PR loop

1. **Open an issue first** for non-trivial work — design discussion catches scope problems before code is written. Trivial fixes (typos, doc tweaks, single-line bug fixes) can skip the issue.
2. **Branch off `main`.** Branch name doesn't matter; we squash on merge.
3. **One concern per PR.** A new primitive + its tests + its wiki docs is one PR. A new primitive + an unrelated lint cleanup is two.
4. **Fail-loud verification before push:**
   - `node test/smoke.js` ends with `CHECKS <n>` and a count no lower than the previous release.
   - `cd examples/wiki && rm -rf data data-e2e && node test/e2e.js` passes.
   - `npx eslint@latest --max-warnings 0 .` exits 0.
   - `node test/layer-0-primitives/codebase-patterns.test.js` exits 0 — the structural-drift and discipline detectors are clean.
   - `node scripts/validate-source-comment-blocks.js` exits 0 — every `@module` / `@primitive` block is well-formed (the wiki at pkijs.com is generated from these blocks).
   - `node scripts/check-api-snapshot.js` exits 0 — guards the public API surface against accidental breaking changes. Intentional surface changes regenerate the baseline (`node scripts/refresh-api-snapshot.js`) and commit `api-snapshot.json` alongside the change.
   - `shellcheck $(git ls-files '*.sh')` exits 0 — every tracked shell script parses clean.
   - **Interop gate** — when the diff changes a wire format (a structure the toolkit encodes or decodes), bring up the fixture stack and run `node scripts/test-integration.js` so an independent implementation validates the bytes. This catches divergences a self-round-trip can't.
   - `npm run fuzz` — clean. The DER decoder is the primary fuzz target; a new parser adds a fuzz harness in the same ship.
5. **Commit message style:** lowercase imperative. The first line is a one-sentence summary; the body explains *why* and *what tradeoff*, cites the governing RFC / CVE, and carries no internal-process narrative (no phase / pass / batch vocabulary, no "modeled on X", no "all tests passing").
6. **Open the PR.** Wait for CI green via `gh pr checks --watch`.
7. **Review feedback** focuses on:
   - Does this match the toolkit's existing patterns? (Did you sweep internals for one-off code the new primitive replaces?)
   - Is malformed input a loud, typed failure — not a silent default?
   - Does a structure the toolkit emits interoperate with an independent implementation?
   - Does the patch ship complete, or leave a "future" bullet behind?

## What to contribute

**New here?** Issues labeled `good first issue` are deliberately scoped small — a doc or wiki-example fix, a test for an uncovered branch, an error message that could better say what to do next. Pick one, comment that you're taking it, and open a PR per the loop above.

Good contribution areas, ordered by current need:

1. **Adversarial test vectors** — malformed-DER corpora, non-minimal encodings, name-constraint edge cases, cross-tool round-trip fixtures. The decoder and path-validation surfaces are the highest-value places to harden.
2. **Interop coverage** — a certificate / CMS / PKCS#12 structure validated by OpenSSL or NSS that we don't yet round-trip.
3. **Documentation and runnable examples** — the wiki at pkijs.com is source-driven; filling in the common tasks (sign with your own CA, parse a certificate, build a CSR with a SAN, PEM conversion) helps every consumer.
4. **Vendored-dep refreshes** — when a vendored library publishes a security or feature release, diff the published tarball against the prior version before approving, and refresh the manifest.

What we don't want:

- New runtime npm deps. Period.
- TypeScript ports / transpiler builds.
- Classical-only crypto fallbacks "for compatibility."
- A convenience default that papers over a real decision (e.g. a parser that accepts non-canonical BER where the standard requires DER).

## Maintainer responsibilities

If you're being added as a maintainer, the additional commitments:

- Triage incoming issues within 7 days.
- Respond to security reports per the SLA in [SECURITY.md](SECURITY.md).
- Review PRs in your domain area within 14 days.
- Sign-off + tag releases via `node scripts/release.js`.

## Getting help

- **General questions:** GitHub Discussions on the repo.
- **Real-time:** the project doesn't run a Discord / Slack — async-by-design.
- **Security:** `security@pkijs.com` ([SECURITY.md](SECURITY.md)).

This document is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
