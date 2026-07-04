<!--
Thanks for the PR! Fill in the sections below. CI (smoke + static
gates) is required to pass before merge — local pre-flight:

  node test/smoke.js
  npx eslint@latest --max-warnings 0 .
  node test/layer-0-primitives/codebase-patterns.test.js
  node scripts/validate-source-comment-blocks.js
  node scripts/check-api-snapshot.js

Security-sensitive patches: don't open here, see SECURITY.md.
-->

## Summary

<!-- One or two sentences. What does this change and why. -->

## Type of change

<!-- Check all that apply -->

- [ ] Bug fix (no API change)
- [ ] New PKI primitive / codec
- [ ] New CLI subcommand
- [ ] Docs / ROADMAP / CHANGELOG update
- [ ] Vendored dep refresh
- [ ] Test coverage / CI improvement
- [ ] Refactor (no behavior change)
- [ ] Other:

## Linked issue

Closes #

## House rules checklist

- [ ] No new npm runtime dependencies (vendored under `lib/vendor/` with a MANIFEST.json entry if a new external library was needed)
- [ ] PQC-first: new material uses ML-DSA / ML-KEM / SLH-DSA and SHA-3 / SHAKE; classical algorithms are verify/parse-only
- [ ] CommonJS / `var` / no TypeScript / no transpilation
- [ ] Every `.js` file starts with the SPDX + copyright + `"use strict"` header
- [ ] Used framework primitives (`C.TIME.*`, `C.BYTES.*`, `pki.errors`) instead of raw literals or hand-rolled helpers
- [ ] Untrusted-byte parsers fail closed (reject non-DER / oversized / malformed before walking input)
- [ ] No "future patch" deferrals — sweep across all existing call sites in this same PR if introducing a shared helper

## Tests

- [ ] `node test/smoke.js` passes — count: `____`
- [ ] `npx eslint@latest --max-warnings 0 .` exits 0
- [ ] `node test/layer-0-primitives/codebase-patterns.test.js` clean
- [ ] New tests added for the new behavior (RED before the fix, GREEN after):
  - [ ] Layer 0 (primitive)
  - [ ] Interop (cross-implementation, if a wire format changed)

## Documentation

- [ ] `@module` / `@primitive` comment blocks added/updated in the same diff (the wiki is source-driven)
- [ ] CHANGELOG.md entry under the relevant `## vX.Y.Z`
- [ ] SECURITY.md updated for new threat-model entries / supported versions
- [ ] README.md updated if the new capability appears in the high-level pitch
- [ ] Commit message explains *why* and *what tradeoff*, not just *what*

## Behavior changes

<!-- If this PR changes existing behavior (output shape, exit code,
default value, accepted-input set), call it out so the next release
notes can flag it. -->

## Open questions / reviewer focus
