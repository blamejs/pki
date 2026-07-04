---
name: Feature request
about: Propose a new PKI primitive, codec, or CLI subcommand
title: ''
labels: enhancement
assignees: ''
---

<!--
Every primitive lands with its full operator-facing scope, not
"minimum viable with key features deferred." File the issue first to
discuss scope before opening a PR; it saves a round of rework. See
ROADMAP.md for what's already planned.
-->

## Problem

<!-- What PKI task are you solving? Concrete scenario preferred over
abstract. Cite the RFC / standard if the surface is spec-defined
(e.g. RFC 5280 X.509, RFC 5652 CMS, RFC 6960 OCSP, RFC 3161 TSP). -->

## Proposed primitive / surface

<!-- What does the caller's API look like? Show the call site. -->

```js
var pki = require("@blamejs/pki");

// Imagined usage
var result = pki.<namespace>.<fn>(input, opts);
```

If it's a CLI subcommand, the imagined invocation:

```bash
pki <subcommand> --flag value
```

## Standards reference

<!-- Which RFC / NIST publication / ASN.1 module defines the format?
Link the section that pins the wire encoding. -->

## Initial-release scope

What's IN the first shipped version:
-

What's explicitly OUT (and why each "out" is a complete decision, not a
deferred bullet):
-

## Configuration surface

<!-- Which opts keys does the new primitive accept? -->

```
allowedKeys: [
  ...
]
```

## Failure modes

<!-- Pick the input-validation policy consciously per call site:

  - Config-time / entry-point inputs:  THROW with a stable domain/reason
    code so callers see the typo immediately.
  - Defensive parsers of untrusted bytes:  fail CLOSED — reject non-DER
    / malformed / oversized input before walking it, never coerce a
    hostile shape into a partial parse.
-->

- Bad opts at the entry point → throw with `PkiError` domain/reason
- Malformed / hostile input bytes → reject fail-closed

## Crypto posture

<!-- PQC-first: ML-DSA / ML-KEM / SLH-DSA and SHA-3 / SHAKE are the
defaults; classical algorithms are supported for parsing existing
artifacts but not chosen as new-material defaults. -->

- [ ] Parses existing artifacts using a classical algorithm (verify-only)
- [ ] Produces new material (which algorithm? is it PQC-first?)
- [ ] No crypto involved (pure structural codec)

## Alternatives considered

<!-- What did you rule out and why. Saves the reviewer asking. -->

## Additional context
