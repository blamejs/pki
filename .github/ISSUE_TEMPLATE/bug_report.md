---
name: Bug report
about: Report a defect in the PKI toolkit (parsing, encoding, verification, CLI)
title: ''
labels: bug
assignees: ''
---

<!--
Security bug? Don't file here — see SECURITY.md for the private
disclosure process. Public issues are for non-security defects.

Before filing: search existing issues to avoid duplicates.
-->

## What happened

<!-- One or two sentences. What did the toolkit do that you didn't expect. -->

## What you expected

## How to reproduce

<!-- Minimal repro. Code snippet preferred over prose. If the bug is
triggered by a specific certificate / DER blob, attach it (or a PEM
excerpt) so the exact bytes can be reproduced. -->

```js
var pki = require("@blamejs/pki");
// minimal repro
```

Or, for CLI bugs, the full command + flags:

```bash
pki <subcommand> --flag value
```

## Environment

- `@blamejs/pki` version: `v0.X.Y` (or main `<sha>`)
- Node.js version: `node --version`
- OS: `uname -a` or Windows version

## Logs / output

<details><summary>Click to expand</summary>

```
paste relevant log lines, error codes, or stack traces here
```

</details>

## What you've already tried

<!-- Helpful for ruling out duplicates / known interactions. -->

## Additional context
