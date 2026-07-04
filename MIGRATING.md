# Migrating

Operator-facing migration recipes per breaking change. The bulk of this file is auto-generated from `deprecate()`-marked surface in the toolkit — the running process warns about each (with `PKI_DEPRECATIONS=warn` set, or by default outside production) before the noted removal version. Re-run `node scripts/gen-migrating.js` before each release; the file is committed so operators can diff it against the prior tag.

**Out-of-band breaking changes** (on-disk format breaks, wire-encoding changes) cannot be expressed as `deprecate()` calls because there is no in-process runtime to warn from. They are hardcoded in the OUT_OF_BAND_BREAKS table inside `scripts/gen-migrating.js` so the operator sees the full upgrade path here without grepping the CHANGELOG.

## No active deprecations

The toolkit has no `deprecate()`-marked surface awaiting removal.
