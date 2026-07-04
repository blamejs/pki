# Migrating

Consumer-facing migration recipes, one per breaking change. The bulk of this file is auto-generated from `deprecate()`-marked surface in the toolkit — the running library warns about each before the noted removal version. Re-run `node scripts/gen-migrating.js` before each release; the file is committed so consumers can diff it against the prior tag.

**Out-of-band breaking changes** (on-disk or wire-format breaks, config-shape changes) cannot be expressed as `deprecate()` calls because there's no in-process runtime to warn from. When they occur they are recorded in the `OUT_OF_BAND_BREAKS` table inside `scripts/gen-migrating.js` so the full upgrade path appears here without needing to grep the changelog.

## No active deprecations

The toolkit is pre-1.0 and has no `deprecate()`-marked surface awaiting removal. Pre-1.0, consumers upgrade across breaking changes directly — there are no backwards-compatibility shims. Read [CHANGELOG.md](CHANGELOG.md) before upgrading across more than a few patches at a time.

## No out-of-band breaking changes recorded

There are no on-disk or wire-format breaks to migrate across yet. As the toolkit adds capabilities, any change that alters bytes a consumer may have persisted (a serialized structure, a cached encoding) will be listed here newest-first, each with the concrete upgrade step.

---

When the first deprecation or out-of-band break ships, this file is regenerated and the recipe appears above, following the shape:

- **What changed** — the exact surface and the version it changed in.
- **Why** — the standards-conformance or security reason.
- **What you do** — the concrete code or data change, or "no change needed" when the new behavior is transparent.
