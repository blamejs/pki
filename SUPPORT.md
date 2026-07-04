# Support

Thanks for using `@blamejs/pki`. This page points you at the right channel for
whatever you need.

## Where to go

| I want to… | Go here |
|---|---|
| Read the API reference | [pkijs.com](https://pkijs.com) — generated from source, always in sync with the shipped release |
| See what ships today and what's planned | [README.md](README.md) and [ROADMAP.md](ROADMAP.md) |
| See what changed between versions | [CHANGELOG.md](CHANGELOG.md) |
| Ask a usage question or propose a feature | [GitHub Discussions](https://github.com/blamejs/pki/discussions) |
| Report a reproducible bug | [GitHub Issues](https://github.com/blamejs/pki/issues) |
| Report a security vulnerability | **Privately** — see [SECURITY.md](SECURITY.md). Do not open a public issue. |

## Before you open an issue

A tight report gets a fast answer. Please include:

- The version you are on — a `v0.X.Y` tag, or the `main` `<sha>` you tested.
- Your Node.js version (`node -v`). The toolkit targets Node 24.18+ and runs on
  the shipped runtime with no build step.
- A **minimal reproducer**. Because most of the surface is parsing bytes, the
  best reproducer is usually the exact certificate, DER blob, PEM, or message
  that triggers the behavior — attach it as base64 or hex rather than describing
  it in prose.
- What you expected, and what actually happened. If a parse threw, include the
  error's `constructor.name` and its `code` (e.g. `asn1/indefinite-length`) —
  those codes are stable and make triage fast.

A parse throwing a typed error on malformed input is usually the toolkit working
as designed (it fails closed on purpose). If you believe a byte string *should*
parse and does not — or *should not* parse and does — that is exactly the kind of
report we want, so include the bytes.

## Versions and upgrades

Pre-1.0, the supported version is the latest published patch on the latest minor.
Older patch lines do not receive backports. The
[versioning policy](README.md) is patch-by-default: bug fixes, vendor refreshes,
and internal changes are patches; additive APIs are minors; breaking changes are
majors and ship a deprecation warning in a prior minor first.

## Security

Security reports do not go through Issues or Discussions. Report privately via
GitHub's ["Report a vulnerability"](https://github.com/blamejs/pki/security/advisories/new)
advisory form — full details, response targets, and release-verification steps are
in [SECURITY.md](SECURITY.md).

## License

`@blamejs/pki` is [Apache-2.0](LICENSE) licensed. Vendored-component attribution
is in [NOTICE](NOTICE).
