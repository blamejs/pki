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

A tight report gets a fast answer. Include:

- The version you are on: a `v0.X.Y` tag, or the `main` `<sha>` you tested.
- Your Node.js version (`node -v`). The toolkit targets Node 24.19+ and runs on
  the shipped runtime with no build step.
- A **minimal reproducer**. Most of the surface is parsing bytes, so the best
  reproducer is usually the exact certificate, DER blob, PEM, or message that
  triggers the behavior. Attach it as base64 or hex rather than describing it in
  prose.
- What you expected, and what actually happened. If a parse threw, include the
  error's `constructor.name` and its `code`, for example
  `asn1/indefinite-length`. Those codes are stable and make triage fast.

A parse throwing a typed error on malformed input is usually the toolkit working
as designed, since it fails closed on purpose. If you believe a byte string
should parse and does not, or should not parse and does, that is exactly the kind
of report we want, so include the bytes.

## Versions and upgrades

Pre-1.0, the supported version is the latest published patch on the latest minor,
and older patch lines do not receive backports.

Releases are patch-by-default. Pre-1.0 that covers bug fixes, vendor refreshes,
internal changes, and additive surface — a new format parser or a new public API
ships as a patch. A minor is an explicit maintainer decision documented in the
release notes rather than something inferred from a feature landing. A major
carries breaking changes and ships deprecation warnings in a prior minor first.
[GOVERNANCE.md](GOVERNANCE.md) records how those calls are made, and
[LTS-CALENDAR.md](LTS-CALENDAR.md) records the post-1.0 support window.

## Security

Security reports do not go through Issues or Discussions. Report privately via
GitHub's ["Report a vulnerability"](https://github.com/blamejs/pki/security/advisories/new)
advisory form. Full details, response targets, and release-verification steps are
in [SECURITY.md](SECURITY.md).

## License

`@blamejs/pki` is [Apache-2.0](LICENSE) licensed. Vendored-component attribution
is in [NOTICE](NOTICE).
