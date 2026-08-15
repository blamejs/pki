# Migrating

One migration recipe per breaking change. Every deprecated surface listed here also warns from the running process before its removal version, with `PKI_DEPRECATIONS=warn` set or by default outside production. This file ships in the repository, so you can diff it against the tag you are upgrading from.

Some breaking changes cannot warn at runtime: an on-disk format break or a wire-encoding change has no in-process call to attach a warning to. Those are listed below alongside the runtime deprecations, so the full upgrade path is here rather than spread through the changelog.

## No active deprecations

The toolkit has no `deprecate()`-marked surface awaiting removal.

---

## Out-of-band breaking changes

Listed newest-first.

### v0.5.5 — `require("@blamejs/pki/lib/...")`

The package resolves one entry point; a path into the package no longer resolves.

`require("@blamejs/pki")` and `import ... from "@blamejs/pki"` are unchanged. What no
longer resolves is a path INTO the package:

```
require("@blamejs/pki/lib/schema-x509")   // ERR_PACKAGE_PATH_NOT_EXPORTED
```

Every module under `lib/` carries `@internal` in its own header and none has ever appeared
in the API snapshot that freezes the public surface. They were reachable because the package
declared no `exports` map, not because they were offered -- and one of them mints the
provenance record the OCSP and PKCS#12 integrity verbs rely on, which reachable from outside
could be minted for any object.

Everything the internals do is on `pki.*`: the decoders are `pki.schema.<format>.parse`, the
codec is `pki.asn1`, the OID registry is `pki.oid`, the error classes are `pki.errors`. If you
are reaching for something with no `pki.*` route, that is a gap worth reporting rather than a
module worth importing -- the internals change shape between patch releases and carry no
compatibility promise.

`require("@blamejs/pki/package.json")` still resolves, for tooling that reads the version.
