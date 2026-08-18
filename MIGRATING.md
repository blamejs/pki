# Migrating

One migration recipe per breaking change. Every deprecated surface listed here also warns from the running process before its removal version, with `PKI_DEPRECATIONS=warn` set or by default outside production. This file ships in the repository, so you can diff it against the tag you are upgrading from.

Some breaking changes cannot warn at runtime: an on-disk format break or a wire-encoding change has no in-process call to attach a warning to. Those are listed below alongside the runtime deprecations, so the full upgrade path is here rather than spread through the changelog.

## No active deprecations

The toolkit has no `deprecate()`-marked surface awaiting removal.

---

## Out-of-band breaking changes

Listed newest-first.

### v0.5.8 — `pki.smime.verify(...).headerProtection.fromMismatch`

Now null when there was no protected From to compare against, where it used to be false.

The field reported `false` on every message without RFC 9788 header protection, which is nearly all
mail. That made `!fromMismatch` read as a passed sender check on messages where no comparison had
happened. It is now three-valued: `true` when the outer From differs from the protected one, `false`
when they agree, and `null` when there was nothing to compare.

```js
if (!res.headerProtection.fromMismatch) { /* used to accept unprotected mail as "From checked" */ }
if (res.headerProtection.fromMismatch === false) { /* only when a comparison actually ran */ }
```

`null` is falsy, so a `!fromMismatch` test keeps compiling and keeps accepting the unchecked case.
Compare against `false` explicitly.

To bind a sender without depending on the composer having protected the headers, pass
`expectedSender` and test `res.sender.match === true`. That compares the address against the
`rfc822Name` the signer's certificate asserts (RFC 8550 sec. 4.4.3) under the RFC 5280 sec. 7.5 rule.
`sender.match` is also three-valued, and `null` there is likewise not a pass.

### v0.5.8 — `pki.merkle.verifyConsistency({ oldSize: 0, newSize: n }) where n > 0`

Refused as merkle/no-consistency-claim rather than answered `true`.

RFC 6962 sec. 2.1.2 defines a consistency proof for `0 < oldSize < newSize`. An empty older
tree is a prefix of every tree by definition, so there is no proof to check and nothing binds
the `newRoot` you passed. Any value returned `true`, including a root from a different log.

```js
pki.merkle.verifyConsistency({ oldSize: 0n, oldRoot, newSize: 7n, newRoot, proof });
// was: true, for every newRoot.  now: throws merkle/no-consistency-claim
```

Two empty trees are unchanged: `oldSize` and `newSize` both 0 still checks each root against
`pki.merkle.emptyRootHash()` and returns a real verdict.

A monitor with no prior tree has an inclusion question about the new tree. Use
`pki.merkle.verifyInclusion`, or start from a signed tree head you already trust and pass that
as the older one. If you were treating the empty case as a startup no-op, skip the call at
size 0 instead of relying on its return value.

### v0.5.7 — `content that is an encoded SignedAttributes block`

Signing or verifying such content WITHOUT signed attributes is refused as cms/ambiguous-content.

A CMS signature does not commit to whether signed attributes were present, so a signature made
over a SignedAttributes block can be re-presented as one made over content. The shape is now
refused at both ends.

This only affects you if your CMS content genuinely IS a DER SET OF Attribute carrying both a
content-type and a message-digest attribute -- the shape RFC 5652 sec. 5.3 gives a
SignedAttributes -- AND you sign it with `signedAttributes: false`. Ordinary content is
unaffected, and so is a set of attributes missing either of those two.

```js
await pki.cms.sign(attrShapedContent, signer, { signedAttributes: false });  // cms/ambiguous-content
await pki.cms.sign(attrShapedContent, signer);                              // signed attributes: fine
```

Signing it WITH signed attributes makes the message unambiguous and it verifies normally.
Existing messages of this shape already in your archive will not verify; re-sign them with
signed attributes.

### v0.5.6 — `try { pki.<verb>(...) } catch`

A verb documented `-> Promise` rejects on a bad input instead of throwing before the promise exists.

If you awaited the call, or attached `.catch`, nothing changes and there is nothing to do.

What changes is the undocumented shape: a synchronous `try`/`catch` that never consumed the
returned promise.

```js
try {
  pki.cms.verify(bytes);            // no await, no .catch
} catch (e) { /* used to fire on a malformed input */ }
```

That `catch` no longer runs, and the rejection surfaces as an unhandled one. It worked by
accident on exactly the verbs where a check happened to run before the promise existed --
`pki.cms.verify`, `pki.cms.sign`, `pki.cms.countersign`, `pki.ocsp.sign`, `pki.tsp.sign`, six
`pki.acme` verbs, and nine verbs on the client `pki.acme.client(...)` returns. Which verbs
those were was not visible from the call, which is why they are now uniform.

```js
await pki.cms.verify(bytes);        // or pki.cms.verify(bytes).catch(handleIt)
```

### v0.5.6 — `pki.pkcs12.build(spec)`

An omitted password is refused rather than encoded as the empty one.

A store whose password option was missing or misspelled no longer builds silently under `""`.

```js
await pki.pkcs12.build(spec);                    // now pkcs12/bad-input
await pki.pkcs12.build(spec, { password: "" });  // the empty password, asked for
```

If you were relying on the default, the second form restores the previous output byte for
byte. `opts.integrity.mode` is validated the same way: a spelling other than `"public-key"`
is now `pkcs12/bad-integrity-mode` instead of silently selecting password integrity and
dropping the signer.

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
