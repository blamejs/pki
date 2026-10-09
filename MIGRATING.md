# Migrating

One migration recipe per breaking change. Every deprecated surface listed here also warns from the running process before its removal version, with `PKI_DEPRECATIONS=warn` set or by default outside production. This file ships in the repository, so you can diff it against the tag you are upgrading from.

Some breaking changes cannot warn at runtime: an on-disk format break or a wire-encoding change has no in-process call to attach a warning to. Those are listed below alongside the runtime deprecations, so the full upgrade path is here rather than spread through the changelog.

## No active deprecations

The toolkit has no `deprecate()`-marked surface awaiting removal.

---

## Out-of-band breaking changes

Listed newest-first.

### v0.9.3 — `pki.relatedCert.verifyRequest, the pki.cms signer descriptor, and a bare name string`

verifyRequest returns a verdict object instead of a bare boolean; a signer descriptor and a bare name string are both held to what the verb actually reads.

Three changes, each refusing or re-shaping something that was previously accepted and then
quietly read as something else.

**`pki.relatedCert.verifyRequest` returns a verdict object.** Read `res.valid` where you read
the boolean:

```js
if (await pki.relatedCert.verifyRequest(attr, cert, opts))        // an always-true object now

var res = await pki.relatedCert.verifyRequest(attr, cert, opts);
if (res.valid) { /* ... */ }
```

This is a SILENT break: the old return was a boolean, so an unmigrated `if (await ...)` reads
the new object as truthy and accepts what it used to reject. The verdict is
`{ valid, verified, signerMaySign, signatureAlgorithm }`, plus `code` and `reason` when it did
not pass. `verified` is the proof's own signature and `signerMaySign` is whether the related
certificate's keyUsage authorizes that signature, which RFC 5280 sec. 4.2.1.3 decides; a bare
boolean could not tell the two apart. A key-establishment certificate still passes, because
RFC 9763 sec. 3.1 has such a key sign once for proof of possession, so `keyEncipherment` and
`keyAgreement` authorize this one signature. A certificate confined to `keyCertSign`,
`cRLSign`, `encipherOnly` or `dataEncipherment` is now refused with
`relatedcert/signer-may-not-sign`.

**A signer descriptor is held to the fields the verb reads.** `pki.cms.sign`,
`pki.cms.countersign`, `pki.cms.authenticate` and `pki.smime.sign` raise `cms/bad-input`
naming any field they do not recognize, as `pki.pkcs12.build` already did:

```js
pki.cms.sign(content, [{ cert, key, digestAlgoritm: "sha384" }])   // signed under sha256
pki.cms.sign(content, [{ cert, key, digestAlgorithm: "sha384" }])  // signs under sha384
```

A descriptor takes `{ cert, key }` or `{ spki, keyIdentifier, key }`, plus `pss`,
`digestAlgorithm` and `combinedRsaSig`. Passing a wider object through, such as a test helper's
whole bag, now names the extra field rather than ignoring it.

**A bare name string is a common name, and one written as a distinguished name is refused.**

```js
pki.x509.sign({ subject: "CN=Example CA, O=Example", ... })   // certified CN=CN=Example CA\, O=Example
pki.x509.sign({ subject: pki.x509.parseDn("CN=Example CA, O=Example").bytes, ... })
pki.x509.sign({ subject: "Example CA", ... })                 // unchanged: one common name
```

The refusal is in the shared name encoder, so it covers every builder that takes a name and a
`directoryName` in a GeneralName. A string whose opening characters are not an attribute type
followed by `=` is a common name and is unaffected, including one containing an `=` later on.
The message names both ways forward.

If you issue from a verified request, take the request's own `subject.bytes` rather than its
`subject.dn`: the DER is what was requested, and the text form is read as a common name.

### v0.9.1 — `pki.smime.verify, pki.smime.decrypt, pki.est.splitMultipartMixed, and pki.est.parseServerKeygenResponse`

A MIME entity that names one Content-Type parameter twice, or one header field twice, is refused rather than resolved by position, and one entity is bounded at 1024 body parts, 1024 header lines, and 256 Content-Type parameters.

No API shape changed, so there is nothing to rewrite. What changes is which messages produce a
verdict.

Two shapes are refused outright, in either order of the two occurrences:

- A `Content-Type` naming one parameter twice, such as `boundary="a"; boundary="b"`, or two
  `micalg`, `protocol`, or `smime-type` parameters. Raises `smime/bad-mime`.
- A header area naming one field twice, such as two `Content-Type` lines. Raises
  `smime/bad-mime`.

RFC 2045 sec. 5.1 gives a parameter one occurrence and RFC 5322 sec. 3.6 gives a singleton field
one, so an entity naming either twice has two conforming readings that disagree about what the
entity is: the `boundary` decides which octets a detached signature covers. Before this release
the verdict followed the order the two occurrences appeared in, so the same two values swapped
flipped between `valid: true` and a refusal.

A field that may legally repeat, such as `Received`, is unaffected, and every occurrence stays
readable from `headers`. Only resolving a repeated name to a single value is refused.

Three bounds apply to one entity:

| bound | value | `pki.constants.LIMITS` row |
| --- | --- | --- |
| body parts | 1024 | `MIME_MAX_PARTS` |
| header lines | 1024 | `MIME_MAX_HEADERS` |
| `Content-Type` parameters | 256 | `MIME_MAX_PARAMS` |

A folded field spends one of the 1024 header lines for each physical line it occupies, so a field
folded over three lines costs three. From `pki.smime`, an entity over the part bound raises
`smime/bad-multipart` and one over the header-line or parameter bound raises `smime/bad-mime`;
the `pki.est` readers raise `est/bad-multipart` for all three. The 16 MiB `MIME_MAX_BYTES` entity
cap is unchanged.

If a message you must keep reading carries one of the refused shapes, it is ambiguous to every
other S/MIME implementation as well, and the sender has to emit each parameter and each field
once. No option restores the previous behavior, because a precedence rule no other reader is
obliged to share cannot settle which octets a signature covers.

Separately, the entity record and the `content` a verdict is read with no longer share the buffer
passed in. If you relied on mutating your own input buffer to change what a returned record reads
back, that no longer works, and the record now holds the bytes the verdict was computed over.

### v0.6.12 — `pki.crl.verify, pki.pkcs12.verifyMac, and pki.ct.verifySctWithLogList`

Each returned a bare boolean and now returns a verdict object; read `res.valid` where you read the boolean.

A bare boolean hides which checks ran. Each of these three verbs now returns an object whose
`valid` field is the boolean it used to return, alongside the checks and data it had dropped:

- `pki.crl.verify` -> `{ valid, issuerMaySign, signatureValid, issuer, code?, reason? }`
- `pki.pkcs12.verifyMac` -> `{ valid, macAlgorithm, macAlgorithmName, iterationCount }`
- `pki.ct.verifySctWithLogList` -> `{ valid, logId, logIdHex, operator, logState, timestamp }`

```js
if (await pki.crl.verify(crl, { cert }))       // used to be the verdict; now an always-true object

var res = await pki.crl.verify(crl, { cert });
if (res.valid) { /* ... */ }
```

This is a SILENT break: the old return was a boolean, so an unmigrated `if (await verify(...))`
reads the new object as truthy and accepts what it used to reject. Switch every such test to
`res.valid`. The new fields let a caller act on the detail the boolean hid: `pki.crl.verify`
reports whether the certificate was allowed to sign the CRL (`issuerMaySign`) separately from the
signature (`signatureValid`); `pki.pkcs12.verifyMac` names the integrity algorithm so a legacy
SHA-1 MAC can be refused; `pki.ct.verifySctWithLogList` carries the resolved trusted-log record.

### v0.6.11 — `pki.path.validate(path, opts) and pki.tsp.verify(token, data, opts)`

The trust anchor option is now `trustAnchors` (a single anchor or an array); the former singular `trustAnchor` is removed and refused by name.

Both verbs read the trust anchor from `opts.trustAnchors`, the spelling pki.path.build,
pki.cms.verify, pki.cmp.verify, and pki.smime.verify already use. It accepts a single anchor
tuple or root certificate, or a non-empty array of them.

```js
var res = await pki.path.validate(path, { time: t, trustAnchor: anchor });   // removed

var res = await pki.path.validate(path, { time: t, trustAnchors: anchor });          // one anchor
var res = await pki.path.validate(path, { time: t, trustAnchors: [rootA, rootB] });  // several
```

With several anchors, pki.path.validate selects the one that issued the path's top certificate,
and a one-element array reproduces the previous single-anchor result. The removed `trustAnchor`
is refused as an unknown option (`path/bad-input` or `tsp/bad-input`) naming it, rather than read
as absent, so a request that was silently unanchored now fails closed with a named error.

### v0.5.24 — `pki.acme.client(...).downloadCertificate(url, opts)`

The verb needs to be told which certificate the download is allowed to be, and refuses with acme/binding-required when it is not.

Pass `expectedSpki` (the DER SubjectPublicKeyInfo this order's CSR asked to have certified) and
`identifiers` (the order's own identifier array). Either alone is accepted, and each is checked
on its own.

Nothing previously bound the certificate a CA returned to the order that was placed, so a
certificate resource answering with a certificate for another key, or another name, came back as
the issued certificate for that order. The outbound half of the exchange already refuses a CSR
whose identifier set is not the order's, and the other enrollment clients bind the issued
certificate to the requested key, so this closes the one direction that did not.

```js
var order = await client.pollOrder(orderUrl);
var res = await client.downloadCertificate(order.certificate);   // used to accept any answer

var res = await client.downloadCertificate(order.certificate,
  { expectedSpki: csrSpki, identifiers: order.identifiers });
// res.boundToKey === true, res.boundToIdentifiers === true
```

A mismatch is `acme/certificate-key-mismatch` or `acme/certificate-identifier-mismatch`.

Where the material genuinely is not available -- reading a certificate resource outside an
enrollment -- pass `requireBinding: false`. The result then reports `boundToKey: false` and
`boundToIdentifiers: false` rather than reading as a checked download. That waiver drops the
requirement to supply material and never the check on material that is supplied, so a value
passed alongside it is still compared.

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
