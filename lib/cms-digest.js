// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.cms
 * @nav        Messaging
 * @title      CMS DigestedData
 * @order      95
 * @slug       cms-digest
 *
 * @intro
 *   RFC 5652 sec. 7 DigestedData, the integrity-only CMS content type. It carries the
 *   content, the digest algorithm, and the digest over the content octets. There is no
 *   signer and no key, so it establishes that content matches a digest and nothing about
 *   who produced either: its worth is the worth of the channel the message and the digest
 *   traveled over. `pki.cms.sign` establishes origin, `pki.cms.authenticate` establishes
 *   origin under a shared key.
 *
 *   The version follows the encapsulated type, 0 for `id-data` and 2 for anything else.
 *   The verifying half recomputes the digest and compares it in constant time, and its
 *   verdict carries no signer and no trust field, so it cannot be read as a signature.
 *
 * @spec RFC 5652 sec. 7
 * @card
 *   Build and verify RFC 5652 DigestedData: SHA-256/384/512 over the content octets,
 *   attached or detached, constant-time comparison, fail-closed.
 */

var nodeCrypto = require("node:crypto");
var oid = require("./oid");
var schemaCms = require("./schema-cms");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var asn1 = require("./asn1-der");
var b = asn1.build;

var CmsError = frameworkError.CmsError;
function _err(code, message, cause) { return new CmsError(code, message, cause); }
function O(name) { return oid.byName(name); }

var OID_DATA = O("data");
var OID_DIGESTED_DATA = O("digestedData");

var NODE_DIGEST = intrinsic.assign(intrinsic.create(null), {
  sha256: "sha256", sha384: "sha384", sha512: "sha512",
});

var _DIGEST_OPTS = intrinsic.assign(intrinsic.create(null), {
  digestAlgorithm: 1, contentType: 1, detached: 1, pem: 1,
});
var _VERIFY_DIGEST_OPTS = intrinsic.assign(intrinsic.create(null), { content: 1 });

function _digestName(opts) {
  var name = opts.digestAlgorithm === undefined ? "sha256" : opts.digestAlgorithm;
  var key = guard.text.keyOf(name);
  if (!NODE_DIGEST[key]) {
    throw _err("cms/unsupported-algorithm", "unsupported digest algorithm " + guard.text.showValue(name) +
      " (sha256 / sha384 / sha512)");
  }
  return key;
}

/**
 * @primitive  pki.cms.digest
 * @signature  pki.cms.digest(content, opts?) -> Promise<Buffer|string>
 * @since      0.8.1
 * @status     stable
 * @spec       RFC 5652 sec. 7
 * @related    pki.cms.verifyDigest, pki.cms.sign, pki.cms.authenticate
 *
 * Build an RFC 5652 `DigestedData`: the content, the digest algorithm, and the digest over
 * the content octets. It carries no signer and no key, so it establishes that content
 * matches a digest and nothing about who produced either. Use `pki.cms.sign` for origin,
 * or `pki.cms.authenticate` for origin under a shared key.
 *
 * The version follows the encapsulated type, 0 for `id-data` and 2 for anything else.
 *
 * @opts
 *   - `digestAlgorithm` (string) -- `sha256` (default), `sha384` or `sha512`.
 *   - `contentType` (string) -- the encapsulated content type by OID name, default `data`.
 *   - `detached` (boolean) -- omit the content, leaving the digest to travel alone.
 *   - `pem` (boolean) -- return a PEM `CMS` block instead of DER.
 * @example
 *   var der = await pki.cms.digest(Buffer.from("hello"));
 *   (await pki.cms.verifyDigest(der)).valid;   // -> true
 */
function digest(content, opts) {
  return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
    [content, "content"], [opts, "pki.cms.digest options"],
  ], _digest);
}

async function _digest(content, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.digest options");
  guard.identifier.assertKnownKeys(opts, _DIGEST_OPTS, _err, "cms/bad-input",
    "pki.cms.digest has an unknown option ");
  var raw = guard.bytes.source(content, CmsError, "cms/bad-input", "content");
  var alg = _digestName(opts);
  var ctName = opts.contentType === undefined ? "data" : opts.contentType;
  var ctOid = O(ctName);
  if (!ctOid) throw _err("cms/bad-input", "opts.contentType is not a known OID name: " + guard.text.showValue(ctName));

  var value = nodeCrypto.createHash(NODE_DIGEST[alg]).update(raw).digest();
  var eciChildren = opts.detached === true
    ? [b.oid(ctOid)]
    : [b.oid(ctOid), b.explicit(0, b.octetString(raw))];
  var dd = b.sequence([
    b.integer(ctOid === OID_DATA ? 0 : 2),
    b.sequence([b.oid(O(alg))]),
    b.sequence(eciChildren),
    b.octetString(value),
  ]);
  var ci = b.sequence([b.oid(OID_DIGESTED_DATA), b.explicit(0, dd)]);
  return opts.pem === true ? schemaCms.pemEncode(ci, "CMS") : ci;
}

/**
 * @primitive  pki.cms.verifyDigest
 * @signature  pki.cms.verifyDigest(input, opts?) -> Promise<verdict>
 * @since      0.8.1
 * @status     stable
 * @spec       RFC 5652 sec. 7
 * @related    pki.cms.digest, pki.cms.verify
 *
 * Recompute the digest of a `DigestedData`'s content and compare it with the digest the
 * message carries, in constant time. Returns `{ valid, digestAlgorithm, content, contentType }`,
 * with `code` set to `cms/digest-mismatch` when the content does not match.
 *
 * A DigestedData proves neither origin nor authority. A caller that needs either verifies a
 * `SignedData` instead; this verdict carries no signer and no trust field, so it cannot be
 * mistaken for one.
 *
 * @opts
 *   - `content` (BufferSource) -- the detached content the digest covers. Required when the
 *     message omits its own content, refused as redundant when it carries it.
 * @example
 *   var der = await pki.cms.digest(Buffer.from("hello"));
 *   var v = await pki.cms.verifyDigest(der);
 *   v.valid;             // -> true
 *   v.digestAlgorithm;   // -> "sha256"
 */
function verifyDigest(input, opts) {
  return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
    [input, "the CMS message"], [opts, "pki.cms.verifyDigest options"],
  ], _verifyDigest);
}

async function _verifyDigest(input, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.verifyDigest options");
  guard.identifier.assertKnownKeys(opts, _VERIFY_DIGEST_OPTS, _err, "cms/bad-input",
    "pki.cms.verifyDigest has an unknown option ");
  var parsed = guard.parsed.acceptDerived(input, "cms", function (bytes) {
    return schemaCms.parse(bytes);
  }, _err, "cms/bad-input", "the DigestedData");
  if (parsed.contentType !== OID_DIGESTED_DATA) {
    throw _err("cms/not-a-digested-data", "pki.cms.verifyDigest reads a DigestedData (RFC 5652 sec. 7) and this is " +
      (oid.name(parsed.contentType) || parsed.contentType));
  }
  var alg = guard.text.keyOf(parsed.digestAlgorithm.name || "");
  if (!NODE_DIGEST[alg]) {
    throw _err("cms/unsupported-algorithm", "unsupported digest algorithm " +
      guard.text.showValue(parsed.digestAlgorithm.name || parsed.digestAlgorithm.oid));
  }
  guard.der.assertParams(parsed.digestAlgorithm.parameters, "absentOrNull", _err,
    "cms/unsupported-algorithm", parsed.digestAlgorithm.name + " digest algorithm (RFC 5754 sec. 2)");
  var embedded = parsed.encapContentInfo.eContent;
  var supplied = opts.content === undefined ? null
    : guard.bytes.snapshotSource(opts.content, CmsError, "cms/bad-input", "opts.content");
  if (embedded != null && supplied != null) {
    throw _err("cms/bad-input", "the DigestedData carries its own content, so opts.content is redundant");
  }
  if (embedded == null && supplied == null) {
    throw _err("cms/bad-input", "the DigestedData is detached, so opts.content must supply the content it covers");
  }
  var covered = embedded != null
    ? guard.bytes.snapshotSource(embedded, CmsError, "cms/bad-input", "the encapsulated content")
    : supplied;
  var recomputed = nodeCrypto.createHash(NODE_DIGEST[alg]).update(covered).digest();
  var matched = guard.crypto.constantTimeEqual(recomputed, parsed.digest);
  return guard.verdict.of({
    valid: matched,
    code: matched ? undefined : "cms/digest-mismatch",
    digestAlgorithm: alg,
    contentType: parsed.encapContentInfo.eContentType,
    contentTypeName: oid.name(parsed.encapContentInfo.eContentType) || null,
    content: covered,
  });
}

module.exports = { digest: digest, verifyDigest: verifyDigest };
