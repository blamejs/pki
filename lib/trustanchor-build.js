// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.trustanchor
 * @nav        Trust
 * @title      Trust anchor lists
 * @order      178
 * @slug       trustanchor-build
 *
 * @intro
 *   Write the RFC 5914 `TrustAnchorList` a root program publishes: each anchor
 *   as a certificate, as a bare `TBSCertificate`, or as a `TrustAnchorInfo`
 *   carrying the name it is known by and the constraints a relying party
 *   applies to paths beneath it. Every anchor is held to the same rules
 *   `pki.schema.trustanchor.parse` holds one to, and the result round-trips
 *   through that parser before it is returned.
 *
 * @card
 *   Build RFC 5914 trust anchor lists: the anchor carries its own policies,
 *   name constraints and path length.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var trustanchor = require("./schema-trustanchor");
var x509 = require("./schema-x509");
var pkiBuild = require("./pki-build");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var intrinsic = require("./guard-intrinsic");
var guard = require("./guard-all");

var TrustAnchorError = frameworkError.TrustAnchorError;
var b = asn1.build;

function _err(code, message, cause) { return new TrustAnchorError(code, message, cause); }
function O(n) { return oid.byName(n); }

var NS = pkix.makeNS("trustanchor", TrustAnchorError, oid);
var NAME_SCHEMA = pkix.name(NS);
var SPKI_SCHEMA = pkix.spki(NS);
var _b = pkiBuild.makeBuilder({ ErrorClass: TrustAnchorError, prefix: "trustanchor", O: O, NS: NS,
  NAME_SCHEMA: NAME_SCHEMA, SPKI_SCHEMA: SPKI_SCHEMA, EXT_DECODERS: {} });

var CERT_EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var OID_NAME_CONSTRAINTS = oid.byName("nameConstraints");

var _ANCHOR_KEYS = intrinsic.assign(intrinsic.create(null), { certificate: 1, tbsCert: 1, taInfo: 1 });
var _INFO_KEYS = intrinsic.assign(intrinsic.create(null), {
  pubKey: 1, keyId: 1, taTitle: 1, certPath: 1, exts: 1, taTitleLangTag: 1 });
var _CERT_PATH_KEYS = intrinsic.assign(intrinsic.create(null), {
  taName: 1, certificate: 1, policySet: 1, policyFlags: 1, nameConstr: 1, pathLenConstraint: 1 });
var _FLAG_KEYS = intrinsic.assign(intrinsic.create(null), {
  inhibitPolicyMapping: 1, requireExplicitPolicy: 1, inhibitAnyPolicy: 1 });
var _BUILD_KEYS = intrinsic.assign(intrinsic.create(null), { anchors: 1, pem: 1 });

/** @internal The shape check comes first, so every nested record reports a typed refusal naming
 *  the field instead of a native TypeError from the first property read below it. */
function _known(obj, allowed, what) {
  guard.identifier.assertPlainRecord(obj, _err, "trustanchor/bad-input", what);
  guard.identifier.assertKnownKeys(obj, allowed, _err, "trustanchor/bad-input", "unknown " + what + " field ");
}

function _policySetDer(list) {
  if (!intrinsic.isArray(list) || list.length === 0) {
    throw _err("trustanchor/bad-input", "certPath.policySet must be a non-empty array of policy identifiers");
  }
  return b.sequence(intrinsic.map(list, function (p) {
    if (typeof p !== "string" || !oid.isDottedDecimal(p)) {
      throw _err("trustanchor/bad-input", "certPath.policySet entries must be dotted-decimal policy identifiers");
    }
    /** @internal RFC 5914 sec. 2 forbids the qualifiers, so there is no place to put one and a
     * caller cannot supply one: the element is the identifier alone. */
    return b.sequence([b.oid(p)]);
  }));
}

var FLAG_BITS = trustanchor.policyFlagBits;
function _policyFlagsDer(flags) {
  _known(flags, _FLAG_KEYS, "certPath.policyFlags");
  var bits = [];
  for (var i = 0; i < FLAG_BITS.length; i++) {
    var v = flags[FLAG_BITS[i]];
    if (v === undefined || v === false) continue;
    if (v !== true) throw _err("trustanchor/bad-input", "certPath.policyFlags." + FLAG_BITS[i] + " must be a boolean");
    guard.list.append(bits, i);
  }
  if (bits.length === 0) return null;
  return b.implicit(2, b.namedBitString(bits));
}

function _certPathDer(spec) {
  _known(spec, _CERT_PATH_KEYS, "certPath");
  var nameDer = _b.encodeName(spec.taName);
  if (_b.isEmptyName(nameDer)) {
    throw _err("trustanchor/bad-input", "certPath.taName must be a non-empty distinguished name (RFC 5914 sec. 2)");
  }
  var kids = [b.raw(nameDer)];
  /** @internal The RFC 5914 module is IMPLICIT TAGS, so a context tag REPLACES the member's own
   * universal tag rather than wrapping it. `b.implicit` re-tags the value it is given; only the
   * three members the module writes EXPLICIT beside get a wrapper. */
  if (spec.certificate !== undefined) {
    guard.list.append(kids, b.implicit(0, _b.reqDer(spec.certificate, "certPath.certificate")));
  }
  var hasPolicySet = spec.policySet !== undefined;
  if (hasPolicySet) guard.list.append(kids, b.implicit(1, _policySetDer(spec.policySet)));
  if (spec.policyFlags !== undefined) {
    if (!spec.policyFlags || typeof spec.policyFlags !== "object") {
      throw _err("trustanchor/bad-input", "certPath.policyFlags must be an object of boolean flags");
    }
    /** @internal RFC 5914 sec. 2: "This bit MUST be set to FALSE if policySet is absent." Refused
     * here as well as at the parse, so the builder cannot emit what the parser would reject. */
    if (spec.policyFlags.requireExplicitPolicy === true && !hasPolicySet) {
      throw _err("trustanchor/bad-input", "certPath.policyFlags.requireExplicitPolicy requires a policySet (RFC 5914 sec. 2)");
    }
    var flagsDer = _policyFlagsDer(spec.policyFlags);
    if (flagsDer !== null) guard.list.append(kids,flagsDer);
  }
  if (spec.nameConstr !== undefined) {
    var ncDer = _b.reqDer(spec.nameConstr, "certPath.nameConstr");
    try { CERT_EXT_DECODERS[OID_NAME_CONSTRAINTS](ncDer); }
    catch (e) { throw _err("trustanchor/bad-input", "certPath.nameConstr is not a well-formed NameConstraints (RFC 5280 sec. 4.2.1.10)", e); }
    guard.list.append(kids, b.implicit(3, ncDer));
  }
  if (spec.pathLenConstraint !== undefined) {
    var n = spec.pathLenConstraint;
    if (!intrinsic.isInteger(n) || n < 0) {
      throw _err("trustanchor/bad-input", "certPath.pathLenConstraint must be a non-negative integer (INTEGER (0..MAX), RFC 5914 sec. 2)");
    }
    guard.list.append(kids,b.implicit(4, b.integer(intrinsic.BigInt(n))));
  }
  return b.sequence(kids);
}

function _taInfoDer(spec) {
  _known(spec, _INFO_KEYS, "taInfo");
  /** @internal The version is the DEFAULT v1 and DER omits it, so it is not a field a caller sets
   * and there is exactly one encoding of a v1 anchor. */
  var spki = _b.reqDer(spec.pubKey, "taInfo.pubKey");
  _b.assertValidSpki(spki, "taInfo.pubKey");
  var keyId = guard.bytes.snapshotSource(spec.keyId, TrustAnchorError, "trustanchor/bad-input", "taInfo.keyId");
  if (keyId.length === 0) throw _err("trustanchor/bad-input", "taInfo.keyId must not be empty");
  var kids = [b.raw(spki), b.octetString(keyId)];
  if (spec.taTitle !== undefined) {
    /** @internal Counted the way the reader counts, in characters rather than UTF-16 code units,
     * so the writer admits exactly the titles the reader does. */
    if (typeof spec.taTitle !== "string") {
      throw _err("trustanchor/bad-input", "taInfo.taTitle must be a string");
    }
    var titleLen = trustanchor.titleChars(spec.taTitle);
    if (titleLen < 1 || titleLen > 64) {
      throw _err("trustanchor/bad-input", "taInfo.taTitle must be 1 to 64 characters (SIZE (1..64), RFC 5914 sec. 2), got " + titleLen);
    }
    guard.list.append(kids,b.utf8(spec.taTitle));
  }
  if (spec.certPath !== undefined) guard.list.append(kids,_certPathDer(spec.certPath));
  if (spec.exts !== undefined) {
    if (!intrinsic.isArray(spec.exts) || spec.exts.length === 0) {
      throw _err("trustanchor/bad-input", "taInfo.exts must be a non-empty array of pre-encoded Extension DER");
    }
    var extDers = intrinsic.map(spec.exts, function (e, i) {
      var der = _b.reqDer(e, "taInfo.exts[" + i + "]");
      var extnId;
      try { extnId = asn1.read.oid(asn1.decode(der).children[0]); }
      catch (err) { throw _err("trustanchor/bad-input", "taInfo.exts[" + i + "] is not a well-formed Extension", err); }
      /** @internal RFC 5914 sec. 3 names four extension types that MUST NOT appear here. The parser
       * ignores one that does, as the RFC says to; the builder refuses to write one, so this
       * toolkit never produces an anchor carrying a constraint nothing will read. */
      if (trustanchor.excludedExtensionOids[extnId] === true) {
        throw _err("trustanchor/bad-input", "taInfo.exts must not carry " + (oid.name(extnId) || extnId) +
          ", which RFC 5914 sec. 3 excludes and a reader ignores; state it in certPath instead");
      }
      return b.raw(der);
    });
    guard.list.append(kids,b.explicit(1, b.sequence(extDers)));
  }
  if (spec.taTitleLangTag !== undefined) {
    /** @internal The type carries no SIZE constraint, so the reader accepts an empty language tag
     * and this refuses to write one: an empty tag names no language, and the field exists to say
     * which language the title is in. The docstring states it, since the module does not. */
    if (typeof spec.taTitleLangTag !== "string" || spec.taTitleLangTag.length === 0) {
      throw _err("trustanchor/bad-input", "taInfo.taTitleLangTag must be a non-empty string; an empty one names no language");
    }
    /** @internal `[2] UTF8String` with no EXPLICIT beside it in the module, so the context tag
     * replaces the UTF8String tag rather than wrapping it. */
    guard.list.append(kids, b.implicit(2, b.utf8(spec.taTitleLangTag)));
  }
  return b.sequence(kids);
}

function _anchorDer(spec, i) {
  if (!spec || typeof spec !== "object" || intrinsic.isArray(spec)) {
    throw _err("trustanchor/bad-input", "anchors[" + i + "] must be an object naming exactly one of certificate, tbsCert or taInfo");
  }
  _known(spec, _ANCHOR_KEYS, "anchors[" + i + "]");
  var named = [];
  intrinsic.forEach(["certificate", "tbsCert", "taInfo"], function (k) {
    if (spec[k] !== undefined) guard.list.append(named, k);
  });
  if (named.length !== 1) {
    throw _err("trustanchor/bad-input", "anchors[" + i + "] must name exactly one of certificate, tbsCert or taInfo, got " +
      (named.length === 0 ? "none" : intrinsic.join(named, " and ")));
  }
  if (named[0] === "certificate") return b.raw(_b.reqDer(spec.certificate, "anchors[" + i + "].certificate"));
  if (named[0] === "tbsCert") return b.explicit(1, b.raw(_b.reqDer(spec.tbsCert, "anchors[" + i + "].tbsCert")));
  return b.explicit(2, _taInfoDer(spec.taInfo));
}

/**
 * @primitive  pki.trustanchor.build
 * @signature  pki.trustanchor.build(spec, opts?) -> Buffer | string
 * @since      0.8.13
 * @status     stable
 * @spec       RFC 5914
 * @related    pki.schema.trustanchor.parse, pki.trust.parseTrustAnchorList
 *
 * Build an RFC 5914 `TrustAnchorList`, the structure a root program publishes. `spec.anchors` is a
 * non-empty array, each entry naming exactly one of `certificate` (pre-encoded Certificate DER),
 * `tbsCert` (pre-encoded TBSCertificate DER) or `taInfo`.
 *
 * A `taInfo` entry is `{ pubKey, keyId, taTitle?, certPath?, exts?, taTitleLangTag? }`, where
 * `pubKey` is SubjectPublicKeyInfo DER and `keyId` the key identifier bytes. `certPath` carries the
 * constraints: `taName` (a distinguished name string or an array of relative names), `certificate`,
 * `policySet` (an array of policy identifiers), `policyFlags`
 * (`{ inhibitPolicyMapping, requireExplicitPolicy, inhibitAnyPolicy }`), `nameConstr` (pre-encoded
 * NameConstraints DER) and `pathLenConstraint`.
 *
 * Every rule the parser enforces is enforced here, so this toolkit does not emit an anchor it would
 * refuse to read: an empty `taName`, a `requireExplicitPolicy` with no `policySet`, a negative
 * `pathLenConstraint`, and an `exts` entry naming one of the four extension types RFC 5914
 * section 3 excludes. The result round-trips through `pki.schema.trustanchor.parse` before it is
 * returned.
 *
 * The version is not a field a caller sets: v1 is the ASN.1 DEFAULT and DER omits it, so every v1
 * anchor has one encoding.
 *
 * Two refusals are stricter than the module, on the principle that what this
 * writes is what an operator publishes: `taTitleLangTag` may not be the empty string, which
 * names no language, and `exts` may not carry one of the four extension types RFC 5914 section 3
 * excludes, which a reader is told to ignore and which `certPath` states properly.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `TRUST ANCHOR LIST` string instead of DER.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = pki.trustanchor.build({ anchors: [{ taInfo: {
 *     pubKey: await pki.key.export(pair.publicKey),
 *     keyId: Buffer.alloc(20, 1),
 *     taTitle: "Example Root CA",
 *     certPath: { taName: "CN=Example Root", pathLenConstraint: 2 } } }] });
 *   pki.schema.trustanchor.parse(der).anchors[0].taInfo.certPath.pathLenConstraint;  // -> 2
 */
function build(spec, opts) {
  if (!spec || typeof spec !== "object" || intrinsic.isArray(spec)) {
    throw _err("trustanchor/bad-input", "build expects a { anchors } specification object");
  }
  _known(spec, _BUILD_KEYS, "build");
  var checked = guard.identifier.optionsObject(opts, _err, "trustanchor/bad-input", "pki.trustanchor.build options");
  guard.identifier.assertKnownKeys(checked, intrinsic.assign(intrinsic.create(null), { pem: 1 }),
    _err, "trustanchor/bad-input", "unknown pki.trustanchor.build option ");
  if (!intrinsic.isArray(spec.anchors) || spec.anchors.length === 0) {
    throw _err("trustanchor/bad-input", "build: anchors must be a non-empty array (TrustAnchorList is SIZE (1..MAX))");
  }
  var der = b.sequence(intrinsic.map(spec.anchors, function (a, i) { return _anchorDer(a, i); }));
  /** @internal The reader reads the writer's output back before it is returned, so a shape the two
   * disagree about fails the build instead of reaching an operator. */
  try { trustanchor.parse(der); }
  catch (e) { throw _err("trustanchor/bad-input", "the built trust anchor list does not parse: " + guard.text.describeThrown(e), e); }
  if (checked.pem === true) return trustanchor.pemEncode(der);
  return der;
}

void schema;
void x509;

module.exports = { build: build };
