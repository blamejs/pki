// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.trustanchor
 * @nav        Schema
 * @title      Trust anchors
 * @order      175
 * @slug       trustanchor
 *
 * @intro
 *   RFC 5914 trust anchors. A trust anchor as a structure rather than as a
 *   certificate, carrying the constraints a root program otherwise states out
 *   of band: the namespace the root is trusted for, the policies it may assert,
 *   and how far below it a path may run. `parse` reads a `TrustAnchorList` and
 *   `parseInfo` a bare `TrustAnchorInfo`; `pki.trust.parseTrustAnchorList`
 *   turns either into the anchors `pki.path.validate` consumes, and RFC 5937
 *   section 3.2 says how each constraint reaches the validation state.
 *
 * @card
 *   Read and write RFC 5914 trust anchor lists: the anchor, its name, its
 *   constraints, and the certificate that carries them.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var x509 = require("./schema-x509");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var intrinsic = require("./guard-intrinsic");
var guard = require("./guard-all");

var TrustAnchorError = frameworkError.TrustAnchorError;
var PemError = frameworkError.PemError;
var TAGS = asn1.TAGS;

var NS = pkix.makeNS("trustanchor", TrustAnchorError, oid);

var NAME = pkix.name(NS);
var SPKI = pkix.spki(NS);
var EXTENSIONS = pkix.extensions(NS);

/** @internal `TrustAnchorTitle ::= UTF8String (SIZE (1..64))` bounds the CHARACTERS of the string,
 *  which is what `Array.from` counts; `String.prototype.length` counts UTF-16 code units and would
 *  count a character outside the basic plane twice. Shared by the reader and the writer so the two
 *  admit the same titles. */
var _arrayFrom = Array.from;
function titleChars(s) { return _arrayFrom(s).length; }

/** @internal RFC 5914 sec. 3: these four MUST NOT appear in `exts` and "are ignored if they do
 *  appear". Ignored rather than refused, so they are reported and left out of the list a caller
 *  reads: each states a constraint `certPath` states properly, and honoring both would let one
 *  anchor say two different things. */
var EXTS_EXCLUDED = intrinsic.assign(intrinsic.create(null), {});
intrinsic.forEach(["certificatePolicies", "policyConstraints", "inhibitAnyPolicy", "nameConstraints"],
  function (n) { EXTS_EXCLUDED[oid.byName(n)] = true; });

/** @internal RFC 5914 sec. 2: CertificatePolicies where "the OPTIONAL policyQualifiers structure
 *  MUST NOT be included", which is the whole difference from the certificate extension's form. */
var POLICY_INFORMATION = schema.decode(function (n, ctx) {
  if (n.tagClass !== "universal" || n.tagNumber !== TAGS.SEQUENCE || !n.children || n.children.length < 1) {
    throw ctx.E("trustanchor/bad-policy-set", "a policySet element must be a PolicyInformation SEQUENCE");
  }
  if (n.children.length > 1) {
    throw ctx.E("trustanchor/bad-policy-set", "a policySet PolicyInformation must not carry policyQualifiers (RFC 5914 sec. 2)");
  }
  var id;
  try { id = asn1.read.oid(n.children[0]); }
  catch (e) { throw ctx.E("trustanchor/bad-policy-set", "a policySet PolicyInformation must lead with a policyIdentifier OBJECT IDENTIFIER", e); }
  return { policyIdentifier: id, name: oid.name(id) || null };
});
var POLICY_SET = schema.seqOf(POLICY_INFORMATION, {
  assert: "sequence", min: 1, code: "trustanchor/bad-policy-set", what: "policySet",
  build: function (m) { return intrinsic.map(m.items, function (it) { return it.value; }); },
});

var POLICY_FLAG_BITS = ["inhibitPolicyMapping", "requireExplicitPolicy", "inhibitAnyPolicy"];
var POLICY_FLAGS = schema.decode(function (n, ctx) {
  var bs;
  try { bs = asn1.read.bitStringImplicit(n, 2); }
  catch (e) { throw ctx.E("trustanchor/bad-policy-flags", "policyFlags must be a CertPolicyFlags BIT STRING", e); }
  try { schema.assertMinimalNamedBits(bs.unusedBits, bs.bytes, function (msg) { throw ctx.E("trustanchor/bad-policy-flags", msg); }); }
  catch (e) { throw e; }
  var out = intrinsic.create(null);
  for (var i = 0; i < POLICY_FLAG_BITS.length; i++) {
    var byteI = i >> 3;
    var set = byteI < bs.bytes.length && ((bs.bytes[byteI] >> (7 - (i & 7))) & 1) === 1;
    out[POLICY_FLAG_BITS[i]] = set;
  }
  return out;
});

/**
 * @internal The RFC 5914 module is `DEFINITIONS IMPLICIT TAGS`, so a tagged member carries the
 * context tag IN PLACE OF its own unless the module writes EXPLICIT beside it. Only three members
 * in the whole module are written EXPLICIT: `TrustAnchorInfo.exts [1]` and both tagged arms of
 * `TrustAnchorChoice`. Every other tagged member here is implicit, so the inner value's universal
 * tag is gone from the wire and has to be put back before the inner schema can read it.
 */
function _asUniversalSequence(n, ctx, code, what) {
  if (!n.children) throw ctx.E(code, what + " must be a constructed value");
  return pkix.decodeNested(asn1.sequenceTlv(n), ctx, what);
}

/** @internal NameConstraints as RFC 5280 sec. 4.2.1.10 states it, read through the shared
 *  certificate decoder so an anchor's namespace and a certificate's are the same shape. */
var CERT_EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var OID_NAME_CONSTRAINTS = oid.byName("nameConstraints");
var NAME_CONSTRAINTS = schema.decode(function (n, ctx) {
  if (!n.children) throw ctx.E("trustanchor/bad-name-constraints", "nameConstr [3] must be a constructed value");
  try { return CERT_EXT_DECODERS[OID_NAME_CONSTRAINTS](asn1.sequenceTlv(n), ctx); }
  catch (e) { throw ctx.E("trustanchor/bad-name-constraints", "nameConstr is not a well-formed NameConstraints (RFC 5280 sec. 4.2.1.10): " + guard.text.describeThrown(e), e); }
});

/** @internal The Certificate the [0] arm carries, read through the certificate parser's own schema
 *  rather than a second definition of it. */
var EMBEDDED_CERTIFICATE = schema.decode(function (n, ctx) {
  return schema.walk(x509.certificateSchema,
    _asUniversalSequence(n, ctx, "trustanchor/bad-certificate", "certificate [0]"), ctx);
});

/** @internal CertificatePolicies under an implicit [1]: the SEQUENCE OF tag is replaced, so the
 *  elements are read after the universal tag is restored. */
var POLICY_SET_IMPLICIT = schema.decode(function (n, ctx) {
  return schema.walk(POLICY_SET,
    _asUniversalSequence(n, ctx, "trustanchor/bad-policy-set", "policySet [1]"), ctx);
});

var CERT_PATH_CONTROLS = schema.seq([
  schema.field("taName", NAME),
  /** @internal Every one of these five is IMPLICIT: the module is IMPLICIT TAGS and none of them
   * is written EXPLICIT. */
  schema.trailing([
    { tag: 0, name: "certificate", schema: EMBEDDED_CERTIFICATE },
    { tag: 1, name: "policySet", schema: POLICY_SET_IMPLICIT },
    { tag: 2, name: "policyFlags", schema: POLICY_FLAGS },
    { tag: 3, name: "nameConstr", schema: NAME_CONSTRAINTS },
    { tag: 4, name: "pathLenConstraint", schema: schema.implicitInteger(4) },
  ], { minTag: 0, maxTag: 4, unexpectedCode: "trustanchor/bad-cert-path", orderCode: "trustanchor/bad-cert-path" }),
], {
  assert: "sequence", code: "trustanchor/bad-cert-path", what: "CertPathControls",
  build: function (m, ctx) {
    var f = m.fields;
    var taName = f.taName.value.result;
    /** @internal RFC 5914 sec. 2: "The name MUST NOT be an empty sequence." An anchor whose name
     * matches everything would authorize every subject the path chains to. */
    if (!taName.rdns || taName.rdns.length === 0) {
      throw ctx.E("trustanchor/bad-name", "CertPathControls taName must not be an empty distinguished name (RFC 5914 sec. 2)");
    }
    var pathLen = null;
    if (f.pathLenConstraint.present) {
      var raw = f.pathLenConstraint.value;
      if (raw < 0n) throw ctx.E("trustanchor/bad-path-len", "pathLenConstraint must be non-negative (INTEGER (0..MAX), RFC 5914 sec. 2)");
      pathLen = intrinsic.Number(guard.range.uint31(raw, ctx.E, "trustanchor/bad-path-len", "CertPathControls pathLenConstraint"));
    }
    /** @internal `policySet` is a repeat, so its match carries the built list in `result`; the
     * other members are decode leaves and answer with their value directly. */
    /** @internal `policySet` reads through a decode leaf that restores the implicit tag and walks
     * the repeat, so the match it answers with carries the built list in `result`. */
    var policySet = f.policySet.present ? f.policySet.value.result : null;
    var flags = f.policyFlags.present ? f.policyFlags.value : null;
    /** @internal RFC 5914 sec. 2: "This bit MUST be set to FALSE if policySet is absent." The other
     * two flags carry no such condition, since neither names a policy. */
    if (flags !== null && flags.requireExplicitPolicy === true && policySet === null) {
      throw ctx.E("trustanchor/bad-policy-flags", "requireExplicitPolicy must be FALSE when policySet is absent (RFC 5914 sec. 2)");
    }
    var certificate = f.certificate.present ? f.certificate.value.result : null;
    if (certificate !== null) _assertCertificateMatches(certificate, taName, ctx);
    return {
      taName: taName, certificate: certificate, policySet: policySet,
      policyFlags: flags, nameConstr: f.nameConstr.present ? f.nameConstr.value : null,
      pathLenConstraint: pathLen,
    };
  },
});

var OID_SKI = oid.byName("subjectKeyIdentifier");
/**
 * @internal RFC 5914 sec. 2, where `certificate` is present: "the subject name in the certificate
 * MUST exactly match the X.500 distinguished name provided in the taName field, the public key MUST
 * exactly match the public key in the pubKey field, and the subjectKeyIdentifier extension, if
 * present, MUST exactly match the key identifier in the keyId field."
 *
 * The public key and key identifier halves are checked in `_buildInfo`, which is where `pubKey` and
 * `keyId` are in scope; this half is the name, compared under the RFC 5280 sec. 7.1 canonical rule
 * the toolkit decides every distinguished-name identity with.
 */
function _assertCertificateMatches(certificate, taName, ctx) {
  /** @internal The error factory is not optional: the canonical comparison refuses a name carrying
   * an embedded control byte rather than comparing it (CVE-2009-2408), and it reports that refusal
   * through this factory. Omitting it turns that refusal into a bare TypeError, which is not the
   * typed verdict every other fault on this path answers with. */
  if (!guard.name.dnEqual(certificate.subject.rdns, taName.rdns, ctx.E,
      "trustanchor/certificate-mismatch", "the certPath certificate's subject")) {
    throw ctx.E("trustanchor/certificate-mismatch",
      "the certPath certificate's subject does not match taName (RFC 5914 sec. 2)");
  }
}

var TA_INFO_VERSION = schema.decode(function (n, ctx) {
  var v = asn1.read.integer(n);
  if (v !== 1n) throw ctx.E("trustanchor/bad-version", "TrustAnchorInfo version must be v1(1), got " + intrinsic.bigIntToString(v));
  /** @internal DER omits a DEFAULT at its default value (X.690 sec. 11.5), so an explicitly encoded
   * v1 is non-canonical and there is exactly one encoding of a v1 anchor. */
  throw ctx.E("trustanchor/bad-version", "TrustAnchorInfo version v1 is the DEFAULT and must be omitted (X.690 sec. 11.5)");
});

var TRUST_ANCHOR_INFO = schema.seq([
  schema.optional("version", TA_INFO_VERSION, { whenUniversal: [TAGS.INTEGER] }),
  schema.field("pubKey", SPKI),
  schema.field("keyId", schema.octetString()),
  schema.optional("taTitle", schema.decode(function (n, ctx) {
    if (n.tagClass !== "universal" || n.tagNumber !== TAGS.UTF8_STRING) {
      throw ctx.E("trustanchor/bad-title", "taTitle must be a UTF8String");
    }
    var s;
    try { s = asn1.read.string(n); }
    catch (e) { throw ctx.E("trustanchor/bad-title", "taTitle must be a well-formed UTF8String", e); }
    /** @internal The SIZE constraint counts CHARACTERS of the UTF8String, and a JavaScript string's
     * `length` counts UTF-16 code units, so a title using characters outside the basic plane counts
     * double and a conforming one would be refused. */
    var chars = titleChars(s);
    if (chars < 1 || chars > 64) {
      throw ctx.E("trustanchor/bad-title", "taTitle must be 1 to 64 characters (SIZE (1..64), RFC 5914 sec. 2), got " + chars);
    }
    return s;
  }), { whenUniversal: [TAGS.UTF8_STRING] }),
  schema.optional("certPath", CERT_PATH_CONTROLS, { whenUniversal: [TAGS.SEQUENCE] }),
  /** @internal The tag numbering has a gap: TrustAnchorInfo has no [0]. Its two tagged members are
   * tagged DIFFERENTLY from each other, `exts [1] EXPLICIT` and `taTitleLangTag [2]` implicit under
   * the module's IMPLICIT TAGS default, so neither the numbering nor the form can be copied from
   * one to the other. Numbering them from zero reads each field as its neighbor. */
  schema.trailing([
    { tag: 1, name: "exts", schema: EXTENSIONS, explicit: true, emptyCode: "trustanchor/bad-exts" },
    /** @internal `[2] UTF8String` with no EXPLICIT beside it, so the context tag replaces the
     * UTF8String tag and the content is the characters themselves. */
    { tag: 2, name: "taTitleLangTag", schema: schema.decode(function (n, ctx) {
      if (n.children || n.content === null) {
        throw ctx.E("trustanchor/bad-title", "taTitleLangTag [2] must be a primitive UTF8String value");
      }
      /** @internal The universal tag the implicit one replaced is put back, so the string is read
       * by the codec's own UTF8String reader and a malformed encoding is refused there rather than
       * passed through as bytes. */
      var universal = pkix.decodeNested(
        asn1.encodeTLV(0, false, TAGS.UTF8_STRING, n.content), ctx, "a taTitleLangTag value");
      try { return asn1.read.string(universal); }
      catch (e) { throw ctx.E("trustanchor/bad-title", "taTitleLangTag must be a well-formed UTF8String", e); }
    }) },
  ], { minTag: 1, maxTag: 2, unexpectedCode: "trustanchor/bad-info", orderCode: "trustanchor/bad-info" }),
], {
  assert: "sequence", code: "trustanchor/bad-info", what: "TrustAnchorInfo",
  build: function (m, ctx) {
    var f = m.fields;
    /** @internal `version` carries no value to surface: the reader refuses anything but an omitted
     * DEFAULT, so reaching the build at all means v1, which the record states outright. */
    void f.version;
    var pubKey = f.pubKey.value.result;
    var keyId = f.keyId.value;
    var certPath = f.certPath.present ? f.certPath.value.result : null;
    if (certPath !== null && certPath.certificate !== null) {
      _assertCertificateKeyMatches(certPath.certificate, pubKey, keyId, ctx);
    }
    var kept = [], excluded = [];
    if (f.exts.present) {
      intrinsic.forEach(f.exts.value.result, function (ext) {
        if (EXTS_EXCLUDED[ext.oid] === true) { guard.list.append(excluded, ext.oid); return; }
        guard.list.append(kept, ext);
      });
    }
    return {
      version: 1,
      pubKey: pubKey,
      keyId: keyId,
      taTitle: f.taTitle.present ? f.taTitle.value : null,
      certPath: certPath,
      exts: kept,
      excludedExtensions: excluded,
      taTitleLangTag: f.taTitleLangTag.present ? f.taTitleLangTag.value : null,
    };
  },
});

function _assertCertificateKeyMatches(certificate, pubKey, keyId, ctx) {
  if (!guard.crypto.constantTimeEqual(certificate.subjectPublicKeyInfo.bytes, pubKey.bytes)) {
    throw ctx.E("trustanchor/certificate-mismatch",
      "the certPath certificate's public key does not match pubKey (RFC 5914 sec. 2)");
  }
  var ski = null;
  intrinsic.forEach(certificate.extensions || [], function (ext) { if (ext.oid === OID_SKI) ski = ext.value; });
  if (ski === null) return;
  var decoded;
  try { decoded = CERT_EXT_DECODERS[OID_SKI](ski, ctx); }
  catch (e) {
    throw ctx.E("trustanchor/certificate-mismatch", "the certPath certificate's subjectKeyIdentifier does not read, so it cannot be compared to keyId (RFC 5914 sec. 2)", e);
  }
  if (!guard.crypto.constantTimeEqual(decoded, keyId)) {
    throw ctx.E("trustanchor/certificate-mismatch",
      "the certPath certificate's subjectKeyIdentifier does not match keyId (RFC 5914 sec. 2)");
  }
}

/** @internal RFC 5914 sec. 3's TrustAnchorChoice. The gap is the trap: there is no [0], the
 *  `certificate` arm is UNTAGGED, and both tagged arms are EXPLICIT. */
var TRUST_ANCHOR_CHOICE = schema.decode(function (n, ctx) {
  if (n.tagClass === "universal" && n.tagNumber === TAGS.SEQUENCE) {
    return { kind: "certificate", certificate: schema.walk(x509.certificateSchema, n, ctx).result,
      tbsCert: null, taInfo: null };
  }
  if (n.tagClass === "context" && n.tagNumber === 1) {
    if (!n.children || n.children.length !== 1) throw ctx.E("trustanchor/bad-anchor", "tbsCert [1] must wrap exactly one TBSCertificate");
    /** @internal `tbsCertificateSchema` is a decode leaf, so the walk answers with the record
     * itself rather than with a match object carrying it. */
    return { kind: "tbsCert", certificate: null,
      tbsCert: schema.walk(x509.tbsCertificateSchema, n.children[0], ctx), taInfo: null };
  }
  if (n.tagClass === "context" && n.tagNumber === 2) {
    if (!n.children || n.children.length !== 1) throw ctx.E("trustanchor/bad-anchor", "taInfo [2] must wrap exactly one TrustAnchorInfo");
    return { kind: "taInfo", certificate: null, tbsCert: null,
      taInfo: schema.walk(TRUST_ANCHOR_INFO, n.children[0], ctx).result };
  }
  throw ctx.E("trustanchor/bad-anchor",
    "a TrustAnchorChoice is an untagged Certificate, a [1] EXPLICIT TBSCertificate or a [2] EXPLICIT TrustAnchorInfo (RFC 5914 sec. 3)");
});

var TRUST_ANCHOR_LIST = schema.seqOf(TRUST_ANCHOR_CHOICE, {
  assert: "sequence", min: 1, code: "trustanchor/bad-list", what: "TrustAnchorList",
  build: function (m) { return { anchors: intrinsic.map(m.items, function (it) { return it.value; }) }; },
});

/**
 * @primitive  pki.schema.trustanchor.parse
 * @signature  pki.schema.trustanchor.parse(input, caps?) -> trustAnchorList
 * @since      0.8.13
 * @status     stable
 * @spec       RFC 5914
 * @related    pki.schema.trustanchor.parseInfo, pki.trust.parseTrustAnchorList, pki.trustanchor.build
 *
 * Parse a DER `Buffer` or a PEM (`TRUST ANCHOR LIST`) string into `{ anchors }`, one entry per
 * `TrustAnchorChoice`. Each entry names the arm it came from in `kind`, one of `"certificate"`,
 * `"tbsCert"` or `"taInfo"`, and carries that arm's decoded value with the other two `null`.
 *
 * A `taInfo` entry is `{ version, pubKey, keyId, taTitle, certPath, exts, excludedExtensions,
 * taTitleLangTag }`. `certPath` is the RFC 5914 section 2 `CertPathControls`, carrying the name the
 * anchor is known by and the constraints a relying party applies: `policySet`, `policyFlags`,
 * `nameConstr` and `pathLenConstraint`. `excludedExtensions` lists the identifiers of any
 * extensions the RFC excludes from `exts` that the anchor carried anyway; those are left out of
 * `exts`, because the RFC ignores them rather than refusing the anchor.
 *
 * Every rule RFC 5914 states is enforced: an empty `taName` is refused, a `policySet` carrying
 * policy qualifiers is refused, a negative `pathLenConstraint` is refused, `requireExplicitPolicy`
 * with no `policySet` is refused, and where `certPath` carries a certificate its subject, its
 * public key and its `subjectKeyIdentifier` must match `taName`, `pubKey` and `keyId`.
 *
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (number) -- decode caps for this parse. Each
 *     defaults to the matching `pki.C.LIMITS` figure and may only be set lower.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spki = await pki.key.export(pair.publicKey);
 *   var der = pki.trustanchor.build({ anchors: [{ taInfo: {
 *     pubKey: spki, keyId: Buffer.alloc(20, 1), certPath: { taName: "CN=Example Root" } } }] });
 *   pki.schema.trustanchor.parse(der).anchors[0].kind;   // -> "taInfo"
 */
var parse = pkix.makeParser({
  pemLabel: "TRUST ANCHOR LIST", PemError: PemError, ErrorClass: TrustAnchorError,
  prefix: "trustanchor", what: "trust anchor list", topSchema: TRUST_ANCHOR_LIST, ns: NS,
});

/**
 * @primitive  pki.schema.trustanchor.parseInfo
 * @signature  pki.schema.trustanchor.parseInfo(input, caps?) -> trustAnchorInfo
 * @since      0.8.13
 * @status     stable
 * @spec       RFC 5914 sec. 2
 * @related    pki.schema.trustanchor.parse
 *
 * Parse a bare `TrustAnchorInfo`, the structure the `[2]` arm of a `TrustAnchorChoice` wraps, for a
 * caller holding one on its own rather than inside a list. The result is the same record
 * `parse().anchors[i].taInfo` carries.
 *
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (number) -- decode caps for this parse.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spki = await pki.key.export(pair.publicKey);
 *   var list = pki.schema.trustanchor.parse(pki.trustanchor.build({ anchors: [{ taInfo: {
 *     pubKey: spki, keyId: Buffer.alloc(20, 1), certPath: { taName: "CN=Example Root" } } }] }));
 *   list.anchors[0].taInfo.certPath.taName.dn;   // -> "CN=Example Root"
 */
var parseInfo = pkix.makeParser({
  pemLabel: "TRUST ANCHOR INFO", PemError: PemError, ErrorClass: TrustAnchorError,
  prefix: "trustanchor", what: "trust anchor", topSchema: TRUST_ANCHOR_INFO, ns: NS,
});

/**
 * @primitive  pki.schema.trustanchor.pemDecode
 * @signature  pki.schema.trustanchor.pemDecode(text, label?) -> Buffer
 * @since      0.8.13
 * @status     stable
 * @spec       RFC 7468, RFC 5914
 * @related    pki.schema.trustanchor.pemEncode
 *
 * Extract the DER bytes from a PEM trust anchor list (default label `TRUST ANCHOR LIST`).
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = pki.trustanchor.build({ anchors: [{ taInfo: {
 *     pubKey: await pki.key.export(pair.publicKey), keyId: Buffer.alloc(20, 1),
 *     certPath: { taName: "CN=Example Root" } } }] });
 *   pki.schema.trustanchor.pemDecode(pki.schema.trustanchor.pemEncode(der)).equals(der);  // -> true
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "TRUST ANCHOR LIST", PemError); }

/**
 * @primitive  pki.schema.trustanchor.pemEncode
 * @signature  pki.schema.trustanchor.pemEncode(der, label?) -> string
 * @since      0.8.13
 * @status     stable
 * @spec       RFC 7468
 * @related    pki.schema.trustanchor.pemDecode
 *
 * Wrap DER bytes in a PEM trust anchor list envelope (default label `TRUST ANCHOR LIST`).
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = pki.trustanchor.build({ anchors: [{ taInfo: {
 *     pubKey: await pki.key.export(pair.publicKey), keyId: Buffer.alloc(20, 1),
 *     certPath: { taName: "CN=Example Root" } } }] });
 *   pki.schema.trustanchor.pemEncode(der).indexOf("-----BEGIN TRUST ANCHOR LIST-----");  // -> 0
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "TRUST ANCHOR LIST", PemError); }

/**
 * @internal A structural detector, mutually exclusive with the other formats: a TrustAnchorList is a
 * SEQUENCE whose every element is a context [1] or [2], or a universal SEQUENCE that is itself a
 * Certificate. The all-certificates case cannot be told from a bare certificate chain by shape
 * alone, so it is NOT detected: a list carrying only untagged arms is read by calling `parse`
 * explicitly. Detecting it would take `pki.schema.parse` on a Certificate away from `x509`.
 */
function matches(root) {
  var kids = pkix.rootSequenceChildren(root, 1);
  if (kids === null) return false;
  var sawTagged = false;
  for (var i = 0; i < kids.length; i++) {
    var k = kids[i];
    if (schema.isContextOneOf(k, [1, 2])) { sawTagged = true; continue; }
    if (schema.isUniversal(k, TAGS.SEQUENCE) && x509.matches(k)) continue;
    return false;
  }
  return sawTagged;
}

module.exports = {
  parse: parse,
  parseInfo: parseInfo,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  /** @internal The schemas the builder encodes against, so the writer and the reader cannot
   *  disagree about a shape. Not on the curated `pki.schema.trustanchor` surface. */
  trustAnchorListSchema: TRUST_ANCHOR_LIST,
  trustAnchorInfoSchema: TRUST_ANCHOR_INFO,
  policyFlagBits: POLICY_FLAG_BITS,
  excludedExtensionOids: EXTS_EXCLUDED,
  /** @internal The reader's own character count, so the writer bounds a title the same way rather
   *  than with a second reading of the SIZE constraint. */
  titleChars: titleChars,
};
