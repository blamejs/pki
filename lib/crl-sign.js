// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.crl
 * @nav        Signing
 * @title      CRLs
 * @intro The X.509 CRL producing side. `pki.crl.sign` builds a `TBSCertList`, signs it, and emits a
 *   `CertificateList` (RFC 5280 sec. 5) that `pki.schema.crl.parse`, `pki.path.crlChecker`, and OpenSSL
 *   all accept -- over any signature algorithm the toolkit registry resolves: RSA (PKCS#1 v1.5 / PSS),
 *   ECDSA, EdDSA, ML-DSA, SLH-DSA, and the composite (hybrid) arms. `pki.crl.verify` checks a CRL
 *   signature through the one path-validation signature engine, and `pki.crl.isRevoked` looks a serial up
 *   in a parsed CRL. Parsing lives at `pki.schema.crl.parse`.
 * @spec RFC 5280
 * @card Build, sign, and verify an X.509 CRL (RFC 5280 sec. 5) over any registry algorithm.
 */
//
// The signature matrix comes from the shared sign-scheme resolver (the same registry pki.x509.sign /
// pki.cms.sign drive), so a new algorithm is a registry row, never a branch here. The TBSCertList DER is
// assembled through the canonical asn1.build.* layer + the shared pki-build producing primitives; the
// strict schema-crl decoder round-trips it and OpenSSL cross-checks it. VERIFY composes the ONE
// path-validate.verifyCrlSignature engine pki.path.crlChecker uses -- there is no second, weaker verifier.

var asn1 = require("./asn1-der");
var oid = require("./oid");
var crlSchema = require("./schema-crl");
var x509Schema = require("./schema-x509");
var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var constants = require("./constants");
var pathValidate = require("./path-validate");

var CrlError = frameworkError.CrlError;
var NS = pkix.makeNS("crl", CrlError, oid);
var NAME_SCHEMA = pkix.name(NS);
var SPKI_SCHEMA = pkix.spki(NS);
var b = asn1.build;
var TAGS = asn1.TAGS;

// Two error factories (x509-sign pattern): `_err` takes a full crl/* code; `_signE` prepends the domain so
// the shared sign-scheme resolver/signer faults keep crl/* codes. Both are FACTORIES (guard.* and
// resolveSignScheme invoke them as E(code, msg) with no `new`).
function _err(code, message, cause) { return new CrlError(code, message, cause); }
function _signE(kind, message, cause) { return new CrlError("crl/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

// The shared PKIX producing primitives (lib/pki-build.js), bound to the crl namespace so they keep the
// frozen crl/* codes (Hard rule #5 -- one encode definition, no per-format hand-roll).
var _b = pkiBuild.makeBuilder({ ErrorClass: CrlError, prefix: "crl", O: O, NS: NS, NAME_SCHEMA: NAME_SCHEMA, SPKI_SCHEMA: SPKI_SCHEMA, EXT_DECODERS: {} });
var _encodeName = _b.encodeName, _isEmptyName = _b.isEmptyName, _reqDer = _b.reqDer,
  _assertValidSpki = _b.assertValidSpki, _assertValidExtension = _b.assertValidExtension,
  _timeDer = _b.timeDer, _ext = _b.ext, _extAki = _b.extAki, _spkiKeyId = _b.spkiKeyId,
  _serialInteger = _b.serialInteger, _encodeGeneralName = _b.encodeGeneralName,
  _encodeGeneralNames = _b.encodeGeneralNames, _certLikeFromSpki = _b.certLikeFromSpki,
  _assertSignatureVerifies = _b.assertSignatureVerifies;
// The RFC 5280 sec. 4.2.1 extension value decoders (shared with pki.schema.x509.parse), used to confirm an
// issuer certificate's keyUsage asserts cRLSign before a CRL is signed under it.
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;

var OID_SKI = O("subjectKeyIdentifier");

// CRLReason value<->name (RFC 5280 sec. 5.3.1). The value->name table is the frozen constants source;
// build the name->value reverse once at load. Value 7 is unused/reserved and absent from the table.
var CRL_REASON = constants.NAMES.CRL_REASON;
var REASON_BY_NAME = {};
Object.keys(CRL_REASON).forEach(function (v) { REASON_BY_NAME[CRL_REASON[v]] = Number(v); });

var KNOWN_CRL_EXT_KEYS = { authorityKeyIdentifier: 1, issuingDistributionPoint: 1, deltaCRLIndicator: 1, freshestCRL: 1, authorityInfoAccess: 1 };
var KNOWN_IDP_KEYS = { fullName: 1, onlyContainsUserCerts: 1, onlyContainsCACerts: 1, onlyContainsAttributeCerts: 1, indirectCRL: 1 };

// RFC 5280 sec. 5.2 -- the profile-fixed criticality of each recognized CRL extension. cRLNumber (5.2.3),
// authorityKeyIdentifier (5.2.1), freshestCRL (5.2.6), and authorityInfoAccess (5.2.7) MUST be non-critical;
// issuingDistributionPoint (5.2.5) and deltaCRLIndicator (5.2.4) MUST be critical. Enforced on the object
// form by construction AND on the pre-encoded escape hatch, so the hatch cannot bypass the profile.
var REQUIRED_CRITICALITY = {};
[["cRLNumber", false], ["authorityKeyIdentifier", false], ["freshestCRL", false], ["authorityInfoAccess", false],
  ["issuingDistributionPoint", true], ["deltaCRLIndicator", true]].forEach(function (r) { REQUIRED_CRITICALITY[O(r[0])] = r[1]; });

// RFC 5280 sec. 5.3 -- the profile-fixed criticality of each recognized crlEntryExtension: reasonCode (5.3.1)
// and invalidityDate (5.3.2) MUST be non-critical; certificateIssuer (5.3.3) MUST be critical.
var REQUIRED_ENTRY_CRITICALITY = {};
[["reasonCode", false], ["invalidityDate", false], ["certificateIssuer", true]].forEach(function (r) { REQUIRED_ENTRY_CRITICALITY[O(r[0])] = r[1]; });

// ---- shared numeric / reason / key-id helpers ------------------------------

// A non-negative INTEGER (0..MAX) of at most 20 content octets -- cRLNumber (sec. 5.2.3) and
// deltaCRLIndicator baseCRLNumber (sec. 5.2.4). b.integer has no size cap of its own (unlike serialInteger).
function _boundedInteger(v, label) {
  var n;
  if (typeof v === "bigint") n = v;
  else if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw _err("crl/bad-crl-number", label + " number must be a safe integer (pass a BigInt, hex string, or Buffer for a larger value)"); n = BigInt(v); }
  else if (typeof v === "string") { try { n = BigInt(v); } catch (e) { throw _err("crl/bad-crl-number", label + " string must be a decimal or 0x-hex integer", e); } }
  else if (Buffer.isBuffer(v)) { n = v.length ? BigInt("0x" + v.toString("hex")) : 0n; }
  else throw _err("crl/bad-crl-number", label + " must be a BigInt, integer, hex string, or Buffer");
  if (n < 0n) throw _err("crl/bad-crl-number", label + " must be non-negative (INTEGER 0..MAX, RFC 5280 sec. 5.2.3)");
  var tlv = b.integer(n);
  if (asn1.decode(tlv).content.length > 20) throw _err("crl/bad-crl-number", label + " must not exceed 20 octets (RFC 5280 sec. 5.2.3)");
  return { tlv: tlv, value: n };
}

// Decode a pre-encoded Extension's extnValue (the trailing OCTET STRING's content) to one well-formed DER
// node, or reject -- so a recognized extension's value is validated on the escape hatch, not emitted opaque.
function _extInner(node, label) {
  try { return asn1.decode(asn1.read.octetString(node.children[node.children.length - 1])); }
  catch (e) { throw _err("crl/bad-input", "pre-encoded " + label + " extension value is not valid DER", e); }
}
// A pre-encoded cRLNumber / baseCRLNumber value: a non-negative INTEGER of at most 20 octets, or reject.
function _requireBoundedInt(inner, label) {
  if (inner.tagClass !== "universal" || inner.tagNumber !== TAGS.INTEGER) throw _err("crl/bad-crl-number", "pre-encoded " + label + " value must be an INTEGER (RFC 5280 sec. 5.2.3 / 5.2.4)");
  var v = asn1.read.integer(inner);
  if (v < 0n) throw _err("crl/bad-crl-number", label + " must be non-negative (RFC 5280 sec. 5.2.3)");
  if (inner.content.length > 20) throw _err("crl/bad-crl-number", label + " must not exceed 20 octets (RFC 5280 sec. 5.2.3)");
  return v;
}

// Resolve a CRLReason to its numeric code: validate membership, reject 7/undefined, gate removeFromCRL(8)
// to a delta CRL. unspecified(0) is returned so the caller OMITS it (SHOULD be absent, sec. 5.3.1).
function _resolveReason(reason, isDelta) {
  var codeNum;
  if (typeof reason === "number") codeNum = reason;
  else if (typeof reason === "string") {
    if (!Object.prototype.hasOwnProperty.call(REASON_BY_NAME, reason)) throw _err("crl/bad-reason-code", "unknown CRLReason " + JSON.stringify(reason));
    codeNum = REASON_BY_NAME[reason];
  } else throw _err("crl/bad-reason-code", "reason must be a CRLReason name or number");
  if (!Object.prototype.hasOwnProperty.call(CRL_REASON, String(codeNum))) throw _err("crl/bad-reason-code", "undefined or reserved CRLReason " + codeNum + " (RFC 5280 sec. 5.3.1)");
  if (codeNum === 8 && !isDelta) throw _err("crl/bad-reason-code", "removeFromCRL(8) may appear only in a delta CRL (RFC 5280 sec. 5.3.1)");
  return codeNum;
}

// The AKI keyIdentifier from the issuer: an explicit Buffer, or true -> the issuer cert's subjectKeyIdentifier,
// else the SHA-1 of the issuer SPKI (RFC 5280 sec. 5.2.1 key-identifier method).
function _akiKeyId(val, ctx) {
  if (Buffer.isBuffer(val)) return val;
  if (val === true) {
    if (ctx.issuerCert) {
      var ski = (ctx.issuerCert.extensions || []).filter(function (e) { return e.oid === OID_SKI; })[0];
      if (ski) { try { return asn1.read.octetString(asn1.decode(ski.value)); } catch (_e) { /* fall through to re-derive from the issuer SPKI */ } }
    }
    return _spkiKeyId(ctx.issuerSpki);
  }
  throw _err("crl/bad-input", "authorityKeyIdentifier must be true (auto-derive from the issuer) or a Buffer key id");
}

// ---- CRL extension value encoders (sec. 5.2) -------------------------------

// IssuingDistributionPoint (sec. 5.2.5): critical; MUST NOT DER-encode to an empty SEQUENCE; at most one
// scope boolean TRUE; onlyContainsAttributeCerts MUST be FALSE; DEFAULT-FALSE booleans omitted.
function _idpValue(idp) {
  if (!idp || typeof idp !== "object" || Array.isArray(idp) || Buffer.isBuffer(idp)) throw _err("crl/bad-idp", "issuingDistributionPoint must be an object");
  Object.keys(idp).forEach(function (k) { if (!KNOWN_IDP_KEYS[k]) throw _err("crl/bad-idp", "unknown issuingDistributionPoint field " + JSON.stringify(k) + " (pass a pre-encoded Extension DER via the extensions array for an exotic field like onlySomeReasons)"); });
  if (idp.onlyContainsAttributeCerts === true) throw _err("crl/bad-idp", "onlyContainsAttributeCerts=TRUE is not permitted for a conforming CRL issuer (RFC 5280 sec. 5.2.5)");
  var children = [];
  if (idp.fullName != null) {
    var entries = Array.isArray(idp.fullName) ? idp.fullName : [idp.fullName];
    if (!entries.length) throw _err("crl/bad-idp", "issuingDistributionPoint fullName must carry at least one GeneralName");
    // distributionPoint [0] { fullName [0] IMPLICIT GeneralNames }
    children.push(b.contextConstructed(0, b.contextConstructed(0, Buffer.concat(entries.map(_encodeGeneralName)))));
  }
  var scopeTrue = 0;
  if (idp.onlyContainsUserCerts === true) { children.push(b.contextPrimitive(1, Buffer.from([0xff]))); scopeTrue++; }
  if (idp.onlyContainsCACerts === true) { children.push(b.contextPrimitive(2, Buffer.from([0xff]))); scopeTrue++; }
  if (idp.indirectCRL === true) children.push(b.contextPrimitive(4, Buffer.from([0xff])));
  if (scopeTrue > 1) throw _err("crl/bad-idp", "at most one of onlyContainsUserCerts / onlyContainsCACerts may be TRUE (RFC 5280 sec. 5.2.5)");
  if (!children.length) throw _err("crl/bad-idp", "issuingDistributionPoint MUST NOT be empty (RFC 5280 sec. 5.2.5)");
  return b.sequence(children);
}

// freshestCRL / CRLDistributionPoints (sec. 5.2.6): SEQUENCE OF DistributionPoint carrying only
// distributionPoint (reasons + cRLIssuer omitted). Accepts an array of GeneralName entries (one DP's
// fullName) or an array of { fullName } distribution points.
function _freshestValue(spec) {
  if (!Array.isArray(spec) || !spec.length) throw _err("crl/bad-input", "freshestCRL must be a non-empty array of GeneralNames (or { fullName } distribution points)");
  var dps = spec.every(function (e) { return e && typeof e === "object" && !Buffer.isBuffer(e) && Object.keys(e).length === 1 && e.fullName != null; })
    ? spec.map(function (dp) { return dp.fullName; })
    : [spec];
  return b.sequence(dps.map(function (fullName) {
    var entries = Array.isArray(fullName) ? fullName : [fullName];
    if (!entries.length) throw _err("crl/bad-input", "a freshestCRL distribution point must carry at least one GeneralName (GeneralNames is SIZE(1..MAX), RFC 5280 sec. 4.2.1.13)");
    return b.sequence([b.contextConstructed(0, b.contextConstructed(0, Buffer.concat(entries.map(_encodeGeneralName))))]);
  }));
}

// authorityInfoAccess (sec. 5.2.7): SEQUENCE OF AccessDescription, caIssuers-only. Accepts an array of
// GeneralName entries, each a caIssuers accessLocation.
function _aiaValue(spec) {
  if (!Array.isArray(spec) || !spec.length) throw _err("crl/bad-input", "authorityInfoAccess must be a non-empty array of caIssuers GeneralNames");
  var caIssuers = O("caIssuers");
  return b.sequence(spec.map(function (gn) { return b.sequence([b.oid(caIssuers), _encodeGeneralName(gn)]); }));
}

// The crlExtensions [0] set. Fixed per-extension criticality (sec. 5.2); at most one instance of each
// (sec. 5.2). `spec.extensions` is an object of the recognized keys OR an array of pre-encoded Extension
// DER (escape hatch for an extension the object form does not model). Returns { exts, isDelta }.
function _buildCrlExtensions(spec, ctx) {
  var out = [], seen = {}, isDelta = false;
  function push(oidName, critical, valueDer) {
    var id = O(oidName);
    if (seen[id]) throw _err("crl/bad-input", "duplicate CRL extension " + oidName + " (RFC 5280 sec. 5.2 -- at most one instance)");
    seen[id] = true;
    out.push(_ext(id, critical, valueDer));
  }
  var crlNumberVal = null;
  if (spec.crlNumber != null) { var cn = _boundedInteger(spec.crlNumber, "cRLNumber"); crlNumberVal = cn.value; push("cRLNumber", false, cn.tlv); }
  var ext = spec.extensions;
  if (ext == null) return { exts: out, isDelta: isDelta };
  if (Array.isArray(ext)) {
    var arrBase = null, arrCrlNum = null;
    ext.forEach(function (e, i) {
      var der = _reqDer(e, "extension");
      _assertValidExtension(der, i);
      var node = asn1.decode(der);
      var extnId = asn1.read.oid(node.children[0]);
      if (seen[extnId]) throw _err("crl/bad-input", "duplicate extension " + extnId + " (RFC 5280 sec. 5.2)");
      seen[extnId] = true;
      // RFC 5280 sec. 5.2 -- a recognized CRL extension is held to the profile even via the escape hatch: its
      // fixed criticality (assertValidExtension rejects an explicit critical=FALSE, so 3 children == critical,
      // 2 == non-critical) AND a well-formed value of the right type (INTEGER for cRLNumber/deltaCRLIndicator,
      // else a SEQUENCE), never emitted opaque.
      if (Object.prototype.hasOwnProperty.call(REQUIRED_CRITICALITY, extnId)) {
        if ((node.children.length === 3) !== REQUIRED_CRITICALITY[extnId]) {
          throw _err("crl/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension has the wrong criticality (RFC 5280 sec. 5.2 requires it " + (REQUIRED_CRITICALITY[extnId] ? "critical" : "non-critical") + ")");
        }
        var inner = _extInner(node, oid.name(extnId) || extnId);
        if (extnId === O("cRLNumber")) arrCrlNum = _requireBoundedInt(inner, "cRLNumber");
        else if (extnId === O("deltaCRLIndicator")) arrBase = _requireBoundedInt(inner, "deltaCRLIndicator baseCRLNumber");
        else if (inner.tagClass !== "universal" || inner.tagNumber !== TAGS.SEQUENCE) throw _err("crl/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension value must be a SEQUENCE (RFC 5280 sec. 5.2)");
      }
      if (extnId === O("deltaCRLIndicator")) isDelta = true;
      out.push(b.raw(der));
    });
    // RFC 5280 sec. 5.2.3 / 5.2.4 -- a delta CRL MUST carry a cRLNumber greater than its baseCRLNumber, whether
    // that cRLNumber is pre-encoded here or supplied via spec.crlNumber; the escape hatch is held to the same rule.
    if (isDelta) {
      // RFC 5280 sec. 5.2.6 -- freshestCRL MUST NOT appear in a delta CRL, including via the pre-encoded hatch.
      if (seen[O("freshestCRL")]) throw _err("crl/bad-input", "freshestCRL MUST NOT appear in a delta CRL (RFC 5280 sec. 5.2.6)");
      var eff = crlNumberVal != null ? crlNumberVal : arrCrlNum;
      if (eff == null) throw _err("crl/bad-input", "a delta CRL MUST include a cRLNumber (RFC 5280 sec. 5.2.3 / 5.2.4)");
      if (arrBase != null && eff <= arrBase) throw _err("crl/bad-crl-number", "a delta CRL's cRLNumber MUST be greater than its baseCRLNumber (RFC 5280 sec. 5.2.4)");
    }
    return { exts: out, isDelta: isDelta };
  }
  if (typeof ext !== "object") throw _err("crl/bad-input", "extensions must be an object or an array of pre-encoded Extension DER");
  Object.keys(ext).forEach(function (k) { if (!KNOWN_CRL_EXT_KEYS[k]) throw _err("crl/bad-input", "unknown CRL extension " + JSON.stringify(k) + " in the extensions spec; pass a pre-encoded Extension DER via the array form"); });
  isDelta = ext.deltaCRLIndicator != null;
  if (ext.authorityKeyIdentifier != null) push("authorityKeyIdentifier", false, _extAki(_akiKeyId(ext.authorityKeyIdentifier, ctx)));
  if (ext.issuingDistributionPoint != null) push("issuingDistributionPoint", true, _idpValue(ext.issuingDistributionPoint));
  if (ext.deltaCRLIndicator != null) {
    var base = _boundedInteger(ext.deltaCRLIndicator, "deltaCRLIndicator baseCRLNumber");
    // RFC 5280 sec. 5.2.3 / 5.2.4 -- a conforming delta CRL MUST carry a cRLNumber (sec. 5.2.3 requires it in
    // every CRL), and that cRLNumber MUST be greater than the BaseCRLNumber it is built against (sec. 5.2.4).
    if (crlNumberVal == null) throw _err("crl/bad-input", "a delta CRL MUST include a cRLNumber (set spec.crlNumber) (RFC 5280 sec. 5.2.3 / 5.2.4)");
    if (crlNumberVal <= base.value) throw _err("crl/bad-crl-number", "a delta CRL's cRLNumber (" + crlNumberVal + ") MUST be greater than its baseCRLNumber (" + base.value + ") (RFC 5280 sec. 5.2.4)");
    push("deltaCRLIndicator", true, base.tlv);
  }
  if (ext.freshestCRL != null) {
    if (isDelta) throw _err("crl/bad-input", "freshestCRL MUST NOT appear in a delta CRL (RFC 5280 sec. 5.2.6)");
    push("freshestCRL", false, _freshestValue(ext.freshestCRL));
  }
  if (ext.authorityInfoAccess != null) push("authorityInfoAccess", false, _aiaValue(ext.authorityInfoAccess));
  return { exts: out, isDelta: isDelta };
}

// The revokedCertificates entries (sec. 5.1.2.6 / 5.3). Each entry: serial + revocationDate + optional
// crlEntryExtensions (reasonCode ENUMERATED, invalidityDate GeneralizedTime-only, certificateIssuer, or a
// pre-encoded escape hatch). Returns { entries, anyExt } -- anyExt forces v2 (sec. 5.1.2.1).
function _buildRevoked(entryList, isDelta) {
  if (!Array.isArray(entryList)) throw _err("crl/bad-input", "revoked must be an array of revoked-certificate entries");
  var anyExt = false;
  var entries = entryList.map(function (e, idx) {
    if (!e || typeof e !== "object" || Buffer.isBuffer(e)) throw _err("crl/bad-input", "each revoked entry must be an object");
    if (e.serialNumber == null) throw _err("crl/bad-input", "revoked entry [" + idx + "] requires a serialNumber");
    var children = [_serialInteger(e.serialNumber), _timeDer(e.revocationDate, "revocationDate")];
    var entryExts = [], seen = {};
    function pushE(oidName, critical, valueDer) {
      var id = O(oidName);
      if (seen[id]) throw _err("crl/bad-input", "duplicate entry extension " + oidName + " in revoked entry [" + idx + "]");
      seen[id] = true;
      entryExts.push(_ext(id, critical, valueDer));
    }
    if (e.reason != null) {
      var codeNum = _resolveReason(e.reason, isDelta);
      if (codeNum !== 0) pushE("reasonCode", false, b.enumerated(BigInt(codeNum)));   // unspecified(0) omitted (sec. 5.3.1)
    }
    if (e.invalidityDate != null) {
      guard.time.assertValid(e.invalidityDate, _err, "crl/bad-input", "invalidityDate");
      // sec. 5.3.2 -- ALWAYS GeneralizedTime (never the UTCTime cutover), no fractional seconds.
      pushE("invalidityDate", false, b.generalizedTime(e.invalidityDate));
    }
    if (e.certificateIssuer != null) pushE("certificateIssuer", true, _encodeGeneralNames(Array.isArray(e.certificateIssuer) ? e.certificateIssuer : [e.certificateIssuer]));
    if (e.extensions != null) {
      if (!Array.isArray(e.extensions)) throw _err("crl/bad-input", "revoked entry [" + idx + "] extensions must be an array of pre-encoded Extension DER");
      e.extensions.forEach(function (x, j) {
        var der = _reqDer(x, "entry extension");
        _assertValidExtension(der, j);
        var xnode = asn1.decode(der);
        var extnId = asn1.read.oid(xnode.children[0]);
        if (seen[extnId]) throw _err("crl/bad-input", "duplicate entry extension " + extnId + " in revoked entry [" + idx + "]");
        seen[extnId] = true;
        // RFC 5280 sec. 5.3 -- a recognized entry extension is held to the profile even via the escape hatch:
        // its fixed criticality AND a well-formed value of the right type (reasonCode an ENUMERATED in the
        // legal set, invalidityDate a GeneralizedTime, certificateIssuer a non-empty GeneralNames SEQUENCE).
        if (Object.prototype.hasOwnProperty.call(REQUIRED_ENTRY_CRITICALITY, extnId)) {
          if ((xnode.children.length === 3) !== REQUIRED_ENTRY_CRITICALITY[extnId]) throw _err("crl/bad-input", "pre-encoded entry extension " + (oid.name(extnId) || extnId) + " has the wrong criticality (RFC 5280 sec. 5.3 requires it " + (REQUIRED_ENTRY_CRITICALITY[extnId] ? "critical" : "non-critical") + ")");
          var einner = _extInner(xnode, oid.name(extnId) || extnId);
          if (extnId === O("reasonCode")) {
            if (einner.tagClass !== "universal" || einner.tagNumber !== TAGS.ENUMERATED) throw _err("crl/bad-reason-code", "pre-encoded reasonCode value must be an ENUMERATED (RFC 5280 sec. 5.3.1)");
            var rc = asn1.read.enumerated(einner);
            if (!Object.prototype.hasOwnProperty.call(CRL_REASON, rc.toString())) throw _err("crl/bad-reason-code", "pre-encoded reasonCode " + rc + " is undefined or reserved (RFC 5280 sec. 5.3.1)");
            if (rc === 8n && !isDelta) throw _err("crl/bad-reason-code", "removeFromCRL(8) may appear only in a delta CRL (RFC 5280 sec. 5.3.1)");
          } else if (extnId === O("invalidityDate")) {
            if (einner.tagClass !== "universal" || einner.tagNumber !== TAGS.GENERALIZED_TIME) throw _err("crl/bad-input", "pre-encoded invalidityDate value must be a GeneralizedTime (RFC 5280 sec. 5.3.2)");
            try { asn1.read.time(einner); } catch (e) { throw _err("crl/bad-input", "pre-encoded invalidityDate is not a well-formed GeneralizedTime (RFC 5280 sec. 5.3.2)", e); }
          } else if (extnId === O("certificateIssuer")) {
            if (einner.tagClass !== "universal" || einner.tagNumber !== TAGS.SEQUENCE || !einner.children || !einner.children.length) throw _err("crl/bad-input", "pre-encoded certificateIssuer value must be a non-empty GeneralNames SEQUENCE (RFC 5280 sec. 5.3.3)");
            einner.children.forEach(function (gn) { if (gn.tagClass !== "context") throw _err("crl/bad-input", "pre-encoded certificateIssuer must be a GeneralNames SEQUENCE of context-tagged GeneralName choices (RFC 5280 sec. 5.3.3)"); });
          }
        }
        entryExts.push(b.raw(der));
      });
    }
    if (entryExts.length) { anyExt = true; children.push(b.sequence(entryExts)); }
    return b.sequence(children);
  });
  return { entries: entries, anyExt: anyExt };
}

// ---- the primitives --------------------------------------------------------

function _parseIssuerCert(cert) {
  var parsed = (Buffer.isBuffer(cert) || typeof cert === "string") ? x509Schema.parse(cert) : cert;
  if (!parsed || !parsed.tbsBytes || !parsed.subjectPublicKeyInfo) throw _err("crl/bad-input", "issuer.cert must be a certificate DER/PEM or a parsed certificate");
  return parsed;
}

// RFC 5280 sec. 4.2.1.3 -- a certificate whose key signs CRLs asserts the cRLSign keyUsage bit. When the
// issuer certificate carries a keyUsage extension it MUST include cRLSign, or the CRL it signs is rejected
// by a conforming relying party (pki.path.crlChecker included). Mirrors x509-sign's keyCertSign gate; a
// certificate with no keyUsage extension is unrestricted.
function _assertIssuerCanSignCrl(issuerCert) {
  var kuExt = (issuerCert.extensions || []).filter(function (e) { return e.oid === O("keyUsage"); })[0];
  if (!kuExt) return;
  var ku;
  try { ku = EXT_DECODERS[O("keyUsage")](kuExt.value); }
  catch (e) { if (e instanceof CrlError) throw e; throw _err("crl/bad-input", "the issuer certificate keyUsage is malformed", e); }
  if (ku.cRLSign !== true) throw _err("crl/bad-input", "the issuer certificate keyUsage does not assert cRLSign -- it cannot sign CRLs (RFC 5280 sec. 4.2.1.3)");
}

function _sign(spec, issuer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("crl/bad-input", "the CRL spec must be an object");
  issuer = issuer || {};
  if (issuer.key == null) throw _err("crl/bad-input", "a signing key (issuer.key, a PKCS#8 private key) is required");

  // Resolve the issuer name + signing-key SPKI. `{ cert }` supplies both; else `{ name|spec.issuer, publicKey }`.
  var issuerDer, issuerSpki, issuerCert = null;
  if (issuer.cert != null) {
    issuerCert = _parseIssuerCert(issuer.cert);
    _assertIssuerCanSignCrl(issuerCert);
    issuerDer = pkiBuild.tbsNameField(issuerCert, "subject");
    issuerSpki = issuerCert.subjectPublicKeyInfo.bytes;
  } else {
    issuerSpki = _reqDer(issuer.publicKey, "issuer.publicKey (the issuer SPKI DER)");
    _assertValidSpki(issuerSpki, "issuer.publicKey");
    var dnSource = issuer.name != null ? issuer.name : spec.issuer;
    if (dnSource == null) throw _err("crl/bad-issuer", "an issuer distinguished name is required (issuer.name or spec.issuer) when no issuer.cert is given");
    issuerDer = _encodeName(dnSource);
  }
  // RFC 5280 sec. 5.1.2.3 -- the issuer MUST be a non-empty distinguished name.
  if (_isEmptyName(issuerDer)) throw _err("crl/bad-issuer", "issuer must be a non-empty distinguished name (RFC 5280 sec. 5.1.2.3)");

  // thisUpdate (required) + nextUpdate (optional; MUST NOT precede thisUpdate). _timeDer validates each date
  // and applies the RFC 5280 sec. 5.1.2.4/.5 UTCTime<=2049-else-GeneralizedTime cutover.
  if (spec.thisUpdate == null) throw _err("crl/bad-input", "thisUpdate is required (RFC 5280 sec. 5.1.2.4)");
  var thisU = _timeDer(spec.thisUpdate, "thisUpdate");
  var nextU = null;
  if (spec.nextUpdate != null) {
    nextU = _timeDer(spec.nextUpdate, "nextUpdate");
    // allow:nan-date-comparison-unguarded -- both operands are guard.time.assertValid'd via _timeDer on the
    // two lines above (thisUpdate + nextUpdate), so an Invalid Date throws before this comparison.
    if (spec.nextUpdate.getTime() < spec.thisUpdate.getTime()) throw _err("crl/bad-input", "nextUpdate must not be before thisUpdate (RFC 5280 sec. 5.1.2.5)");
  }

  var extResult = _buildCrlExtensions(spec, { issuerCert: issuerCert, issuerSpki: issuerSpki });
  var crlExts = extResult.exts;
  var revoked = spec.revoked != null ? _buildRevoked(spec.revoked, extResult.isDelta) : { entries: [], anyExt: false };
  // RFC 5280 sec. 5.1.2.1 -- v2 iff any CRL or entry extension is present, else v1 (version omitted).
  var version = (crlExts.length || revoked.anyExt) ? 2 : 1;

  // The signature scheme resolves from the SIGNING key's SPKI algorithm (the whole registry, for free).
  var scheme = signScheme.resolveSignScheme(_certLikeFromSpki(issuerSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  var tbsChildren = [];
  if (version === 2) tbsChildren.push(b.integer(1n));   // bare INTEGER(1), NOT a [0] EXPLICIT tag like a certificate
  tbsChildren.push(scheme.sigAlgId);                    // signature == signatureAlgorithm (sec. 5.1.1.2), single source
  tbsChildren.push(issuerDer);
  tbsChildren.push(thisU);
  if (nextU) tbsChildren.push(nextU);
  if (revoked.entries.length) tbsChildren.push(b.sequence(revoked.entries));   // omit the field when empty (sec. 5.1.2.6)
  if (crlExts.length) tbsChildren.push(b.explicit(0, b.sequence(crlExts)));    // crlExtensions [0] EXPLICIT
  var tbsDer = b.sequence(tbsChildren);

  return signScheme.signOverTbs(scheme, issuer.key, tbsDer, _signE).then(function (sig) {
    // The signature MUST verify under the issuer public key before returning, or the CRL would be rejected
    // downstream (composite returns a promise; the classical/PQC path throws synchronously on a mismatch).
    return Promise.resolve(_assertSignatureVerifies(tbsDer, sig, issuerSpki, scheme)).then(function () {
      var crlDer = b.sequence([tbsDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? crlSchema.pemEncode(crlDer, "X509 CRL") : crlDer;
    });
  }, function (e) {
    if (e instanceof CrlError) throw e;
    throw _err("crl/bad-input", "signing the CRL failed -- the signing key does not match the resolved algorithm or is invalid", e);
  });
}

/**
 * @primitive pki.crl.sign
 * @signature pki.crl.sign(spec, issuer, opts?) -> Promise<Buffer|string>
 * @since 0.3.9
 * @status experimental
 * @spec RFC 5280 sec. 5, RFC 9882, RFC 9814
 * @defends crl-forgery (CWE-347)
 * @related pki.schema.crl.parse, pki.crl.verify, pki.path.crlChecker
 *
 * Build, sign, and DER-encode an X.509 certificate revocation list. `spec` describes the CRL --
 * `thisUpdate` / `nextUpdate` (`Date`s), an optional `crlNumber`, a `revoked` array (each entry a
 * `serialNumber` + `revocationDate` with an optional `reason`, `invalidityDate`, or `certificateIssuer`),
 * and an optional `extensions` object (`authorityKeyIdentifier`, `issuingDistributionPoint`,
 * `deltaCRLIndicator`, `freshestCRL`, `authorityInfoAccess`) or an array of pre-encoded `Extension` DER.
 * `issuer` is the signing side: `{ cert, key }` takes the issuer DN + SPKI from a CA certificate;
 * `{ name, publicKey, key }` (or `spec.issuer` + `{ publicKey, key }`) supplies them explicitly. The
 * signature algorithm is resolved from the signing key, so every algorithm the toolkit signs with (RSA
 * PKCS#1 v1.5 / PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, composite) is available without a per-algorithm branch.
 *
 * The version is derived from the field set (v2 when any CRL or entry extension is present, else v1). The
 * outer `signatureAlgorithm` is emitted from the same source as `tbsCertList.signature` (sec. 5.1.1.2); an
 * empty revocation list omits `revokedCertificates` rather than emitting an empty SEQUENCE (sec. 5.1.2.6);
 * `reasonCode` is an ENUMERATED and `invalidityDate` is always GeneralizedTime (sec. 5.3.1/5.3.2);
 * per-extension criticality is fixed by the RFC; and the produced signature is verified under the issuer
 * key before return. A violation throws a typed `CrlError`.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `X509 CRL` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS rather than PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var der = await pki.crl.sign({
 *     thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"),
 *     crlNumber: 7n,
 *     revoked: [{ serialNumber: 0x1234n, revocationDate: new Date("2026-01-15T00:00:00Z"), reason: "keyCompromise" }],
 *     extensions: { authorityKeyIdentifier: true },
 *   }, { cert: signerCertDer, key: signerKeyPkcs8 });
 *   pki.schema.crl.parse(der).revokedCertificates[0].serialNumberHex;   // "1234"
 */
function sign(spec, issuer, opts) { return Promise.resolve().then(function () { return _sign(spec, issuer, opts); }); }

function _coerceCrl(crl) {
  if (Buffer.isBuffer(crl) || typeof crl === "string") return crlSchema.parse(crl);
  if (crl && typeof crl === "object" && crl.tbsBytes && crl.signatureValue && crl.signatureAlgorithm) return crl;
  throw _err("crl/bad-input", "crl must be a CRL DER Buffer, a PEM string, or a parsed CRL (from pki.schema.crl.parse)");
}

function _resolveIssuerSpki(issuer) {
  if (issuer == null) throw _err("crl/bad-input", "an issuer is required to verify a CRL");
  if (Buffer.isBuffer(issuer)) { _assertValidSpki(issuer, "issuer SPKI"); return issuer; }
  if (issuer.cert != null) return _parseIssuerCert(issuer.cert).subjectPublicKeyInfo.bytes;
  if (issuer.publicKey != null) { var spki = _reqDer(issuer.publicKey, "issuer.publicKey"); _assertValidSpki(spki, "issuer.publicKey"); return spki; }
  if (issuer.subjectPublicKeyInfo && issuer.subjectPublicKeyInfo.bytes) return issuer.subjectPublicKeyInfo.bytes;   // a parsed certificate
  throw _err("crl/bad-input", "issuer must be { cert }, { publicKey } (SPKI DER), or a raw SPKI Buffer");
}

/**
 * @primitive pki.crl.verify
 * @signature pki.crl.verify(crl, issuer) -> Promise<boolean>
 * @since 0.3.9
 * @status experimental
 * @spec RFC 5280 sec. 5.1.1.3, RFC 9814
 * @defends crl-signature-bypass (CWE-347)
 * @related pki.crl.sign, pki.path.crlChecker, pki.schema.crl.parse
 *
 * Verify a CRL's signature over its exact parsed `tbsCertList` bytes under the issuer public key. `crl`
 * is a DER `Buffer`, a PEM string, or a parsed CRL; `issuer` is `{ cert }` (DER/PEM/parsed), `{ publicKey }`
 * (SPKI DER), or a raw SPKI `Buffer`. Verification composes the one path-validation signature engine
 * `pki.path.crlChecker` uses -- the same algorithm-confusion (RFC 9814 sec. 4 key-OID == sig-OID) and
 * EdDSA low-order-point gates -- so there is no second, weaker CRL verifier. It fails closed to `false` on
 * any resolution, import, or verification fault; malformed input throws a typed `CrlError`. This checks the
 * signature only -- issuer authorization, currency, and distribution-point scope are `pki.path.crlChecker`.
 *
 * @example
 *   var ok = await pki.crl.verify(crlDer, { publicKey: signerSpki });   // true / false
 */
function verify(crl, issuer) { return Promise.resolve().then(function () { return _verify(crl, issuer); }); }
function _verify(crl, issuer) {
  var parsed = _coerceCrl(crl);
  var spki = _resolveIssuerSpki(issuer);
  return pathValidate.verifyCrlSignature(parsed, { workingPublicKey: spki });
}

function _serialHexOf(serial) {
  var v;
  if (typeof serial === "bigint") v = serial;
  else if (typeof serial === "number") { if (!Number.isSafeInteger(serial)) throw _err("crl/bad-input", "serialNumber number must be a safe integer (pass a BigInt, hex string, or Buffer)"); v = BigInt(serial); }
  else if (typeof serial === "string") { try { v = BigInt(serial); } catch (e) { throw _err("crl/bad-input", "serialNumber string must be a decimal or 0x-hex integer", e); } }
  else if (Buffer.isBuffer(serial)) { v = serial.length ? BigInt("0x" + serial.toString("hex")) : 0n; }
  else throw _err("crl/bad-input", "serialNumber must be a BigInt, integer, hex string, or Buffer");
  if (v <= 0n) throw _err("crl/bad-input", "serialNumber must be a positive integer");
  // Match schema-crl's serialNumberHex: the DER INTEGER content octets (preserving sign padding).
  return asn1.decode(b.integer(v)).content.toString("hex");
}

/**
 * @primitive pki.crl.isRevoked
 * @signature pki.crl.isRevoked(crl, serialNumber) -> entry | null
 * @since 0.3.9
 * @status experimental
 * @spec RFC 5280 sec. 5.1.2.6
 * @related pki.crl.verify, pki.schema.crl.parse
 *
 * Look a certificate serial number up in a CRL's `revokedCertificates` list. `crl` is a DER `Buffer`, a
 * PEM string, or a parsed CRL; `serialNumber` is a `BigInt`, a safe integer, a decimal / `0x`-hex string,
 * or a magnitude `Buffer`. Returns the matching revoked-certificate entry (`{ serialNumber, serialNumberHex,
 * revocationDate, crlEntryExtensions }`) or `null` when the serial is not listed. A structural lookup only --
 * it does NOT verify the CRL signature or its currency; call `pki.crl.verify` / `pki.path.crlChecker` for that.
 *
 * @example
 *   pki.crl.isRevoked(crlDer, 0x1234n) ? "revoked" : "not listed";
 */
function isRevoked(crl, serialNumber) {
  var parsed = _coerceCrl(crl);
  var hex = _serialHexOf(serialNumber);
  for (var i = 0; i < parsed.revokedCertificates.length; i++) {
    if (parsed.revokedCertificates[i].serialNumberHex === hex) return parsed.revokedCertificates[i];
  }
  return null;
}

module.exports = { sign: sign, verify: verify, isRevoked: isRevoked };
