// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.crl
 * @nav        Signing
 * @title      CRLs
 * @fullname   CRLs (certificate revocation lists): read, sign and shard
 * @intro The X.509 CRL producing side. `pki.crl.sign` builds a `TBSCertList`, signs it, and emits a
 *   `CertificateList` (RFC 5280 sec. 5) that `pki.schema.crl.parse`, `pki.path.crlChecker`, and OpenSSL
 *   all accept, over any signature algorithm the toolkit registry resolves: RSA (PKCS#1 v1.5 / PSS),
 *   ECDSA, EdDSA, ML-DSA, SLH-DSA, and the composite (hybrid) arms. `pki.crl.verify` checks a CRL
 *   signature through the one path-validation signature engine, and `pki.crl.isRevoked` looks a serial up
 *   in a parsed CRL. Parsing lives at `pki.schema.crl.parse`.
 * @spec RFC 5280
 * @card Build, sign, and verify an X.509 CRL (RFC 5280 sec. 5) over any registry algorithm.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var crlSchema = require("./schema-crl");
var x509Schema = require("./schema-x509");
var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var frameworkError = require("./framework-error");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
var pkiBuild = require("./pki-build");
var constants = require("./constants");
require("./path-validate");
var crlVerify = require("./crl-verify");

var CrlError = frameworkError.CrlError;
var NS = pkix.makeNS("crl", CrlError, oid);
var NAME_SCHEMA = pkix.name(NS);
var SPKI_SCHEMA = pkix.spki(NS);
var b = asn1.build;
var TAGS = asn1.TAGS;

function _err(code, message, cause) { return new CrlError(code, message, cause); }
function _signE(kind, message, cause) { return new CrlError("crl/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var _b = pkiBuild.makeBuilder({ ErrorClass: CrlError, prefix: "crl", O: O, NS: NS, NAME_SCHEMA: NAME_SCHEMA, SPKI_SCHEMA: SPKI_SCHEMA, EXT_DECODERS: {} });
var _encodeName = _b.encodeName, _isEmptyName = _b.isEmptyName, _reqDer = _b.reqDer,
  _assertValidSpki = _b.assertValidSpki, _assertValidExtension = _b.assertValidExtension,
  _timeDer = _b.timeDer, _ext = _b.ext, _extAki = _b.extAki, _spkiKeyId = _b.spkiKeyId,
  _serialInteger = _b.serialInteger, _encodeGeneralName = _b.encodeGeneralName,
  _certLikeFromSpki = _b.certLikeFromSpki, _assertSignatureVerifies = _b.assertSignatureVerifies;
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;

var OID_SKI = O("subjectKeyIdentifier");

var CRL_REASON = constants.NAMES.CRL_REASON;
var REASON_BY_NAME = intrinsic.create(null);
Object.keys(CRL_REASON).forEach(function (v) { REASON_BY_NAME[CRL_REASON[v]] = Number(v); });

var KNOWN_CRL_EXT_KEYS = { authorityKeyIdentifier: 1, issuingDistributionPoint: 1, deltaCRLIndicator: 1, freshestCRL: 1, authorityInfoAccess: 1 };
var KNOWN_SPEC_KEYS = {
  issuer: 1, thisUpdate: 1, nextUpdate: 1, revoked: 1, crlNumber: 1, extensions: 1,
};
var KNOWN_SPEC_KEYS_ISSUER_NAMED = {
  thisUpdate: 1, nextUpdate: 1, revoked: 1, crlNumber: 1, extensions: 1,
};
var KNOWN_ISSUER_CERT_KEYS = { key: 1, cert: 1 };
var KNOWN_ISSUER_EXPLICIT_KEYS = { key: 1, name: 1, publicKey: 1 };
var KNOWN_SIGN_OPTS = { digestAlgorithm: 1, pem: 1, pss: 1 };

var KNOWN_IDP_KEYS = { fullName: 1, onlyContainsUserCerts: 1, onlyContainsCACerts: 1, onlyContainsAttributeCerts: 1, indirectCRL: 1 };

var KNOWN_REVOKED_KEYS = {
  serialNumber: 1, revocationDate: 1, reason: 1, invalidityDate: 1, certificateIssuer: 1, extensions: 1,
};

var REQUIRED_CRITICALITY = {};
[["cRLNumber", false], ["authorityKeyIdentifier", false], ["freshestCRL", false], ["authorityInfoAccess", false],
  ["issuingDistributionPoint", true], ["deltaCRLIndicator", true]].forEach(function (r) { REQUIRED_CRITICALITY[O(r[0])] = r[1]; });

var REQUIRED_ENTRY_CRITICALITY = {};
[["reasonCode", false], ["invalidityDate", false]].forEach(function (r) { REQUIRED_ENTRY_CRITICALITY[O(r[0])] = r[1]; });

var _CERT_ISSUER_DEFERRED = "certificateIssuer (indirect CRLs) is not yet supported -- pki.path.crlChecker skips a CRL carrying any critical entry extension other than reasonCode, so an indirect CRL would never be authoritative for revocation. Re-enabled once the checker processes certificateIssuer / indirect CRLs.";
var _INDIRECT_IDP_DEFERRED = "issuingDistributionPoint indirectCRL (indirect CRLs) is not yet supported -- pki.path.crlChecker skips a CRL whose IDP marks it indirect, so it would never be authoritative for revocation. Re-enabled once the checker processes indirect CRLs.";


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

function _extInner(node, label) {
  try { return asn1.decode(asn1.read.octetString(node.children[node.children.length - 1])); }
  catch (e) { throw _err("crl/bad-input", "pre-encoded " + label + " extension value is not valid DER", e); }
}
function _requireBoundedInt(inner, label) {
  if (inner.tagClass !== "universal" || inner.tagNumber !== TAGS.INTEGER) throw _err("crl/bad-crl-number", "pre-encoded " + label + " value must be an INTEGER (RFC 5280 sec. 5.2.3 / 5.2.4)");
  var v = asn1.read.integer(inner);
  if (v < 0n) throw _err("crl/bad-crl-number", label + " must be non-negative (RFC 5280 sec. 5.2.3)");
  if (inner.content.length > 20) throw _err("crl/bad-crl-number", label + " must not exceed 20 octets (RFC 5280 sec. 5.2.3)");
  return v;
}

function _resolveReason(reason, isDelta) {
  var codeNum;
  if (typeof reason === "number") codeNum = reason;
  else if (typeof reason === "string") {
    if (!_hasOwn(REASON_BY_NAME, guard.text.keyOf(reason))) throw _err("crl/bad-reason-code", "unknown CRLReason " + guard.text.showValue(reason));
    codeNum = REASON_BY_NAME[reason];
  } else throw _err("crl/bad-reason-code", "reason must be a CRLReason name or number");
  if (!_hasOwn(CRL_REASON, String(codeNum))) throw _err("crl/bad-reason-code", "undefined or reserved CRLReason " + codeNum + " (RFC 5280 sec. 5.3.1)");
  if (codeNum === 8 && !isDelta) throw _err("crl/bad-reason-code", "removeFromCRL(8) may appear only in a delta CRL (RFC 5280 sec. 5.3.1)");
  return codeNum;
}

function _akiKeyId(val, ctx) {
  if (guard.bytes.isByteSource(val)) return guard.bytes.snapshotSource(val, CrlError, "crl/bad-input", "the authorityKeyIdentifier keyIdentifier");
  if (val === true) {
    if (ctx.issuerCert) {
      var ski = (ctx.issuerCert.extensions || []).filter(function (e) { return e.oid === OID_SKI; })[0];
      if (ski) { try { return asn1.read.octetString(asn1.decode(ski.value)); } catch (_e) { } }   // allow:swallow-unverified -- a malformed issuer SKI is read as absent; the authorityKeyIdentifier keyIdentifier is then derived from the issuer public key
    }
    return _spkiKeyId(ctx.issuerSpki);
  }
  throw _err("crl/bad-input", "authorityKeyIdentifier must be true (auto-derive from the issuer) or a Buffer key id");
}


function _idpValue(idp) {
  if (!idp || typeof idp !== "object" || Array.isArray(idp) || Buffer.isBuffer(idp)) throw _err("crl/bad-idp", "issuingDistributionPoint must be an object");
  guard.identifier.assertKnownKeys(idp, KNOWN_IDP_KEYS, _err, "crl/bad-idp", function (k) {
    return "unknown issuingDistributionPoint field " + JSON.stringify(k) + " (pass a pre-encoded Extension DER via the extensions array for an exotic field like onlySomeReasons)";
  });
  if (idp.onlyContainsAttributeCerts === true) throw _err("crl/bad-idp", "onlyContainsAttributeCerts=TRUE is not permitted for a conforming CRL issuer (RFC 5280 sec. 5.2.5)");
  var children = [];
  if (idp.fullName != null) {
    var entries = Array.isArray(idp.fullName) ? pkiBuild.reqDenseArray(idp.fullName, "issuingDistributionPoint.fullName", _err, "crl/bad-idp") : [idp.fullName];
    if (!entries.length) throw _err("crl/bad-idp", "issuingDistributionPoint fullName must carry at least one GeneralName");
    children.push(b.contextConstructed(0, b.contextConstructed(0, Buffer.concat(entries.map(_encodeGeneralName)))));
  }
  var scopeTrue = 0;
  if (idp.onlyContainsUserCerts === true) { children.push(b.contextPrimitive(1, Buffer.from([0xff]))); scopeTrue++; }
  if (idp.onlyContainsCACerts === true) { children.push(b.contextPrimitive(2, Buffer.from([0xff]))); scopeTrue++; }
  if (idp.indirectCRL === true) throw _err("crl/bad-idp", _INDIRECT_IDP_DEFERRED);
  if (scopeTrue > 1) throw _err("crl/bad-idp", "at most one of onlyContainsUserCerts / onlyContainsCACerts may be TRUE (RFC 5280 sec. 5.2.5)");
  if (!children.length) throw _err("crl/bad-idp", "issuingDistributionPoint MUST NOT be empty (RFC 5280 sec. 5.2.5)");
  return b.sequence(children);
}

var _PRE_ENCODED_IDP_SCHEMA = pkix.issuingDistributionPoint("crl/bad-idp");
function _validatePreEncodedIdp(inner) {
  if (!inner.children || !inner.children.length) throw _err("crl/bad-idp", "pre-encoded issuingDistributionPoint MUST NOT be empty (RFC 5280 sec. 5.2.5)");
  var f = schema.walk(_PRE_ENCODED_IDP_SCHEMA, inner, NS).fields;
  ["onlyContainsUserCerts", "onlyContainsCACerts", "onlyContainsAttributeCerts"].forEach(function (name) {
    if (f[name].present && f[name].value !== true) throw _err("crl/bad-idp", "pre-encoded issuingDistributionPoint " + name + " encodes its DEFAULT FALSE, which DER omits (X.690 sec. 11.5)");
  });
  if (f.indirectCRL.present) throw _err("crl/bad-idp", _INDIRECT_IDP_DEFERRED);
  if (f.onlyContainsAttributeCerts.present) throw _err("crl/bad-idp", "onlyContainsAttributeCerts=TRUE is not permitted for a conforming CRL issuer (RFC 5280 sec. 5.2.5)");
  if (f.onlyContainsUserCerts.present && f.onlyContainsCACerts.present) throw _err("crl/bad-idp", "at most one of onlyContainsUserCerts / onlyContainsCACerts may be TRUE (RFC 5280 sec. 5.2.5)");
}

function _freshestValue(spec) {
  if (!Array.isArray(spec) || !spec.length) throw _err("crl/bad-input", "freshestCRL must be a non-empty array of GeneralNames (or { fullName } distribution points)");
  var dense = _b.reqDenseArray(spec, "freshestCRL");
  var dps = dense.every(function (e) { return e && typeof e === "object" && !Buffer.isBuffer(e) && Object.keys(e).length === 1 && e.fullName != null; })
    ? dense.map(function (dp) { return dp.fullName; })
    : [dense];
  return b.sequence(dps.map(function (fullName) {
    var entries = Array.isArray(fullName) ? _b.reqDenseArray(fullName, "a freshestCRL distribution point fullName") : [fullName];
    if (!entries.length) throw _err("crl/bad-input", "a freshestCRL distribution point must carry at least one GeneralName (GeneralNames is SIZE(1..MAX), RFC 5280 sec. 4.2.1.13)");
    return b.sequence([b.contextConstructed(0, b.contextConstructed(0, Buffer.concat(entries.map(_encodeGeneralName))))]);
  }));
}

function _aiaValue(spec) {
  if (!Array.isArray(spec) || !spec.length) throw _err("crl/bad-input", "authorityInfoAccess must be a non-empty array of caIssuers GeneralNames");
  var caIssuers = O("caIssuers");
  return b.sequence(spec.map(function (gn) { return b.sequence([b.oid(caIssuers), _encodeGeneralName(gn)]); }));
}

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
      if (_hasOwn(REQUIRED_CRITICALITY, extnId)) {
        if ((node.children.length === 3) !== REQUIRED_CRITICALITY[extnId]) {
          throw _err("crl/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension has the wrong criticality (RFC 5280 sec. 5.2 requires it " + (REQUIRED_CRITICALITY[extnId] ? "critical" : "non-critical") + ")");
        }
        var inner = _extInner(node, oid.name(extnId) || extnId);
        if (extnId === O("cRLNumber")) arrCrlNum = _requireBoundedInt(inner, "cRLNumber");
        else if (extnId === O("deltaCRLIndicator")) arrBase = _requireBoundedInt(inner, "deltaCRLIndicator baseCRLNumber");
        else {
          if (inner.tagClass !== "universal" || inner.tagNumber !== TAGS.SEQUENCE) throw _err("crl/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension value must be a SEQUENCE (RFC 5280 sec. 5.2)");
          if (extnId === O("issuingDistributionPoint")) _validatePreEncodedIdp(inner);
        }
      }
      if (extnId === O("deltaCRLIndicator")) isDelta = true;
      out.push(b.raw(der));
    });
    if (isDelta) {
      if (seen[O("freshestCRL")]) throw _err("crl/bad-input", "freshestCRL MUST NOT appear in a delta CRL (RFC 5280 sec. 5.2.6)");
      var eff = crlNumberVal != null ? crlNumberVal : arrCrlNum;
      if (eff == null) throw _err("crl/bad-input", "a delta CRL MUST include a cRLNumber (RFC 5280 sec. 5.2.3 / 5.2.4)");
      if (arrBase != null && eff <= arrBase) throw _err("crl/bad-crl-number", "a delta CRL's cRLNumber MUST be greater than its baseCRLNumber (RFC 5280 sec. 5.2.4)");
    }
    return { exts: out, isDelta: isDelta };
  }
  if (typeof ext !== "object") throw _err("crl/bad-input", "extensions must be an object or an array of pre-encoded Extension DER");
  guard.identifier.assertKnownKeys(ext, KNOWN_CRL_EXT_KEYS, _err, "crl/bad-input", function (k) {
    return "unknown CRL extension " + JSON.stringify(k) + " in the extensions spec; pass a pre-encoded Extension DER via the array form";
  });
  isDelta = ext.deltaCRLIndicator != null;
  if (ext.authorityKeyIdentifier != null) push("authorityKeyIdentifier", false, _extAki(_akiKeyId(ext.authorityKeyIdentifier, ctx)));
  if (ext.issuingDistributionPoint != null) push("issuingDistributionPoint", true, _idpValue(ext.issuingDistributionPoint));
  if (ext.deltaCRLIndicator != null) {
    var base = _boundedInteger(ext.deltaCRLIndicator, "deltaCRLIndicator baseCRLNumber");
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

function _buildRevoked(entryList, isDelta) {
  if (!Array.isArray(entryList)) throw _err("crl/bad-input", "revoked must be an array of revoked-certificate entries");
  var anyExt = false, seenSerials = {};
  var entries = _b.reqDenseArray(entryList, "revoked").map(function (e, idx) {
    if (!e || typeof e !== "object" || Buffer.isBuffer(e)) throw _err("crl/bad-input", "each revoked entry must be an object");
    guard.identifier.assertKnownKeys(e, KNOWN_REVOKED_KEYS, _err, "crl/bad-input", function (k) {
      return "unknown field " + JSON.stringify(k) + " in revoked entry [" + idx +
        "]; an entry is { serialNumber, revocationDate, reason?, invalidityDate?, extensions? }";
    });
    if (e.serialNumber == null) throw _err("crl/bad-input", "revoked entry [" + idx + "] requires a serialNumber");
    var serialTlv = _serialInteger(e.serialNumber);
    var serialKey = asn1.decode(serialTlv).content.toString("hex");
    if (seenSerials[serialKey]) throw _err("crl/bad-input", "revoked entry [" + idx + "] duplicates a serial number already listed in this CRL (RFC 5280 sec. 5.1.2.6)");
    seenSerials[serialKey] = true;
    var children = [serialTlv, _timeDer(e.revocationDate, "revocationDate")];
    var entryExts = [], seen = {};
    function pushE(oidName, critical, valueDer) {
      var id = O(oidName);
      if (seen[id]) throw _err("crl/bad-input", "duplicate entry extension " + oidName + " in revoked entry [" + idx + "]");
      seen[id] = true;
      entryExts.push(_ext(id, critical, valueDer));
    }
    if (e.reason != null) {
      var codeNum = _resolveReason(e.reason, isDelta);
      if (codeNum !== 0) pushE("reasonCode", false, b.enumerated(BigInt(codeNum)));
    }
    if (e.invalidityDate != null) {
      guard.time.assertValid(e.invalidityDate, _err, "crl/bad-input", "invalidityDate");
      pushE("invalidityDate", false, b.generalizedTime(e.invalidityDate));
    }
    if (e.certificateIssuer != null) throw _err("crl/bad-input", _CERT_ISSUER_DEFERRED);
    if (e.extensions != null) {
      if (!Array.isArray(e.extensions)) throw _err("crl/bad-input", "revoked entry [" + idx + "] extensions must be an array of pre-encoded Extension DER");
      e.extensions.forEach(function (x, j) {
        var der = _reqDer(x, "entry extension");
        _assertValidExtension(der, j);
        var xnode = asn1.decode(der);
        var extnId = asn1.read.oid(xnode.children[0]);
        if (seen[extnId]) throw _err("crl/bad-input", "duplicate entry extension " + extnId + " in revoked entry [" + idx + "]");
        seen[extnId] = true;
        if (extnId === O("certificateIssuer")) throw _err("crl/bad-input", _CERT_ISSUER_DEFERRED);
        if (_hasOwn(REQUIRED_ENTRY_CRITICALITY, extnId)) {
          if ((xnode.children.length === 3) !== REQUIRED_ENTRY_CRITICALITY[extnId]) throw _err("crl/bad-input", "pre-encoded entry extension " + (oid.name(extnId) || extnId) + " has the wrong criticality (RFC 5280 sec. 5.3 requires it " + (REQUIRED_ENTRY_CRITICALITY[extnId] ? "critical" : "non-critical") + ")");
          var einner = _extInner(xnode, oid.name(extnId) || extnId);
          if (extnId === O("reasonCode")) {
            if (einner.tagClass !== "universal" || einner.tagNumber !== TAGS.ENUMERATED) throw _err("crl/bad-reason-code", "pre-encoded reasonCode value must be an ENUMERATED (RFC 5280 sec. 5.3.1)");
            var rc = asn1.read.enumerated(einner);
            if (!_hasOwn(CRL_REASON, rc.toString())) throw _err("crl/bad-reason-code", "pre-encoded reasonCode " + rc + " is undefined or reserved (RFC 5280 sec. 5.3.1)");
            if (rc === 8n && !isDelta) throw _err("crl/bad-reason-code", "removeFromCRL(8) may appear only in a delta CRL (RFC 5280 sec. 5.3.1)");
          } else if (extnId === O("invalidityDate")) {
            if (einner.tagClass !== "universal" || einner.tagNumber !== TAGS.GENERALIZED_TIME) throw _err("crl/bad-input", "pre-encoded invalidityDate value must be a GeneralizedTime (RFC 5280 sec. 5.3.2)");
            try { asn1.read.time(einner); } catch (e) { throw _err("crl/bad-input", "pre-encoded invalidityDate is not a well-formed GeneralizedTime (RFC 5280 sec. 5.3.2)", e); }
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


function _parseIssuerCert(cert) {
  return guard.parsed.acceptDerived(cert, "certificate", x509Schema.parse, _err, "crl/bad-input", "issuer.cert");
}

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
  var byCert = issuer.cert != null, byName = issuer.name != null;
  guard.identifier.assertKnownKeys(spec, byCert || byName ? KNOWN_SPEC_KEYS_ISSUER_NAMED : KNOWN_SPEC_KEYS,
    _err, "crl/bad-input", function (k) {
      return "unknown CRL spec field " + JSON.stringify(k) +
        (k === "revokedCertificates" ? "; the producer reads `revoked` (the parser reports the same list as `revokedCertificates`)"
          : k === "issuer" ? "; the issuer argument already names one, through " + (byCert ? "issuer.cert" : "issuer.name") +
            ", and that is the name the CRL is signed under"
            : "");
    });
  guard.identifier.assertKnownKeys(issuer, byCert ? KNOWN_ISSUER_CERT_KEYS : KNOWN_ISSUER_EXPLICIT_KEYS,
    _err, "crl/bad-input", function (k) {
      return "unknown issuer field " + JSON.stringify(k) + " for the " + (byCert
        ? "certificate form; issuer.cert supplies the name and the public key, so they are not read here"
        : "explicit form; the issuer takes { key, name, publicKey }, or { key, cert } to take both from a certificate");
    });
  guard.identifier.assertKnownKeys(opts, KNOWN_SIGN_OPTS, _err, "crl/bad-input", "pki.crl.sign has an unknown option ");
  if (issuer.key == null) throw _err("crl/bad-input", "a signing key (issuer.key, a WebCrypto CryptoKey or a PKCS#8 private key DER/PEM) is required");

  var issuerDer, issuerSpki, issuerCert = null;
  if (byCert) {
    issuerCert = _parseIssuerCert(issuer.cert);
    _assertIssuerCanSignCrl(issuerCert);
    issuerDer = pkiBuild.tbsNameField(issuerCert, "subject");
    issuerSpki = issuerCert.subjectPublicKeyInfo.bytes;
  } else {
    issuerSpki = _reqDer(issuer.publicKey, "issuer.publicKey (the issuer SPKI DER)");
    _assertValidSpki(issuerSpki, "issuer.publicKey");
    var dnSource = byName ? issuer.name : spec.issuer;
    if (dnSource == null) throw _err("crl/bad-issuer", "an issuer distinguished name is required (issuer.name or spec.issuer) when no issuer.cert is given");
    issuerDer = _encodeName(dnSource);
  }
  if (_isEmptyName(issuerDer)) throw _err("crl/bad-issuer", "issuer must be a non-empty distinguished name (RFC 5280 sec. 5.1.2.3)");

  if (spec.thisUpdate == null) throw _err("crl/bad-input", "thisUpdate is required (RFC 5280 sec. 5.1.2.4)");
  var thisU = _timeDer(spec.thisUpdate, "thisUpdate");
  var nextU = null;
  if (spec.nextUpdate != null) {
    nextU = _timeDer(spec.nextUpdate, "nextUpdate");
    // allow:nan-date-comparison-unguarded -- both operands are guard.time.assertValid'd via _timeDer on the
    if (guard.time.instantOf(spec.nextUpdate) < guard.time.instantOf(spec.thisUpdate)) throw _err("crl/bad-input", "nextUpdate must not be before thisUpdate (RFC 5280 sec. 5.1.2.5)");
  }

  var extResult = _buildCrlExtensions(spec, { issuerCert: issuerCert, issuerSpki: issuerSpki });
  var crlExts = extResult.exts;
  var revoked = spec.revoked != null ? _buildRevoked(spec.revoked, extResult.isDelta) : { entries: [], anyExt: false };
  var version = (crlExts.length || revoked.anyExt) ? 2 : 1;

  var scheme = signScheme.resolveSignScheme(_certLikeFromSpki(issuerSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  var tbsChildren = [];
  if (version === 2) tbsChildren.push(b.integer(1n));
  tbsChildren.push(scheme.sigAlgId);
  tbsChildren.push(issuerDer);
  tbsChildren.push(thisU);
  if (nextU) tbsChildren.push(nextU);
  if (revoked.entries.length) tbsChildren.push(b.sequence(revoked.entries));
  if (crlExts.length) tbsChildren.push(b.explicit(0, b.sequence(crlExts)));
  var tbsDer = b.sequence(tbsChildren);

  return signScheme.signOverTbs(scheme, issuer.key, tbsDer, _signE).then(function (sig) {
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
 * @status stable
 * @spec RFC 5280 sec. 5, RFC 9882, RFC 9814
 * @defends crl-forgery (CWE-347)
 * @related pki.schema.crl.parse, pki.crl.verify, pki.path.crlChecker
 *
 * Build, sign, and DER-encode an X.509 certificate revocation list. `spec` describes the CRL:
 * `thisUpdate` / `nextUpdate` (`Date`s), an optional `crlNumber`, a `revoked` array (each entry a
 * `serialNumber` + `revocationDate` with an optional `reason` or `invalidityDate`),
 * and an optional `extensions` object (`authorityKeyIdentifier`, `issuingDistributionPoint`,
 * `deltaCRLIndicator`, `freshestCRL`, `authorityInfoAccess`) or an array of pre-encoded `Extension` DER.
 * `issuer` is the signing side: `{ cert, key }` takes the issuer DN + SPKI from a CA certificate;
 * `{ name, publicKey, key }` (or `spec.issuer` + `{ publicKey, key }`) supplies them explicitly. The
 * signature algorithm is resolved from the signing key, so every algorithm the toolkit signs with (RSA
 * PKCS#1 v1.5 / PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, composite) is available without a per-algorithm branch.
 *
 * The version is derived from the field set (v2 when any CRL or entry extension is present, else v1). The
 * outer `signatureAlgorithm` is emitted from the same source as `tbsCertList.signature` (sec. 5.1.1.2); an
 * empty revocation list omits `revokedCertificates` instead of emitting an empty SEQUENCE (sec. 5.1.2.6);
 * `reasonCode` is an ENUMERATED and `invalidityDate` is always GeneralizedTime (sec. 5.3.1/5.3.2);
 * per-extension criticality is fixed by the RFC; and the produced signature is verified under the issuer
 * key before return. A violation throws a typed `CrlError`; where the spec carries raw DER (an issuer
 * `Name` Buffer or a pre-encoded `Extension`), a malformed leaf inside those bytes throws `Asn1Error`.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `X509 CRL` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS instead of PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } },
 *     { key: signerKeyPkcs8 });
 *   var der = await pki.crl.sign({
 *     thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"),
 *     crlNumber: 7n,
 *     revoked: [{ serialNumber: 0x1234n, revocationDate: new Date("2026-01-15T00:00:00Z"), reason: "keyCompromise" }],
 *     extensions: { authorityKeyIdentifier: true },
 *   }, { cert: signerCertDer, key: signerKeyPkcs8 });
 *   pki.schema.crl.parse(der).revokedCertificates[0].serialNumberHex;   // "1234"
 */
function sign(spec, issuer, opts) {
  return guard.bytes.fixedCall(CrlError, "crl/bad-input", [
    [spec, "the CRL spec"], [issuer, "the issuer"], [opts, "pki.crl.sign options"],
  ], _sign);
}

function _coerceCrl(crl) {
  return guard.parsed.acceptDerived(crl, "crl", crlSchema.parse, _err, "crl/bad-input", "the CRL");
}

function _resolveIssuer(issuer) {
  if (issuer == null) throw _err("crl/bad-input", "an issuer is required to verify a CRL");
  if (guard.bytes.isByteSource(issuer)) { var _isp = guard.bytes.source(issuer, CrlError, "crl/bad-input", "issuer SPKI"); _assertValidSpki(_isp, "issuer SPKI"); return { spki: _isp, cert: null }; }
  if (issuer.cert != null) { var ic = _parseIssuerCert(issuer.cert); return { spki: ic.subjectPublicKeyInfo.bytes, cert: ic }; }
  if (issuer.publicKey != null) { var spki = _reqDer(issuer.publicKey, "issuer.publicKey"); _assertValidSpki(spki, "issuer.publicKey"); return { spki: spki, cert: null }; }
  if (issuer.subjectPublicKeyInfo && issuer.subjectPublicKeyInfo.bytes) {
    var pc = _parseIssuerCert(issuer);
    return { spki: pc.subjectPublicKeyInfo.bytes, cert: pc };
  }
  throw _err("crl/bad-input", "issuer must be { cert }, { publicKey } (SPKI DER), or a raw SPKI Buffer");
}

function _issuerMaySign(parsed, cert) {
  if (!guard.name.dnEqual(parsed.issuer.rdns, cert.subject.rdns, _err, "crl/bad-issuer", "the CRL issuer")) return false;
  var ku = pkix.keyUsageOf(NS, cert, _err, "crl/bad-issuer", "issuer certificate");
  if (!ku) return true;
  return ku.cRLSign === true;
}

/**
 * @primitive pki.crl.verify
 * @signature pki.crl.verify(crl, issuer) -> Promise<{ valid, issuerMaySign, signatureValid, issuer, code?, reason? }>
 * @since 0.3.9
 * @status stable
 * @spec RFC 5280 sec. 5.1.1.3, RFC 9814
 * @defends crl-signature-bypass (CWE-347)
 * @related pki.crl.sign, pki.path.crlChecker, pki.schema.crl.parse
 *
 * Verify a CRL's signature over its exact parsed `tbsCertList` bytes under the issuer public key. `crl`
 * is a DER `Buffer`, a PEM string, or a parsed CRL; `issuer` is `{ cert }` (DER/PEM/parsed), `{ publicKey }`
 * (SPKI DER), or a raw SPKI `Buffer`. Verification composes the one path-validation signature engine
 * `pki.path.crlChecker` uses, the same algorithm-confusion (RFC 9814 sec. 4 key-OID == sig-OID) and
 * EdDSA low-order-point gates, so there is no second, weaker CRL verifier. The verdict's `valid` is
 * `false` on any verification fault, and `signatureValid` reports the signature check on its own; malformed
 * input throws a typed `CrlError`.
 *
 * Given a certificate in place of a bare key, it also asks what only a certificate can answer: that
 * the certificate is the issuer this CRL names, and that its keyUsage, when it carries one, asserts
 * `cRLSign` (RFC 5280 sec. 4.2.1.3, the same rule this module's signing side already enforces). Those two
 * are `issuerMaySign`, reported beside `signatureValid` so a caller sees which held: `valid` is their
 * conjunction. A signature verifying says only that SOME key signed these bytes, so a bare `valid` boolean
 * would let a CRL minted under an end-entity certificate of the same CA read as that CA's own. Handed a bare
 * SPKI there is no certificate to carry either restriction, so `issuerMaySign` is `true` and only the
 * signature is checked. `issuer` is the CRL's issuer name; on a failure `code` / `reason` name which check
 * failed. Currency and distribution-point scope remain `pki.path.crlChecker`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerSpki = await pki.key.export(pair.publicKey);
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: signerSpki,
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: signerKeyPkcs8 });
 *   var crlDer = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 1n, revoked: [] },
 *     { cert: signerCertDer, key: signerKeyPkcs8 });
 *   var res = await pki.crl.verify(crlDer, { publicKey: signerSpki });   // { valid, signatureValid, issuerMaySign, issuer }
 */
function verify(crl, issuer) { return guard.async.deferred(function () { return _verify(crl, issuer); }); }
function _verify(crl, issuer) {
  var parsed = _coerceCrl(crl);
  var resolved = _resolveIssuer(issuer);
  var issuerMaySign = resolved.cert ? _issuerMaySign(parsed, resolved.cert) : true;
  return crlVerify.verifyCrlSignature(parsed, resolved.spki).then(function (sigOk) {
    var signatureValid = sigOk === true;
    var valid = issuerMaySign && signatureValid;
    var out = { valid: valid, issuerMaySign: issuerMaySign, signatureValid: signatureValid, issuer: parsed.issuer };
    if (!valid) {
      out.code = !issuerMaySign ? "crl/issuer-may-not-sign" : "crl/bad-signature";
      out.reason = !issuerMaySign
        ? "the issuer certificate is not this CRL's issuer, or its keyUsage does not assert cRLSign (RFC 5280 sec. 4.2.1.3)"
        : "the CRL signature did not verify under the issuer key";
    }
    return out;
  });
}

function _serialHexOf(serial) {
  var v;
  if (typeof serial === "bigint") v = serial;
  else if (typeof serial === "number") { if (!Number.isSafeInteger(serial)) throw _err("crl/bad-input", "serialNumber number must be a safe integer (pass a BigInt, hex string, or Buffer)"); v = BigInt(serial); }
  else if (typeof serial === "string") { try { v = BigInt(serial); } catch (e) { throw _err("crl/bad-input", "serialNumber string must be a decimal or 0x-hex integer", e); } }
  else if (guard.bytes.isByteSource(serial)) { var _sb = guard.bytes.source(serial, CrlError, "crl/bad-input", "serialNumber"); v = _sb.length ? BigInt("0x" + _sb.toString("hex")) : 0n; }
  else throw _err("crl/bad-input", "serialNumber must be a BigInt, integer, hex string, or BufferSource");
  if (v <= 0n) throw _err("crl/bad-input", "serialNumber must be a positive integer");
  return asn1.decode(b.integer(v)).content.toString("hex");
}

/**
 * @primitive pki.crl.isRevoked
 * @signature pki.crl.isRevoked(crl, serialNumber, opts?) -> entry | null
 * @since 0.3.9
 * @status stable
 * @spec RFC 5280 sec. 5.1.2.6
 * @related pki.crl.verify, pki.schema.crl.parse
 *
 * Look a certificate serial number up in a CRL's `revokedCertificates` list. `crl` is a DER `Buffer`, a
 * PEM string, or a parsed CRL; `serialNumber` is a `BigInt`, a safe integer, a decimal / `0x`-hex string,
 * or a magnitude `Buffer`. Returns the matching revoked-certificate entry (`{ serialNumber, serialNumberHex,
 * revocationDate, crlEntryExtensions }`) or `null` when the serial is not listed. It does not verify the CRL
 * signature; call `pki.crl.verify` or `pki.path.crlChecker` for that.
 *
 * With `opts.time` and `opts.historicalMode`, an entry is read against that instant the way
 * `pki.path.crlChecker` reads it: by default a listed serial is revoked whatever its `revocationDate`
 * says, since a date in the future is post-dating or clock skew and must not read good, and only an
 * explicit historical reading has an entry dated after the instant not yet applying. `historicalMode`
 * without `time` names no instant to read against and is refused.
 *
 * Pass `opts.time` to ask the question at an instant, and a CRL that does not speak for that instant is
 * refused rather than answered from (`crl/not-current`): one whose `thisUpdate` is later, one whose
 * `nextUpdate` has passed, and one carrying no `nextUpdate` at all, which states no window and so cannot
 * be told from a replayed copy. Without `opts.time` currency goes unasked and the verb is the structural
 * lookup it has always been; `null` then means "not listed on this CRL", which is weaker than "not
 * revoked". `pki.path.crlChecker` decides currency against the material it fetched and is the verb to
 * reach for when the answer has to mean the stronger thing.
 *
 * It does check scope first, because a serial number means something only within the set of
 * certificates a CRL speaks for, and this verb is given a serial and nothing else. So a CRL that
 * speaks for part of its issuer's certificates is refused, never answered from:
 *
 * - A DELTA CRL lists changes since a base, so a serial in it may be there to say the certificate
 *   was RELEASED; read alone, the entry meaning "no longer revoked" reads as "revoked"
 *   (`crl/delta-not-authoritative`). Merge it with its base through `pki.path.crlChecker`.
 * - An INDIRECT CRL carries entries for other issuers, whose serials are unrelated to yours
 *   (`crl/indirect-not-supported`), as does any CRL carrying `certificateIssuer` on an entry
 *   while not declaring itself indirect, a contradiction about whose certificates it lists.
 * - Any other `issuingDistributionPoint` narrows the CRL to one distribution point, one kind of
 *   certificate, or a subset of revocation reasons (`crl/scope-not-authoritative`). Which part
 *   applies is decided against fields of the CERTIFICATE, which this verb never sees, so an absent
 *   serial is not an unrevoked certificate. `pki.path.crlChecker` is handed the certificate and
 *   performs the RFC 5280 sec. 6.3.3 correspondence.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: signerKeyPkcs8 });
 *   var crlDer = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 1n,
 *     revoked: [{ serialNumber: 0x1234n, revocationDate: new Date("2026-01-15T00:00:00Z") }] },
 *     { cert: signerCertDer, key: signerKeyPkcs8 });
 *   pki.crl.isRevoked(crlDer, 0x1234n) ? "revoked" : "not listed";
 */
var KNOWN_IS_REVOKED_KEYS = { time: 1, historicalMode: 1 };
function isRevoked(crl, serialNumber, opts) {
  var o = guard.identifier.optionsObject(opts, _err, "crl/bad-input", "pki.crl.isRevoked options");
  guard.identifier.assertKnownKeys(o, KNOWN_IS_REVOKED_KEYS, _err, "crl/bad-input", function (k) {
    return "pki.crl.isRevoked has an unknown option " + JSON.stringify(k) +
      "; it takes `time` and `historicalMode`";
  });
  if (o.historicalMode !== undefined && o.time === undefined) {
    throw _err("crl/bad-input", "pki.crl.isRevoked opts.historicalMode says how to read an entry " +
      "against the instant asked about, so it needs opts.time as well");
  }
  if (o.historicalMode !== undefined && typeof o.historicalMode !== "boolean") {
    throw _err("crl/bad-input", "pki.crl.isRevoked opts.historicalMode must be a boolean");
  }
  var parsed = _coerceCrl(crl);
  var hex = _serialHexOf(serialNumber);
  if (o.time !== undefined) {
    guard.time.assertValid(o.time, _err, "crl/bad-input", "pki.crl.isRevoked opts.time");
    var at = guard.time.instantOf(o.time);
    if (at < guard.time.instantOf(parsed.thisUpdate)) {
      throw _err("crl/not-current", "this CRL takes effect at " + parsed.thisUpdate.toISOString() +
        ", after the time asked about, so it says nothing about the certificate then");
    }
    if (!parsed.nextUpdate) {
      throw _err("crl/not-current", "this CRL carries no nextUpdate, so it states no window it " +
        "speaks for and a replayed copy cannot be told from a current one (RFC 5280 sec. 5.1.2.5 " +
        "requires one of a conforming CA); ask pki.path.crlChecker, which decides currency against " +
        "the material it fetched");
    }
    if (at > guard.time.instantOf(parsed.nextUpdate)) {
      throw _err("crl/not-current", "this CRL was superseded after " +
        parsed.nextUpdate.toISOString() + "; a serial missing from it says nothing about the " +
        "certificate at the time asked about, since the issuer promised a further list by then");
    }
  }
  if (_findExtOid(parsed.crlExtensions, "deltaCRLIndicator")) {
    throw _err("crl/delta-not-authoritative", "this is a delta CRL: it lists changes since a base CRL, so a serial appearing in it may be RELEASED rather than revoked. Merge it with its base -- pki.path.crlChecker does -- rather than reading a revocation status out of the delta alone");
  }
  var idp = _findExtOid(parsed.crlExtensions, "issuingDistributionPoint");
  if (idp) _assertAuthoritativeScope(idp);
  for (var i = 0; i < parsed.revokedCertificates.length; i++) {
    if (_findExtOid(parsed.revokedCertificates[i].crlEntryExtensions, "certificateIssuer")) {
      throw _err("crl/indirect-not-supported", "a revoked-certificate entry carries certificateIssuer, which names another issuer, on a CRL that does not declare itself indirect -- the entry and the CRL disagree about whose certificates this list covers, so no revocation status follows from it");
    }
  }
  for (var j = 0; j < parsed.revokedCertificates.length; j++) {
    if (parsed.revokedCertificates[j].serialNumberHex !== hex) continue;
    if (o.historicalMode === true &&
      guard.time.instantOf(parsed.revokedCertificates[j].revocationDate) >
        guard.time.instantOf(o.time)) continue;
    return parsed.revokedCertificates[j];
  }
  return null;
}

function _findExtOid(list, name) {
  var want = O(name);
  return (list || []).filter(function (e) { return e.oid === want; })[0] || null;
}

var _IDP_SCHEMA = pkix.issuingDistributionPoint("crl/scope-not-authoritative");
var _INDIRECT_REFUSAL = "this CRL is marked indirect (issuingDistributionPoint indirectCRL): its entries name their own issuers, so a serial alone does not identify a certificate. Reading a revocation status from it by serial would attribute another issuer's revocation to yours";
var _SCOPED_REFUSAL = "this CRL carries an issuingDistributionPoint, so it speaks for part of its issuer's certificates rather than all of them, and which part is decided against fields of the certificate -- which this verb is not given. A serial absent from it is not a certificate that is unrevoked. Use pki.path.crlChecker, which is handed the certificate and performs the RFC 5280 sec. 6.3.3 scope correspondence";
function _assertAuthoritativeScope(ext) {
  var m;
  try { m = schema.walk(_IDP_SCHEMA, asn1.decode(ext.value), NS); }
  catch (e) { throw _err("crl/scope-not-authoritative", "the issuingDistributionPoint cannot be read, so this CRL's scope cannot be established", e); }
  var f = m.fields;
  if (f.indirectCRL.present && f.indirectCRL.value === true) throw _err("crl/indirect-not-supported", _INDIRECT_REFUSAL);
  throw _err("crl/scope-not-authoritative", _SCOPED_REFUSAL);
}

module.exports = { sign: sign, verify: verify, isRevoked: isRevoked };
