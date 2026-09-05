// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var bytes = require("./guard-bytes");
var time = require("./guard-time");
var _isArray = require("./guard-intrinsic").isArray;
var _freezeExports = require("./guard-intrinsic").freeze;
var _bufferFrom = require("./guard-intrinsic").bufferFrom;
var _ObjectProto = require("./guard-intrinsic").ObjectProto;
var _isBuffer = require("./guard-intrinsic").isBuffer;
var _create = require("./guard-intrinsic").create;
var _assign = require("./guard-intrinsic").assign;
var _getPrototypeOf = require("./guard-intrinsic").getPrototypeOf;
var _getOwnPropertyNames = require("./guard-intrinsic").getOwnPropertyNames;
var _every = require("./guard-intrinsic").every;
var _weakGet = require("./guard-intrinsic").weakGet;
var _weakSet = require("./guard-intrinsic").weakSet;
var _weakHas = require("./guard-intrinsic").weakHas;
var _WeakMap = require("./guard-intrinsic").WeakMap;
var _defineProperty = require("./guard-intrinsic").defineProperty;
var _append = require("./guard-list").append;

function _isBytes(x) {
  return bytes.isByteSource(x);
}


function _isAttributeTypeAndValue(a) {
  return !!a && typeof a.type === "string" && _isOptName(a.name) && typeof a.value === "string";
}
function _isRdnSequence(rdns) {
  if (!_isArray(rdns)) return false;
  for (var i = 0; i < rdns.length; i++) {
    if (!_isArray(rdns[i]) || rdns[i].length === 0) return false;
    if (!_every(rdns[i], _isAttributeTypeAndValue)) return false;
  }
  return true;
}
function _isName(n) {
  return !!n && _isRdnSequence(n.rdns) && _isBuffer(n.bytes) && typeof n.dn === "string";
}

function _isOptName(v) { return typeof v === "string" || v === null; }

function _isAlgorithmIdentifier(a) {
  return !!a && typeof a.oid === "string" && _isOptName(a.name) &&
    (_isBuffer(a.parameters) || a.parameters === null);
}

function _isBitString(b) {
  return !!b && _isBuffer(b.bytes) && typeof b.unusedBits === "number";
}

function _isExtensionEntry(e) {
  return !!e && typeof e.oid === "string" && _isOptName(e.name) &&
    typeof e.critical === "boolean" && _isBuffer(e.value);
}

function _isCrlExtensionEntry(e) {
  return !!e && typeof e.oid === "string" && _isOptName(e.name) &&
    typeof e.critical === "boolean" && e.value !== undefined;
}

// @enforced-by guard-shape-reinlined -- shares the `accept` shape below: any door
function isCert(o) {
  return !!o && typeof o === "object" &&
    _isBuffer(o.tbsBytes) &&
    typeof o.version === "number" &&
    typeof o.serialNumber === "bigint" &&
    typeof o.serialNumberHex === "string" &&
    _isAlgorithmIdentifier(o.signatureAlgorithm) &&
    _isAlgorithmIdentifier(o.tbsSignatureAlgorithm) &&
    _isBitString(o.signatureValue) &&
    !!o.validity && time.isDate(o.validity.notBefore) && time.isDate(o.validity.notAfter) &&
    _isName(o.issuer) &&
    _isName(o.subject) &&
    !!o.subjectPublicKeyInfo && _isBuffer(o.subjectPublicKeyInfo.bytes) &&
    _isAlgorithmIdentifier(o.subjectPublicKeyInfo.algorithm) &&
    _isBitString(o.subjectPublicKeyInfo.publicKey) &&
    _isArray(o.extensions) && _every(o.extensions, _isExtensionEntry);
}

// @enforced-by guard-shape-reinlined -- shares the `accept` shape below.
function isCrl(o) {
  return !!o && typeof o === "object" &&
    _isBuffer(o.tbsBytes) &&
    typeof o.version === "number" &&
    _isAlgorithmIdentifier(o.signatureAlgorithm) &&
    _isBitString(o.signatureValue) &&
    _isName(o.issuer) &&
    time.isDate(o.thisUpdate) &&
    (o.nextUpdate === null || time.isDate(o.nextUpdate)) &&
    _isArray(o.crlExtensions) && _every(o.crlExtensions, _isCrlExtensionEntry) &&
    _isArray(o.revokedCertificates) && _every(o.revokedCertificates, function (e) {
      return !!e && typeof e.serialNumber === "bigint" &&
        typeof e.serialNumberHex === "string" &&
        time.isDate(e.revocationDate) &&
        _isArray(e.crlEntryExtensions) && _every(e.crlEntryExtensions, _isCrlExtensionEntry);
    });
}

function _safe(shape) {
  return function (o) {
    try { return shape(o) === true; }
    catch (_e) {
      return false;
    }
  };
}
var certShape = _safe(isCert);
var crlShape = _safe(isCrl);

var _SHAPES = _assign(_create(null), { certificate: certShape, crl: crlShape });

// @enforced-by guard-shape-reinlined
// @guard-shape (?:if\s*\(|return\s*\(?)[^;\n]*\.tbsBytes[^;\n]*\)\s*(?:\{\s*)?return\s+\w+\s*;
// @guard-via guard\.parsed\.(?:accept|isCert|isCrl)\(
function accept(input, kind, parse, E, code, label) {
  var who = label || "the argument";
  var shape = _SHAPES[kind];
  if (!shape) throw new TypeError("guard.parsed.accept: unknown kind " + kind);
  if (_isBytes(input) || typeof input === "string") return parse(input);
  var claimsParsed = false;
  if (input && typeof input === "object") {
    try { claimsParsed = input.tbsBytes !== undefined; }
    catch (_e) {
      claimsParsed = true;
    }
  }
  if (claimsParsed) {
    if (!shape(input)) {
      throw E(code, who + " claims to be a parsed " + kind + " (it carries tbsBytes) but is not a complete one -- pass the bytes, or the unmodified output of the matching pki.schema parser, since a partial object would be read as though the parser had produced it");
    }
    return input;
  }
  throw E(code, who + " must be a " + kind + " DER Buffer, a PEM string, or a parsed " + kind);
}

var PROVENANCE = new _WeakMap();

// @enforced-by guard-shape-reinlined -- shares the fromTrustedSource shape below; a
function recordingParser(kind, parse, ErrorClass, code, label) {
  return function (input) {
    var isText = typeof input === "string";
    var snap = isText ? input : bytes.snapshotSource(input, ErrorClass, code, label);
    var out = parse(snap);
    if (out && typeof out === "object") {
      _weakSet(PROVENANCE, out, { kind: kind, source: isText ? snap : _bufferFrom(snap),
        shape: _shapeOf(out) });
    }
    return out;
  };
}

// @enforced-by guard-shape-reinlined -- shares recordingParser's shape below: the PROVENANCE.set
function recordingWalker(kind, walkNode, decodeBytes) {
  return function (node) {
    var out = walkNode(node);
    if (out && typeof out === "object" && node && _isBytes(node.bytes)) {
      _weakSet(PROVENANCE, out, {
        kind: kind,
        source: _bufferFrom(node.bytes),
        shape: _shapeOf(out),
        derive: function (src) { return walkNode(decodeBytes(src)); },
      });
    }
    return out;
  };
}

// @internal
function _recordOf(obj, kind) {
  if (!obj || typeof obj !== "object") return undefined;
  var rec = _weakGet(PROVENANCE, obj);
  return (rec && rec.kind === kind) ? rec : undefined;
}

// @enforced-by behavioral -- a predicate has no rename-proof shape to detect, and re-inlining it is
function isRecorded(obj) {
  return !!obj && typeof obj === "object" && _weakHas(PROVENANCE, obj);
}

// @enforced-by behavioral -- a predicate has no rename-proof shape to detect, and the registry it
function isRecordedAsProduced(obj) {
  if (!isRecorded(obj)) return false;
  var shape = _weakGet(PROVENANCE, obj).shape;
  var keys = _allNames(obj);
  for (var i = 0; i < keys.length; i++) {
    if (!shape[keys[i]]) return false;
  }
  return true;
}

function _shapeOf(obj) {
  var shape = _create(null);
  var keys = _allNames(obj);
  for (var i = 0; i < keys.length; i++) shape[keys[i]] = true;
  return shape;
}

function _allNames(obj) {
  var names = [];
  var seen = _create(null);
  for (var o = obj; o && o !== _ObjectProto; o = _getPrototypeOf(o)) {
    var own = _getOwnPropertyNames(o);
    for (var i = 0; i < own.length; i++) {
      if (seen[own[i]]) continue;
      seen[own[i]] = true;
      _append(names, own[i]);
    }
  }
  return names;
}

// @enforced-by guard-shape-reinlined
// @guard-shape (?:responseStatus|integrityMode|macedBytes|tbsResponseDataBytes)\s*!==\s*undefined
// @guard-via guard\.parsed\.(?:fromTrustedSource|recordingParser)\(
function fromTrustedSource(input, kind, claimFields, parse, E, code, why) {
  if (input && typeof input === "object" && !_isBytes(input)) {
    var rec = _recordOf(input, kind);
    if (rec !== undefined) return (rec.derive || parse)(rec.source);
    for (var i = 0; i < claimFields.length; i++) {
      var claims;
      try { claims = input[claimFields[i]] !== undefined; }
      catch (_e) {
        claims = true;
      }
      if (claims) throw E(code, why);
    }
  }
  return parse(input);
}

var _CLAIMS = _assign(_create(null), {
  certificate: ["tbsBytes", "subjectPublicKeyInfo", "serialNumberHex"],
  crl: ["tbsBytes", "revokedCertificates", "crlExtensions"],
  cms: ["signerInfos", "encapContentInfo"],
  csr: ["certificationRequestInfoBytes", "subjectPublicKeyInfo", "attributes"],
  crmf: ["messages"],
  attributeCertificate: ["tbsBytes", "holder", "attributes"],
});
var _WHY = _assign(_create(null), {
  certificate: "the signed byte range, the signature and the fields that range encodes are separate properties of a parsed object, so a rebuilt certificate (Object.assign, spread, a JSON round-trip) could have them describe different certificates: keep a real CA certificate's signed bytes and signature, replace only its public key, and every field is still well-formed",
  crl: "the signed byte range, the revocation list and the scope extensions are separate properties of a parsed object, so a rebuilt CRL could have them describe different CRLs: empty the revocation list and a correctly signed CRL reports a revoked certificate as good",
  cms: "the signed attribute bytes, the signature, the encapsulated content and the certificates that verify it are separate properties of a parsed object, so a rebuilt SignedData could have them describe different messages: keep a genuine signer's signature and signed attributes, put other content beside them, and every part of the check passes for content that signer never signed",
  csr: "the signed byte range, the key it proves possession of and the subject and requested extensions that range encodes are separate properties of a parsed object, so a rebuilt request could have them describe different requests: keep a genuine requester's signed bytes and signature, replace only the subject or the extensionRequest, and the proof of possession still verifies while the certificate a CA issues from those fields is for a name and a set of extensions nobody signed",
  crmf: "the byte range a proof of possession covers, the key that possession is proven for and the subject a CA will issue to are separate properties of a parsed object, so a rebuilt message set could have them describe different requests: keep a genuine requester's signed range and signature, replace only the certTemplate subject or public key, and the proof still verifies while the certificate is issued for a name and a key nobody proved anything about",
  attributeCertificate: "the signed byte range, the holder the privileges attach to and the attributes granting them are separate properties of a parsed object, so a rebuilt attribute certificate could have them describe different grants: keep a genuine issuer's signed bytes and signature, replace only the holder or an attribute, and the signature still verifies while the privileges are read for someone the issuer never granted them to",
});
// @enforced-by guard-shape-reinlined -- shares the fromTrustedSource shape it composes: a door that
function acceptDerived(input, kind, parse, E, code, label) {
  var claims = _CLAIMS[kind];
  if (!claims) throw new TypeError("guard.parsed.acceptDerived: unknown kind " + kind);
  var who = label || "the argument";
  if (input !== null && input !== undefined && typeof input === "object" && !_isBytes(input)) {
    var claimsSomething = false;
    for (var i = 0; i < claims.length && !claimsSomething; i++) {
      try { claimsSomething = input[claims[i]] !== undefined; }
      catch (_e) {
        claimsSomething = true;
      }
    }
    if (!claimsSomething) {
      throw E(code, who + " must be a " + kind + " DER Buffer, a PEM string, or a parsed " + kind);
    }
  }
  var ns = { certificate: "x509", crl: "crl", cms: "cms", csr: "csr", crmf: "crmf",
    attributeCertificate: "attrcert" }[kind];
  return fromTrustedSource(input, kind, claims, parse, E, code,
    who + " must be its DER bytes, a PEM string, or an unmodified pki.schema." + ns +
    ".parse result: " + _WHY[kind]);
}

module.exports = _freezeExports({
  accept: accept, acceptDerived: acceptDerived,
  fromTrustedSource: fromTrustedSource, recordingParser: recordingParser,
  recordingWalker: recordingWalker,
  isCert: certShape, isCrl: crlShape, isRecorded: isRecorded,
  isRecordedAsProduced: isRecordedAsProduced,
});
