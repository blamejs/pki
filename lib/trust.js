// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.trust
 * @nav        Path validation
 * @title      Trust-store ingestion
 * @fullname   Trust stores: load and pin root certificate anchors
 * @order      230
 * @slug       trust
 *
 * @intro
 *   Mozilla / CCADB root-program ingestion into constraint-carrying trust
 *   anchors. The bare root list (`tls.rootCertificates`) throws away exactly
 *   the metadata that decides which roots may vouch for what: the per-purpose
 *   trust bits (a root trusted for TLS is not thereby trusted for S/MIME) and
 *   the per-purpose distrust-after dates (a sunsetting root keeps validating
 *   already-issued certificates while certificates issued after the cutoff are
 *   rejected). `parseCertdata` reads the NSS `certdata.txt` object stream and
 *   `parseCcadbCsv` the CCADB CSV export into one identical `Anchor` shape, so
 *   enforcement downstream is source-agnostic; `anchor()` hands an entry to
 *   `pki.path.validate({ trustAnchor, checkPurpose })`.
 *
 *   Everything is fail-closed and offline: the caller supplies the text (no
 *   network fetch); every malformed or oversized input throws a typed
 *   `trust/*` error before the offending allocation; a certificate object and
 *   its trust object are paired by byte-exact (CKA_ISSUER, CKA_SERIAL_NUMBER),
 *   never by adjacency, and cross-checked against the parsed DER, so
 *   trust metadata can never attach to the wrong root; only
 *   `CKT_NSS_TRUSTED_DELEGATOR` grants a purpose (everything else, including
 *   an absent bit, is untrusted).
 *
 * @card
 *   `parseCertdata` / `parseCcadbCsv` -> constraint-carrying trust anchors
 *   (per-purpose trust bits + distrust-after dates); `anchor()` feeds
 *   `pki.path.validate`. Fail-closed, offline, source-agnostic.
 */

var constants = require("./constants");
var errors = require("./framework-error");
var asn1 = require("./asn1-der");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var x509 = require("./schema-x509");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var nodeFs = require("fs");
var nodeTls = require("tls");
var trustanchorSchema = require("./schema-trustanchor");

var TrustError = errors.TrustError;
var LIMITS = constants.LIMITS;

function E(code, message, cause) { return new TrustError(code, message, cause); }
var _NS = pkix.makeNS("trust", TrustError, oid);

var PURPOSES = ["serverAuth", "emailProtection", "codeSigning"];

var PURPOSE_ATTRS = [
  ["CKA_TRUST_SERVER_AUTH", "serverAuth"],
  ["CKA_TRUST_EMAIL_PROTECTION", "emailProtection"],
  ["CKA_TRUST_CODE_SIGNING", "codeSigning"],
];

var CKT_RECOGNIZED = Object.create(null);
["CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_TRUSTED", "CKT_NSS_MUST_VERIFY_TRUST",
  "CKT_NSS_TRUST_UNKNOWN", "CKT_NSS_NOT_TRUSTED", "CKT_NSS_VALID_DELEGATOR"]
  .forEach(function (t) { CKT_RECOGNIZED[t] = true; });
var CKT_DELEGATOR = "CKT_NSS_TRUSTED_DELEGATOR";

function _isNameChar(c) { return (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 95; }
function _isDigitCode(c) { return c >= 48 && c <= 57; }
function _isDateSepCode(c) { return c === 46 || c === 47 || c === 45; }
function _isOctalDigit(c) { return c >= 48 && c <= 55; }
function _isWsCode(c) { return pkix.isJsWhitespace(c); }
function _containsWs(s) { for (var i = 0; i < s.length; i++) { if (_isWsCode(_charCodeAt(s, i))) return true; } return false; }

function _parseAttrLine(s) {
  var n = s.length;
  if (_strSlice(s, 0, 4) !== "CKA_") return null;
  var p = 4;
  while (p < n && _isNameChar(_charCodeAt(s, p))) p += 1;
  if (p === 4) return null;
  var name = _strSlice(s, 0, p);
  if (p === n) return [name, undefined, undefined];
  if (!_isWsCode(_charCodeAt(s, p))) return null;
  while (p < n && _isWsCode(_charCodeAt(s, p))) p += 1;
  var typeStart = p;
  while (p < n && !_isWsCode(_charCodeAt(s, p))) p += 1;
  if (p === typeStart) return null;
  var type = _strSlice(s, typeStart, p);
  if (p === n) return [name, type, undefined];
  if (!_isWsCode(_charCodeAt(s, p))) return null;
  while (p < n && _isWsCode(_charCodeAt(s, p))) p += 1;
  return [name, type, _strSlice(s, p)];
}

function _unquote(s) {
  var n = s.length;
  if (n < 2 || _charCodeAt(s, 0) !== 34 || _charCodeAt(s, n - 1) !== 34) return null;
  for (var i = 1; i < n - 1; i++) if (_charCodeAt(s, i) === 34) return null;
  return _strSlice(s, 1, n - 1);
}

function _splitWhitespace(s) {
  var out = [], i = 0, n = s.length, pieceStart = 0;
  while (i < n) {
    if (_isWsCode(_charCodeAt(s, i))) {
      out[out.length] = _strSlice(s, pieceStart, i);
      while (i < n && _isWsCode(_charCodeAt(s, i))) i += 1;
      pieceStart = i;
    } else i += 1;
  }
  out[out.length] = _strSlice(s, pieceStart);
  return out;
}

function _isOctal3(d) {
  if (d.length !== 3) return false;
  for (var i = 0; i < 3; i++) { if (!_isOctalDigit(_charCodeAt(d, i))) return false; }
  return true;
}

function _splitLines(text) {
  var out = [], start = 0, i = 0, n = text.length;
  while (i < n) {
    var c = _charCodeAt(text, i);
    if (c === 13) {
      out[out.length] = _strSlice(text, start, i);
      if (i + 1 < n && _charCodeAt(text, i + 1) === 10) i += 1;
      i += 1; start = i;
    } else if (c === 10) {
      out[out.length] = _strSlice(text, start, i);
      i += 1; start = i;
    } else i += 1;
  }
  out[out.length] = _strSlice(text, start);
  return out;
}

function _parseYmd(s) {
  var n = s.length;
  for (var a = 0; a < 4; a++) if (!_isDigitCode(_charCodeAt(s, a))) return null;
  var year = _strSlice(s, 0, 4), p = 4;
  if (!_isDateSepCode(_charCodeAt(s, p))) return null; p += 1;
  var ms = p;
  while (p < n && p - ms < 2 && _isDigitCode(_charCodeAt(s, p))) p += 1;
  if (p === ms) return null;
  var month = _strSlice(s, ms, p);
  if (!_isDateSepCode(_charCodeAt(s, p))) return null; p += 1;
  var ds = p;
  while (p < n && p - ds < 2 && _isDigitCode(_charCodeAt(s, p))) p += 1;
  if (p === ds) return null;
  var day = _strSlice(s, ds, p);
  if (p !== n) return null;
  return [year, month, day];
}


function _readOctalBody(lines, idx) {
  var out = [];
  var cap = LIMITS.TRUST_MAX_OCTAL_BYTES;
  for (var i = idx; i < lines.length; i++) {
    var t = lines[i].trim();
    if (t === "END") return { bytes: Buffer.from(out), next: i + 1 };
    if (t === "") throw E("trust/bad-octal", "MULTILINE_OCTAL body interrupted by a blank line before END");
    var chunks = _splitWhitespace(t);
    for (var c = 0; c < chunks.length; c++) {
      var chunk = chunks[c];
      for (var k = 0; k < chunk.length; k += 4) {
        if (chunk.charCodeAt(k) !== 92 ) {
          throw E("trust/bad-octal", "MULTILINE_OCTAL expects \\ooo escapes, got " + JSON.stringify(chunk.slice(k, k + 4)));
        }
        var d = chunk.slice(k + 1, k + 4);
        if (!_isOctal3(d)) {
          throw E("trust/bad-octal", "a MULTILINE_OCTAL escape is a backslash + exactly three octal digits, got " + JSON.stringify("\\" + d));
        }
        if (d.charCodeAt(0) > 51 ) {
          throw E("trust/bad-octal", "octal escape \\" + d + " exceeds \\377 (one byte)");
        }
        if (out.length >= cap) throw E("trust/bad-block", "MULTILINE_OCTAL blob exceeds LIMITS.TRUST_MAX_OCTAL_BYTES");
        out.push(parseInt(d, 8));
      }
    }
  }
  throw E("trust/bad-octal", "MULTILINE_OCTAL body reached end of input before END");
}

function _lexObjects(text) {
  var lines = _splitLines(text);
  var n = lines.length;
  var i = 0, sawBegin = false;
  for (; i < n; i++) {
    if (lines[i].trim() === "BEGINDATA") { sawBegin = true; i++; break; }
  }
  if (!sawBegin) throw E("trust/bad-input", "not a certdata stream: no BEGINDATA line");

  var objects = [];
  var cur = null;
  while (i < n) {
    var t = lines[i].trim();
    if (t === "") {
      if (cur) { objects.push(cur); cur = null; }
      i++; continue;
    }
    if (t.charAt(0) === "#") { i++; continue; }
    var m = _parseAttrLine(t);
    if (!m) throw E("trust/bad-block", "unexpected line in the certdata object stream: " + JSON.stringify(t.slice(0, 64)));
    var name = m[0], type = m[1];
    var rawVal = m[2] !== undefined ? m[2].trim() : undefined;
    if (!type) throw E("trust/bad-block", "attribute line is missing its type token: " + name);
    if (!cur) {
      if (objects.length >= LIMITS.TRUST_MAX_OBJECTS) throw E("trust/bad-block", "certdata object count exceeds LIMITS.TRUST_MAX_OBJECTS");
      cur = { attrs: Object.create(null) };
    }
    if (cur.attrs[name]) throw E("trust/bad-block", "duplicate attribute " + name + " within one object block");

    var entry;
    if (type === "MULTILINE_OCTAL") {
      if (rawVal !== undefined && rawVal !== "") throw E("trust/bad-block", name + " MULTILINE_OCTAL carries an unexpected inline value");
      var r = _readOctalBody(lines, i + 1);
      cur.attrs[name] = { type: type, bytes: r.bytes };
      i = r.next;
      continue;
    }
    if (type === "CK_BBOOL") {
      if (rawVal !== "CK_TRUE" && rawVal !== "CK_FALSE") throw E("trust/bad-block", name + " CK_BBOOL must be CK_TRUE or CK_FALSE");
      entry = { type: type, value: rawVal === "CK_TRUE" };
    } else if (type === "UTF8") {
      var q = rawVal !== undefined ? _unquote(rawVal) : null;
      if (q === null) throw E("trust/bad-block", name + " UTF8 must carry one double-quoted value");
      entry = { type: type, value: q };
    } else if (type === "CK_TRUST") {
      if (rawVal === undefined || _containsWs(rawVal)) throw E("trust/bad-block", name + " CK_TRUST must carry a single token value");
      if (!CKT_RECOGNIZED[rawVal]) throw E("trust/bad-trust-value", "unrecognized CK_TRUST value " + JSON.stringify(rawVal) + " on " + name);
      entry = { type: type, value: rawVal };
    } else if (type === "CK_OBJECT_CLASS" || type === "CK_CERTIFICATE_TYPE") {
      if (rawVal === undefined || _containsWs(rawVal)) throw E("trust/bad-block", name + " " + type + " must carry a single token value");
      entry = { type: type, value: rawVal };
    } else {
      throw E("trust/bad-block", "unrecognized attribute type " + JSON.stringify(type) + " on " + name);
    }
    cur.attrs[name] = entry;
    i++;
  }
  if (cur) objects.push(cur);
  return objects;
}


function _requireOctal(obj, name, what) {
  var a = obj.attrs[name];
  if (!a || a.type !== "MULTILINE_OCTAL") {
    throw E("trust/bad-block", what + " object is missing its " + name + " MULTILINE_OCTAL attribute");
  }
  return a.bytes;
}

function _strictTime(payload, code, label) {
  var tlv;
  if (payload.length === 13) tlv = Buffer.concat([Buffer.from([0x17, 0x0d]), payload]);
  else if (payload.length === 15) tlv = Buffer.concat([Buffer.from([0x18, 0x0f]), payload]);
  else throw E(code, label + " must be a 13-byte UTCTime or a 15-byte GeneralizedTime payload, got " + payload.length + " bytes");
  try { return asn1.read.time(asn1.decode(tlv)); }
  catch (e) { throw E(code, label + " does not decode as a strict time", e); }
}

function _distrustDate(obj, name) {
  var a = obj.attrs[name];
  if (!a) return null;
  if (a.type === "CK_BBOOL") {
    if (a.value === false) return null;
    throw E("trust/bad-distrust-after", name + " CK_BBOOL may only be CK_FALSE");
  }
  if (a.type !== "MULTILINE_OCTAL") throw E("trust/bad-distrust-after", name + " must be CK_BBOOL CK_FALSE or MULTILINE_OCTAL");
  return _strictTime(a.bytes, "trust/bad-distrust-after", name);
}

function _certEntry(obj) {
  var der = _requireOctal(obj, "CKA_VALUE", "certificate");
  var cert;
  try { cert = x509.parse(der); }
  catch (e) { throw E("trust/not-a-certificate", "CKA_VALUE does not parse as an X.509 certificate", e); }

  var issuer = _requireOctal(obj, "CKA_ISSUER", "certificate");
  var serial = _requireOctal(obj, "CKA_SERIAL_NUMBER", "certificate");

  if (!issuer.equals(cert.issuer.bytes)) {
    throw E("trust/pairing-mismatch", "CKA_ISSUER disagrees with the certificate's issuer DER");
  }
  var serialContentHex;
  try {
    var sn = asn1.decode(serial);
    asn1.read.integer(sn);
    serialContentHex = sn.content.toString("hex");
  } catch (e) {
    throw E("trust/pairing-mismatch", "CKA_SERIAL_NUMBER is not a DER INTEGER", e);
  }
  if (serialContentHex !== cert.serialNumberHex) {
    throw E("trust/pairing-mismatch", "CKA_SERIAL_NUMBER disagrees with the certificate's serial");
  }
  var subject = obj.attrs["CKA_SUBJECT"];
  if (subject && (subject.type !== "MULTILINE_OCTAL" || !subject.bytes.equals(cert.subject.bytes))) {
    throw E("trust/pairing-mismatch", "CKA_SUBJECT disagrees with the certificate's subject DER");
  }

  var label = obj.attrs["CKA_LABEL"];
  if (label && label.type !== "UTF8") throw E("trust/bad-block", "CKA_LABEL must be UTF8");
  var policy = obj.attrs["CKA_NSS_MOZILLA_CA_POLICY"];
  if (policy && policy.type !== "CK_BBOOL") throw E("trust/bad-block", "CKA_NSS_MOZILLA_CA_POLICY must be CK_BBOOL");

  var distrustAfter = {};
  var server = _distrustDate(obj, "CKA_NSS_SERVER_DISTRUST_AFTER");
  if (server) distrustAfter.serverAuth = server;
  var email = _distrustDate(obj, "CKA_NSS_EMAIL_DISTRUST_AFTER");
  if (email) distrustAfter.emailProtection = email;

  return {
    key: issuer.toString("hex") + "/" + serial.toString("hex"),
    der: der,
    cert: cert,
    label: label ? label.value : null,
    mozillaCaPolicy: !!(policy && policy.value === true),
    distrustAfter: distrustAfter,
    purposes: null,
  };
}

function _trustEntry(obj) {
  var issuer = _requireOctal(obj, "CKA_ISSUER", "trust");
  var serial = _requireOctal(obj, "CKA_SERIAL_NUMBER", "trust");
  var purposes = intrinsic.assign(intrinsic.create(null), { serverAuth: false, emailProtection: false, codeSigning: false });
  PURPOSE_ATTRS.forEach(function (pair) {
    var a = obj.attrs[pair[0]];
    if (!a) return;
    if (a.type !== "CK_TRUST") throw E("trust/bad-block", pair[0] + " must be CK_TRUST");
    purposes[pair[1]] = a.value === CKT_DELEGATOR;
  });
  return { key: issuer.toString("hex") + "/" + serial.toString("hex"), purposes: purposes };
}


function _mkAnchor(cert, meta) {
  var spki = cert.subjectPublicKeyInfo;
  var entry = {
    name: cert.subject,
    publicKey: spki.bytes,
    algorithm: spki.algorithm.oid,
    parameters: spki.algorithm.parameters,
    subjectDer: cert.subject.bytes,
    distrustAfter: meta.distrustAfter,
    purposes: meta.purposes,
    label: meta.label,
    mozillaCaPolicy: meta.mozillaCaPolicy,
  };
  /** @internal The certificate's own basic constraints are associated with the anchor, so its
   * pathLenConstraint bounds the path below it (RFC 5937 sec. 3.2). */
  var certPathLen = pkix.anchorPathLenFromExtensions(cert.extensions, _NS, "the trust anchor certificate");
  if (certPathLen !== null) {
    var cc = intrinsic.create(null);
    cc.pathLenConstraint = certPathLen;
    guard.verdict.set(entry, "constraints", cc);
  }
  var derived = {
    name: _copyName(cert.subject),
    publicKey: Buffer.from(spki.bytes),
    algorithm: spki.algorithm.oid,
    parameters: spki.algorithm.parameters == null ? spki.algorithm.parameters : Buffer.from(spki.algorithm.parameters),
    purposes: _purposesOrNull(meta.purposes),
    distrustAfter: _copyDistrustAfter(meta.distrustAfter),
  };
  /** @internal An independent copy, so editing the entry's own constraints cannot change what
   * `anchor()` enforces; it reads this record where there is one. */
  if (certPathLen !== null) {
    var dc = intrinsic.create(null);
    dc.pathLenConstraint = certPathLen;
    derived.constraints = dc;
  }
  _DERIVED_FROM.set(entry, derived);
  return entry;
}
var _DERIVED_FROM = new WeakMap();

function _copyPurposes(src) {
  return intrinsic.assign(intrinsic.create(null), {
    serverAuth: !!src && src.serverAuth === true,
    emailProtection: !!src && src.emailProtection === true,
    codeSigning: !!src && src.codeSigning === true,
  });
}

/** @internal An EXPLICIT null purposes set stays null; an absent one still defaults to all-false,
 *  which is the fail-closed reading of a store entry that named no purpose.
 *
 *  The two differ because the formats do. A store that lists a root and grants it nothing says
 *  something, and all-false is how that is written. A format carrying no purpose bits at all, such
 *  as an RFC 5914 trust anchor, says nothing: turning that into all-false would read as "trusted
 *  for no purpose" and make `pki.path.validate` demand a purpose to check a constraint the anchor
 *  never stated. The `anchor` entry gate directly below reads a null the same way, refusing an
 *  entry whose `purposes` is `!= null` and letting a null through as absent. */
function _purposesOrNull(src) { return src === null ? null : _copyPurposes(src); }

function _copyDistrustAfter(src) {
  var out = intrinsic.create(null);
  if (!src || typeof src !== "object") return out;
  var names = guard.identifier.optionNames(src);
  for (var i = 0; i < names.length; i++) {
    out[names[i]] = guard.time.isDate(src[names[i]]) ? new Date(guard.time.instantOf(src[names[i]])) : src[names[i]];
  }
  return out;
}

function _copyName(name) {
  if (!name || !Array.isArray(name.rdns)) return name;
  var out = guard.identifier.ownOptions(name);
  out.rdns = guard.list.copyMap(name.rdns, function (rdn) {
    return Array.isArray(rdn) ? guard.list.copyMap(rdn, function (atv) { return guard.identifier.ownOptions(atv); }) : rdn;
  });
  out.bytes = Buffer.isBuffer(name.bytes) ? Buffer.from(name.bytes) : name.bytes;
  return out;
}

function _datesEqual(x, y) {
  var kx = guard.identifier.optionNames(x).sort(), ky = guard.identifier.optionNames(y).sort();
  if (kx.join(",") !== ky.join(",")) return false;
  return kx.every(function (k) { return guard.time.instantOf(x[k]) === guard.time.instantOf(y[k]); });
}

function _purposesEqual(x, y) {
  return PURPOSES.every(function (p) { return x[p] === y[p]; });
}

function _paramsEqual(x, y) {
  if (x === null || y === null) return x === y;
  return Buffer.isBuffer(x) && Buffer.isBuffer(y) && x.equals(y);
}

function _anchorsAgree(x, y) {
  return x.label === y.label &&
    x.mozillaCaPolicy === y.mozillaCaPolicy &&
    x.algorithm === y.algorithm &&
    _paramsEqual(x.parameters, y.parameters) &&
    _purposesEqual(x.purposes, y.purposes) &&
    _datesEqual(x.distrustAfter, y.distrustAfter);
}

function _dedupAnchors(anchors) {
  var seen = Object.create(null);
  var out = [];
  anchors.forEach(function (a) {
    var key = a.subjectDer.toString("hex") + "/" + a.publicKey.toString("hex");
    var prev = seen[key];
    if (!prev) { seen[key] = a; out.push(a); return; }
    if (!_anchorsAgree(prev, a)) {
      throw E("trust/pairing-mismatch", "two entries for one root (same subject + key) disagree on trust metadata");
    }
  });
  return out;
}


/**
 * @primitive  pki.trust.parseCertdata
 * @signature  pki.trust.parseCertdata(text) -> { anchors }
 * @since      0.2.0
 * @status     stable
 * @spec       RFC 5280 (NSS certdata.txt object stream)
 * @defends    trust-metadata-misattribution (CWE-345), trust-store-parser-DoS (CWE-770)
 * @related    pki.trust.parseCcadbCsv, pki.trust.anchor, pki.path.validate
 *
 * Parse the Mozilla/NSS `certdata.txt` root-store object stream into
 * constraint-carrying trust anchors. Each CKO_CERTIFICATE object's
 * MULTILINE_OCTAL `CKA_VALUE` is decoded and parsed as a DER certificate; the
 * paired CKO_NSS_TRUST object (joined by byte-exact CKA_ISSUER +
 * CKA_SERIAL_NUMBER, never adjacency, and cross-checked against the parsed
 * DER) contributes the purpose trust bits (only CKT_NSS_TRUSTED_DELEGATOR
 * grants a purpose); the per-purpose distrust-after dates ride in the
 * certificate object as bare ASCII times routed through the strict DER time
 * reader. Every anchor carries the exact `{ name, publicKey, algorithm,
 * parameters }` shape `pki.path.validate` consumes plus `distrustAfter`,
 * `purposes`, `subjectDer`, `label`, `mozillaCaPolicy`. A certificate with no
 * trust object becomes an anchor trusted for nothing (never silently
 * dropped); a trust object with no certificate grants nothing. Malformed
 * octal, an oversized block, an unrecognized trust value, a mispaired or
 * ambiguous-duplicate block, or an undecodable distrust-after time throws a
 * typed `trust/*` error, never a silently truncated or misattributed root.
 *
 * @example
 *   // Real input is the NSS certdata.txt read from disk; a one-root stream is
 *   // synthesized here from a DER certificate to show the object shape.
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "Example Root", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var cert = pki.schema.x509.parse(der);
 *   var oct = function (buf) { return Array.prototype.map.call(buf, function (b) { return "\\" + ("000" + b.toString(8)).slice(-3); }).join(""); };
 *   var blk = function (n, v) { return n + " MULTILINE_OCTAL\n" + oct(v) + "\nEND\n"; };
 *   var store = pki.trust.parseCertdata("BEGINDATA\n\n" +
 *     "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n" +
 *     blk("CKA_ISSUER", cert.issuer.bytes) +
 *     blk("CKA_SERIAL_NUMBER", pki.asn1.build.integer(cert.serialNumber)) +
 *     blk("CKA_VALUE", der));
 *   store.anchors[0].purposes.serverAuth;   // -> false (no trust object: trusted for nothing)
 */
function parseCertdata(text) {
  text = guard.text.decode(text, LIMITS.TRUST_MAX_BYTES, TrustError, {
    charset: "latin1", tooLarge: "trust/bad-block", badInput: "trust/bad-input", label: "certdata input",
  });
  var objects = _lexObjects(text);

  var certs = [];
  var byKey = Object.create(null);
  var trusts = [];
  objects.forEach(function (obj) {
    var cls = obj.attrs["CKA_CLASS"];
    if (!cls || cls.type !== "CK_OBJECT_CLASS") {
      throw E("trust/bad-block", "object block is missing CKA_CLASS CK_OBJECT_CLASS");
    }
    if (cls.value === "CKO_CERTIFICATE") {
      var e = _certEntry(obj);
      var prev = byKey[e.key];
      if (prev) {
        if (!prev.der.equals(e.der) || prev.label !== e.label ||
            prev.mozillaCaPolicy !== e.mozillaCaPolicy ||
            !_datesEqual(prev.distrustAfter, e.distrustAfter)) {
          throw E("trust/pairing-mismatch", "two certificate objects share an (issuer, serial) but disagree");
        }
        return;
      }
      byKey[e.key] = e;
      certs.push(e);
    } else if (cls.value === "CKO_NSS_TRUST") {
      trusts.push(_trustEntry(obj));
    }
  });

  trusts.forEach(function (t) {
    var c = byKey[t.key];
    if (!c) return;
    if (c.purposes) {
      if (!_purposesEqual(c.purposes, t.purposes)) {
        throw E("trust/pairing-mismatch", "two trust objects for one certificate disagree on purpose bits");
      }
      return;
    }
    c.purposes = t.purposes;
  });

  return {
    anchors: _dedupAnchors(certs.map(function (c) {
      return _mkAnchor(c.cert, {
        distrustAfter: c.distrustAfter,
        purposes: c.purposes || _copyPurposes(null),
        label: c.label,
        mozillaCaPolicy: c.mozillaCaPolicy,
      });
    })),
  };
}


var CSV_REQUIRED = [
  "Common Name or Certificate Name",
  "Trust Bits",
  "Distrust for TLS After Date",
  "Distrust for S/MIME After Date",
  "PEM Info",
];

function _csvRows(text) {
  var rows = [], row = [], field = "";
  var inQuotes = false, quoted = false, closed = false;
  var fieldCap = LIMITS.TRUST_MAX_CSV_FIELD_BYTES;

  function appendChar(c) {
    if (field.length >= fieldCap) throw E("trust/bad-csv", "a CSV field exceeds LIMITS.TRUST_MAX_CSV_FIELD_BYTES");
    field += c;
  }
  function endField() { row.push(field); field = ""; quoted = false; closed = false; }
  function endRow() {
    endField();
    if (rows.length >= LIMITS.TRUST_MAX_CSV_ROWS) throw E("trust/bad-csv", "CSV row count exceeds LIMITS.TRUST_MAX_CSV_ROWS");
    rows.push(row); row = [];
  }

  var i = 0, n = text.length;
  while (i < n) {
    var ch = text.charAt(i);
    if (inQuotes) {
      if (ch === "\"") {
        if (text.charAt(i + 1) === "\"") { appendChar("\""); i += 2; continue; }
        inQuotes = false; closed = true; i++; continue;
      }
      appendChar(ch); i++; continue;
    }
    if (ch === "\"") {
      if (field !== "" || quoted) throw E("trust/bad-csv", "a quote may only open at the start of a field (RFC 4180)");
      inQuotes = true; quoted = true; i++; continue;
    }
    if (ch === ",") { endField(); i++; continue; }
    if (ch === "\r" && text.charAt(i + 1) === "\n") { endRow(); i += 2; continue; }
    if (ch === "\n" || ch === "\r") { endRow(); i++; continue; }
    if (closed) throw E("trust/bad-csv", "content after a closing quote (RFC 4180)");
    appendChar(ch); i++;
  }
  if (inQuotes) throw E("trust/bad-csv", "unterminated quoted field at end of input");
  if (field !== "" || quoted || row.length > 0) endRow();
  return rows;
}

var _TRUST_BIT_TOKENS = intrinsic.assign(intrinsic.create(null), {
  "websites": "serverAuth", "server authentication": "serverAuth",
  "email": "emailProtection", "secure email": "emailProtection",
  "code": "codeSigning", "code signing": "codeSigning",
  "client authentication": null, "document signing": null,
  "time stamping": null, "ocsp signing": null,
});
function _trustBits(cell) {
  var purposes = intrinsic.assign(intrinsic.create(null), { serverAuth: false, emailProtection: false, codeSigning: false });
  String(cell).split(";").forEach(function (tok) {
    var t = tok.trim();
    if (t === "") return;
    var l = t.toLowerCase();
    if (!_hasOwn(_TRUST_BIT_TOKENS, l)) {
      throw E("trust/bad-csv", "unrecognized Trust Bits token " + JSON.stringify(t));
    }
    var p = _TRUST_BIT_TOKENS[l];
    if (p) purposes[p] = true;
  });
  return purposes;
}

function _csvDate(cell, label) {
  var s = String(cell).trim();
  if (s === "") return null;
  var m = _parseYmd(s);
  if (!m) throw E("trust/bad-csv", label + " must be a Y-M-D date, got " + JSON.stringify(s));
  var pad = function (x) { return x.length === 1 ? "0" + x : x; };
  var payload = Buffer.from(m[0] + pad(m[1]) + pad(m[2]) + "235959Z", "latin1");
  try { return _strictTime(payload, "trust/bad-csv", label); }
  catch (e) {
    if (e && e.code === "trust/bad-csv") throw e;
    throw E("trust/bad-csv", label + " is not a real calendar date: " + JSON.stringify(s), e);
  }
}

function _pemCell(cell) {
  var s = String(cell).trim();
  if (s.charAt(0) === "'") s = s.slice(1);
  if (s.charAt(s.length - 1) === "'") s = s.slice(0, -1);
  s = s.trim();
  if (s === "") throw E("trust/bad-csv", "PEM Info cell is empty");
  try { return x509.parse(s); }
  catch (e) { throw E("trust/not-a-certificate", "PEM Info does not parse as an X.509 certificate", e); }
}

/**
 * @primitive  pki.trust.parseCcadbCsv
 * @signature  pki.trust.parseCcadbCsv(text) -> { anchors }
 * @since      0.2.0
 * @status     stable
 * @spec       RFC 4180, RFC 5280 (CCADB certificate-records CSV)
 * @defends    trust-metadata-misattribution (CWE-345), trust-store-parser-DoS (CWE-770)
 * @related    pki.trust.parseCertdata, pki.trust.anchor, pki.path.validate
 *
 * Parse a CCADB certificate-records CSV export into the same `Anchor` shape
 * `parseCertdata` produces, so downstream enforcement is source-agnostic.
 * Columns are located by header name, never by position, and unknown,
 * reordered, or extra columns are tolerated; a MISSING required column
 * (`Common Name or Certificate Name`, `Trust Bits`, `Distrust for TLS After
 * Date`, `Distrust for S/MIME After Date`, `PEM Info`) fails closed with
 * `trust/bad-csv`. Fields follow RFC 4180 quoting (embedded commas, newlines,
 * doubled-quote escapes; the PEM Info column depends on it). `Trust Bits`
 * is set-valued (Websites -> serverAuth, Email -> emailProtection, Code ->
 * codeSigning; absent -> untrusted). A DATE-only distrust cell expands to the
 * end-of-day `...T23:59:59Z` instant, matching the NSS `...235959Z`
 * encoding, through the same strict time reader.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var pemText = await pki.x509.sign({ subject: "Example Root", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } },
 *     { key: await pki.key.export(pair.privateKey) }, { pem: true });
 *   var csv = "Common Name or Certificate Name,Trust Bits," +
 *             "Distrust for TLS After Date,Distrust for S/MIME After Date,PEM Info\n" +
 *             'Example Root,"Websites; Email",2027.06.01,,"' + pemText + '"';
 *   var store = pki.trust.parseCcadbCsv(csv);
 *   store.anchors[0].purposes.serverAuth;                    // -> true
 *   store.anchors[0].distrustAfter.serverAuth.toISOString(); // -> "2027-06-01T23:59:59.000Z"
 */
function parseCcadbCsv(text) {
  text = guard.text.decode(text, LIMITS.TRUST_MAX_BYTES, TrustError, {
    charset: "utf-8", fatal: true,
    tooLarge: "trust/bad-block", badDecode: "trust/bad-csv", badInput: "trust/bad-input",
    label: "CCADB CSV input",
  });
  var rows = _csvRows(text);
  if (rows.length === 0) throw E("trust/bad-csv", "CSV input carries no header row");

  var header = rows[0].map(function (h) { return h.trim(); });
  var col = Object.create(null);
  header.forEach(function (h, idx) {
    if (col[h] !== undefined) {
      if (CSV_REQUIRED.indexOf(h) !== -1) throw E("trust/bad-csv", "duplicate required column " + JSON.stringify(h));
      return;
    }
    col[h] = idx;
  });
  CSV_REQUIRED.forEach(function (r) {
    if (col[r] === undefined) throw E("trust/bad-csv", "CSV is missing the required column " + JSON.stringify(r));
  });

  var anchors = [];
  for (var i = 1; i < rows.length; i++) {
    var row = rows[i];
    if (row.length !== header.length) {
      throw E("trust/bad-csv", "CSV row " + (i + 1) + " has " + row.length + " fields; the header has " + header.length);
    }
    var distrustAfter = {};
    var tls = _csvDate(row[col["Distrust for TLS After Date"]], "Distrust for TLS After Date");
    if (tls) distrustAfter.serverAuth = tls;
    var smime = _csvDate(row[col["Distrust for S/MIME After Date"]], "Distrust for S/MIME After Date");
    if (smime) distrustAfter.emailProtection = smime;
    var label = row[col["Common Name or Certificate Name"]].trim();
    anchors.push(_mkAnchor(_pemCell(row[col["PEM Info"]]), {
      distrustAfter: distrustAfter,
      purposes: _trustBits(row[col["Trust Bits"]]),
      label: label === "" ? null : label,
      mozillaCaPolicy: false,
    }));
  }
  return { anchors: _dedupAnchors(anchors) };
}

/**
 * @primitive  pki.trust.anchor
 * @signature  pki.trust.anchor(entry, opts?) -> trustAnchor
 * @since      0.2.0
 * @status     stable
 * @spec       RFC 5280 sec. 6.1.1 (NSS trust-bit semantics)
 * @related    pki.trust.parseCertdata, pki.trust.parseCcadbCsv, pki.path.validate
 *
 * Turn a parsed trust-store entry into the `trustAnchor` object
 * `pki.path.validate` consumes: `{ name, publicKey, algorithm, parameters,
 * distrustAfter, purposes }`, a straight hand-off (validate reads
 * `distrustAfter` as a per-purpose map and `purposes` as the delegator set,
 * selected by its own `opts.checkPurpose`). With `opts.purpose` it
 * fail-fasts: an entry that is not a trusted delegator for that purpose
 * throws `trust/purpose-not-trusted` at build time, so an operator wiring a
 * store catches the wrong root before a single validation runs (the
 * authoritative gate stays inside `validate`).
 *
 * `opts.nameConstraints` attaches the namespace a root program trusts a root
 * for, when that is narrower than the root certificate itself states. Such a
 * restriction lives in the program's data rather than in any `nameConstraints`
 * extension the certificate carries, so it has to be supplied here. It is a
 * `{ permitted, excluded }` pair of `{ tag, base }` subtrees, the same shape
 * `pki.path.validate` takes for `opts.initialPermittedSubtrees`, and validate
 * seeds it as the RFC 5280 sec. 6.1.1(h)(i) initial value: it intersects with
 * every certificate's own constraints, so a leaf must satisfy both, and an
 * excluded subtree rejects whatever is permitted. The subtrees are copied out
 * of the caller's object, so changing that object afterwards does not change
 * the namespace an anchor already vouches for. An overlay naming no subtree,
 * or one supplying its subtrees through an accessor, is refused rather than
 * carried, since either would widen the namespace the operator meant to
 * restrict. A verdict reports `anchorConstraints.nameConstraintsApplied`.
 *
 * A base is held to the form its tag names, and one outside that form is
 * refused here rather than carried to a comparison that cannot reach a verdict
 * on it. Tag 1 (`rfc822Name`) is a mailbox, a host name, or a host name written
 * as a subtree with a leading dot, and a mailbox may name its domain as a
 * bracketed address literal; tag 2 (`dNSName`) is a host name, with or
 * without that leading dot; tag 6 (`uniformResourceIdentifier`) is the dotted
 * host name a certificate's URI is compared by, not a URI; tag 4
 * (`directoryName`) is `{ rdns }` naming at least one relative name, whose
 * attribute types are dotted-decimal object identifiers and whose values are
 * strings; tag 7 (`iPAddress`) is 8 bytes for IPv4 or 32 for IPv6, an address
 * followed by its mask. A host name is labels of letters, digits and hyphens,
 * with a hyphen at neither edge of a label, 63 characters to a label and 253 to
 * the name, and it may carry the one trailing dot the comparison strips. Tags
 * outside that set are refused.
 *
 * @opts
 *   purpose: string   // "serverAuth" | "emailProtection" | "codeSigning"; fail-fast purpose check
 *   nameConstraints: { permitted?: [{ tag, base }], excluded?: [{ tag, base }] }   // the root program's applied namespace; tags 1, 2, 4, 6, 7
 *
 * @example
 *   var ca = await pki.key.generate("Ed25519");
 *   var caKey = await pki.key.export(ca.privateKey);
 *   var caDer = await pki.x509.sign({ subject: "Example Root", subjectPublicKey: await pki.key.export(ca.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } },
 *     { key: caKey });
 *   var pemText = pki.schema.x509.pemEncode(caDer, "CERTIFICATE");
 *   var leaf = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "leaf.example", subjectPublicKey: await pki.key.export(leaf.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["serverAuth"], authorityKeyIdentifier: true } },
 *     { cert: caDer, key: caKey });
 *   var csv = "Common Name or Certificate Name,Trust Bits," +
 *             "Distrust for TLS After Date,Distrust for S/MIME After Date,PEM Info\n" +
 *             'Example Root,Websites,,,"' + pemText + '"';
 *   var entry = pki.trust.parseCcadbCsv(csv).anchors[0];
 *   var anchor = pki.trust.anchor(entry, { purpose: "serverAuth" });
 *   await pki.path.validate([pki.schema.x509.parse(der)],
 *     { time: new Date("2026-06-01T00:00:00Z"), trustAnchors: anchor, checkPurpose: "serverAuth" });
 */
var _ANCHOR_OPTS = intrinsic.assign(intrinsic.create(null), { purpose: 1, nameConstraints: 1 });

/** @internal A subtree list copied entry by entry, reading `tag` and `base` from their own data
 * properties. An accessor could answer with a narrow subtree while it is checked and a wide one
 * when it is read again, and a dropped entry widens the namespace the anchor vouches for, so a
 * list that does not describe itself in plain values is refused rather than partly copied. */
function _copySubtrees(list, where) {
  if (list === undefined || list === null) return [];
  if (!intrinsic.isArray(list) || intrinsic.types.isProxy(list)) {
    throw E("trust/bad-input", "anchor: nameConstraints." + where + " must be a plain array of { tag, base } subtree entries");
  }
  var out = [];
  for (var i = 0; i < list.length; i++) {
    var d = intrinsic.getOwnPropertyDescriptor(list, i);
    if (!d || !_hasOwn(d, "value")) {
      throw E("trust/bad-input", "anchor: nameConstraints." + where + " entry " + i + " must be a data property, not a hole or an accessor");
    }
    var st = d.value;
    if (!st || typeof st !== "object" || intrinsic.types.isProxy(st)) {
      throw E("trust/bad-input", "anchor: nameConstraints." + where + " entry " + i + " must be a { tag, base } object");
    }
    var tagD = intrinsic.getOwnPropertyDescriptor(st, "tag");
    var baseD = intrinsic.getOwnPropertyDescriptor(st, "base");
    if (!tagD || !_hasOwn(tagD, "value") || !baseD || !_hasOwn(baseD, "value")) {
      throw E("trust/bad-input", "anchor: nameConstraints." + where + " entry " + i + " must carry its own tag and base as plain values");
    }
    var tag = tagD.value;
    if (typeof tag !== "number" || !intrinsic.isInteger(tag) || tag < 0 || tag > 8) {
      throw E("trust/bad-input", "anchor: nameConstraints." + where + " entry " + i + " tag must be a GeneralName tag number 0..8, got " + guard.text.showValue(tag));
    }
    _assertSubtreeBaseForm(tag, baseD.value, where, i);
    /** @internal Appended through the list guard: a setter planted on the array prototype swallows
     * a plain index assignment, and a subtree list that came back empty would restrict nothing. */
    guard.list.append(out, { tag: tag, base: _copySubtreeBase(tag, baseD.value, where) });
  }
  return out;
}

/** @internal The base of one subtree, copied by its name form so the anchor holds no reference the
 * caller can still reach. A byte base is snapshotted through the byte guard, which accepts every
 * source `pki.path.validate` does rather than Buffers alone, so bytes changed afterwards do not
 * change the namespace. A directoryName goes through the guard that owns distinguished-name
 * capture, which refuses a Proxy or an accessor anywhere in the name instead of running it: reading
 * such a name is caller code, and it could clear the restriction it is being asked to describe. */
function _copySubtreeBase(tag, base, where) {
  if (typeof base === "string") return base;
  if (tag === 7) {
    return guard.bytes.snapshotSource(base, TrustError, "trust/bad-input", "anchor: nameConstraints." + where + " iPAddress base");
  }
  var rdns = guard.name.capturedRdns(base, E, "trust/bad-input", "anchor: nameConstraints." + where + " directoryName base");
  if (rdns === undefined) {
    throw E("trust/bad-input", "anchor: nameConstraints." + where + " directoryName base must carry its own rdns array");
  }
  return { rdns: rdns };
}

var _NC_KEYS = intrinsic.assign(intrinsic.create(null), { permitted: 1, excluded: 1 });

/** @internal One of the overlay's two subtree lists, taken from its own data property. A list the
 * object only inherits is refused rather than read as absent: treating it as absent drops the
 * restriction it carries, and dropping an exclusion admits the namespace it was written to keep
 * out. An accessor is refused for the same reason, since it decides what it says while it is read. */
function _subtreeListDescriptor(nc, key) {
  var d = intrinsic.getOwnPropertyDescriptor(nc, key);
  if (d === undefined) {
    if (key in intrinsic.Object(nc)) {
      throw E("trust/bad-input", "anchor: opts.nameConstraints." + key + " must be the object's own property, not one it inherits");
    }
    return undefined;
  }
  if (!_hasOwn(d, "value")) {
    throw E("trust/bad-input", "anchor: opts.nameConstraints." + key + " must be a plain value, not an accessor");
  }
  return d;
}

/** @internal A subtree base held to the form its tag names, so a base that cannot describe a
 * namespace is refused here rather than carried to the validator, and so no shape falls through to
 * being returned by reference: a base the anchor still shares with the caller is one the caller can
 * complete afterwards, which moves the namespace an anchor has already vouched for. */
function _assertSubtreeBaseForm(tag, base, where, index) {
  var who = "anchor: nameConstraints." + where + " entry " + index;
  if (tag === 1 || tag === 2 || tag === 6) {
    var why = guard.name.constraintBaseRefusal(tag, base);
    if (why !== null) throw E("trust/bad-input", who + " base " + why);
    return;
  }
  if (tag === 7) {
    if (!guard.bytes.isByteSource(base)) throw E("trust/bad-input", who + " iPAddress base must be a byte source");
    /** @internal An iPAddress subtree is an address followed by its mask, so 8 bytes for IPv4 and
     * 32 for IPv6. Any other length names no range, and the validator refuses it later; refusing it
     * here means the anchor an operator is handed is one that can be enforced. */
    var ipLen = guard.bytes.lengthOf(guard.bytes.source(base, TrustError, "trust/bad-input", who + " iPAddress base"));
    if (ipLen !== 8 && ipLen !== 32) {
      throw E("trust/bad-input", who + " iPAddress base must be 8 bytes (IPv4 address and mask) or 32 (IPv6), got " + ipLen);
    }
    return;
  }
  if (tag === 4) {
    if (base === null || typeof base !== "object") throw E("trust/bad-input", who + " directoryName base must be an object carrying rdns");
    return;
  }
  throw E("trust/bad-input", who + " tag " + tag + " names a form this overlay cannot constrain; use tag 1, 2, 4, 6 or 7");
}

/** @internal The overlay a root program applies to a root outside any nameConstraints extension the
 * certificate carries. It only ever narrows, so an absent one is the status quo and is left off the
 * anchor entirely; a malformed one is refused, since carrying it wrongly would widen a namespace the
 * operator meant to restrict. The subtrees are held to their shapes again by `pki.path.validate`,
 * which is where the RFC 5280 sec. 6.1.1(h)(i) seeding happens. */
function _copyNameConstraints(nc) {
  if (nc === undefined || nc === null) return null;
  if (typeof nc !== "object" || intrinsic.isArray(nc) || intrinsic.types.isProxy(nc)) {
    throw E("trust/bad-input", "anchor: opts.nameConstraints must be a { permitted, excluded } object of { tag, base } subtree entries");
  }
  /** @internal Runs before the membership tests below, which is what makes them safe to ask: this
   * refuses an overlay inheriting from a Proxy, whose has trap would otherwise answer `in` with
   * caller code while the lists are being read. It also names a misspelled field, which would
   * otherwise be read as an absent list, and an absent excluded list admits the namespace the
   * operator wrote it to keep out. */
  guard.identifier.assertKnownKeys(nc, _NC_KEYS, E, "trust/bad-input", "anchor: opts.nameConstraints has an unknown field ");
  var pD = _subtreeListDescriptor(nc, "permitted");
  var eD = _subtreeListDescriptor(nc, "excluded");
  var out = {
    permitted: _copySubtrees(pD ? pD.value : null, "permitted"),
    excluded: _copySubtrees(eD ? eD.value : null, "excluded"),
  };
  if (!out.permitted.length && !out.excluded.length) {
    throw E("trust/bad-input", "anchor: opts.nameConstraints names no subtree; omit it rather than passing an empty restriction");
  }
  return out;
}
function anchor(entry, opts) {
  if (!entry || typeof entry !== "object") {
    throw E("trust/bad-input", "anchor expects a trust-store entry ({ name, publicKey, algorithm, ... })");
  }
  opts = guard.identifier.optionsObject(opts, E, "trust/bad-input", "pki.trust.anchor options");
  guard.identifier.assertKnownKeys(opts, _ANCHOR_OPTS, E, "trust/bad-input", "unknown pki.trust.anchor option ");
  var derived = _DERIVED_FROM.get(entry);
  var meta = derived || entry;
  if (!derived && (!Buffer.isBuffer(entry.publicKey) || typeof entry.algorithm !== "string" ||
      !entry.name || !Array.isArray(entry.name.rdns))) {
    throw E("trust/bad-input", "anchor expects a trust-store entry ({ name, publicKey, algorithm, ... })");
  }
  if (opts.purpose !== undefined) {
    if (PURPOSES.indexOf(opts.purpose) === -1) {
      throw E("trust/bad-input", "anchor: opts.purpose must be one of " + PURPOSES.join(" | "));
    }
    if (!meta.purposes || meta.purposes[opts.purpose] !== true) {
      throw E("trust/purpose-not-trusted", "this root is not a trusted delegator for " + opts.purpose);
    }
  }
  if (!derived && (entry.purposes != null || (entry.distrustAfter && guard.identifier.optionNames(entry.distrustAfter).length))) {
    throw E("trust/bad-input", "this entry carries a trust store's per-purpose metadata but is not the entry the store produced -- it has been rebuilt, and the metadata is a statement about the key the store read, not about whichever key the copy now names. Pass pki.trust.parseCertdata / parseCcadbCsv output unmodified");
  }
  var nameConstraints = _copyNameConstraints(opts.nameConstraints);
  var out = {
    name: _copyName(meta.name),
    publicKey: Buffer.isBuffer(meta.publicKey) ? Buffer.from(meta.publicKey) : meta.publicKey,
    algorithm: meta.algorithm,
    parameters: Buffer.isBuffer(meta.parameters) ? Buffer.from(meta.parameters)
      : (meta.parameters !== undefined ? meta.parameters : null),
    distrustAfter: _copyDistrustAfter(meta.distrustAfter),
    purposes: _purposesOrNull(meta.purposes),
  };
  /** @internal Set only when an overlay was supplied, so an anchor without one is the object this
   * verb returned before the option existed, and defined rather than assigned: an accessor planted
   * on Object.prototype under this name would otherwise take the assignment and leave the anchor
   * carrying no restriction at all. */
  if (nameConstraints) guard.verdict.set(out, "nameConstraints", nameConstraints);
  /** @internal The RFC 5914 anchor's own constraints, kept separate from the `nameConstraints`
   * overlay a caller may also supply: RFC 5937 sec. 3.2 intersects every permitting set rather than
   * letting one replace another, so the two have to reach the validator as two statements.
   *
   * Read from `meta`, which is the derived record when there is one and the caller's entry when
   * there is not, so a copy of an entry keeps the restrictions the original carried. They can only
   * narrow a validation, so an entry that states them is safe to honor whoever built it. */
  if (meta.constraints) guard.verdict.set(out, "constraints", _copyConstraints(meta.constraints));
  return out;
}

/** @internal Copied entry by entry, for the same reason every other anchor field is: what the
 *  validator enforces must be what this verb read, not what a caller's object answers later. */
function _copyConstraints(c) {
  var out = intrinsic.create(null);
  if (c.nameConstraints) {
    out.nameConstraints = {
      permitted: _copySubtrees(c.nameConstraints.permitted, "permitted"),
      excluded: _copySubtrees(c.nameConstraints.excluded, "excluded"),
    };
  }
  if (c.policySet) out.policySet = intrinsic.map(c.policySet, function (p) { return p; });
  if (c.policyFlags) {
    var f = intrinsic.create(null);
    intrinsic.forEach(trustanchorSchema.policyFlagBits, function (k) { f[k] = c.policyFlags[k] === true; });
    out.policyFlags = f;
  }
  if (c.pathLenConstraint !== undefined) out.pathLenConstraint = c.pathLenConstraint;
  return out;
}

/** @internal An RFC 5914 anchor's constraints, in the shape `pki.path.validate` reads them. Each
 *  field is absent rather than null when the anchor states nothing, so an anchor that constrains
 *  nothing is the object this module produced before the format existed. */
function _anchorConstraintsOf(taInfo) {
  var cp = taInfo.certPath;
  /** @internal `exts` is where RFC 5914 sec. 2.6 says an anchor associates any extension outside
   * the four `certPath` already carries, and basic constraints is one of them, so a path length
   * stated there binds as much as one stated in `certPath` (RFC 5937 sec. 3.2). Where both state
   * one, the stricter wins: an anchor may only narrow. */
  var extsPathLen = pkix.anchorPathLenFromExtensions(taInfo.exts, _NS, "the TrustAnchorInfo exts");
  if (cp === null) {
    if (extsPathLen === null) return null;
    var only = intrinsic.create(null);
    only.pathLenConstraint = extsPathLen;
    return only;
  }
  var out = intrinsic.create(null);
  var any = false;
  if (cp.nameConstr !== null) {
    out.nameConstraints = {
      permitted: intrinsic.map(cp.nameConstr.permittedSubtrees || [], _subtreeOf),
      excluded: intrinsic.map(cp.nameConstr.excludedSubtrees || [], _subtreeOf),
    };
    any = true;
  }
  if (cp.policySet !== null) {
    out.policySet = intrinsic.map(cp.policySet, function (p) { return p.policyIdentifier; });
    any = true;
  }
  if (cp.policyFlags !== null) { out.policyFlags = cp.policyFlags; any = true; }
  var pathLen = pkix.lowerPathLen(cp.pathLenConstraint, extsPathLen);
  if (pathLen !== null) { out.pathLenConstraint = pathLen; any = true; }
  return any ? out : null;
}
function _subtreeOf(st) { return { tag: st.base.tagNumber, base: st.base.value }; }

/**
 * @primitive  pki.trust.parseTrustAnchorList
 * @signature  pki.trust.parseTrustAnchorList(input, opts?) -> { anchors }
 * @since      0.8.13
 * @status     stable
 * @spec       RFC 5914, RFC 5937 sec. 3.2
 * @related    pki.trust.anchor, pki.schema.trustanchor.parse, pki.path.validate
 *
 * Read an RFC 5914 `TrustAnchorList` into the trust-store entries `pki.trust.anchor` takes, the
 * same shape `parseCertdata` and `parseCcadbCsv` produce. Each entry carries the anchor's name,
 * public key and algorithm, so a list published by a root program drives `pki.path.validate`
 * without the operator mapping it by hand.
 *
 * A `taInfo` anchor's constraints ride on the entry and are applied as RFC 5937 section 3.2 states,
 * which is that the stricter of the anchor's value and the caller's always wins: its name
 * constraints intersect the caller's permitted subtrees and union its excluded ones, its
 * `policySet` intersects `opts.userInitialPolicySet`, each of its `policyFlags` may turn the
 * matching `initial*` option on and never off, and its `pathLenConstraint` bounds the path.
 *
 * The `certificate` and `tbsCert` arms carry no constraints of their own, so an entry from either
 * is the anchor that certificate's subject and key describe.
 *
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (integer) -- decode caps for the parse.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = pki.trustanchor.build({ anchors: [{ taInfo: {
 *     pubKey: await pki.key.export(pair.publicKey), keyId: Buffer.alloc(20, 1),
 *     certPath: { taName: "CN=Example Root" } } }] });
 *   pki.trust.parseTrustAnchorList(der).anchors.length;   // -> 1
 */
function parseTrustAnchorList(input, opts) {
  var list = trustanchorSchema.parse(input, opts);
  var out = [];
  intrinsic.forEach(list.anchors, function (a, i) {
    guard.list.append(out, _entryFromAnchor(a, i));
  });
  return { anchors: out };
}

function _entryFromAnchor(a, i) {
  if (a.kind === "certificate" || a.kind === "tbsCert") {
    var cert = a.kind === "certificate" ? a.certificate : a.tbsCert;
    return _mkAnchor(cert, { distrustAfter: {}, purposes: null, label: null, mozillaCaPolicy: false });
  }
  var info = a.taInfo;
  if (info.certPath === null) {
    throw E("trust/bad-input", "anchors[" + i + "] is a TrustAnchorInfo carrying no certPath, so it names no " +
      "distinguished name to chain to; a trust anchor needs one (RFC 5914 sec. 2)");
  }
  var spki = info.pubKey;
  var constraints = _anchorConstraintsOf(info);
  var entry = {
    name: info.certPath.taName,
    publicKey: spki.bytes,
    algorithm: spki.algorithm.oid,
    parameters: spki.algorithm.parameters,
    subjectDer: info.certPath.taName.bytes,
    distrustAfter: {},
    purposes: null,
    label: info.taTitle,
    mozillaCaPolicy: false,
  };
  /** @internal On the ENTRY, not only in the derived record behind it. The entry carries a name, a
   * public key and an algorithm, which is exactly the anchor tuple `pki.path.validate` accepts, so
   * an operator passing `parseTrustAnchorList(der).anchors` straight to `trustAnchors` is doing the
   * obvious thing. Keeping the constraints out of reach of that call would hand them an
   * UNCONSTRAINED anchor and silently drop every restriction the list stated. */
  if (constraints) guard.verdict.set(entry, "constraints", constraints);
  _DERIVED_FROM.set(entry, {
    name: _copyName(info.certPath.taName),
    publicKey: intrinsic.bufferFrom(spki.bytes),
    algorithm: spki.algorithm.oid,
    parameters: spki.algorithm.parameters == null ? spki.algorithm.parameters : intrinsic.bufferFrom(spki.algorithm.parameters),
    purposes: null,
    distrustAfter: _copyDistrustAfter({}),
    /** @internal Its OWN copy, not the object the entry carries. The derived record is what
     * `anchor` trusts in preference to the entry, precisely because the entry is reachable: a
     * caller who edits `entry.constraints` would otherwise be editing what the anchor enforces,
     * which is the one thing this record exists to prevent for the name and the key. */
    constraints: constraints === null ? null : _copyConstraints(constraints),
  });
  return entry;
}

/** @internal The bundle paths a Unix host keeps its CA set in, in the order a reader should try
 *  them. Each is a concatenated PEM file the distribution maintains. macOS and Windows keep theirs
 *  in a binary keychain and a registry-backed store, so neither has a path here. */
var _BUNDLE_PATHS = [
  "/etc/ssl/certs/ca-certificates.crt",
  "/etc/pki/tls/certs/ca-bundle.crt",
  "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
  "/etc/ssl/ca-bundle.pem",
  "/etc/ssl/cert.pem",
  "/usr/local/share/certs/ca-root-nss.crt",
];

var _SYSTEM_ANCHOR_OPTS = intrinsic.assign(intrinsic.create(null), {
  path: 1, allowNodeBundle: 1, maxBytes: 1,
});

/** @internal What an operator runs to produce a bundle this verb can read, per platform. Named in
 *  the refusal, because the alternative an operator reaches for otherwise is Node's compiled-in
 *  set, which is not what their host trusts. */
function _exportHint() {
  if (process.platform === "darwin") {
    return "export the host's roots with: security find-certificate -a -p " +
      "/System/Library/Keychains/SystemRootCertificates.keychain > roots.pem";
  }
  if (process.platform === "win32") {
    return "export the host's roots with: certutil -store ROOT";
  }
  return "point opts.path at the CA bundle this host keeps";
}

/**
 * @primitive  pki.trust.discoversBundles
 * @signature  pki.trust.discoversBundles(platform) -> boolean
 * @since      0.8.15
 * @status     stable
 * @spec       RFC 5280
 * @defends    trust-store-misattribution (CWE-345)
 * @related    pki.trust.systemAnchors
 *
 * Whether `systemAnchors` searches for a CA bundle on this platform. A Unix host's bundle IS the
 * set its TLS stack trusts. macOS keeps its trust decisions in Keychain and Windows in a
 * registry-backed store, and on macOS `/etc/ssl/cert.pem` can exist as OpenSSL's own copy, which
 * is not the host's trust and omits both locally installed roots and Keychain overrides. Reporting
 * that file as the host's anchors is the misattribution this verb exists to prevent, so those
 * platforms are refused rather than searched. `opts.path` still reads an exported bundle anywhere.
 *
 * @example
 *   pki.trust.discoversBundles("linux");  // -> true
 *   pki.trust.discoversBundles("darwin"); // -> false
 */
function discoversBundles(platform) {
  if (typeof platform !== "string" || platform.length === 0) {
    throw E("trust/bad-input", "discoversBundles takes a process.platform string");
  }
  return platform !== "darwin" && platform !== "win32";
}

/** @internal Reads at most `maxBytes + 1` so the cap bounds what is ALLOCATED rather than being
 *  checked after an unbounded read: a file far above the cap must not reach memory first. */
function _readBundleText(chosen, maxBytes) {
  var fd = null, raw, read;
  try {
    fd = nodeFs.openSync(chosen, "r");
    var buf = intrinsic.bufferAlloc(maxBytes + 1);
    /** @internal readSync may return fewer bytes than asked for, so the prefix of one call is not
     * the file. Taking it as the whole bundle would drop the roots below the break with nothing
     * reported, and would let a file above the cap pass the check underneath it. */
    read = 0;
    for (;;) {
      var got = nodeFs.readSync(fd, buf, read, (maxBytes + 1) - read, read);
      if (got === 0) break;
      read += got;
      if (read >= maxBytes + 1) break;
    }
    raw = buf.subarray(0, read);
  } catch (e) {
    throw E("trust/no-readable-store", "no CA bundle could be read at " + guard.text.showValue(chosen) +
      "; " + _exportHint() + ", or pass opts.allowNodeBundle to use the Mozilla set compiled into " +
      "Node, which is NOT what this host trusts", e);
  } finally {
    if (fd !== null) {
      try { nodeFs.closeSync(fd); }
      // allow:swallow-unverified the descriptor is released on a best-effort basis
      catch (_e) { void 0; }
    }
  }
  if (read > maxBytes) {
    throw E("trust/too-large", "the CA bundle at " + guard.text.showValue(chosen) +
      " is larger than the " + maxBytes + "-byte cap this read admits");
  }
  return raw;
}

/**
 * @primitive  pki.trust.systemAnchors
 * @signature  pki.trust.systemAnchors(opts?) -> { anchors, source, path, skipped }
 * @since      0.8.15
 * @status     stable
 * @spec       RFC 7468 (PEM), RFC 5280
 * @defends    trust-store-misattribution (CWE-345), trust-store-parser-DoS (CWE-770)
 * @related    pki.trust.parseCertdata, pki.trust.parseCcadbCsv, pki.trust.anchor, pki.path.validate
 *
 * Read the host's CA bundle into the trust anchors `pki.path.validate` consumes. `source` names
 * which set was read: `"ca-bundle"` for a file on this host, with `path` naming it, or
 * `"node-bundled"` for the Mozilla set compiled into Node, whose `path` is `null`. A block the
 * bundle carries that is not a certificate is listed in `skipped` with the label that named it,
 * rather than dropped.
 *
 * A host whose roots are not in a readable PEM file is refused, and the refusal names the command
 * that exports them. macOS keeps its roots in a binary keychain and Windows in a registry-backed
 * store, and reading either means running another program, which this toolkit does not do. Falling
 * back to Node's set instead would report anchors the host does not use, so that takes the
 * explicit `opts.allowNodeBundle`.
 *
 * @opts
 *   - `path` -- read this file instead of searching the per-platform list.
 *   - `allowNodeBundle` -- return Node's compiled-in set when no bundle can be read.
 *   - `maxBytes` -- cap the bundle read (default `C.LIMITS.TRUST_MAX_BYTES`).
 *
 * @example
 *   // Read the host's bundle where there is one, and say so when there is not. Check `source`
 *   // before trusting the answer: "node-bundled" is Node's compiled-in set, not this machine's.
 *   var store = pki.trust.systemAnchors({ allowNodeBundle: true });
 *   console.log(store.source);            // -> "ca-bundle" on a Unix host, else "node-bundled"
 *   console.log(store.anchors.length > 0); // -> true
 *   console.log(store.skipped.length >= 0); // -> true (entries named, never dropped silently)
 */
function systemAnchors(opts) {
  opts = opts || {};
  guard.identifier.assertPlainRecord(opts, E, "trust/bad-input", "systemAnchors opts");
  guard.identifier.assertKnownKeys(opts, _SYSTEM_ANCHOR_OPTS, E, "trust/bad-input",
    "unknown systemAnchors option ");
  var maxBytes = guard.limits.cap(opts.maxBytes, "systemAnchors: opts.maxBytes",
    LIMITS.TRUST_MAX_BYTES, { E: E, code: "trust/bad-input", min: 1, max: LIMITS.TRUST_MAX_BYTES });

  var chosen = null;
  if (opts.path !== undefined) {
    if (typeof opts.path !== "string" || opts.path.length === 0) {
      throw E("trust/bad-input", "systemAnchors: opts.path must be a non-empty string");
    }
    chosen = opts.path;
  }

  var text = null;
  if (chosen !== null) {
    /** @internal `allowNodeBundle` says what to do when there is NO readable bundle, so an absent
     * file falls back to Node's set under it. A bundle that EXISTS and breaks the cap does not:
     * the caller asked about that file, and a resource refusal must never quietly swap the trust
     * set a validation runs against for a different one. */
    try { text = _readBundleText(chosen, maxBytes); }
    catch (e) {
      if (opts.allowNodeBundle !== true || !e || e.code !== "trust/no-readable-store") throw e;
      text = null;
      chosen = null;
    }
  } else if (discoversBundles(process.platform)) {
    for (var i = 0; i < _BUNDLE_PATHS.length && text === null; i++) {
      /** @internal Readability is established by READING, not by a stat: a candidate that exists
       * but cannot be opened must not stop the search and strand a readable one below it. */
      try { text = _readBundleText(_BUNDLE_PATHS[i], maxBytes); chosen = _BUNDLE_PATHS[i]; }
      catch (e) {
        if (e && e.code === "trust/too-large") throw e;
        // allow:swallow-unverified a candidate this host cannot read is not this host's bundle
        text = null;
      }
    }
  }

  if (text === null) {
    if (opts.allowNodeBundle !== true) {
      throw E("trust/no-readable-store", "this host keeps no CA bundle this toolkit can read" +
        (chosen === null ? "" : " at " + guard.text.showValue(chosen)) + "; " + _exportHint() +
        ", or pass opts.allowNodeBundle to use the Mozilla set compiled into Node, which is NOT " +
        "what this host trusts");
    }
    return _anchorsFromPems(nodeTls.rootCertificates, "node-bundled", null);
  }
  return _anchorsFromBundle(text, chosen);
}

/** @internal A line that reads as a BEGIN boundary but does not start one, because RFC 7468 sec. 2
 *  puts the boundary at the start of a line and this one is indented or trailed. The decoder is
 *  right to pass over it as explanatory text, and in a trust bundle that is an anchor the operator
 *  believes they installed and does not have. Reported with the offset, never a throw: the file is
 *  readable and the other roots in it are usable. */
/** @internal The bytes of "-----BEGIN ", held as codes because this directory scans by character
 *  code rather than by pattern. */
var _BEGIN_MARK = [0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20];

function _reportUnusableBoundaries(bytes, rows, skipped) {
  var used = intrinsic.create(null);
  for (var r = 0; r < rows.length; r++) used[rows[r].offset] = true;
  var lineStart = 0;
  for (var i = 0; i <= bytes.length; i++) {
    if (i !== bytes.length && bytes[i] !== 0x0a) continue;
    var at = lineStart;
    while (at < i && (bytes[at] === 0x20 || bytes[at] === 0x09)) at += 1;
    var indented = at > lineStart;
    var matches = indented && at + _BEGIN_MARK.length <= i;
    for (var m = 0; matches && m < _BEGIN_MARK.length; m++) {
      if (bytes[at + m] !== _BEGIN_MARK[m]) matches = false;
    }
    if (matches && used[at] !== true) {
      guard.list.append(skipped, {
        index: null, offset: at, label: null,
        reason: "pem/unusable-boundary: a BEGIN boundary at byte " + at + " does not start its " +
          "line, so RFC 7468 sec. 2 reads it as text and the object it opens is not decoded",
      });
    }
    lineStart = i + 1;
  }
}

/** @internal Every certificate block becomes an anchor and every other block is reported, because
 *  a bundle an operator assembled by hand is exactly where a key or a CRL ends up, and a reader
 *  that drops one silently leaves them believing it was read. */
function _anchorsFromBundle(text, chosen) {
  var rows;
  try { rows = pkix.pemDecodeBundle(text, {}, errors.PemError); }
  catch (e) {
    if (e && e.code === "pem/no-block") {
      throw E("trust/no-anchors", "the CA bundle at " + guard.text.showValue(chosen) +
        " carries no PEM block, so it names no trust anchor", e);
    }
    throw E("trust/bad-bundle", "the CA bundle at " + guard.text.showValue(chosen) +
      " is not readable as PEM: " + guard.text.describeThrown(e), e);
  }
  var anchors = [], skipped = [];
  _reportUnusableBoundaries(text, rows, skipped);
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (row.label === "TRUSTED CERTIFICATE") {
      /** @internal OpenSSL's TRUSTED CERTIFICATE is a Certificate followed by an X509_CERT_AUX
       * carrying the purposes the operator trusted it FOR. Reading the leading certificate and
       * dropping the aux would hand back a root restricted to one purpose as an unrestricted
       * anchor, which is a widening, so the block is reported until the aux is read. */
      guard.list.append(skipped, {
        index: row.index, offset: row.offset, label: row.label,
        reason: "trust/aux-not-read: an OpenSSL trusted certificate carries the purposes it is " +
          "trusted for in a trailing X509_CERT_AUX this reader does not decode, and ingesting it " +
          "without them would widen the trust it states; convert it with " +
          "`openssl x509 -in <file> -out <file>.pem` and pass the result",
      });
      continue;
    }
    if (row.label !== "CERTIFICATE") {
      guard.list.append(skipped, {
        index: row.index, offset: row.offset, label: row.label,
        reason: "trust/not-a-certificate-block: a " + guard.text.showValue(row.label) +
          " block names no trust anchor",
      });
      continue;
    }
    var cert = null, why = null;
    try { cert = x509.parse(row.der); }
    catch (e) { why = (e && e.code ? e.code : "trust/not-a-certificate") + ": " + guard.text.describeThrown(e); }
    if (cert === null) {
      /** @internal Reported, not thrown. A host CA bundle is distribution-managed and real ones
       * carry certificates this toolkit refuses: the Mozilla set Node ships has a root encoding
       * pre-2050 dates as GeneralizedTime against the RFC 5280 sec. 4.1.2.5 MUST. Refusing the
       * whole file would leave the operator with no anchors over a root they do not control,
       * and relaxing the reader to admit it would weaken every other caller. The entry is named
       * with the reason instead, so a missing anchor is visible rather than silent. */
      guard.list.append(skipped, { index: row.index, offset: row.offset, label: row.label, reason: why });
      continue;
    }
    guard.list.append(anchors, _mkAnchor(cert, {
      distrustAfter: {}, purposes: null, label: null, mozillaCaPolicy: false,
    }));
  }
  if (anchors.length === 0) {
    throw E("trust/no-anchors", "the CA bundle at " + guard.text.showValue(chosen) +
      " carries no certificate, so it names no trust anchor");
  }
  return _systemResult(anchors, "ca-bundle", chosen, skipped);
}

function _anchorsFromPems(pems, source, chosen) {
  var anchors = [], skipped = [];
  for (var i = 0; i < pems.length; i++) {
    var cert = null, why = null;
    try { cert = x509.parse(x509.pemDecode(pems[i], "CERTIFICATE")); }
    catch (e) { why = (e && e.code ? e.code : "trust/not-a-certificate") + ": " + guard.text.describeThrown(e); }
    if (cert === null) {
      guard.list.append(skipped, { index: i, offset: null, label: "CERTIFICATE", reason: why });
      continue;
    }
    guard.list.append(anchors, _mkAnchor(cert, {
      distrustAfter: {}, purposes: null, label: null, mozillaCaPolicy: false,
    }));
  }
  if (anchors.length === 0) throw E("trust/no-anchors", "the " + source + " set carries no certificate");
  return _systemResult(anchors, source, chosen, skipped);
}

/** @internal Defined rather than assigned, and a fresh list each call: the caller owns what it is
 *  handed, so emptying it must not change what the next call returns. */
function _systemResult(anchors, source, chosen, skipped) {
  var out = intrinsic.create(null);
  guard.verdict.set(out, "anchors", anchors);
  guard.verdict.set(out, "source", source);
  guard.verdict.set(out, "path", chosen);
  guard.verdict.set(out, "skipped", skipped);
  return out;
}

module.exports = {
  parseCertdata: parseCertdata,
  parseCcadbCsv: parseCcadbCsv,
  parseTrustAnchorList: parseTrustAnchorList,
  systemAnchors: systemAnchors,
  discoversBundles: discoversBundles,
  anchor: anchor,
};
