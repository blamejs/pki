// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.smime
 * @nav        Messaging
 * @title      S/MIME
 * @fullname   S/MIME signed and encrypted mail
 * @order      175
 * @slug       smime
 *
 * @intro
 *   RFC 8551 S/MIME assembly + verification + encryption over the shipped CMS
 *   layer. `sign` wraps a MIME entity as a signed S/MIME message and `verify`
 *   unwraps and verifies one, in both forms: `multipart/signed` (clear-signed:
 *   the content stays readable, a detached CMS signature rides alongside) and
 *   `application/pkcs7-mime` (opaque, where the whole entity is a base64 CMS
 *   SignedData). `encrypt` envelopes a MIME entity as an opaque
 *   `application/pkcs7-mime` message and `decrypt` opens one: `authEnveloped-data`
 *   (AES-GCM, confidentiality AND integrity, the default) or `enveloped-data`
 *   (AES-CBC, confidentiality only, so `decrypt` surfaces `authenticated:false`,
 *   the EFAIL / RFC 8551 sec. 3.3 no-integrity caveat). The crypto is entirely
 *   `pki.cms.sign` / `verify` / `encrypt` / `decrypt`; the new work is the MIME
 *   frame and the RFC 8551 sec. 3.1.1 canonicalization signer and verifier share
 *   one canonicalizer (`lib/mime.js`) so their digests cannot diverge. Like
 *   `cms.verify`, `verify` returns the per-signer cryptographic verdict; chaining
 *   a signer to a trust anchor is the caller's `pki.path.validate` step.
 *
 * @card
 *   Assemble, verify, and encrypt RFC 8551 S/MIME messages (signed:
 *   multipart/signed + application/pkcs7-mime; encrypted: enveloped-data +
 *   authEnveloped-data) over any CMS signer / recipient, fail-closed,
 *   algorithm-agnostic.
 */

var frameworkError = require("./framework-error.js");
var mime = require("./mime.js");
var cms = require("./cms-verify.js");
var schemaCms = require("./schema-cms.js");
var schemaX509 = require("./schema-x509.js");
var pkix = require("./schema-pkix.js");
var oid = require("./oid.js");
var guard = require("./guard-all.js");
var C = require("./constants.js");
var nodeCrypto = require("crypto");

var SmimeError = frameworkError.SmimeError;

function _err(code, msg, cause) { return new SmimeError(code, msg, cause); }

var SIGN_OPTS = Object.assign(Object.create(null), {
  form: 1, entity: 1, contentType: 1, signingTime: 1, protectHeaders: 1, headers: 1, hcp: 1,
  sid: 1, signedAttributes: 1, additionalSignedAttributes: 1,
});
var VERIFY_OPTS = Object.assign(Object.create(null), {
  certs: 1, trustAnchors: 1, time: 1, requiredEku: 1, checkPurpose: 1, strictMicalg: 1,
  legacyHeaderProtection: 1, expectedSender: 1,
});
var ENCRYPT_OPTS = Object.assign(Object.create(null), {
  entity: 1, contentType: 1, protectHeaders: 1, headers: 1, hcp: 1,
  contentEncryptionAlgorithm: 1, oaepHash: 1, keyIdentifier: 1, ukm: 1,
});
var DECRYPT_OPTS = Object.assign(Object.create(null), { recipientIndex: 1, maxIterations: 1, strictSmimeType: 1, legacyHeaderProtection: 1 });
var COMPRESS_OPTS = Object.assign(Object.create(null), { entity: 1, contentType: 1, level: 1 });
var DECOMPRESS_OPTS = Object.assign(Object.create(null), { maxOutputBytes: 1 });

function _knownOpts(opts, known, verb) {
  guard.identifier.assertKnownKeys(opts, known, _err, "smime/bad-input", function (k) {
    return "unknown option " + JSON.stringify(k) + " for pki.smime." + verb + " -- accepted: " +
      Object.keys(known).sort().join(", ");
  });
}

function _isPkcs7(type, kind) {
  var t = (type || "").toLowerCase();
  return t === "application/pkcs7-" + kind || t === "application/x-pkcs7-" + kind;
}

var MICALG = Object.assign(Object.create(null), { sha1: "sha-1", sha224: "sha-224", sha256: "sha-256", sha384: "sha-384", sha512: "sha-512", md5: "md5", shake128: "shake128", shake256: "shake256" });

function _entityBytes(content, opts) {
  var raw = guard.bytes.view(content, SmimeError, "smime/bad-input", "content");
  if (opts.entity) return mime.canonicalize(raw, SmimeError, "smime/bad-mime");
  var cte = _is7bit(raw) ? "7bit" : "8bit";
  return mime.buildEntity([{ name: "Content-Type", value: opts.contentType || "text/plain; charset=utf-8" }, { name: "Content-Transfer-Encoding", value: cte }], raw, SmimeError, "smime/bad-header");
}
function _is7bit(buf) { for (var i = 0; i < buf.length; i++) if (buf[i] > 0x7f) return false; return true; }


function _isStructural(lname) {
  return lname === "mime-version" || lname.indexOf("content-") === 0;
}

function _hpHeaderList(headers) {
  if (headers == null) return [];
  var out = [];
  if (Array.isArray(headers)) {
    headers.forEach(function (h) {
      if (!h || typeof h !== "object") throw _err("smime/bad-input", "each opts.headers entry must be { name, value }");
      var name = h.name, v = h.value;
      if (typeof name !== "string") throw _err("smime/bad-input", "each opts.headers entry must be { name, value }");
      out.push({ name: name, value: v == null ? "" : String(v) });
    });
  } else if (typeof headers === "object") {
    Object.keys(headers).forEach(function (k) { var v = headers[k]; out.push({ name: k, value: v == null ? "" : String(v) }); });
  } else {
    throw _err("smime/bad-input", "opts.headers must be an object or an array of { name, value }");
  }
  var seen = Object.create(null);
  out.forEach(function (h) {
    var ln = h.name.toLowerCase();
    if (_isStructural(ln)) throw _err("smime/bad-input", "opts.headers must not include the Structural header " + JSON.stringify(h.name) + " (RFC 9787); only Non-Structural fields (Subject / From / To / ...) are protected");
    if (ln === "hp-outer") throw _err("smime/bad-input", "opts.headers must not include the reserved HP-Outer field (RFC 9788 sec. 2.2); the library emits it");
    if (seen[ln]) throw _err("smime/bad-input", "opts.headers must not repeat a protected field name (" + JSON.stringify(h.name) + "); a repeated protected field is not supported");
    seen[ln] = 1;
  });
  return out;
}

function _applyHcp(name, value, hcp) {
  if (hcp === "hcp_no_confidentiality") return value;
  var ln = name.toLowerCase();
  if (ln === "subject") return "[...]";
  if (ln === "comments" || ln === "keywords") return null;
  return value;
}

function _outerHeaderList(list, mode, hcp) {
  var policy = hcp == null ? "hcp_baseline" : hcp;
  if (policy !== "hcp_baseline" && policy !== "hcp_no_confidentiality") throw _err("smime/bad-input", "unknown opts.hcp policy " + guard.text.showValue(hcp) + " (only \"hcp_baseline\" or \"hcp_no_confidentiality\")");
  var out = [];
  list.forEach(function (h) {
    if (mode === "cipher") {
      var v = _applyHcp(h.name, h.value, policy);
      if (v !== null) out.push({ name: h.name, value: v });
    } else {
      out.push({ name: h.name, value: h.value });
    }
  });
  return out;
}

function _protectedInnerEntity(content, opts, mode, hpList, outerList) {
  if (opts.entity) throw _err("smime/bad-input", "opts.entity is not supported with protectHeaders -- pass raw content + opts.contentType");
  var raw = guard.bytes.view(content, SmimeError, "smime/bad-input", "content");
  var cty = opts.contentType;
  if (cty != null && typeof cty !== "string") throw _err("smime/bad-input", "opts.contentType must be a string, got " + guard.text.showValue(cty));
  if (cty != null && mime.hasParam(cty, "hp")) throw _err("smime/bad-input", "opts.contentType must not set the hp parameter -- header protection sets it (hp=" + guard.text.showValue(mode) + ")");
  var ct = (cty || "text/plain; charset=utf-8") + "; hp=\"" + mode + "\"";
  var fields = [{ name: "Content-Type", value: ct }, { name: "Content-Transfer-Encoding", value: _is7bit(raw) ? "7bit" : "8bit" }];
  hpList.forEach(function (h) { fields.push(h); });
  if (mode === "cipher") {
    outerList.forEach(function (h) { fields.push({ name: "HP-Outer", value: h.name + ": " + h.value }); });
  }
  return mime.buildEntity(fields, raw, SmimeError, "smime/bad-header");
}

function _outerPrefix(list) {
  var s = "";
  for (var i = 0; i < list.length; i++) {
    guard.header.assertField(list[i].name, list[i].value, SmimeError, "smime/bad-header");
    s += list[i].name + ": " + list[i].value + "\r\n";
  }
  return s + "MIME-Version: 1.0\r\n";
}

function _utf8Header(s) { return Buffer.from(s, "latin1").toString("utf8"); }

function _asciiLower(c) { return (c >= 65 && c <= 90) ? c + 32 : c; }
var _CONTENT_TYPE = "content-type";

function _unfoldHeaderFolds(s) {
  var out = "", i = 0, n = s.length;
  while (i < n) {
    if (s.charCodeAt(i) === 0x0d && i + 1 < n && s.charCodeAt(i + 1) === 0x0a &&
        i + 2 < n && (s.charCodeAt(i + 2) === 0x20 || s.charCodeAt(i + 2) === 0x09)) {
      out += " ";
      i += 2;
      while (i < n && (s.charCodeAt(i) === 0x20 || s.charCodeAt(i) === 0x09)) i += 1;
    } else {
      out += s.charAt(i);
      i += 1;
    }
  }
  return out;
}

function _contentTypeLineAt(s, start) {
  var n = s.length, p = start;
  while (p < n && (s.charCodeAt(p) === 0x20 || s.charCodeAt(p) === 0x09)) p += 1;
  if (p + _CONTENT_TYPE.length > n) return null;
  for (var k = 0; k < _CONTENT_TYPE.length; k++) {
    if (_asciiLower(s.charCodeAt(p + k)) !== _CONTENT_TYPE.charCodeAt(k)) return null;
  }
  p += _CONTENT_TYPE.length;
  while (p < n && (s.charCodeAt(p) === 0x20 || s.charCodeAt(p) === 0x09)) p += 1;
  if (p >= n || s.charCodeAt(p) !== 0x3a) return null;
  p += 1;
  while (p < n && s.charCodeAt(p) !== 0x0d && s.charCodeAt(p) !== 0x0a) p += 1;
  return s.slice(start, p);
}

function _contentTypeLines(s) {
  var lines = [], lineStart = 0;
  while (lineStart <= s.length) {
    var line = _contentTypeLineAt(s, lineStart);
    if (line !== null) lines.push(line);
    var nl = s.indexOf("\n", lineStart);
    if (nl === -1) break;
    lineStart = nl + 1;
  }
  return lines.length ? lines : null;
}

function _contentTypeValue(s) {
  var n = s.length, p = 0;
  while (p < n && (s.charCodeAt(p) === 0x20 || s.charCodeAt(p) === 0x09)) p += 1;
  if (p + _CONTENT_TYPE.length > n) return s;
  for (var k = 0; k < _CONTENT_TYPE.length; k++) {
    if (_asciiLower(s.charCodeAt(p + k)) !== _CONTENT_TYPE.charCodeAt(k)) return s;
  }
  p += _CONTENT_TYPE.length;
  while (p < n && (s.charCodeAt(p) === 0x20 || s.charCodeAt(p) === 0x09)) p += 1;
  if (p >= n || s.charCodeAt(p) !== 0x3a) return s;
  return s.slice(p + 1);
}

function _declaresHp(content) {
  var s = content.toString("latin1");
  var sep = s.indexOf("\r\n\r\n");
  var head = _unfoldHeaderFolds(sep !== -1 ? s.slice(0, sep) : s);
  var cts = _contentTypeLines(head);
  if (!cts) return false;
  for (var i = 0; i < cts.length; i++) {
    if (mime.hasParam(_contentTypeValue(cts[i]), "hp")) return true;
  }
  return false;
}

function _noneSurface() { return { protectedHeaders: null, headerProtection: { present: false, mode: null, fromMismatch: null, confidential: [], legacy: null } }; }

function _contentTypeCount(headers) { var n = 0; headers.forEach(function (h) { if (h.lname === "content-type") n++; }); return n; }

var RFC5322_SINGLETON = new Set(["date", "from", "sender", "reply-to", "to", "cc", "bcc", "message-id", "in-reply-to", "references", "subject", "return-path"]);

function _extractProtected(headerList) {
  var protectedHeaders = Object.create(null), innerFrom = null, seen = Object.create(null), dup = null, dupSingleton = null;
  var entries = [];
  var refouter = [];
  headerList.forEach(function (h) {
    if (_isStructural(h.lname)) return;
    if (h.lname === "hp-outer") {
      var ci = h.rawValue.indexOf(":");
      if (ci >= 0) refouter.push({ name: h.rawValue.slice(0, ci).trim().toLowerCase(), value: h.rawValue.slice(ci + 1).trim() });
      return;
    }
    var val = _utf8Header(h.rawValue);
    entries.push({ name: h.name, value: val, raw: h.rawValue });
    if (seen[h.lname]) { dup = h.name; if (RFC5322_SINGLETON.has(h.lname)) dupSingleton = h.name; }
    seen[h.lname] = 1;
    protectedHeaders[h.name] = val;
    if (h.lname === "from") innerFrom = h.value;
  });
  return { protectedHeaders: protectedHeaders, entries: entries, innerFrom: innerFrom, refouter: refouter, dup: dup, dupSingleton: dupSingleton };
}

function _computeConfidential(entries, refouter) {
  var byName = new Map();
  refouter.forEach(function (r) {
    var m = byName.get(r.name); if (!m) { m = new Map(); byName.set(r.name, m); }
    m.set(r.value, (m.get(r.value) || 0) + 1);
  });
  var confidential = [], seen = Object.create(null);
  entries.forEach(function (e) {
    var m = byName.get(e.name.toLowerCase()), val = e.raw.trim(), n = (m && m.get(val)) || 0;
    if (n > 0) { m.set(val, n - 1); return; }
    if (!seen[e.name]) { seen[e.name] = 1; confidential.push(e.name); }
  });
  return confidential;
}

function _computeFromMismatch(innerFrom, outerEnt) {
  if (innerFrom == null) return null;
  var outerFroms = [];
  outerEnt.headers.forEach(function (h) { if (h.lname === "from") outerFroms.push(h.value.trim()); });
  return outerFroms.length !== 1 || outerFroms[0] !== innerFrom.trim();
}

function _isCryptoLayer(type) {
  return _isPkcs7(type, "mime") || type === "multipart/signed" || type === "multipart/encrypted";
}

function _outerRefouter(outerEnt) {
  var r = [];
  outerEnt.headers.forEach(function (h) { if (!_isStructural(h.lname) && h.lname !== "hp-outer") r.push({ name: h.lname, value: h.rawValue.trim() }); });
  return r;
}

function _legacyHpSurface(canon, outerEnt, mode, enabled) {
  if (!enabled) return _noneSurface();
  var partC, partD;
  try {
    partC = mime.parse(canon, SmimeError, "smime/bad-header-protection");
    if (partC.contentType.type !== "message/rfc822") return _noneSurface();
    partD = mime.parse(partC.body, SmimeError, "smime/bad-header-protection");
  } catch (_e) { return _noneSurface(); }
  if (_contentTypeCount(partC.headers) > 1 || _contentTypeCount(partD.headers) > 1) return _noneSurface();
  if (mime.hasParam(partD.contentType.value, "hp")) return _noneSurface();
  if (_isCryptoLayer(partD.contentType.type)) return _noneSurface();
  var ex = _extractProtected(partD.headers);
  if (ex.dupSingleton) return _noneSurface();
  if (!ex.entries.length) return _noneSurface();
  var confidential = mode === "cipher" ? _computeConfidential(ex.entries, _outerRefouter(outerEnt)) : [];
  var headers = ex.entries.map(function (e) { return { name: e.name, value: e.value }; });
  return { protectedHeaders: null, headerProtection: { present: false, mode: null, fromMismatch: null, confidential: [], legacy: { headers: headers, mode: mode, fromMismatch: _computeFromMismatch(ex.innerFrom, outerEnt), confidential: confidential } } };
}

var SAN_OID = oid.byName("subjectAltName");
var SMTP_UTF8_MAILBOX = oid.byName("smtpUtf8Mailbox");
var EMAIL_ADDRESS_ATTR = oid.byName("emailAddress");
var _extNs = pkix.makeNS("smime", SmimeError, oid);
var _extDecoders = pkix.certExtensionDecoders(_extNs);
var _extCtx = Object.assign(Object.create(null), { E: function (c, m, cause) { return new SmimeError(c, m, cause); }, oid: oid });
function _signerEmails(certDer) {
  var out = { addresses: [], unreadable: 0 };
  var parsed = null;
  try { parsed = schemaX509.parse(certDer); }
  catch (parseFailed) { out.unreadable++; out.reason = parseFailed.code || "unparseable"; }
  if (parsed === null) return out;
  (parsed.extensions || []).forEach(function (e) {
    if (e.oid !== SAN_OID) return;
    var dec = null;
    try { dec = _extDecoders.byOid[SAN_OID](e.value, _extCtx); }
    catch (sanFailed) { out.unreadable++; out.reason = sanFailed.code || "bad-san"; }
    if (dec === null) return;
    (dec.names || []).forEach(function (n) {
      if (n.tagNumber === 1) { guard.list.append(out.addresses, String(n.value)); return; }
      if (n.tagNumber !== 0) return;
      var typeId = n.value && typeof n.value === "object" ? n.value.typeId : undefined;
      if (typeId === undefined) { out.unreadable++; return; }
      if (String(typeId) === SMTP_UTF8_MAILBOX) out.unreadable++;
    });
  });
  var sanCarriedIdentity = out.addresses.length > 0 || out.unreadable > 0;
  var rdns = !sanCarriedIdentity && parsed.subject ? parsed.subject.rdns : null;
  (rdns || []).forEach(function (rdn) {
    (rdn || []).forEach(function (attr) {
      if (!attr || attr.type !== EMAIL_ADDRESS_ATTR || typeof attr.value !== "string") return;
      if (out.addresses.indexOf(attr.value) === -1) guard.list.append(out.addresses, attr.value);
    });
  });
  return out;
}

function _senderSurface(signers, outerEnt, expectedSender) {
  var expected = null, source = null;
  if (expectedSender != null) {
    if (typeof expectedSender !== "string") {
      throw _err("smime/bad-input", "expectedSender must be a string email address, got " + typeof expectedSender);
    }
    expected = expectedSender; source = "expectedSender";
  }
  else {
    var froms = [];
    outerEnt.headers.forEach(function (h) { if (h.lname === "from") guard.list.append(froms, h.value.trim()); });
    if (froms.length === 1) { expected = _addrSpec(froms[0]); source = expected === null ? null : "from"; }
  }
  var identities = [], undecidable = false, sawIdentity = false;
  (signers || []).forEach(function (s) {
    if (!s || s.ok !== true || s.trusted !== true) { undecidable = true; return; }
    var e = s.cert ? _signerEmails(s.cert) : null;
    if (e === null) { undecidable = true; return; }
    if (e.unreadable > 0) { undecidable = true; sawIdentity = true; }
    e.addresses.forEach(function (a) { sawIdentity = true; if (identities.indexOf(a) === -1) guard.list.append(identities, a); });
  });
  if (expected === null) return { checked: false, expected: null, source: null, identities: identities, match: null };
  if (!sawIdentity) return { checked: true, expected: expected, source: source, identities: identities, match: null };
  var sawMatch = false, sawNotComparable = false;
  for (var i = 0; i < identities.length; i++) {
    var v = guard.name.emailEqual(identities[i], expected);
    if (v === "match") sawMatch = true;
    else if (v === "not-comparable") sawNotComparable = true;
  }
  var verdict;
  if (sawMatch) verdict = true;
  else if (undecidable || sawNotComparable) verdict = null;
  else verdict = false;
  return { checked: true, expected: expected, source: source, identities: identities, match: verdict };
}

function _addrSpec(v) {
  var lt = v.indexOf("<"), gt = v.lastIndexOf(">");
  if (lt === -1 && gt === -1) return v.indexOf(",") === -1 ? v.trim() : null;
  if (lt === -1 || gt < lt) return null;
  if (v.slice(gt + 1).trim().length) return null;
  var inner = v.slice(lt + 1, gt).trim();
  return inner.length && inner.indexOf(",") === -1 && inner.indexOf("<") === -1 ? inner : null;
}

function _hpSurface(content, outerEnt, expectedMode, authenticated, legacyEnabled) {
  if (!authenticated) return _noneSurface();
  var canon = mime.canonicalizeText(content);
  if (!_declaresHp(canon)) return _legacyHpSurface(canon, outerEnt, expectedMode, legacyEnabled);
  var inner = mime.parse(canon, SmimeError, "smime/bad-header-protection");
  var ctCount = _contentTypeCount(inner.headers);
  if (ctCount > 1) throw _err("smime/bad-header-protection", "a header-protected payload must carry exactly one Content-Type field (found " + ctCount + ")");
  if (mime.paramNameCount(inner.contentType.value, "hp") > 1) throw _err("smime/bad-header-protection", "a header-protected payload declares the hp parameter more than once");
  var raw = inner.contentType.params.hp;
  if (raw === undefined) throw _err("smime/bad-header-protection", "a header-protected payload declares a bare hp parameter with no value (expected hp=\"clear\" or hp=\"cipher\")");
  var hp = raw.toLowerCase();
  if (hp !== "clear" && hp !== "cipher") throw _err("smime/bad-header-protection", "the header-protected payload declares an invalid hp value " + JSON.stringify(raw) + " (only clear / cipher)");
  if (hp !== expectedMode) throw _err("smime/bad-header-protection", "the payload hp=" + JSON.stringify(hp) + " contradicts the cryptographic envelope (a " + (expectedMode === "cipher" ? "decrypted" : "signed") + " message requires hp=" + JSON.stringify(expectedMode) + ")");
  var ex = _extractProtected(inner.headers);
  if (ex.dup) throw _err("smime/bad-header-protection", "a header-protected payload has a duplicate protected header field " + JSON.stringify(ex.dup));
  var confidential = hp === "cipher" ? _computeConfidential(ex.entries, ex.refouter) : [];
  return { protectedHeaders: ex.protectedHeaders, headerProtection: { present: true, mode: hp, fromMismatch: _computeFromMismatch(ex.innerFrom, outerEnt), confidential: confidential, legacy: null } };
}

function _cmsSignOpts(opts, detached) {
  var o = { detached: detached };
  if (opts.signingTime !== undefined) o.signingTime = opts.signingTime;
  if (opts.sid) o.sid = opts.sid;
  if (opts.signedAttributes !== undefined) o.signedAttributes = opts.signedAttributes;
  if (opts.additionalSignedAttributes) o.additionalSignedAttributes = opts.additionalSignedAttributes;
  return o;
}

function _micName(name) { return name ? (MICALG[name] || name) : null; }
function _micalgSet(value) {
  var seen = [];
  String(value).split(",").forEach(function (m) { var t = m.trim().toLowerCase(); if (t && seen.indexOf(t) < 0) seen.push(t); });
  return seen.sort().join(",");
}
function _micalgOf(p7Der) {
  var parsed;
  try { parsed = schemaCms.parse(guard.bytes.view(p7Der, SmimeError, "smime/bad-mime", "the CMS body")); }
  catch (e) { throw _err("smime/bad-mime", "the CMS SignedData body could not be parsed", e); }
  var out = [];
  (parsed.signerInfos || []).forEach(function (si) {
    var mic = _micName(si.digestAlgorithm && si.digestAlgorithm.name);
    if (mic && out.indexOf(mic) < 0) out.push(mic);
  });
  return out.length ? out.sort().join(",") : null;
}

function _boundary() { return "----=_pki_smime_" + nodeCrypto.randomBytes(18).toString("hex"); }

function _wrap64Crlf(s) {
  var out = "";
  for (var i = 0; i < s.length; i += 64) {
    if (i > 0) out += "\r\n";
    out += s.slice(i, i + 64);
  }
  return out;
}

function _base64Body(der) {
  return Buffer.from(_wrap64Crlf(der.toString("base64")), "latin1");
}

/**
 * @primitive  pki.smime.sign
 * @signature  pki.smime.sign(content, signers, opts?) -> Promise<Buffer>
 * @since      0.2.25
 * @status     stable
 * @spec       RFC 8551, RFC 5652
 * @related    pki.smime.verify, pki.cms.sign
 *
 * Assemble a signed S/MIME message (RFC 8551). `content` is the payload: a raw body wrapped as a
 * `text/plain` entity by default, or the caller's own complete MIME entity when `opts.entity` is set;
 * `signers` is the `pki.cms.sign` signer array (any RSA / RSASSA-PSS / ECDSA / EdDSA / ML-DSA / SLH-DSA
 * signer: the S/MIME layer is algorithm-agnostic). Two forms via `opts.form`:
 *   - `"multipart"` (default, clear-signed): a `multipart/signed` message carrying the canonical entity
 *     verbatim in the first part and a DETACHED CMS SignedData (`application/pkcs7-signature`) over its
 *     canonical form in the second, with `protocol="application/pkcs7-signature"` + a matching `micalg`.
 *   - `"pkcs7-mime"` (opaque): one `application/pkcs7-mime; smime-type=signed-data` entity whose base64
 *     body is an ATTACHED CMS SignedData over the canonical entity.
 * The signed bytes are the entity's RFC 8551 sec. 3.1.1 canonical form (CRLF line endings); the same
 * canonicalizer runs on verify. With `opts.protectHeaders`, the message is header-protected (RFC 9788): the
 * caller's `opts.headers` are inlined on the Cryptographic Payload root (its Content-Type gains `hp="clear"`),
 * so the signature covers them, and copied to the outer display headers; `verify` surfaces the
 * authenticated inner set. Returns the assembled message bytes. Fail-closed with `SmimeError`.
 *
 * @opts form        `"multipart"` (default) or `"pkcs7-mime"`.
 * @opts entity      treat `content` as a complete MIME entity (default: wrap it as text/plain).
 * @opts contentType the wrapped entity's Content-Type (default `text/plain; charset=utf-8`).
 * @opts signingTime a `Date` for the CMS signing-time attribute, or false to omit it.
 * @opts protectHeaders enable RFC 9788 header protection (`hp="clear"`), inlining `opts.headers` on the signed payload + the outer display headers.
 * @opts headers     the Non-Structural fields to protect + display: an object `{ Name: value }` or an array `[{ name, value }]` (Subject / From / To / Date / ...); used with `protectHeaders`.
 * @opts hcp         the Header Confidentiality Policy applied to the OUTER display copies: `"hcp_baseline"` (default) or `"hcp_no_confidentiality"`. A signed message's payload is not encrypted, so this governs presentation, not secrecy; used with `protectHeaders`.
 * @opts sid                       forwarded to cms.sign: the SignerIdentifier form, `"issuerAndSerial"` (default) or `"subjectKeyIdentifier"`.
 * @opts signedAttributes          forwarded: `false` omits the signed-attributes set entirely (a bare-signature SignedData).
 * @opts additionalSignedAttributes forwarded: extra signed attributes to carry, as `[{ type, values }]`.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var msg = await pki.smime.sign(Buffer.from("hello"), [{ cert: signerCertDer, key: signerKeyPkcs8 }]);
 */
async function sign(content, signers, opts) {
  opts = opts || {};
  _knownOpts(opts, SIGN_OPTS, "sign");
  var hp = opts.protectHeaders === true;
  var hpList = hp ? _hpHeaderList(opts.headers) : null;
  var outerList = hp ? _outerHeaderList(hpList, "clear", opts.hcp) : null;
  var entity = hp ? _protectedInnerEntity(content, opts, "clear", hpList, outerList) : _entityBytes(content, opts);
  var outer = hp ? _outerPrefix(outerList) : "";
  var form = opts.form || "multipart";
  if (form === "pkcs7-mime") {
    var p7m = await cms.sign(entity, signers, _cmsSignOpts(opts, false));
    var head = Buffer.from(outer + "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=smime.p7m\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=smime.p7m\r\n\r\n", "utf8");
    return _capped(Buffer.concat([head, _base64Body(_toBuf(p7m)), mime.CRLF]));
  }
  if (form !== "multipart") throw _err("smime/bad-input", "form must be \"multipart\" or \"pkcs7-mime\"");
  var p7s = _toBuf(await cms.sign(entity, signers, _cmsSignOpts(opts, true)));
  var micalg = _micalgOf(p7s) || "sha-256";
  var boundary = _boundary();
  var head2 = Buffer.from(outer + "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=" + micalg + "; boundary=\"" + boundary + "\"\r\n\r\n", "utf8");
  var sigPart = Buffer.concat([
    Buffer.from("Content-Type: application/pkcs7-signature; name=smime.p7s\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=smime.p7s\r\n\r\n", "latin1"),
    _base64Body(p7s),
  ]);
  var dl = Buffer.from("--" + boundary + "\r\n", "latin1"), close = Buffer.from("--" + boundary + "--\r\n", "latin1");
  return _capped(Buffer.concat([head2, dl, entity, mime.CRLF, dl, sigPart, mime.CRLF, close]));
}

function _capped(msg) {
  guard.limits.byteCap(msg, C.LIMITS.MIME_MAX_BYTES, _err, "smime/too-large", "the assembled S/MIME message");
  return msg;
}

/**
 * @primitive  pki.smime.verify
 * @signature  pki.smime.verify(message, opts?) -> Promise<{ valid, trusted, signers, form, content, micalg, sender, protectedHeaders, headerProtection }>
 * @since      0.2.25
 * @status     stable
 * @spec       RFC 8551, RFC 5652, RFC 9788
 * @related    pki.smime.sign, pki.cms.verify, pki.path.validate
 *
 * Unwrap and verify a signed S/MIME message (RFC 8551), both `multipart/signed` and
 * `application/pkcs7-mime; smime-type=signed-data`. For `multipart/signed` the detached CMS signature
 * is recomputed over the first part's RFC 8551 sec. 3.1.1 canonical form (the same canonicalizer the
 * signer used); for `application/pkcs7-mime` the base64 body is the attached CMS SignedData. Returns
 * `pki.cms.verify`'s `{ valid, trusted, signers }` verdict PLUS `form`, the recovered `content` (the
 * signed MIME entity bytes), and the `micalg`.
 *
 * `valid` and `trusted` are separate claims, exactly as in `cms.verify`: a SignedData carries its own
 * certificates, so `valid` says the signature is sound under one of them and nothing about who signed.
 * Name the roots you accept in `opts.trustAnchors` and `trusted` says every signer chained to one,
 * validated for EMAIL, at both ends of the chain. The signer certificate must carry the
 * `emailProtection` key purpose (RFC 8551 sec. 4.4.4), because a certificate restricted to `serverAuth`
 * chains to its root perfectly well and is still the wrong key to have signed a message; and the anchor's
 * own trust metadata must permit that purpose, because a root distributed with NSS trust bits can be
 * marked untrusted for email while remaining a good TLS root. Override either with `opts.requiredEku`
 * and `opts.checkPurpose`. Supply no anchors and `trusted` is `false`, since there was nothing to chain to.
 * A `micalg`
 * that disagrees with the actual digest is advisory unless `opts.strictMicalg` (then `smime/micalg-mismatch`).
 * If the message is header-protected (RFC 9788), `protectedHeaders` is the AUTHENTICATED inner header set (a
 * tampered outer header cannot alter it) and `headerProtection` is `{ present, mode, fromMismatch, confidential, legacy }`.
 * `present` is `true` only for cryptographically-DECLARED (`hp=`) protection you may trust; `fromMismatch` is
 * `true` when the outer From differs from the protected one, `false` when they agree, and `null` when there was
 * no protected From to compare against, which is every message without header protection. Test it against
 * `false` rather than for falsiness: `!fromMismatch` treats the unanswered case as a passed check, and that is
 * the common case. For a binding that does not depend on the composer having protected headers, use `sender`
 * with `opts.expectedSender`; `confidential` lists the protected fields the composer kept
 * end-to-end confidential (per the authenticated HP-Outer records, RFC 9788 sec. 4.3; only for an encrypted
 * `hp="cipher"` payload). A non-protected message reports `protectedHeaders: null`, `present: false`. A payload
 * whose declared `hp` is malformed, invalid, or contradicts the envelope fails closed (`smime/bad-header-protection`),
 * never a silent downgrade. `legacy` is `null` unless `opts.legacyHeaderProtection` detected a legacy RFC 8551
 * `message/rfc822` wrap (see that option), in which case it is its own `{ headers, mode, fromMismatch, confidential }`
 * object (`headers` an ordered `[{ name, value }]` array that retains legally-repeated fields like `Received`). A
 * legacy inference is never placed in `protectedHeaders` and never sets `present: true`, because it is
 * indistinguishable from an ordinary forwarded `message/rfc822`, so a caller keying trust off `present` /
 * `protectedHeaders` cannot mistake the opt-in heuristic for authenticated headers.
 *
 * `sender` answers who the message is from, which `valid` does not: a signature proves a key signed,
 * never that the message came from the mailbox the reader sees. Name the address you expect in
 * `opts.expectedSender` and `sender.match` is `true` only when the signer certificate asserts it,
 * compared under RFC 5280 sec. 7.5: the local-part exactly, the host-part case-insensitively. The
 * address is read from the `subjectAltName` `rfc822Name` entries (RFC 8550 sec. 4.4.3) and, where the
 * extension carries none, from the subject DN's PKCS #9 `emailAddress` attribute, which RFC 8550 sec. 3
 * requires a receiving agent to recognize. Where both are present the extension wins. Only a signer
 * whose signature verified contributes an identity, so a tampered message cannot report a binding. `match` is THREE-valued and a caller enforcing sender binding tests
 * `match === true`; `false` means every identity was comparable and none matched, and `null` means the
 * question was not answered (no `expectedSender` and no single outer `From`, a signer certificate
 * asserting no readable email identity, or an internationalized address needing an IDNA transform this
 * toolkit does not perform). `null` is not a pass. `sender.identities` lists what the certificate
 * actually asserts, `sender.checked` whether a comparison ran, and `sender.source` which input it ran
 * against. `"from"` is ADVISORY, because on a message without header protection the outer From is
 * attacker-controlled.
 *
 * @opts certs        extra signer certificates (DER `Buffer`s) to match, forwarded to `cms.verify`.
 * @opts expectedSender  the email address the signer's certificate must assert for `sender.match` to be
 *                    `true`. Without it the outer `From` is used when there is exactly one, and reported
 *                    as `source: "from"` -- advisory, never a verified binding.
 * @opts trustAnchors the roots you accept, forwarded to `cms.verify`; supplying them is what makes
 *                    `trusted` answerable. Certificate DER or anchor tuples.
 * @opts time         the instant the signer's chain is judged at (default now). Only read with `trustAnchors`.
 * @opts requiredEku  key purposes the SIGNER certificate must carry. Defaults to `["emailProtection"]`.
 * @opts checkPurpose the purpose the ANCHOR's own trust metadata must permit. Defaults to `"emailProtection"`.
 * @opts strictMicalg reject a `multipart/signed` whose `micalg` disagrees with the SignerInfo digest.
 * @opts legacyHeaderProtection  opt in to detecting a LEGACY RFC 8551 header-protected message (RFC 9788 sec. 4.10): a Cryptographic Payload that is a bare `message/rfc822` wrap with no `hp=` parameter. When set, a precisely-identified legacy message surfaces the inner message's headers under `headerProtection.legacy = { headers, mode, fromMismatch, confidential }`, where `headers` is an ordered `[{ name, value }]` array (retaining legally-repeated fields such as `Received`) and the mode is inferred from the envelope (`clear` here). They are not placed under `protectedHeaders`, and `present` stays `false`. Consuming `headerProtection.legacy.headers` is an explicit choice: a legacy message is structurally indistinguishable from an ordinary forwarded `message/rfc822`, so this is a heuristic (RFC 9788 sec. 4.10.2: "not based on any strong end-to-end guarantees"); cross-check `legacy.fromMismatch`. Anything not precisely identified (a nested crypto layer, an `hp=` on the inner message, a non-`message/rfc822` payload, a duplicate of a singleton field, or a duplicate Content-Type) reports `legacy: null`. Off by default. The signed-and-encrypted form (RFC 9788 Appendix C.3.17) is a documented gap (`legacy: null` at `decrypt`; surfaces as `clear` only via the caller's re-`verify` step), because the non-recursive layered API exposes no single seam holding both the inner signature verdict and the outer header section.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var smimeMessageBytes = await pki.smime.sign(Buffer.from("hello"), [{ cert: cert, key: key }]);
 *   var res = await pki.smime.verify(smimeMessageBytes);
 *   if (res.valid) { res.content; res.signers[0].sid; }
 */
async function verify(message, opts) {
  opts = opts || {};
  _knownOpts(opts, VERIFY_OPTS, "verify");
  var ent = mime.parse(message, SmimeError, "smime/bad-mime");
  var ct = ent.contentType;
  var vOpts = {};
  if (opts.certs) vOpts.certs = opts.certs;
  if (opts.trustAnchors != null) {
    vOpts.trustAnchors = opts.trustAnchors;
    vOpts.requiredEku = opts.requiredEku != null ? opts.requiredEku : ["emailProtection"];
    vOpts.checkPurpose = opts.checkPurpose != null ? opts.checkPurpose : "emailProtection";
  }
  if (opts.time !== undefined) vOpts.time = opts.time;
  if (_isPkcs7(ct.type, "mime")) {
    if (ct.params["smime-type"] && ct.params["smime-type"] !== "signed-data") throw _err("smime/unsupported-type", "unsupported smime-type " + JSON.stringify(ct.params["smime-type"]) + " (only signed-data)");
    var p7m = _decodeCms(ent);
    var res = await cms.verify(p7m, vOpts);
    var inner;
    try { inner = _toBuf(schemaCms.parse(p7m).encapContentInfo.eContent); }
    catch (e) { throw _err("smime/bad-mime", "the pkcs7-mime SignedData has no encapsulated content", e); }
    return guard.verdict.of({ valid: res.valid, trusted: res.trusted, signers: res.signers, form: "pkcs7-mime", content: inner, micalg: null, sender: _senderSurface(res.signers, ent, opts.expectedSender) }, _hpSurface(inner, ent, "clear", res.valid, opts.legacyHeaderProtection === true));
  }
  if (ct.type === "multipart/signed") {
    if (ct.params.protocol && !_isPkcs7(ct.params.protocol, "signature")) throw _err("smime/bad-multipart", "multipart/signed protocol must be application/pkcs7-signature");
    var parts = mime.splitMultipart(ent.body, ct.params.boundary, SmimeError, "smime/bad-multipart");
    if (parts.length !== 2) throw _err("smime/bad-multipart", "multipart/signed must have exactly two body parts, got " + parts.length);
    var sigEnt = mime.parse(parts[1], SmimeError, "smime/bad-mime");
    if (!_isPkcs7(sigEnt.contentType.type, "signature")) throw _err("smime/bad-multipart", "the second part must be application/pkcs7-signature");
    var p7s = _decodeCms(sigEnt);
    var sd;
    try { sd = schemaCms.parse(p7s); }
    catch (e) { throw _err("smime/bad-mime", "the pkcs7-signature part is not a CMS SignedData", e); }
    if (sd.encapContentInfo && sd.encapContentInfo.eContent != null) {
      throw _err("smime/bad-multipart", "the pkcs7-signature part must carry a DETACHED SignedData (no encapsulated content) (RFC 8551 sec. 3.4)");
    }
    var canon = mime.canonicalize(parts[0], SmimeError, "smime/bad-mime");
    var res2 = await cms.verify(p7s, Object.assign({}, vOpts, { content: canon }));
    var micalg = ct.params.micalg || null;
    if (opts.strictMicalg && micalg && _micalgSet(micalg) !== (_micalgOf(p7s) || "")) {
      throw _err("smime/micalg-mismatch", "the multipart/signed micalg " + JSON.stringify(micalg) + " disagrees with the SignerInfo digests");
    }
    return guard.verdict.of({ valid: res2.valid, trusted: res2.trusted, signers: res2.signers, form: "multipart/signed", content: parts[0], micalg: micalg, sender: _senderSurface(res2.signers, ent, opts.expectedSender) }, _hpSurface(parts[0], ent, "clear", res2.valid, opts.legacyHeaderProtection === true));
  }
  throw _err("smime/unsupported-type", "not a signed S/MIME message (Content-Type " + JSON.stringify(ct.type) + ")");
}

function _pkcs7MimeHead(smimeType, name) {
  return Buffer.from("Content-Type: application/pkcs7-mime; smime-type=" + smimeType + "; name=" + name + "\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=" + name + "\r\n\r\n", "latin1");
}

function _envelopedTypeOf(der, badParseCode) {
  var name;
  try { name = schemaCms.parse(guard.bytes.view(der, SmimeError, "smime/bad-mime", "the CMS body")).contentTypeName; }
  catch (e) { throw _err("smime/bad-mime", "the pkcs7-mime body is not a parseable CMS structure", e); }
  if (name === "authEnvelopedData") return "authEnveloped-data";
  if (name === "envelopedData") return "enveloped-data";
  throw _err(badParseCode, "the pkcs7-mime body is a " + name + ", not an EnvelopedData / AuthEnvelopedData");
}

function _cmsEncryptOpts(opts) {
  var o = {};
  if (opts.contentEncryptionAlgorithm !== undefined) o.contentEncryptionAlgorithm = opts.contentEncryptionAlgorithm;
  if (opts.oaepHash !== undefined) o.oaepHash = opts.oaepHash;
  if (opts.keyIdentifier !== undefined) o.keyIdentifier = opts.keyIdentifier;
  if (opts.ukm !== undefined) o.ukm = opts.ukm;
  return o;
}

/**
 * @primitive  pki.smime.encrypt
 * @signature  pki.smime.encrypt(content, recipients, opts?) -> Promise<Buffer>
 * @since      0.2.26
 * @status     stable
 * @spec       RFC 8551, RFC 5652, RFC 5083
 * @related    pki.smime.decrypt, pki.cms.encrypt
 *
 * Envelope a MIME entity as an encrypted S/MIME message (RFC 8551 sec. 3.3 / sec. 3.4). `content` is the
 * payload: a raw body wrapped as a `text/plain` entity by default, or the caller's own complete MIME
 * entity when `opts.entity` is set; `recipients` is the `pki.cms.encrypt` recipient array (any RSA-OAEP
 * ktri / EC or X25519/X448 kari / ML-KEM ori-KEM / password pwri / kek kekri: the S/MIME layer is
 * recipient-agnostic; a single descriptor is accepted and normalized to a one-element array). Enveloping
 * has a single form, opaque `application/pkcs7-mime` with the whole entity base64-encoded. The `smime-type`
 * is derived from the produced CMS: AES-GCM (the default) yields an AuthEnvelopedData with
 * `smime-type=authEnveloped-data` (confidentiality AND integrity); a CBC choice yields an EnvelopedData
 * with `smime-type=enveloped-data` (confidentiality only, no integrity, RFC 8551 sec. 3.3). With
 * `opts.protectHeaders`, the message is header-protected (RFC 9788): the real `opts.headers` are inlined
 * inside the ciphertext (the payload Content-Type gains `hp="cipher"`), and only the Header-Confidentiality-
 * Policy-processed display copies appear outside. The default `hcp_baseline` obscures Subject to `[...]`
 * and removes Comments / Keywords, so those values live only in the ciphertext; `decrypt` recovers the real
 * inner set. Returns the assembled message bytes. Fail-closed with `SmimeError`.
 *
 * @opts entity                     treat `content` as a complete MIME entity (default: wrap it as text/plain).
 * @opts contentType                the wrapped entity's MIME Content-Type (default `text/plain; charset=utf-8`).
 * @opts protectHeaders             enable RFC 9788 header protection (`hp="cipher"`): inline `opts.headers` inside the ciphertext, emit HCP-processed outer copies, and embed the authenticated HP-Outer records (RFC 9788 sec. 2.2) documenting which fields were left visible outside.
 * @opts headers                    the Non-Structural fields to protect (object `{ Name: value }` or array `[{ name, value }]`); the real values, hidden by the HCP.
 * @opts hcp                        the Header Confidentiality Policy: `"hcp_baseline"` (the default, obscuring Subject and removing Comments/Keywords) or `"hcp_no_confidentiality"` (leave all outer values visible). Per RFC 9788 sec. 3.2.1 / sec. 11.4, `hcp_baseline` deliberately does not strip `Bcc` (removing it can break deliverability to a Bcc'd recipient); to keep a blind recipient out of the plaintext outer headers, omit `Bcc` from `opts.headers`.
 * @opts contentEncryptionAlgorithm forwarded to cms.encrypt: `"aes-256-gcm"` (default) / `"aes-128-gcm"` / `"aes-256-cbc"` / `"aes-128-cbc"`.
 * @opts oaepHash                   forwarded: the RSAES-OAEP hash for ktri recipients.
 * @opts keyIdentifier              forwarded: `"issuerAndSerial"` (default) or `"subjectKeyIdentifier"`.
 * @opts ukm                        forwarded: user keying material for kari / kemri recipients.
 * @example
 *   var rsa = { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
 *   var pair = await pki.key.generate(rsa);
 *   var recipientCertDer = await pki.x509.sign({ subject: "Recipient", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var enc = await pki.smime.encrypt(Buffer.from("secret"), [{ cert: recipientCertDer }]);
 */
async function encrypt(content, recipients, opts) {
  opts = opts || {};
  _knownOpts(opts, ENCRYPT_OPTS, "encrypt");
  var hp = opts.protectHeaders === true;
  var hpList = hp ? _hpHeaderList(opts.headers) : null;
  var outerList = hp ? _outerHeaderList(hpList, "cipher", opts.hcp) : null;
  var entity = hp ? _protectedInnerEntity(content, opts, "cipher", hpList, outerList) : _entityBytes(content, opts);
  var outer = hp ? Buffer.from(_outerPrefix(outerList), "utf8") : Buffer.alloc(0);
  var recips = Array.isArray(recipients) ? recipients : [recipients];
  var der = _toBuf(await cms.encrypt(entity, recips, _cmsEncryptOpts(opts)));
  var head = _pkcs7MimeHead(_envelopedTypeOf(der, "smime/bad-mime"), "smime.p7m");
  return _capped(Buffer.concat([outer, head, _base64Body(der), mime.CRLF]));
}

/**
 * @primitive  pki.smime.decrypt
 * @signature  pki.smime.decrypt(message, keyMaterial, opts?) -> Promise<{ content, smimeType, authenticated, recipientType, recipientIndex, contentEncryptionAlgorithm, protectedHeaders, headerProtection }>
 * @since      0.2.26
 * @status     stable
 * @spec       RFC 8551, RFC 5652, RFC 5083, RFC 9788
 * @related    pki.smime.encrypt, pki.cms.decrypt, pki.smime.verify
 *
 * Open an encrypted S/MIME message (RFC 8551 sec. 3.3 / sec. 3.4), an `application/pkcs7-mime` entity
 * whose base64 body is a CMS EnvelopedData or AuthEnvelopedData. `keyMaterial` is the `pki.cms.decrypt`
 * key material (`{ key, cert }`, `{ password }`, or `{ kek, kekId? }`). Returns the recovered inner MIME
 * entity as `content`, the `smimeType`, `authenticated` (true only for AuthEnvelopedData; a CBC
 * `enveloped-data` message reports `false`, the RFC 8551 sec. 3.3 / EFAIL no-integrity caveat), and the
 * `recipientType` / `recipientIndex` / `contentEncryptionAlgorithm` from the CMS layer. Fail-closed and
 * oracle-free: every secret-dependent failure collapses to the uniform `cms/decrypt-failed` the CMS layer
 * emits (this layer only propagates it). A recovered `content` that is itself a signed S/MIME message is
 * returned as-is for the caller to feed back to `pki.smime.verify` (no auto-recursion). Accepts OpenSSL's
 * legacy `application/x-pkcs7-mime` and a missing `smime-type`. If the decrypted payload is header-protected
 * (RFC 9788, `hp="cipher"`), `protectedHeaders` is the recovered real inner header set (the values the outer
 * Header Confidentiality Policy hid) and `headerProtection` is `{ present, mode, fromMismatch, confidential, legacy }`,
 * where `present` is `true` only for a declared `hp=` payload, and `confidential` names the fields the composer
 * kept end-to-end confidential (via the authenticated HP-Outer records, RFC 9788 sec. 4.3), so a caller can
 * reply/forward without leaking them (sec. 6.1); a payload whose `hp` is malformed or contradicts the envelope
 * fails closed (`smime/bad-header-protection`). `legacy` is `null` unless `opts.legacyHeaderProtection` detected a
 * legacy RFC 8551 `message/rfc822` wrap (its own `{ headers, mode, fromMismatch, confidential }` object, where `headers`
 * is an ordered `[{ name, value }]` array; it is never merged into `protectedHeaders` / `present`).
 *
 * @opts recipientIndex  forwarded to cms.decrypt: explicitly select the recipient by index.
 * @opts maxIterations   forwarded to cms.decrypt: lower the PBKDF2 iteration cap (downward only).
 * @opts strictSmimeType reject a header `smime-type` that disagrees with the CMS body (`smime/smime-type-mismatch`).
 * @opts legacyHeaderProtection  opt in to detecting a LEGACY RFC 8551 header-protected message (RFC 9788 sec. 4.10): an encrypted Cryptographic Payload that is a bare `message/rfc822` wrap with no `hp=` parameter. When set, a precisely-identified legacy message surfaces the inner headers under `headerProtection.legacy = { headers, mode: "cipher", fromMismatch, confidential }`, with `headers` an ordered `[{ name, value }]` array (retaining repeated fields) and the `confidential` set derived from the actual visible outer Header Section. They are not placed under `protectedHeaders`, and `present` stays `false`, since a legacy message is structurally indistinguishable from a forwarded `message/rfc822` (a heuristic; cross-check `legacy.fromMismatch`). Anything not precisely identified reports `legacy: null`. Off by default.
 * @example
 *   var rsa = { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
 *   var pair = await pki.key.generate(rsa);
 *   var recipientKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var recipientCertDer = await pki.x509.sign({ subject: "Recipient", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: recipientKeyPkcs8 });
 *   var smimeMessageBytes = await pki.smime.encrypt(Buffer.from("secret"), [{ cert: recipientCertDer }]);
 *   var res = await pki.smime.decrypt(smimeMessageBytes, { key: recipientKeyPkcs8, cert: recipientCertDer });
 *   res.content;        // the recovered inner MIME entity
 *   res.authenticated;  // true here (an AEAD content cipher); false for an enveloped-only CBC message, which carries no integrity
 */
async function decrypt(message, keyMaterial, opts) {
  opts = opts || {};
  _knownOpts(opts, DECRYPT_OPTS, "decrypt");
  var ent = mime.parse(message, SmimeError, "smime/bad-mime");
  var ct = ent.contentType;
  if (!_isPkcs7(ct.type, "mime")) throw _err("smime/unsupported-type", "not an encrypted S/MIME message (Content-Type " + JSON.stringify(ct.type) + ")");
  var st = ct.params["smime-type"];
  var stLower = st ? st.toLowerCase() : st;
  if (st && stLower !== "enveloped-data" && stLower !== "authenveloped-data") throw _err("smime/unsupported-type", "unsupported smime-type " + JSON.stringify(st) + " (only enveloped-data / authEnveloped-data)");
  var der = _decodeCms(ent);
  var smimeType = _envelopedTypeOf(der, "smime/unsupported-type");
  if (opts.strictSmimeType && st && stLower !== smimeType.toLowerCase()) throw _err("smime/smime-type-mismatch", "the header smime-type " + JSON.stringify(st) + " disagrees with the CMS body (" + smimeType + ")");
  var cmsOpts = {};
  if (opts.recipientIndex !== undefined) cmsOpts.recipientIndex = opts.recipientIndex;
  if (opts.maxIterations !== undefined) cmsOpts.maxIterations = opts.maxIterations;
  var res = await cms.decrypt(der, keyMaterial, cmsOpts);
  return Object.assign({
    content: res.content, smimeType: smimeType, authenticated: res.authenticated,
    recipientType: res.recipientType, recipientIndex: res.recipientIndex,
    contentEncryptionAlgorithm: res.contentEncryptionAlgorithm,
  }, _hpSurface(res.content, ent, "cipher", res.authenticated, opts.legacyHeaderProtection === true));
}

/**
 * @primitive  pki.smime.compress
 * @signature  pki.smime.compress(content, opts?) -> Promise<Buffer>
 * @since      0.2.27
 * @status     stable
 * @spec       RFC 8551, RFC 3274
 * @related    pki.smime.decompress, pki.cms.compress
 *
 * Compress a MIME entity as an opaque compressed S/MIME message (RFC 8551 sec. 3.6). `content` is the
 * payload: a raw body wrapped as a `text/plain` entity by default, or the caller's own complete MIME
 * entity when `opts.entity` is set. The entity is canonicalized (RFC 8551 sec. 3.1) and ZLIB-compressed
 * into a CMS `CompressedData` (`pki.cms.compress`), carried opaque in one `application/pkcs7-mime;
 * smime-type=compressed-data; name=smime.p7z` entity (base64). Compression is a size transform with NO
 * integrity, confidentiality, or authentication (RFC 8551 sec. 2.4.5). Sign or encrypt the result if
 * you need protection. Returns the assembled message bytes; fail-closed with `SmimeError`.
 *
 * @opts entity      treat `content` as a complete MIME entity (default: wrap it as text/plain).
 * @opts contentType the wrapped entity's MIME Content-Type (default `text/plain; charset=utf-8`).
 * @opts level       forwarded to cms.compress: the DEFLATE compression level (an integer).
 * @example
 *   var z = await pki.smime.compress(Buffer.from("compress this message"));
 */
async function compress(content, opts) {
  opts = opts || {};
  _knownOpts(opts, COMPRESS_OPTS, "compress");
  var entity = _entityBytes(content, opts);
  var cOpts = {};
  if (opts.level !== undefined) cOpts.level = opts.level;
  var der = _toBuf(await cms.compress(entity, cOpts));
  var head = _pkcs7MimeHead("compressed-data", "smime.p7z");
  return _capped(Buffer.concat([head, _base64Body(der), mime.CRLF]));
}

/**
 * @primitive  pki.smime.decompress
 * @signature  pki.smime.decompress(message, opts?) -> Promise<{ content, contentType, contentTypeName, compressionAlgorithm }>
 * @since      0.2.27
 * @status     stable
 * @spec       RFC 8551, RFC 3274
 * @related    pki.smime.compress, pki.cms.decompress, pki.smime.verify, pki.smime.decrypt
 *
 * Decompress a compressed S/MIME message (RFC 8551 sec. 3.6), an `application/pkcs7-mime` entity whose
 * base64 body is a CMS `CompressedData`. Returns the recovered inner MIME entity as `content` plus the
 * inner `contentType` / `contentTypeName` and the `compressionAlgorithm`. The inflate is BOUNDED (a
 * decompression-bomb defense, `cms/decompress-too-large`; `opts.maxOutputBytes` tightens it downward).
 * The verdict carries NO `authenticated` / `valid` field, because CompressedData is not a security assertion
 * (RFC 8551 sec. 2.4.5). A recovered content that is itself a signed or enveloped S/MIME message is
 * returned as-is for the caller to feed back to `pki.smime.verify` / `pki.smime.decrypt` (no
 * auto-recursion). Accepts OpenSSL's legacy `application/x-pkcs7-mime` and a missing `smime-type`.
 *
 * @opts maxOutputBytes forwarded to cms.decompress: lower the decompressed-output cap (a DoS bound; downward only).
 * @example
 *   var compressedSmimeBytes = await pki.smime.compress(Buffer.from("compress me"));
 *   var res = await pki.smime.decompress(compressedSmimeBytes);
 *   res.content;   // the recovered inner MIME entity
 */
async function decompress(message, opts) {
  opts = opts || {};
  _knownOpts(opts, DECOMPRESS_OPTS, "decompress");
  var ent = mime.parse(message, SmimeError, "smime/bad-mime");
  var ct = ent.contentType;
  if (!_isPkcs7(ct.type, "mime")) throw _err("smime/unsupported-type", "not a compressed S/MIME message (Content-Type " + JSON.stringify(ct.type) + ")");
  var st = ct.params["smime-type"];
  if (st && st.toLowerCase() !== "compressed-data") throw _err("smime/unsupported-type", "unsupported smime-type " + JSON.stringify(st) + " (only compressed-data)");
  var der = _decodeCms(ent);
  var dOpts = {};
  if (opts.maxOutputBytes !== undefined) dOpts.maxOutputBytes = opts.maxOutputBytes;
  var res = await cms.decompress(der, dOpts);
  return { content: res.content, contentType: res.contentType, contentTypeName: res.contentTypeName, compressionAlgorithm: res.compressionAlgorithm };
}

function _decodeCms(ent) {
  if (ent.cte === "base64") return guard.encoding.base64(pkix.stripBase64Whitespace(ent.body.toString("latin1")), C.LIMITS.MIME_MAX_BYTES, _err, "smime/bad-mime", "the CMS body");
  return ent.body;
}

function _toBuf(v) { return Buffer.isBuffer(v) ? v : Buffer.from(v); }

var CERTS_ONLY_OPTS = Object.assign(Object.create(null), { crls: 1 });

/**
 * @primitive  pki.smime.buildCertsOnly
 * @signature  pki.smime.buildCertsOnly(certs, opts?) -> Buffer
 * @since      0.6.3
 * @status     stable
 * @spec       RFC 8551, RFC 5652
 * @related    pki.cms.certsOnly, pki.cms.parseCertsOnly, pki.smime.encrypt
 *
 * Wrap a certs-only certificate-management message (RFC 8551 sec. 3.8) in one S/MIME
 * `application/pkcs7-mime; smime-type=certs-only; name=smime.p7c` entity: the base64 body is the
 * `pki.cms.certsOnly` DER, with `Content-Disposition: attachment; filename=smime.p7c` (RFC 8551
 * sec. 3.2.1). `certs` and `opts.crls` are the certificate/CRL inputs `pki.cms.certsOnly` accepts, and
 * at least one certificate or CRL is required. A certs-only message carries no user content, so the
 * header-protection options of `pki.smime.encrypt` do not apply here.
 *
 * @opts crls A CRL or array of CRLs (DER Buffer or PEM string) to convey alongside the certificates.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var leafDer = await pki.x509.sign({ subject: "Leaf", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: await pki.key.export(pair.privateKey) });
 *   var p7c = pki.smime.buildCertsOnly([leafDer]);
 */
function buildCertsOnly(certs, opts) {
  opts = opts || {};
  _knownOpts(opts, CERTS_ONLY_OPTS, "buildCertsOnly");
  var der = _toBuf(cms.certsOnly(certs, { crls: opts.crls }));
  return _capped(Buffer.concat([_pkcs7MimeHead("certs-only", "smime.p7c"), _base64Body(der), mime.CRLF]));
}

module.exports = { sign: sign, verify: verify, encrypt: encrypt, decrypt: decrypt, compress: compress, decompress: decompress, buildCertsOnly: buildCertsOnly };
