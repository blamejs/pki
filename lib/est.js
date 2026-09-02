// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.est
 * @nav        Schema
 * @title      EST
 * @fullname   EST (Enrollment over Secure Transport, RFC 7030)
 * @order      190
 * @slug       est
 *
 * @intro
 *   Enrollment over Secure Transport (RFC 7030, updated by RFC 8951 and RFC 9908).
 *   The network verbs -- `cacerts`, `simpleenroll`, `simplereenroll` -- run the thin
 *   RFC 7030 client: they compose the codecs below over the shared `pki.transport`
 *   (a caller MAY inject `opts.transport`; the default is a fail-closed
 *   `pki.transport.https`). This module opens no socket itself: the sole socket
 *   choke point is `pki.transport`, so the verbs stay a thin, fail-closed shell:
 *   https-only (`est/insecure-url`), an explicit trust anchor required
 *   (`est/no-trust-anchors`), same-origin redirects followed but a downgrade / loop
 *   refused, a 202 Retry-After SURFACED and never slept, HTTP Basic answered only
 *   after the transport authenticated the server, and the issued certificate chosen
 *   by public-key match. Under them sit the transport-agnostic codecs, validators, and
 *   request builders over the shipped CMS / CSR / PKCS#8 / X.509 parsers:
 *   `transferDecode` / `transferEncode` are the RFC 8951
 *   sec. 3 base64 transfer codec (RFC 4648, and deliberately blind to any
 *   Content-Transfer-Encoding header, per errata 5904/5107); `splitMultipartMixed`
 *   is the /serverkeygen `multipart/mixed` splitter; `parseCertsOnly` validates a
 *   certs-only Simple PKI Response (RFC 5272 sec. 4.1) over `cms.parse` output;
 *   `parseServerKeygenResponse` dispatches the two-part key + certificate
 *   response with recipient-arm coherence; `classifyResponse` is the HTTP status
 *   / content-type / Retry-After state machine (202 accepted-not-ready surfaces
 *   `retryAfterSeconds` -- never an internal sleep; 204/404 on /csrattrs is a
 *   "none available" verdict, not an error). The builders assemble the CSR
 *   attributes EST adds -- a channel-binding challengePassword, the
 *   out-of-band-key identifiers, SMIMECapabilities, and the RFC 9908
 *   template-priority enroll plan.
 *
 *   Altitude matches the toolkit: structural validation, no crypto verdicts.
 *   Certificates come back raw and unordered ("Clients MUST NOT assume the
 *   certificates are in any order", RFC 5272 sec. 4.1), so `findIssuedCert` picks
 *   the issued certificate by a public-key match, never a positional guess. The
 *   serverkeygen encrypted-key part's EnvelopedData is surfaced structurally
 *   (ciphertext raw, decryption external). A /fullcmc response is classified:
 *   a 200 may carry either arm RFC 7030 sec. 4.3.2 permits (`certs-only` or
 *   `CMC-response`), and a 404 or 501 is the distinct `not-implemented`
 *   verdict, meaning this service is absent, not that the transport faulted. Reading the
 *   CMC message itself is the CMC module's job. DER-only where DER,
 *   fail-closed everywhere.
 *
 * @card
 *   EST (RFC 7030 / 8951 / 9908) client: the cacerts / simpleenroll / simplereenroll
 *   verbs over the shared pki.transport, plus the codecs they compose: base64 transfer,
 *   multipart splitter, certs-only + serverkeygen validators over CMS, the
 *   enroll-attribute builders, and the HTTP response classifier. Fail-closed.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var constants = require("./constants");
var cms = require("./schema-cms");
var x509 = require("./schema-x509");
var pkcs8 = require("./schema-pkcs8");
var key = require("./key");
var csr = require("./schema-csr");
var csrattrsFmt = require("./schema-csrattrs");
var cmcVerify = require("./cmc-verify");
var cmcFmt = require("./schema-cmc");
var OID_CMC_TRANSACTION_ID = oid.byName("id-cmc-transactionId");
var OID_CMC_SENDER_NONCE = oid.byName("id-cmc-senderNonce");
var OID_CMC_DATA_RETURN = oid.byName("id-cmc-dataReturn");
var crmfFmt = require("./schema-crmf");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _toLowerCase = intrinsic.uncurry(String.prototype.toLowerCase);
var pkix = require("./schema-pkix");
var _hasOwn = intrinsic.hasOwn;
var httpTransport = require("./http-transport");
var httpDigest = require("./http-digest");
var retryAfter = require("./http-retry-after");

var EstError = frameworkError.EstError;
function E(code, message, cause) { return new EstError(code, message, cause); }
var ID_SIGNED_DATA = oid.byName("signedData");
var OID_CHALLENGE_PASSWORD = oid.byName("challengePassword");
var OID_DECRYPT_KEY_ID = oid.byName("decryptKeyID");

var _DIGITS_TABLE = pkix.charTable("0123456789");
var _LABEL_TABLE = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-");

function _stripTrailingSlashEnd(s) { var end = s.length; while (end > 0 && _charCodeAt(s, end - 1) === 0x2f) end -= 1; return end; }
var OID_ASYMM_DECRYPT_KEY_ID = oid.byName("asymmDecryptKeyID");
var OID_SMIME_CAPABILITIES = oid.byName("smimeCapabilities");
var OID_TEMPLATE = oid.byName("certificationRequestInfoTemplate");

var OPERATIONS = ["cacerts", "simpleenroll", "simplereenroll", "fullcmc", "serverkeygen", "csrattrs"];

var CLIENT_OPTS = {
  transport: 1, tls: 1, label: 1, timeout: 1, maxResponseBytes: 1, maxRedirects: 1, now: 1,
  auth: 1, username: 1, password: 1, allowCrossOriginRedirect: 1,
};
function _withClient(extra) {
  var out = {};
  Object.keys(CLIENT_OPTS).forEach(function (k) { out[k] = 1; });
  Object.keys(extra || {}).forEach(function (k) { out[k] = 1; });
  return out;
}
var CACERTS_OPTS = _withClient(null);
var SIMPLEENROLL_OPTS = _withClient({ strict: 1 });
var SIMPLEREENROLL_OPTS = _withClient({ strict: 1, oldCert: 1 });
var SERVERKEYGEN_OPTS = _withClient({
  requestedEncryption: 1, expectedRecipientKeyId: 1, expectedRecipientIssuerSerial: 1,
});
var CSRATTRS_OPTS = _withClient(null);
var FULLCMC_OPTS = _withClient({
  transactionId: 1, senderNonce: 1, dataReturn: 1,
  responderCerts: 1, responseRecipient: 1, allowUnverifiedResponse: 1, allowUnboundResponse: 1,
});
var CLASSIFY_OPTS = { op: 1, now: 1 };
var PATHS_OPTS = { label: 1 };
var PARSE_SERVERKEYGEN_OPTS = {
  requestedEncryption: 1, expectedRecipientKeyId: 1, expectedRecipientKind: 1,
  expectedRecipientIssuerSerial: 1,
};

function _knownOpts(opts, known, verb) {
  guard.identifier.assertKnownKeys(opts, known, E, "est/bad-input", function (k) {
    return "unknown option " + JSON.stringify(k) + " for pki.est." + verb + " -- accepted: " +
      Object.keys(known).sort().join(", ");
  });
}


/**
 * @primitive  pki.est.transferDecode
 * @signature  pki.est.transferDecode(body) -> Buffer
 * @since      0.1.24
 * @status     stable
 * @spec       RFC 8951, RFC 4648
 * @related    pki.est.transferEncode
 *
 * Decode an EST payload body (a base64 string or Buffer) to DER. CR/LF/space/tab
 * are stripped anywhere (RFC 8951 sec. 3.1); any other non-alphabet byte fails
 * closed with `est/bad-base64`. A Content-Transfer-Encoding header is never read
 * (errata 5904/5107). Bounded twice: the raw length before decode and the
 * decoded DER against `DER_MAX_BYTES` (`est/too-large`).
 *
 * @example
 *   var der = pki.asn1.build.sequence([pki.asn1.build.integer(1n)]);
 *   var roundTripped = pki.est.transferDecode(pki.est.transferEncode(der));
 */
function transferDecode(body) {
  var b64Len = Math.ceil(constants.LIMITS.DER_MAX_BYTES * 4 / 3);
  var cap = b64Len + Math.ceil(b64Len / 8) + constants.BYTES.kib(64);
  var s = guard.text.decode(body, cap, EstError, {
    charset: "latin1", tooLarge: "est/too-large", badInput: "est/bad-input", label: "the EST payload",
  });
  var stripped = pkix.stripBase64Whitespace(s);
  var der = guard.encoding.base64(stripped, null, E, "est/bad-base64", "the EST payload");
  if (der.length > constants.LIMITS.DER_MAX_BYTES) throw E("est/too-large", "the decoded EST DER exceeds the size cap");
  return der;
}

function _bodyLen(res) {
  var body = res.body;
  return body == null ? 0 : (typeof body === "string" ? Buffer.byteLength(body, "utf8")
    : (Buffer.isBuffer(body) ? guard.bytes.lengthOf(body) : guard.bytes.lengthOf(guard.bytes.source(body, EstError, "est/bad-input", "the response body"))));
}

/**
 * @primitive  pki.est.transferEncode
 * @signature  pki.est.transferEncode(der) -> string
 * @since      0.1.24
 * @status     stable
 * @spec       RFC 8951, RFC 4648
 * @related    pki.est.transferDecode
 *
 * Encode DER as an EST payload body: bare RFC 4648 base64, no line wrapping
 * (senders need not insert whitespace, RFC 8951 sec. 3.1).
 *
 * @example
 *   var der = pki.asn1.build.sequence([pki.asn1.build.integer(1n)]);
 *   var body = pki.est.transferEncode(der);
 */
function transferEncode(der) {
  if (!Buffer.isBuffer(der)) throw E("est/bad-input", "transferEncode requires a DER Buffer");
  der = guard.bytes.view(der, EstError, "est/bad-input", "transferEncode DER input");
  return der.toString("base64");
}


function _ciStartsWith(s, litUpper) {
  if (s.length < litUpper.length) return false;
  for (var k = 0; k < litUpper.length; k++) {
    var c = _charCodeAt(s, k);
    if (c >= 97 && c <= 122) c -= 32;
    if (c !== _charCodeAt(litUpper, k)) return false;
  }
  return true;
}
var _MULTIPART_MIXED = "MULTIPART/MIXED";
function _isMultipartMixedPrefix(ct) {
  if (!_ciStartsWith(ct, _MULTIPART_MIXED)) return false;
  var p = _MULTIPART_MIXED.length;
  while (p < ct.length && pkix.isJsWhitespace(_charCodeAt(ct, p))) p++;
  return p === ct.length || _charCodeAt(ct, p) === 0x3b;
}

function _multipartBoundary(contentType) {
  var ct = String(contentType || "");
  if (!_isMultipartMixedPrefix(ct)) return null;
  var bp = _ctParam(ct, "boundary");
  if (bp.duplicated) {
    throw E("est/bad-multipart",
      "the multipart Content-Type declares more than one boundary, so where the parts begin is ambiguous (RFC 2045 sec. 5.1)");
  }
  return bp.value;
}

function _matchDelimAt(text, ls, boundary) {
  var n = text.length, q = ls, blen = boundary.length, k;
  if (q + 2 > n || _charCodeAt(text, q) !== 0x2d || _charCodeAt(text, q + 1) !== 0x2d) return null;
  q += 2;
  if (q + blen > n) return null;
  for (k = 0; k < blen; k++) { if (_charCodeAt(text, q + k) !== _charCodeAt(boundary, k)) return null; }
  q += blen;
  var close = false;
  if (q + 2 <= n && _charCodeAt(text, q) === 0x2d && _charCodeAt(text, q + 1) === 0x2d) { close = true; q += 2; }
  while (q < n && (_charCodeAt(text, q) === 0x20 || _charCodeAt(text, q) === 0x09)) q += 1;
  if (q === n) return { end: q, close: close };
  if (_charCodeAt(text, q) === 0x0a) return { end: q + 1, close: close };
  if (_charCodeAt(text, q) === 0x0d && q + 1 < n && _charCodeAt(text, q + 1) === 0x0a) return { end: q + 2, close: close };
  return null;
}
function _findMultipartMarks(text, boundary) {
  var marks = [], n = text.length, searchStart = 0, p;
  while (searchStart <= n) {
    var found = null, foundAt = -1;
    for (p = searchStart; p <= n; p++) {
      if (p === 0) { var r0 = _matchDelimAt(text, 0, boundary); if (r0) { found = r0; foundAt = 0; break; } }
      var lsN = -1;
      if (_charCodeAt(text, p) === 0x0a) lsN = p + 1;
      else if (_charCodeAt(text, p) === 0x0d && p + 1 < n && _charCodeAt(text, p + 1) === 0x0a) lsN = p + 2;
      if (lsN !== -1) { var r1 = _matchDelimAt(text, lsN, boundary); if (r1) { found = r1; foundAt = p; break; } }
    }
    if (!found) break;
    marks[marks.length] = { at: foundAt, bodyStart: found.end, close: found.close };
    searchStart = found.end === foundAt ? found.end + 1 : found.end;
  }
  return marks;
}
function _stripTwoLeadingEol(seg, from) {
  var q = from;
  for (var t = 0; t < 2; t++) {
    if (_charCodeAt(seg, q) === 0x0d && _charCodeAt(seg, q + 1) === 0x0a) q += 2;
    else if (_charCodeAt(seg, q) === 0x0a) q += 1;
    else return from;
  }
  return q;
}
function _stripOneTrailingEol(seg, end) {
  if (end >= 1 && _charCodeAt(seg, end - 1) === 0x0a) {
    if (end >= 2 && _charCodeAt(seg, end - 2) === 0x0d) return end - 2;
    return end - 1;
  }
  return end;
}
function _unfoldHeaders(raw) {
  var out = "", last = 0, i = 0, n = raw.length;
  while (i < n) {
    var nlLen = 0;
    if (_charCodeAt(raw, i) === 0x0d && i + 1 < n && _charCodeAt(raw, i + 1) === 0x0a) nlLen = 2;
    else if (_charCodeAt(raw, i) === 0x0a) nlLen = 1;
    if (nlLen > 0) {
      var after = i + nlLen;
      if (after < n && (_charCodeAt(raw, after) === 0x20 || _charCodeAt(raw, after) === 0x09)) { out += _strSlice(raw, last, i); last = after; i = after; continue; }
    }
    i += 1;
  }
  return out + _strSlice(raw, last, n);
}
function _splitCrlf(s) {
  var out = [], last = 0, i = 0, n = s.length;
  while (i < n) {
    var nlLen = 0;
    if (_charCodeAt(s, i) === 0x0d && i + 1 < n && _charCodeAt(s, i + 1) === 0x0a) nlLen = 2;
    else if (_charCodeAt(s, i) === 0x0a) nlLen = 1;
    if (nlLen > 0) { out[out.length] = _strSlice(s, last, i); i += nlLen; last = i; } else i += 1;
  }
  out[out.length] = _strSlice(s, last, n);
  return out;
}

function splitMultipartMixed(body, contentType) {
  var boundary = _multipartBoundary(contentType);
  if (!boundary) throw E("est/bad-multipart", "a serverkeygen response must be multipart/mixed with a boundary (RFC 7030 sec. 4.4.2)");
  var text = guard.text.decode(body, constants.LIMITS.DER_MAX_BYTES * 2, EstError, {
    charset: "latin1", tooLarge: "est/too-large", badInput: "est/bad-input", label: "the multipart body",
  });
  var marks = _findMultipartMarks(text, boundary);
  var closeAt = -1;
  for (var c = 0; c < marks.length; c++) { if (marks[c].close) { closeAt = c; break; } }
  if (closeAt === -1) throw E("est/bad-multipart", "the multipart body is missing its terminal boundary (RFC 2046)");
  var parts = [];
  for (var i = 0; i < closeAt; i++) {
    var seg = _strSlice(text, marks[i].bodyStart, marks[i + 1].at);
    var sep = seg.indexOf("\r\n\r\n");
    if (sep === -1) sep = seg.indexOf("\n\n");
    if (sep === -1) throw E("est/bad-multipart", "a multipart part is missing its header/body separator");
    var rawHeaders = _strSlice(seg, 0, sep);
    var partBody = _strSlice(seg, _stripTwoLeadingEol(seg, sep), _stripOneTrailingEol(seg, seg.length));
    var headers = {};
    var lines = _splitCrlf(_unfoldHeaders(rawHeaders));
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      var col = line.indexOf(":");
      if (col > 0) headers[line.slice(0, col).trim().toLowerCase()] = line.slice(col + 1).trim();
    }
    var partCt = headers["content-type"] || "";
    if (_ciStartsWith(partCt, "MULTIPART/")) throw E("est/bad-multipart", "a nested multipart part is not permitted");
    parts.push({ headers: headers, contentType: partCt, body: partBody });
  }
  return parts;
}


/**
 * @primitive  pki.est.parseCertsOnly
 * @signature  pki.est.parseCertsOnly(der) -> { certificates, crls }
 * @since      0.1.24
 * @status     stable
 * @spec       RFC 7030, RFC 5272, RFC 5652
 * @related    pki.est.findIssuedCert, pki.schema.cms.parse
 *
 * Validate a certs-only CMS Simple PKI Response (RFC 5272 sec. 4.1) over the
 * shipped `cms.parse` output: a SignedData with no eContent and EMPTY
 * signerInfos, carrying at least one plain X.509 certificate (a context-tagged
 * CertificateChoices alternative is rejected `est/bad-certificate-choice`). CRLs
 * MAY be present. Certificates come back raw and in as-received order (never
 * sorted, per RFC 5272 sec. 4.1). A non-conformant response throws a typed
 * `EstError` (`est/not-certs-only`, `est/no-certificates`).
 *
 * @example
 *   var b = pki.asn1.build;
 *   var pair = await pki.key.generate("Ed25519");
 *   var certDer = await pki.x509.sign({ subject: "Example CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   // the certs-only Simple PKI Response shape (RFC 7030 sec. 4.1.3): a SignedData
 *   // v1 over id-data with no eContent, the certificates, and an EMPTY signerInfos
 *   var caCertsDer = b.sequence([b.oid("1.2.840.113549.1.7.2"), b.explicit(0, b.sequence([
 *     b.integer(1n), b.set([]), b.sequence([b.oid("1.2.840.113549.1.7.1")]),
 *     b.contextConstructed(0, certDer), b.set([])]))]);
 *   var r = pki.est.parseCertsOnly(caCertsDer);
 *   r.certificates;   // -> [Buffer, ...] raw, unordered
 */
function parseCertsOnly(der) {
  return cms.parseCertsOnly(der, E, "est");
}

function findIssuedCert(certs, target) {
  var want = Buffer.isBuffer(target) ? target : (target && target.bytes);
  if (!Buffer.isBuffer(want)) return null;
  for (var i = 0; i < certs.length; i++) {
    var spki;
    try { spki = x509.parse(certs[i]).subjectPublicKeyInfo; }
    catch (_e) { continue; }
    if (spki && Buffer.isBuffer(spki.bytes) && spki.bytes.equals(want)) return certs[i];
  }
  return null;
}


function _recipientKeyIds(recipientInfos, kind) {
  var ids = [];
  function push(v) { if (Buffer.isBuffer(v)) ids.push(v); }
  (recipientInfos || []).forEach(function (r) {
    if (kind !== "symmetric") {
      if (r.rid) push(r.rid.subjectKeyIdentifier);
      if (r.kemri && r.kemri.rid) push(r.kemri.rid.subjectKeyIdentifier);
      (r.recipientEncryptedKeys || []).forEach(function (rek) { if (rek.rid) push(rek.rid.subjectKeyIdentifier); });
    }
    if (kind !== "asymmetric") {
      if (r.kekid) push(r.kekid.keyIdentifier);
    }
  });
  return ids;
}

function _recipientIssuerSerials(recipientInfos) {
  var out = [];
  function push(rid) { if (rid && rid.issuer && Buffer.isBuffer(rid.issuer.bytes) && rid.serialNumber != null) out.push({ issuer: rid.issuer.bytes, serialNumber: rid.serialNumber }); }
  (recipientInfos || []).forEach(function (r) {
    push(r.rid);
    if (r.kemri) push(r.kemri.rid);
    (r.recipientEncryptedKeys || []).forEach(function (rek) { push(rek.rid); });
  });
  return out;
}

function _recipientMatches(recipientInfos, opts) {
  if (Buffer.isBuffer(opts.expectedRecipientKeyId) &&
      _recipientKeyIds(recipientInfos, opts.expectedRecipientKind).some(function (id) { return id.equals(opts.expectedRecipientKeyId); })) return true;
  var ias = opts.expectedRecipientIssuerSerial;
  if (ias && Buffer.isBuffer(ias.issuer) && ias.serialNumber != null) {
    var sn = ias.serialNumber, want;
    if (typeof sn === "bigint" && sn >= 0n) want = sn;
    else if (typeof sn === "number" && Number.isSafeInteger(sn) && sn >= 0) want = BigInt(sn);
    else if (typeof sn === "string" && pkix.allCharsIn(sn, _DIGITS_TABLE)) want = BigInt(sn);
    else throw E("est/bad-input", "expectedRecipientIssuerSerial.serialNumber must be a NON-NEGATIVE bigint, a safe non-negative integer, or a decimal digit string (a certificate serial is non-negative, RFC 5280 sec. 4.1.2.2)");
    if (opts.expectedRecipientKind !== "symmetric" &&
        _recipientIssuerSerials(recipientInfos).some(function (r) { return r.issuer.equals(ias.issuer) && r.serialNumber === want; })) return true;
  }
  return false;
}

function _splitContentTypeParams(s) {
  var segs = [], cur = "", inQuote = false;
  for (var i = 0; i < s.length; i++) {
    var ch = s[i];
    if (ch === '"') { inQuote = !inQuote; cur += ch; }
    else if (ch === ";" && !inQuote) { segs.push(cur); cur = ""; }
    else cur += ch;
  }
  segs.push(cur);
  return segs;
}

function _ctParam(contentType, name) {
  var segs = _splitContentTypeParams(String(contentType || ""));
  var value = null, count = 0;
  for (var i = 1; i < segs.length; i++) {
    var eq = segs[i].indexOf("=");
    if (eq === -1) continue;
    if (segs[i].slice(0, eq).trim().toLowerCase() !== name) continue;
    count++;
    if (count > 1) continue;
    var val = segs[i].slice(eq + 1).trim();
    if (val.length >= 2 && val.charAt(0) === '"' && val.charAt(val.length - 1) === '"') val = val.slice(1, -1);
    value = val;
  }
  return { value: value, duplicated: count > 1 };
}

var _MT_FIRST = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
var _MT_REST = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$&^_.+-");
function _isMediaToken(s, from, to) {
  if (to <= from || !_MT_FIRST[_charCodeAt(s, from)]) return false;
  for (var i = from + 1; i < to; i++) { if (!_MT_REST[_charCodeAt(s, i)]) return false; }
  return true;
}
function _mediaType(seg) {
  var a = 0, b = seg.length, slash = -1, i;
  while (a < b && pkix.isJsWhitespace(_charCodeAt(seg, a))) a += 1;
  while (b > a && pkix.isJsWhitespace(_charCodeAt(seg, b - 1))) b -= 1;
  for (i = a; i < b; i++) { if (_charCodeAt(seg, i) === 0x2f) { if (slash !== -1) return null; slash = i; } }
  if (slash === -1 || !_isMediaToken(seg, a, slash) || !_isMediaToken(seg, slash + 1, b)) return null;
  return _toLowerCase(_strSlice(seg, a, b));
}

function _partMediaType(contentType) {
  var segs = _splitContentTypeParams(String(contentType || ""));
  var st = _ctParam(contentType, "smime-type");
  return {
    media: _mediaType(segs[0]),
    smimeType: st.value === null ? null : st.value.toLowerCase(),
    ambiguous: st.duplicated,
  };
}

function parseServerKeygenResponse(body, contentType, opts) {
  opts = opts || {};
  _knownOpts(opts, PARSE_SERVERKEYGEN_OPTS, "parseServerKeygenResponse");
  var parts = splitMultipartMixed(body, contentType);
  if (parts.length !== 2) throw E("est/bad-multipart", "a serverkeygen response must have exactly two parts (RFC 7030 sec. 4.4.2)");
  var keyPart = null, certPart = null, encrypted = false;
  for (var i = 0; i < parts.length; i++) {
    var pt = _partMediaType(parts[i].contentType);
    if (pt.ambiguous) {
      throw E("est/bad-multipart",
        "a serverkeygen response part declares more than one smime-type, so which part it is cannot be told from it (RFC 2045 sec. 5.1)");
    }
    if (pt.media === "application/pkcs8") { keyPart = parts[i]; encrypted = false; }
    else if (pt.media === "application/pkcs7-mime" && pt.smimeType === "server-generated-key") { keyPart = parts[i]; encrypted = true; }
    else if (pt.media === "application/pkcs7-mime" && pt.smimeType === "certs-only") certPart = parts[i];
    else throw E("est/bad-multipart", "unrecognized serverkeygen part content-type " + JSON.stringify(parts[i].contentType));
  }
  if (!keyPart || !certPart) throw E("est/bad-multipart", "a serverkeygen response needs one key part and one certificate part");
  if (opts.requestedEncryption && !encrypted) throw E("est/expected-encrypted-key", "encryption was requested but the private-key part is cleartext (RFC 7030 sec. 4.4.2)");
  if (opts.requestedEncryption === false && encrypted) throw E("est/unexpected-encrypted-key", "the server returned an encrypted key but the CSR advertised no DecryptKeyIdentifier / AsymmetricDecryptKeyIdentifier to decrypt it (RFC 7030 sec. 4.4.2)");
  var out = { certificates: parseCertsOnly(transferDecode(certPart.body)).certificates };
  if (encrypted) {
    var parsedKey = cms.parse(transferDecode(keyPart.body));
    if (parsedKey.contentTypeName !== "envelopedData") throw E("est/bad-key-part", "a server-generated encrypted key part must be a CMS EnvelopedData (RFC 7030 sec. 4.4.2), got " + JSON.stringify(parsedKey.contentTypeName));
    if (!parsedKey.encryptedContentInfo || parsedKey.encryptedContentInfo.contentType !== ID_SIGNED_DATA) throw E("est/bad-key-part", "a server-generated encrypted key's EnvelopedData must encapsulate a CMS SignedData (RFC 7030 sec. 4.4.2)");
    cms.assertAttachedCiphertext(parsedKey.encryptedContentInfo, E, "est/bad-key-part", "a server-generated encrypted key's EnvelopedData");
    if (Buffer.isBuffer(opts.expectedRecipientKeyId) || opts.expectedRecipientIssuerSerial) {
      if (!_recipientMatches(parsedKey.recipientInfos, opts)) throw E("est/recipient-mismatch", "the server-generated key is not encrypted to the advertised recipient (RFC 7030 sec. 4.4.2)");
    }
    out.encryptedKey = parsedKey;
  } else {
    var keyDer = transferDecode(keyPart.body);
    out.privateKey = pkcs8.parse(keyDer);
    out.privateKeyDer = keyDer;
  }
  return out;
}


var CONTENT_TYPE_BY_OP = {
  cacerts: { media: "application/pkcs7-mime" },
  simpleenroll: { media: "application/pkcs7-mime", smimeTypes: ["certs-only"] },
  simplereenroll: { media: "application/pkcs7-mime", smimeTypes: ["certs-only"] },
  fullcmc: { media: "application/pkcs7-mime", smimeTypes: ["certs-only", "cmc-response"] },
  serverkeygen: { media: "multipart/mixed" },
  csrattrs: { media: "application/csrattrs" },
};

var CLASSIFIABLE_OPS = ["cacerts", "simpleenroll", "simplereenroll", "fullcmc", "serverkeygen", "csrattrs"];

var NOT_IMPLEMENTED_OPS = { fullcmc: 1 };

/**
 * @primitive  pki.est.classifyResponse
 * @signature  pki.est.classifyResponse(status, headers, body, opts?) -> verdict
 * @since      0.1.24
 * @status     stable
 * @spec       RFC 7030, RFC 8951
 * @related    pki.est.paths, pki.est.parseCertsOnly
 *
 * Classify an EST HTTP response into a verdict or a typed fault. A 200 requires
 * the operation's exact content-type (`est/bad-content-type`); a 202 requires a
 * Retry-After (absent -> `est/missing-retry-after`) -- a delay-seconds value is
 * surfaced as bounded `retryAfterSeconds`, an HTTP-date as absolute
 * `retryAfterDate` (epoch ms; `retryAfterSeconds` too when `opts.now` is given),
 * and any other value is `est/bad-retry-after` (never slept on either way);
 * 204/404 on `/csrattrs` is a `none-available` verdict (an error on any other
 * operation); 4xx/5xx surface the capped diagnostic on `est/http-error`.
 *
 * @opts
 *   op: string   // the EST operation this response answers
 *   now: number  // the response receipt time (epoch ms), to turn an HTTP-date Retry-After into retryAfterSeconds
 *
 * @example
 *   var v = pki.est.classifyResponse(202, { "retry-after": "120" }, "", { op: "simpleenroll" });
 *   v.retryAfterSeconds;   // -> 120
 */
function classifyResponse(status, headers, body, opts) {
  opts = opts || {};
  _knownOpts(opts, CLASSIFY_OPTS, "classifyResponse");
  var op = opts.op;
  if (op !== undefined && op !== null && CLASSIFIABLE_OPS.indexOf(op) === -1) throw E("est/unsupported-operation", "unrecognized EST operation " + guard.text.showValue(op));
  var h = {
    "content-type": _ciHeader(headers, "content-type"),
    "retry-after": _ciHeader(headers, "retry-after"),
    "location": _ciHeader(headers, "location"),
    "www-authenticate": _ciHeaderList(headers, "www-authenticate"),
  };
  if (status === 200) {
    var spec = CONTENT_TYPE_BY_OP[op];
    var ct = h["content-type"] || "";
    if (spec) {
      var pt = _partMediaType(ct);
      var smimeOk = !pt.ambiguous && (!spec.smimeTypes || spec.smimeTypes.indexOf(pt.smimeType) !== -1);
      if (pt.media !== spec.media || !smimeOk) {
        throw E("est/bad-content-type", "a 200 " + op + " response must carry content-type " + spec.media + (spec.smimeTypes ? "; smime-type=" + spec.smimeTypes.join(" or ") : "") + ", got " + JSON.stringify(ct));
      }
    }
    return { status: "ok", contentType: ct };
  }
  if (status === 202) {
    var ra = h["retry-after"];
    if (ra === undefined || ra === null || String(ra).trim() === "") throw E("est/missing-retry-after", "an HTTP 202 EST response must include Retry-After (RFC 7030 sec. 4.2.3)");
    var raStr = String(ra).trim();
    var parsed = retryAfter.parse(raStr, { now: opts.now, E: E, code: "est/bad-retry-after" });
    return { status: "retry", retryAfter: raStr, retryAfterSeconds: parsed.retryAfterSeconds, retryAfterDate: parsed.retryAfterDate };
  }
  if (status === 501 && NOT_IMPLEMENTED_OPS[op]) return { status: "not-implemented", httpStatus: status };
  if (status === 204 || status === 404) {
    if (op === "csrattrs") return { status: "none-available" };
    if (status === 404 && NOT_IMPLEMENTED_OPS[op]) return { status: "not-implemented", httpStatus: status };
    throw E("est/http-error", "HTTP " + status + " is not a valid " + op + " response");
  }
  if (status >= 300 && status < 400) return { status: "redirect", location: h["location"] || null };
  if (status >= 400) {
    var text;
    if (Buffer.isBuffer(body)) {
      text = body.toString("utf8", 0, 512);
    } else if (guard.bytes.isByteSource(body)) {
      try { text = guard.bytes.source(body, EstError, "est/bad-input", "the EST error body").toString("utf8", 0, 512); }
      catch (_e) { /* allow:swallow-unverified a detached / unreadable error body reads as an empty snippet rather than masking the est/http-error verdict with a raw TypeError */ text = ""; }
    } else {
      text = String(body || "").slice(0, 512);
    }
    throw E("est/http-error", "EST server returned HTTP " + status + (text ? ": " + text : ""));
  }
  return { status: "unexpected", httpStatus: status };
}


/**
 * @primitive  pki.est.paths
 * @signature  pki.est.paths(baseUrl, opts?) -> { cacerts, simpleenroll, ... }
 * @since      0.1.24
 * @status     stable
 * @spec       RFC 7030
 * @related    pki.est.classifyResponse
 *
 * Build the RFC 7030 sec. 3.2.2 operation URLs for a base server URL. An OPTIONAL
 * CA label (`opts.label`) MUST be non-empty, carry no `/`, and not collide with
 * an operation name, else `est/bad-label`.
 *
 * @opts
 *   label: string   // an OPTIONAL CA label path segment
 *
 * @example
 *   pki.est.paths("https://ca.example").cacerts;
 *   // -> "https://ca.example/.well-known/est/cacerts"
 */
function paths(baseUrl, opts) {
  opts = opts || {};
  _knownOpts(opts, PATHS_OPTS, "paths");
  var base = String(baseUrl);
  var prefix = base.slice(0, _stripTrailingSlashEnd(base)) + "/.well-known/est";
  if (opts.label != null) {
    var label = String(opts.label);
    if (label === "" || label === "." || label === ".." || !pkix.allCharsIn(label, _LABEL_TABLE) || OPERATIONS.indexOf(label) !== -1) {
      throw E("est/bad-label", "an EST CA label must be a single path segment of unreserved characters, not '.' / '..' or an operation name (RFC 7030 sec. 3.2.2)");
    }
    prefix += "/" + label;
  }
  var out = {};
  OPERATIONS.forEach(function (op) { out[op] = prefix + "/" + op; });
  return out;
}


function _attr(typeOid, valueNodes) { return asn1.build.sequence([asn1.build.oid(typeOid), asn1.build.set(valueNodes)]); }

function challengePasswordFromTlsUnique(channelBinding) {
  if (!guard.bytes.isByteSource(channelBinding)) throw E("est/bad-input", "challengePasswordFromTlsUnique requires the channel-binding bytes");
  var _cb = guard.bytes.source(channelBinding, EstError, "est/bad-input", "the channel-binding bytes");
  if (_cb.length === 0) throw E("est/bad-input", "challengePasswordFromTlsUnique requires the channel-binding bytes");
  var b64 = _cb.toString("base64");
  if (b64.length > 255) throw E("est/tls-unique-too-long", "the base64 tls-unique value exceeds 255 octets (RFC 7030 sec. 3.5)");
  return _attr(OID_CHALLENGE_PASSWORD, [asn1.build.printable(b64)]);
}

function decryptKeyIdentifierAttr(keyId) {
  if (!Buffer.isBuffer(keyId)) throw E("est/bad-input", "decryptKeyIdentifierAttr requires the key-identifier bytes");
  return _attr(OID_DECRYPT_KEY_ID, [asn1.build.octetString(keyId)]);
}
function asymmetricDecryptKeyIdentifierAttr(keyId) {
  if (!Buffer.isBuffer(keyId)) throw E("est/bad-input", "asymmetricDecryptKeyIdentifierAttr requires the key-identifier bytes");
  return _attr(OID_ASYMM_DECRYPT_KEY_ID, [asn1.build.octetString(keyId)]);
}
function smimeCapabilitiesAttr(capabilities) {
  if (!Array.isArray(capabilities) || capabilities.length === 0) throw E("est/bad-input", "smimeCapabilitiesAttr requires a non-empty capability list");
  var caps = capabilities.map(function (c) {
    var seq = [asn1.build.oid(c.capabilityID)];
    if (c.parameters !== undefined && c.parameters !== null) seq.push(Buffer.isBuffer(c.parameters) ? c.parameters : asn1.build.oid(c.parameters));
    return asn1.build.sequence(seq);
  });
  return _attr(OID_SMIME_CAPABILITIES, [asn1.build.sequence(caps)]);
}

function buildEnrollAttributes(csrattrsParsed) {
  var items = (csrattrsParsed && csrattrsParsed.items) || [];
  var template = null;
  for (var i = 0; i < items.length; i++) {
    if (items[i].kind === "attribute" && items[i].oid === OID_TEMPLATE) { template = items[i].template; break; }
  }
  if (template) return { fromTemplate: true, template: template, channelBindingRequired: false, unhandled: [] };
  var plan = { fromTemplate: false, channelBindingRequired: false, keyType: null, extensions: null, unhandled: [] };
  for (var j = 0; j < items.length; j++) {
    var it = items[j];
    if (it.oid === OID_CHALLENGE_PASSWORD) plan.channelBindingRequired = true;
    else if (it.kind === "attribute" && it.extensions) plan.extensions = it.extensions;
    else if (it.kind === "attribute" && it.isKeyType) {
      if (plan.keyType) throw E("est/ambiguous-key-type", "a non-template CsrAttrs response must carry exactly one key-type attribute (RFC 9908 sec. 3.2)");
      plan.keyType = { type: it.name, curve: it.curve || null, keySize: it.keySize || null, values: it.values || [] };
    }
    else plan.unhandled.push({ kind: it.kind, oid: it.oid, name: it.name });
  }
  return plan;
}

var SAN_OID = oid.byName("subjectAltName");

function _san(extList) {
  if (!Array.isArray(extList)) return null;
  for (var i = 0; i < extList.length; i++) {
    if (extList[i].oid === SAN_OID) return { critical: !!extList[i].critical, value: extList[i].value };
  }
  return null;
}

function _csrRequestedExtensions(parsedCsr) {
  var attrs = (parsedCsr && parsedCsr.attributes) || [];
  var extReqOid = oid.byName("extensionRequest");
  var found = null, count = 0;
  for (var i = 0; i < attrs.length; i++) {
    if (attrs[i].type === extReqOid) { count += 1; found = attrs[i].extensions || null; }
  }
  if (count > 1) throw E("est/reenroll-ambiguous-request", "a re-enroll CSR must not carry more than one extensionRequest attribute (RFC 7030 sec. 4.2.2)");
  return found;
}

function reenrollGuard(oldCertDer, newCsrDer) {
  var oldCert = x509.parse(oldCertDer);
  var oldSubject = oldCert.subject.rdns;
  var oldSubjectDn = oldCert.subject.dn;
  var oldSubjectBytes = oldCert.subject.bytes;
  var oldSan = _san(oldCert.extensions);
  if (newCsrDer === undefined) return { subjectDn: oldSubjectDn, subject: oldSubject, subjectAltName: oldSan };
  var parsedCsr = csr.parse(newCsrDer);
  var subjectMatches = Buffer.isBuffer(oldSubjectBytes) && Buffer.isBuffer(parsedCsr.subject.bytes) && oldSubjectBytes.equals(parsedCsr.subject.bytes);
  if (!subjectMatches) throw E("est/reenroll-subject-mismatch", "a re-enroll CSR subject must be byte-identical to the certificate being renewed (RFC 7030 sec. 4.2.2)");
  var newSan = _san(_csrRequestedExtensions(parsedCsr));
  var sanMatches = (oldSan === null && newSan === null) ||
    (oldSan && newSan && oldSan.critical === newSan.critical && Buffer.isBuffer(oldSan.value) && Buffer.isBuffer(newSan.value) && oldSan.value.equals(newSan.value));
  if (!sanMatches) throw E("est/reenroll-san-mismatch", "a re-enroll CSR subjectAltName (names and criticality) must be identical to the certificate being renewed (RFC 7030 sec. 4.2.2)");
  return { subjectDn: oldSubjectDn, subjectAltName: oldSan };
}


var DEFAULT_TIMEOUT = constants.TIME.seconds(30);
var MAX_TIMEOUT = constants.TIME.seconds(600);

function _csrDer(input) {
  if (guard.bytes.isByteSource(input)) return guard.bytes.snapshotSource(input, EstError, "est/bad-input", "a CSR");
  if (typeof input === "string") return csr.pemDecode(input);
  throw E("est/bad-input", "a CSR must be a DER BufferSource or a PEM CERTIFICATE REQUEST string");
}

function _parseUrl(urlStr) {
  var url;
  try { url = new URL(String(urlStr)); }
  catch (e) { throw E("est/bad-url", "the EST server URL did not parse: " + String(urlStr), e); }
  if (url.protocol !== "https:") throw E("est/insecure-url", "EST requires https (RFC 7030 sec. 3.3), got " + url.protocol + " for " + urlStr);
  return url;
}

function _tlsForRequest(opts) {
  var t = opts.tls || {};
  return { anchors: t.anchors, useSystemStore: t.useSystemStore, cert: t.cert, key: t.key, minVersion: t.minVersion, servername: t.servername, checkServerIdentity: t.checkServerIdentity };
}

function _redirectTarget(current, location, method, opts) {
  if (location == null || String(location).trim() === "") throw E("est/http-error", "a redirect response carried no Location header");
  var resolved;
  try { resolved = new URL(String(location), current.href); }
  catch (e) { throw E("est/bad-url", "a redirect Location did not parse: " + location, e); }
  if (resolved.protocol !== "https:") throw E("est/insecure-redirect", "a redirect to a non-https URL is refused (RFC 7030 sec. 3.2.1): " + resolved.protocol);
  var safeMethod = method === "GET" || method === "HEAD";
  if (resolved.origin !== current.origin && !safeMethod && !opts.allowCrossOriginRedirect) {
    throw E("est/cross-origin-redirect", "a cross-origin redirect on a " + method + " needs opts.allowCrossOriginRedirect (RFC 7030 sec. 3.2.1)");
  }
  return resolved;
}

function _blankQuotedStrings(s) {
  var out = "", last = 0, i = 0, n = s.length;
  while (i < n) {
    if (_charCodeAt(s, i) === 0x22) {
      var j = i + 1, closed = -1;
      while (j < n) { var c = _charCodeAt(s, j); if (c === 0x5c) { j += 2; continue; } if (c === 0x22) { closed = j; break; } j += 1; }
      if (closed === -1) break;
      out += _strSlice(s, last, i) + "\"\"";
      last = closed + 1; i = closed + 1;
    } else i += 1;
  }
  return out + _strSlice(s, last, n);
}
function _schemeOffered(s, scheme) {
  var n = s.length, slen = scheme.length, p, k;
  for (p = 0; p <= n; p++) {
    if (p !== 0 && _charCodeAt(s, p - 1) !== 0x2c) continue;
    var q = p;
    while (q < n && pkix.isJsWhitespace(_charCodeAt(s, q))) q += 1;
    if (q + slen > n) continue;
    var ok = true;
    for (k = 0; k < slen; k++) {
      var x = _charCodeAt(s, q + k), y = _charCodeAt(scheme, k);
      if (x >= 65 && x <= 90) x += 32;
      if (y >= 65 && y <= 90) y += 32;
      if (x !== y) { ok = false; break; }
    }
    if (!ok) continue;
    var after = q + slen;
    if (after === n || pkix.isJsWhitespace(_charCodeAt(s, after)) || _charCodeAt(s, after) === 0x2c) return true;
  }
  return false;
}
function _offersScheme(www, scheme) {
  return _schemeOffered(_blankQuotedStrings(String(www || "")), scheme);
}
function _authScheme(opts) {
  if (opts.auth && opts.auth.scheme != null) {
    var sc = String(opts.auth.scheme).toLowerCase();
    if (sc !== "basic" && sc !== "digest") throw E("est/bad-input", "opts.auth.scheme must be \"basic\" or \"digest\"");
    return sc;
  }
  if (opts.username !== undefined || opts.password !== undefined) return "basic";
  return null;
}
function _authUser(opts) { return opts.auth && opts.auth.username !== undefined ? opts.auth.username : opts.username; }
function _authPass(opts) { return opts.auth && opts.auth.password !== undefined ? opts.auth.password : opts.password; }
function _hasCreds(opts) { return _authUser(opts) !== undefined || _authPass(opts) !== undefined; }
var DIGEST_CODES = { unsupportedAlgorithm: "est/digest-unsupported-algorithm", weakAlgorithm: "est/digest-weak-algorithm", noQop: "est/digest-no-qop", badChallenge: "est/digest-bad-challenge" };
function _digestPolicy(opts) { return { allowMD5: !!(opts.auth && opts.auth.allowMD5), allowLegacyQop: !!(opts.auth && opts.auth.allowLegacyQop), codes: DIGEST_CODES }; }

function _drive(method, url, body, headers, opts, transport, budgets) {
  var redirects = 0;
  var authTried = false;
  var staleRetries = 0;
  var authSpaces = 0;
  var lastDigestNonce = null;
  var initialOrigin = url.origin;
  function _tlsFor(u) {
    var t = budgets.tls;
    if (t && u.origin !== initialOrigin) {
      t = Object.assign({}, t);
      t.cert = null; t.key = null; t.servername = null;
    }
    return t;
  }
  var authValue = null;
  var digestChallenge = null;
  var digestNcByNonce = Object.create(null);
  var digestSent = false;
  function _headersFor(u) {
    digestSent = false;
    if (u.origin !== initialOrigin || (!authValue && !digestChallenge)) return headers;
    var hh = Object.assign({}, headers);
    if (digestChallenge) {
      if (!httpDigest.inProtectionSpace(digestChallenge, u.origin, u.pathname + u.search)) return headers;
      var nkey = digestChallenge.nonce;
      digestNcByNonce[nkey] = (digestNcByNonce[nkey] || 0) + 1;
      hh.authorization = httpDigest.answer(digestChallenge, { method: method, uri: u.pathname + u.search, username: _authUser(opts), password: _authPass(opts), body: body, nc: digestNcByNonce[nkey], policy: _digestPolicy(opts) }, E);
      digestSent = true;
    } else { hh.authorization = authValue; }
    return hh;
  }
  function step() {
    return transport({ method: method, url: url.href, headers: _headersFor(url), body: body, tls: _tlsFor(url), timeout: budgets.timeout, maxResponseBytes: budgets.maxResponseBytes }).then(function (res) {
      res = res || {};
      var blen = _bodyLen(res);
      if (blen > budgets.maxResponseBytes) throw E("est/response-too-large", "the response body (" + blen + " bytes) exceeds the " + budgets.maxResponseBytes + "-byte cap (RFC 7030 sec. 6)");
      var h = {
        location: _ciHeader(res.headers, "location"),
        "www-authenticate": _ciHeaderList(res.headers, "www-authenticate"),
      };
      var status = res.status;
      if (status >= 300 && status < 400) {
        if (redirects >= budgets.maxRedirects) throw E("est/too-many-redirects", "the redirect chain exceeded maxRedirects=" + budgets.maxRedirects + " (RFC 7030 sec. 3.2.1)");
        if (status === 303 && method !== "GET" && method !== "HEAD") {
          method = "GET";
          body = null;
          if (headers["content-type"]) { headers = Object.assign({}, headers); delete headers["content-type"]; }
        }
        url = _redirectTarget(url, h.location, method, opts);
        redirects += 1;
        return step();
      }
      if (status === 401) {
        if (url.origin !== initialOrigin) throw E("est/auth-required", "refusing to send HTTP credentials to a redirected origin (RFC 7030 sec. 3.6)");
        var www = String(h["www-authenticate"] || "");
        if (www.length > constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES) throw E("est/auth-required", "the WWW-Authenticate header exceeds the " + constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES + "-byte cap (RFC 7030 sec. 3.2.3)");
        var scheme = _authScheme(opts);
        if (scheme === null) throw E("est/auth-required", "the server requires HTTP authentication but no credentials were supplied (RFC 7030 sec. 3.2.3)");
        if (scheme === "digest") {
          if (!_offersScheme(www, "Digest")) throw E("est/auth-required", "opts.auth.scheme is \"digest\" but the server offered no Digest challenge: " + www);
          if (!_hasCreds(opts)) throw E("est/auth-required", "Digest authentication requires opts.auth.username / password (RFC 7030 sec. 3.2.3)");
          var selPol = _digestPolicy(opts);
          selPol.preferStale = digestSent;
          selPol.priorNonce = lastDigestNonce;
          selPol.priorRealm = digestChallenge && digestChallenge.realm;
          selPol.requestOrigin = url.origin;
          selPol.requestTarget = url.pathname + url.search;
          var ch = httpDigest.parseChallenge(www, E, "est/digest-bad-challenge", selPol);
          if (!ch) throw E("est/auth-required", "the server offered no usable Digest challenge: " + www);
          if (digestSent && digestChallenge && ch.realm === digestChallenge.realm) {
            if (!(ch.stale && ch.nonce !== lastDigestNonce && staleRetries < budgets.maxStaleRetries)) throw E("est/auth-required", "the server rejected the credentialed Digest request (RFC 7030 sec. 3.2.3)");
            staleRetries += 1;
          } else {
            if (authTried && authSpaces >= budgets.maxRedirects) throw E("est/auth-required", "the server demanded Digest authentication for too many distinct protection spaces (RFC 7616 sec. 3.3)");
            if (authTried) authSpaces += 1;
            authTried = true;
            staleRetries = 0;
          }
          lastDigestNonce = ch.nonce;
          digestChallenge = ch;
          return step();
        }
        if (authTried) throw E("est/auth-required", "the server rejected the credentialed request (RFC 7030 sec. 3.2.3)");
        if (!_offersScheme(www, "Basic")) throw E("est/auth-required", "the server requires an unsupported HTTP authentication scheme (only Basic and Digest are supported): " + www);
        if (!_hasCreds(opts)) throw E("est/auth-required", "the server requires HTTP authentication but no credentials were supplied (RFC 7030 sec. 3.2.3)");
        authValue = "Basic " + Buffer.from((_authUser(opts) || "") + ":" + (_authPass(opts) || ""), "utf8").toString("base64");
        authTried = true;
        return step();
      }
      return res;
    });
  }
  return step();
}

function _client(op, method, baseUrl, body, headers, opts) {
  var base;
  try { base = new URL(String(baseUrl)); }
  catch (e) { throw E("est/bad-url", "the EST base URL did not parse: " + String(baseUrl), e); }
  if (base.search || base.hash) throw E("est/bad-url", "the EST base URL must not carry a query or fragment component (RFC 7030 sec. 3.2.2)");
  var url = _parseUrl(paths(baseUrl, { label: opts.label })[op]);
  var transport = opts.transport;
  if (!transport) {
    var t = opts.tls || {};
    var hasAnchors = t.anchors !== undefined && t.anchors !== null && !(Array.isArray(t.anchors) && t.anchors.length === 0);
    if (!hasAnchors && t.useSystemStore !== true) throw E("est/no-trust-anchors", "no explicit trust anchor and tls.useSystemStore not set to true -- refusing an unpinned server (RFC 7030 sec. 3.6)");
    transport = httpTransport.https({ E: E, errPrefix: "est" });
  }
  var budgets = {
    tls: _tlsForRequest(opts),
    timeout: guard.limits.cap(opts.timeout, "timeout", DEFAULT_TIMEOUT, { E: E, code: "est/bad-input", min: 1, max: MAX_TIMEOUT }),
    maxResponseBytes: guard.limits.cap(opts.maxResponseBytes, "maxResponseBytes", constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, { E: E, code: "est/bad-input", min: 1, max: constants.LIMITS.HTTP_MAX_RESPONSE_BYTES }),
    maxRedirects: guard.limits.cap(opts.maxRedirects, "maxRedirects", 5, { E: E, code: "est/bad-input", min: 0, max: 32 }),
    maxStaleRetries: guard.limits.cap(opts.auth && opts.auth.maxStaleRetries, "maxStaleRetries", 1, { E: E, code: "est/bad-input", min: 0, max: 8 }),
  };
  _authScheme(opts);
  return _drive(method, url, body, Object.assign({}, headers), opts, transport, budgets);
}

function _certsResult(op, res, opts, csrSpki) {
  var verdict = classifyResponse(res.status, res.headers, res.body, { op: op, now: opts.now });
  if (verdict.status === "retry") {
    if (op === "cacerts") throw E("est/http-error", "a /cacerts response must be HTTP 200, not 202 (RFC 7030 sec. 4.1.3)");
    return { retry: true, retryAfterSeconds: verdict.retryAfterSeconds, retryAfterDate: verdict.retryAfterDate };
  }
  if (verdict.status !== "ok") throw E("est/http-error", "an EST " + op + " response must be HTTP 200 or 202 (RFC 7030 sec. 4.1.3 / 4.2.3), got " + res.status);
  var bodyLen = _bodyLen(res);
  if (bodyLen === 0) throw E("est/empty-body", "a 200 " + op + " response carried an empty body (RFC 7030 sec. 4.1.3 / 4.2.3)");
  var parsed = parseCertsOnly(transferDecode(res.body));
  if (op === "cacerts") return { certificates: parsed.certificates, crls: parsed.crls };
  var issued = findIssuedCert(parsed.certificates, csrSpki);
  if (!issued) throw E("est/issued-cert-not-found", "no returned certificate matched the submitted CSR public key (RFC 5272 sec. 4.1)");
  var chain = parsed.certificates.filter(function (c) { return c !== issued; });
  if (findIssuedCert(chain, csrSpki)) throw E("est/ambiguous-issued-cert", "the enroll response carried more than one certificate matching the submitted CSR public key; the issued certificate is ambiguous (RFC 5272 sec. 4.1)");
  if (opts.strict && chain.length > 0) throw E("est/unexpected-certs", "strict: the enroll response carried " + parsed.certificates.length + " certificates, expected exactly the issued one");
  return { certificate: issued, chain: chain, certificates: parsed.certificates };
}


/**
 * @primitive  pki.est.fullcmc
 * @signature  pki.est.fullcmc(baseUrl, request, opts?) -> Promise<verdict | { retry, retryAfterSeconds }>
 * @since      0.4.16
 * @status     stable
 * @spec       RFC 7030, RFC 8951, RFC 5273, RFC 5272
 * @related    pki.cmc.build, pki.cmc.verify, pki.est.simpleenroll
 *
 * Enroll through the full CMC message layer: POST a Full PKI Request (from `pki.cmc.build`, as a
 * DER Buffer or a PEM `CMS` block) to `<baseUrl>/.well-known/est/fullcmc` as
 * `application/pkcs7-mime; smime-type=CMC-request`, base64 per RFC 8951, over the shared
 * `pki.transport`.
 *
 * A 200 answers with either `smime-type=certs-only` (a Simple PKI Response) or
 * `smime-type=CMC-response` (a Full PKI Response). RFC 7030 sec. 4.3.2 names both, and the label
 * must agree with the bytes. Either way the result is the `pki.cmc.verify` verdict shape, so a
 * caller reads one `outcome` (`issued` / `pending` / `confirm-required` / `pop-required` /
 * `rejected`) regardless of which arm the server chose.
 *
 * The exchange binding is read out of the request itself, never taken on the caller's word: whatever
 * Transaction Identifier, Sender Nonce or Data Return the submitted bytes carry is what the response
 * must echo, and `transactionId` / `senderNonce` / `dataReturn` are a cross-check that is refused if
 * it disagrees. A request that carries none of the three leaves nothing for the response to echo, so
 * the answer is refused instead of being accepted as an enrollment result that could be a replay of
 * any earlier exchange. The code is `cmc/unbound-response` on the `CMC-response` arm, which the CMC
 * layer interprets, and `est/unbound-response` on the `certs-only` arm, which this verb owns. Build
 * the request with a `senderNonce` (`pki.cmc.build`) to bind it, or pass `allowUnboundResponse: true` to
 * accept that it is unbound. The verdict reports which halves ran as `bound` and `boundToRequest`.
 *
 * A 404 **or** a 501 is the distinct `est/not-implemented` verdict, since support for this verb is
 * optional on both sides (sec. 4.3). A 202 surfaces its Retry-After and does not sleep. A
 * rejection carries a CMC response (sec. 4.3.2 makes it a MUST), which is decoded and attached to
 * a typed `est/cmc-failed` as `err.cmc` and `err.httpStatus`, while a body that cannot be read
 * never masks the HTTP fault it arrived with.
 *
 * On the `certs-only` arm the issued certificates are identified by public-key match against the
 * requests that were submitted, the only identification RFC 5272 sec. 4.1 sanctions, since "the
 * certificates are in any order". Every certification request in the message must be answered
 * before the exchange reads as `issued`: a key wanted by N requests needs N certificates, so a
 * bag that answers only some of them, or none, is a refusal and not a partial success. That arm
 * carries no controls, so it cannot echo a Transaction Identifier, Sender Nonce or Data Return: a
 * request that sent those asked for replay binding it cannot provide (the key match is not one,
 * since an old response for the same key still matches), and it is refused as
 * `est/unbound-response`, never accepted with silently none of what was asked for. A request
 * that asked for no binding reaches the same refusal on this arm, for the same reason: nothing here
 * can tie the bag to the exchange, so `allowUnboundResponse: true` is what accepts it. They are
 * surfaced as `issuedCertificates` (with `certificate` the first), distinct from `certificates`,
 * which is the whole returned bag including any chain. Where the requested keys are distinct that
 * list is in request order; where several requests deliberately SHARE one key it is not, and does
 * not claim to be -- the public key is the only identification sec. 4.1 sanctions, so when it is
 * shared nothing in the response says which of those requests a given certificate answers. That arm reports `signatureVerified: false`: a certs-only body is
 * a degenerate SignedData with no signers by definition, so its security rests on the authenticated
 * TLS channel, not on a signature.
 *
 * Every EST transport gate holds unchanged, including on a bootstrap enrollment: https-only, an
 * explicit trust anchor required, redirect and size bounds. A Publish Trust Anchors control in the
 * response is SURFACED, never acted on (RFC 5272 sec. 6.15 makes accepting one a manual decision).
 *
 * @opts
 *   - `transport` / `tls` / `label` / `timeout` / `maxResponseBytes` / `maxRedirects` / `now`, as in pki.est.cacerts.
 *   - `transactionId` / `senderNonce` / `dataReturn`: what the request sent. The values are read out
 *     of the request itself; supplying them here cross-checks that, and a disagreement is refused.
 *   - `responderCerts`: extra certificates for CMC signer lookup, for a response that does not carry
 *     its own signer; the certificates the response carries are searched either way. The carrier's
 *     signature MUST be verified (RFC 5272 sec. 3.2.1.3.4), so a `CMC-response` whose signer is found
 *     nowhere and which does not name the opt-out below is refused.
 *   - `responseRecipient` -- key material for a response carried in AuthenticatedData, in the shape
 *     `pki.cms.decrypt` takes. Its MAC is then checked and the verdict reports
 *     `signatureVerified: true`, so the carrier is not reachable only unauthenticated.
 *   - `allowUnverifiedResponse` -- accept a `CMC-response` whose signer certificate cannot be found,
 *     without checking its signature; the verdict then reports `signatureVerified: false`. For an
 *     unauthenticated bootstrap only, and it never excuses a signature that is present and wrong.
 *   - `allowUnboundResponse` -- accept an answer to a request that carried no Transaction Identifier,
 *     Sender Nonce or Data Return, so nothing ties it to this exchange; the verdict then reports
 *     `boundToRequest: false`. A separate question from the one above, because a replayed response
 *     is authentic, so naming one does not name the other.
 *   - `username` / `password` / `allowCrossOriginRedirect` -- as pki.est.simpleenroll.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var spki = await pki.key.export(pair.publicKey);
 *   var cert = await pki.x509.sign({ subject: "device.example", subjectPublicKey: spki,
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var csr = await pki.csr.sign({ subject: "device.example", subjectPublicKey: spki }, { key: key });
 *   var request = await pki.cmc.build({ requests: [{ tcr: csr }] }, { cert: cert, key: key });
 *   // a 202 means the CA queued the request -- the verb surfaces the delay, never sleeps
 *   var r = await pki.est.fullcmc("https://ca.example", request,
 *     { transport: function () { return Promise.resolve({ status: 202, headers: { "retry-after": "60" }, body: "" }); } });
 *   r.retry && r.retryAfterSeconds;   // 60
 */
function fullcmc(baseUrl, request, opts) {
  opts = opts || {};
  var der, wanted, sent;
  try {
    if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw E("est/bad-input", "pki.est.fullcmc options must be an object");
    _knownOpts(opts, FULLCMC_OPTS, "fullcmc");
    der = _cmcRequestDer(request);
    wanted = _requestedPublicKeys(der);
    sent = _cmcSent(opts, der);
    opts = _shallowCopy(opts);
    var body = transferEncode(der);
    return _client("fullcmc", "POST", baseUrl, body,
      { accept: "application/pkcs7-mime", "content-type": "application/pkcs7-mime; smime-type=CMC-request" }, opts)
      .then(function (res) { return _fullcmcResult(res, opts, wanted, sent); });
  } catch (e) {
    return Promise.reject(e);
  }
}


function _correlateIssued(bag, wanted, arm) {
  if (!wanted.length) {
    throw E("est/no-issued-cert",
      "this /fullcmc request declared no certification request whose key a returned certificate could be " +
      "matched against, so a " + arm + " response cannot be read as an issuance (RFC 5272 sec. 4.1)");
  }
  var byKey = {};
  wanted.forEach(function (k) {
    var hex = k.toString("hex");
    if (!byKey[hex]) byKey[hex] = { key: k, want: 0, have: null };
    byKey[hex].want += 1;
  });
  Object.keys(byKey).forEach(function (hex) {
    var e = byKey[hex];
    e.have = _allMatching(bag || [], e.key);
    if (e.have.length < e.want) {
      throw E("est/no-issued-cert",
        "the /fullcmc " + arm + " response carried " + e.have.length + " certificate(s) for a public key " +
        e.want + " certification request(s) asked to have certified, so it does not answer this request " +
        "(RFC 5272 sec. 4.1)");
    }
    if (e.have.length > e.want) {
      throw E("est/ambiguous-issued-cert",
        "the /fullcmc response carried more certificates matching a submitted request key than there were " +
        "requests for it; the issued certificate is ambiguous (RFC 5272 sec. 4.1)");
    }
  });
  return wanted.map(function (k) { return byKey[k.toString("hex")].have.shift(); });
}

function _allMatching(bag, key) {
  var rest = bag.slice(), out = [], hit;
  while ((hit = findIssuedCert(rest, key)) !== null) {
    out.push(hit);
    rest = rest.filter(function (c) { return c !== hit; });
  }
  return out;
}

function _requestedPublicKeys(der) {
  var out = [], body;
  try { body = cmcFmt.parse(der); }
  catch (e) {
    throw E("est/bad-input",
      "pki.est.fullcmc requires a Full PKI Request (id-cct-PKIData); this input did not parse as one", e);
  }
  if (body.kind !== "pkiData") {
    throw E("est/bad-input",
      "pki.est.fullcmc sends a Full PKI Request (id-cct-PKIData); this input is a " + body.kind);
  }
  (body.requests || []).forEach(function (r) {
    var before = out.length;
    var keyBearing = !!(r.certificationRequestBytes || r.certReqMsgBytes);
    try {
      if (r.certificationRequestBytes) {
        var spki = csr.parse(r.certificationRequestBytes).subjectPublicKeyInfo;
        if (spki && Buffer.isBuffer(spki.bytes)) out.push(spki.bytes);
        if (out.length === before) _unreadableArm();
        return;
      }
      if (r.certReqMsgBytes) {
        var msgs = crmfFmt.parse(asn1.build.sequence([r.certReqMsgBytes])).messages;
        var msg0 = msgs && msgs[0];
        var tmpl = msg0 && msg0.certReq && msg0.certReq.certTemplate;
        var pk = (tmpl && tmpl.publicKey) ||
          (msg0 && msg0.popo && msg0.popo.poposkInput && msg0.popo.poposkInput.publicKey);
        var pkBytes = Buffer.isBuffer(pk) ? pk : (pk && pk.bytes);
        if (Buffer.isBuffer(pkBytes)) out.push(pkBytes);
        if (out.length === before) _unreadableArm();
      }
    } catch (e) {
      if (!keyBearing) return;
      throw (e && e.code === "est/bad-input") ? e : E("est/bad-input",
        "a certification request in this Full PKI Request could not be read, so a response could not be " +
        "tied back to it; pki.est.fullcmc will not send a request it cannot check the answer to", e);
    }
  });
  return out;
}

function _unreadableArm() {
  throw E("est/bad-input", "a certification request in this Full PKI Request declares no readable public key");
}

function _cmcSent(opts, der) {
  var carried = _requestBinding(der);
  _assertAgrees("transactionId", opts.transactionId, carried.transactionId);
  _assertAgrees("senderNonce", opts.senderNonce, carried.senderNonce);
  _assertAgrees("dataReturn", opts.dataReturn, carried.dataReturn);
  return {
    transactionId: carried.transactionId,
    senderNonce: _copyBytes(carried.senderNonce),
    dataReturn: _copyBytes(carried.dataReturn),
    bodyPartIDs: carried.bodyPartIDs,
    bodyPartPaths: carried.bodyPartPaths,
    certs: Array.isArray(opts.responderCerts) ? opts.responderCerts.map(_copyBytes) : opts.responderCerts,
    recipient: _copyRecipient(opts.responseRecipient),
    allowUnverified: opts.allowUnverifiedResponse === true,
    allowUnbound: opts.allowUnboundResponse === true,
  };
}

function _copyBytes(v) {
  if (!guard.bytes.isByteSource(v)) return v;
  return guard.bytes.snapshotSource(v, EstError, "est/bad-input", "a byte field of the request");
}

function _requestBinding(der) {
  var out = { transactionId: undefined, senderNonce: undefined, dataReturn: undefined, bodyPartIDs: undefined,
    bodyPartPaths: undefined };
  var body = cmcFmt.parse(der);
  var ids = [];
  var paths = [];
  [body.requests, body.controls, body.cmsSequence, body.otherMsgs].forEach(function (list) {
    (list || []).forEach(function (el) {
      if (el && el.bodyPartID != null) { ids.push(el.bodyPartID); paths.push([el.bodyPartID]); }
    });
  });
  _collectNestedPaths(body.cmsSequence, [], paths, 0);
  out.bodyPartIDs = ids;
  out.bodyPartPaths = paths;
  (body.controls || []).forEach(function (c) {
    var field = c.attrType === OID_CMC_TRANSACTION_ID ? "transactionId"
      : c.attrType === OID_CMC_SENDER_NONCE ? "senderNonce"
        : c.attrType === OID_CMC_DATA_RETURN ? "dataReturn" : null;
    if (!field) return;
    if (out[field] !== undefined) {
      throw E("est/bad-input",
        "the Full PKI Request carries more than one " + field + " control, so there is no single value " +
        "the response can be bound to (RFC 5272 sec. 6.6 / 6.4)");
    }
    var v = c.values && c.values.length === 1 ? c.values[0] : null;
    if (!v) {
      throw E("est/bad-input",
        "the Full PKI Request's " + field + " control must carry exactly one value (RFC 5272 sec. 6.6 / 6.4)");
    }
    try {
      out[field] = field === "transactionId"
        ? asn1.read.integer(asn1.decode(v))
        : asn1.read.octetString(asn1.decode(v));
    } catch (e) {
      throw E("est/bad-input",
        "the Full PKI Request's " + field + " control could not be read, so the response could not be " +
        "checked against it; a request is not sent under a binding that cannot be enforced", e);
    }
  });
  return out;
}

var NESTED_PATH_DEPTH_CAP = 8;
function _collectNestedPaths(list, prefix, out, depth) {
  if (depth >= NESTED_PATH_DEPTH_CAP) return;
  (list || []).forEach(function (el) {
    if (!el || el.bodyPartID == null || !el.contentInfoBytes) return;
    var inner;
    try { inner = cmcFmt.parse(el.contentInfoBytes); }
    catch (_e) { /* allow:swallow-unverified the outer request must itself parse for this to run, which already rejects a malformed nested ContentInfo; a payload that survives that and still fails to read back lands on the same no-path refusal the non-pkiData route below takes, which the vectors drive */ return; }
    if (!inner || inner.kind !== "pkiData") return;
    var path = prefix.concat([el.bodyPartID]);
    [inner.requests, inner.controls, inner.cmsSequence, inner.otherMsgs].forEach(function (l) {
      (l || []).forEach(function (e2) { if (e2 && e2.bodyPartID != null) out.push(path.concat([e2.bodyPartID])); });
    });
    _collectNestedPaths(inner.cmsSequence, path, out, depth + 1);
  });
}

function _assertAgrees(name, supplied, carried) {
  if (supplied == null) return;
  var same;
  if (guard.bytes.isByteSource(supplied)) {
    same = Buffer.isBuffer(carried) && guard.bytes.source(supplied, EstError, "est/bad-input", "opts.senderNonce").equals(carried);
  } else {
    same = carried != null &&
      guard.range.authoredInteger(supplied, E, "est/bad-input", "opts." + name) === BigInt(carried);
  }
  if (!same) {
    throw E("est/bad-input",
      "opts." + name + " does not match the " + name + " control the Full PKI Request carries; the " +
      "response is checked against what was sent, so the two must agree (RFC 5272 sec. 6.6 / 6.4)");
  }
}

function _copyRecipient(r) {
  if (!r || typeof r !== "object") return r;
  var out = {}, k;
  for (k in r) { if (_hasOwn(r, k)) out[k] = _copyBytes(r[k]); }
  return out;
}

function _shallowCopy(o) {
  var out = {}, k;
  for (k in o) { if (_hasOwn(o, k)) out[k] = o[k]; }
  if (out.auth && typeof out.auth === "object") {
    var a = {}, ak;
    for (ak in out.auth) { if (_hasOwn(out.auth, ak)) a[ak] = out.auth[ak]; }
    out.auth = a;
  }
  return out;
}

function _cmcRequestDer(request) {
  if (guard.bytes.isByteSource(request)) {
    return guard.bytes.snapshotSource(request, EstError, "est/bad-input", "the Full PKI Request");
  }
  if (typeof request === "string") return cms.pemDecode(request);
  throw E("est/bad-input", "pki.est.fullcmc requires the Full PKI Request as DER bytes or a PEM CMS block");
}

function _fullcmcResult(res, opts, wanted, sent) {
  var verdict;
  try {
    verdict = classifyResponse(res.status, res.headers, res.body, { op: "fullcmc", now: opts.now });
  } catch (httpFault) {
    if (!(res.status >= 400 && res.status <= 599)) throw httpFault;
    return _tryDecodeCmcFault(res, sent).then(function (cmcErr) { throw cmcErr || httpFault; });
  }

  if (verdict.status === "not-implemented") {
    throw E("est/not-implemented",
      "the EST server does not implement /fullcmc (HTTP " + verdict.httpStatus + "; RFC 7030 sec. 4.3.2)");
  }
  if (verdict.status === "retry") {
    return { retry: true, retryAfterSeconds: verdict.retryAfterSeconds, retryAfterDate: verdict.retryAfterDate };
  }
  if (verdict.status !== "ok") {
    throw E("est/http-error",
      "an EST /fullcmc response must be HTTP 200 or 202 (RFC 7030 sec. 4.3.2), got " + res.status);
  }

  var bodyLen = _bodyLen(res);
  if (bodyLen === 0) throw E("est/empty-body", "a 200 /fullcmc response carried an empty body (RFC 7030 sec. 4.3.2)");
  var der = transferDecode(res.body);

  var pt200 = _partMediaType(_ciHeader(res.headers, "content-type"));
  if (pt200.ambiguous) {
    throw E("est/bad-content-type",
      "the 200 /fullcmc Content-Type declares more than one smime-type, so which response arm this is " +
      "cannot be told from it (RFC 7030 sec. 4.3.2)");
  }
  var smimeType = pt200.smimeType;
  if (smimeType === "certs-only") {
    var unecho = ["transactionId", "senderNonce", "dataReturn"].filter(function (k) {
      return sent[k] != null;
    });
    if (unecho.length) {
      throw E("est/unbound-response",
        "the request carried " + unecho.join(" / ") + ", which a certs-only response has no controls to " +
        "echo, so the replay binding it asked for cannot be checked (RFC 5272 sec. 6.6 / 6.4)");
    }
    if (sent.allowUnbound !== true) {
      throw E("est/unbound-response",
        "nothing ties this certs-only response to the request just sent: a certs-only body carries no " +
        "controls at all, so build the request with a `senderNonce` (pki.cmc.build) and use a server that " +
        "answers with a CMC-response, or pass `allowUnboundResponse: true` to accept a bag of certificates " +
        "that could answer any earlier request for the same key (RFC 5272 sec. 6.6)");
    }
    var certs = parseCertsOnly(der);
    var issuedCerts = _correlateIssued(certs.certificates, wanted, "certs-only");
    var issued = issuedCerts[0];
    return { outcome: "issued", certificate: issued, issuedCertificates: issuedCerts,
      certificates: certs.certificates, crls: certs.crls,
      controls: [], statuses: [], publishTrustAnchors: null, trusted: false,
      signatureVerified: false,
      bound: { transactionId: false, senderNonce: false, dataReturn: false, bodyPartIDs: false },
      boundToRequest: false };
  }
  return cmcVerify.verify(der, sent).then(function (verdict) {
    if (verdict.outcome !== "issued") return verdict;
    if (!wanted.length) { verdict.issuedCertificates = []; return verdict; }
    var issuedCerts = _correlateIssued(verdict.certificates, wanted, "CMC-response");
    verdict.certificate = issuedCerts[0];
    verdict.issuedCertificates = issuedCerts;
    return verdict;
  });
}

function _tryDecodeCmcFault(res, sent) {
  return Promise.resolve().then(function () {
    var pt = _partMediaType(_ciHeader(res.headers, "content-type"));
    if (pt.media !== "application/pkcs7-mime") return null;
    if (pt.ambiguous) return null;
    if (String(pt.smimeType || "").toLowerCase() !== "cmc-response") return null;
    return cmcVerify.verify(transferDecode(res.body), sent).then(function (verdict) {
      if (verdict.outcome !== "rejected") return null;
      var e = E("est/cmc-failed",
        "the EST server rejected the Full PKI Request: " + verdict.outcome +
        (verdict.failInfo ? " (" + verdict.failInfo + ")" : "") + " [HTTP " + res.status + "]");
      e.cmc = verdict;
      e.httpStatus = res.status;
      return e;
    });
  }).then(null, function () { return null; });
}

function _enroll(op, baseUrl, csrInput, opts) {
  var csrDer = _csrDer(csrInput);
  var spki = csr.parse(csrDer).subjectPublicKeyInfo;
  var body = transferEncode(csrDer);
  return _client(op, "POST", baseUrl, body, { accept: "application/pkcs7-mime", "content-type": "application/pkcs10" }, opts)
    .then(function (res) { return _certsResult(op, res, opts, spki); });
}

/**
 * @primitive  pki.est.cacerts
 * @signature  pki.est.cacerts(baseUrl, opts?) -> Promise<{ certificates, crls } | { retry, retryAfterSeconds }>
 * @since      0.3.16
 * @status     stable
 * @spec       RFC 7030, RFC 8951
 * @related    pki.est.simpleenroll, pki.transport.https
 *
 * Fetch a CA's certificates over the wire: GET `<baseUrl>/.well-known/est/cacerts` through
 * the shared `pki.transport` (inject `opts.transport`, else a fail-closed
 * `pki.transport.https`). Returns the raw, unordered certs-only set
 * (`{ certificates, crls }`), or `{ retry: true, retryAfterSeconds }` on a 202 (surfaced,
 * never slept). https-only (`est/insecure-url`); an explicit `opts.tls.anchors` (or an
 * `opts.tls.useSystemStore` opt-in) is required (`est/no-trust-anchors`); the returned CA
 * certificate is not auto-trusted: the caller path-validates it and supplies the accepted
 * anchor on the next call.
 *
 * @opts
 *   - `transport`: an injected transport(request) -> {status, headers, body, tls}; default pki.transport.https.
 *   - `tls` -- { anchors, useSystemStore, cert, key, minVersion, servername, checkServerIdentity }.
 *   - `label` -- an OPTIONAL CA label path segment; `timeout` / `maxResponseBytes` / `maxRedirects` -- budgets.
 *   - `now` -- receipt time (epoch ms) to render a 202 Retry-After HTTP-date as seconds.
 *   - `auth` -- HTTP authentication: `{ scheme: "basic" | "digest", username, password, allowMD5, allowLegacyQop, maxStaleRetries }`.
 *     There is no `"auto"`: the scheme is chosen here, not by whatever a server offers. `username` / `password`
 *     at the top level are the older form and mean Basic. Answered only after the transport authenticated the server.
 *   - `allowCrossOriginRedirect` -- opt in to following a cross-origin redirect on an unsafe method.
 * @example
 *   // a live CA uses the default pki.transport.https; here an injected transport returns a canned bag
 *   var r = await pki.est.cacerts("https://ca.example",
 *     { transport: function () { return Promise.resolve({ status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: caCertsDer.toString("base64") }); } });
 *   r.certificates;   // -> [Buffer, ...] raw, unordered
 */
function cacerts(baseUrl, opts) {
  opts = opts || {};
  return Promise.resolve().then(function () {
    _knownOpts(opts, CACERTS_OPTS, "cacerts");
    return _client("cacerts", "GET", baseUrl, null, { accept: "application/pkcs7-mime" }, opts);
  }).then(function (res) { return _certsResult("cacerts", res, opts, null); });
}

/**
 * @primitive  pki.est.simpleenroll
 * @signature  pki.est.simpleenroll(baseUrl, csr, opts?) -> Promise<{ certificate, chain, certificates } | { retry, retryAfterSeconds }>
 * @since      0.3.16
 * @status     stable
 * @spec       RFC 7030, RFC 5272
 * @related    pki.csr.sign, pki.est.simplereenroll, pki.est.cacerts
 *
 * Enroll for a certificate: POST a PKCS#10 `csr` (a DER Buffer or a PEM CERTIFICATE REQUEST,
 * e.g. from `pki.csr.sign`) to `<baseUrl>/.well-known/est/simpleenroll` as
 * `application/pkcs10`, over the shared `pki.transport`. Returns the issued certificate
 * chosen by public-key match against the submitted CSR (`certificate`), the remaining
 * certificates (`chain`), and the raw set (`certificates`); or `{ retry: true,
 * retryAfterSeconds }` on a 202. No returned certificate matching the CSR key fails closed
 * (`est/issued-cert-not-found`); `opts.strict` requires exactly the issued certificate. A
 * 401 is answered once with HTTP Basic only when `opts.username`/`password` are supplied and
 * the transport already authenticated the server.
 *
 * @opts
 *   - `transport` / `tls` / `label` / `timeout` / `maxResponseBytes` / `maxRedirects` / `now`, as in pki.est.cacerts.
 *   - `strict`: reject an enroll response that carries more than the single issued certificate.
 *   - `username` / `password` -- HTTP Basic credentials, answered only after server authorization (empty username allowed).
 *   - `allowCrossOriginRedirect` -- opt in to following a cross-origin redirect on this POST.
 * @example
 *   var req = await pki.csr.sign({ subject: "device.example", subjectPublicKey: signerSpki }, { key: signerKeyPkcs8 });
 *   // a 202 means the CA queued the request -- the verb surfaces the delay, never sleeps
 *   var r = await pki.est.simpleenroll("https://ca.example", req,
 *     { transport: function () { return Promise.resolve({ status: 202, headers: { "retry-after": "60" }, body: "" }); } });
 *   r.retry && r.retryAfterSeconds;   // 60
 */
function simpleenroll(baseUrl, csrInput, opts) {
  opts = opts || {};
  return Promise.resolve().then(function () {
    _knownOpts(opts, SIMPLEENROLL_OPTS, "simpleenroll");
    return _enroll("simpleenroll", baseUrl, csrInput, opts);
  });
}

/**
 * @primitive  pki.est.simplereenroll
 * @signature  pki.est.simplereenroll(baseUrl, csr, opts?) -> Promise<{ certificate, chain, certificates } | { retry, retryAfterSeconds }>
 * @since      0.3.16
 * @status     stable
 * @spec       RFC 7030
 * @related    pki.est.simpleenroll, pki.est.reenrollGuard
 *
 * Renew / rekey a certificate: identical to `pki.est.simpleenroll` but POSTs to
 * `/.well-known/est/simplereenroll` and REQUIRES `opts.oldCert` (the certificate being
 * renewed). Before anything crosses the wire, `reenrollGuard` enforces that the CSR's
 * Subject and SubjectAltName (names and criticality) are byte-identical to `opts.oldCert`
 * (RFC 7030 sec. 4.2.2). A mismatch fails closed (`est/reenroll-subject-mismatch` /
 * `est/reenroll-san-mismatch`) and the transport is never called. A missing `opts.oldCert`
 * is `est/bad-input`.
 *
 * @opts
 *   - `oldCert` -- REQUIRED, the DER certificate being renewed (the re-enroll identity check).
 *   - every option of pki.est.simpleenroll (transport, tls, label, budgets, strict, credentials).
 * @example
 *   // reenrollGuard enforces the RFC 7030 sec. 4.2.2 identity check before anything is sent
 *   var r = await pki.est.simplereenroll("https://ca.example", renewCsr,
 *     { oldCert: signerCertDer, transport: function () { return Promise.resolve({ status: 202, headers: { "retry-after": "60" }, body: "" }); } });
 *   r.retry;   // true
 */
function simplereenroll(baseUrl, csrInput, opts) {
  opts = opts || {};
  return Promise.resolve().then(function () {
    _knownOpts(opts, SIMPLEREENROLL_OPTS, "simplereenroll");
    if (!opts.oldCert) throw E("est/bad-input", "simplereenroll requires opts.oldCert (the certificate being renewed, RFC 7030 sec. 4.2.2)");
    reenrollGuard(opts.oldCert, _csrDer(csrInput));
    return _enroll("simplereenroll", baseUrl, csrInput, opts);
  });
}


function _serverkeygenEncryptionFromCsr(csrDer) {
  var attrs = csr.parse(csrDer).attributes || [];
  var keyId = null, kind = null;
  for (var i = 0; i < attrs.length; i++) {
    if (attrs[i].type !== OID_DECRYPT_KEY_ID && attrs[i].type !== OID_ASYMM_DECRYPT_KEY_ID) continue;
    var thisKind = attrs[i].type === OID_ASYMM_DECRYPT_KEY_ID ? "asymmetric" : "symmetric";
    var vals = attrs[i].values || [];
    if (vals.length !== 1) throw E("est/bad-input", "a serverkeygen key-identifier attribute must carry exactly one value (RFC 7030 sec. 4.4.1)");
    var id;
    try { id = asn1.read.octetString(asn1.decode(vals[0])); }
    catch (e) { throw E("est/bad-input", "a serverkeygen key-identifier attribute value is not a valid OCTET STRING", e); }
    if (keyId !== null && !keyId.equals(id)) throw E("est/bad-input", "the CSR advertised two different serverkeygen key identifiers (RFC 7030 sec. 4.4.1)");
    if (kind !== null && kind !== thisKind) throw E("est/bad-input", "the CSR advertised both a symmetric (DecryptKeyIdentifier) and an asymmetric (AsymmetricDecryptKeyIdentifier) serverkeygen key -- the recipient mechanism is ambiguous (RFC 7030 sec. 4.4.1)");
    keyId = id; kind = thisKind;
  }
  return { requestedEncryption: keyId !== null, expectedRecipientKeyId: keyId, expectedRecipientKind: kind };
}

function _isWordChar(c) { return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95; }
function _subAt(s, sub, i) { var m = sub.length; if (i + m > s.length) return false; for (var k = 0; k < m; k++) { if (_charCodeAt(s, i + k) !== _charCodeAt(sub, k)) return false; } return true; }
function _containsSub(s, sub) { for (var i = 0; i + sub.length <= s.length; i++) { if (_subAt(s, sub, i)) return true; } return false; }
function _wbBefore(s, i) { return i === 0 || !_isWordChar(_charCodeAt(s, i - 1)); }
function _wbAfter(s, j) { return j === s.length || !_isWordChar(_charCodeAt(s, j)); }
function _hasWeakCipherToken(name) {
  if (_containsSub(name, "NULL") || _containsSub(name, "ANON") || _containsSub(name, "EXPORT")) return true;
  var i, n = name.length;
  for (i = 0; i + 3 <= n; i++) {
    if (_subAt(name, "EXP", i) && _wbBefore(name, i)) {
      var c = _charCodeAt(name, i + 3);
      if (c === 45 || c === 95 || (c >= 48 && c <= 57)) return true;
    }
  }
  for (i = 0; i < n; i++) {
    if (_subAt(name, "ADH", i) && _wbBefore(name, i) && _wbAfter(name, i + 3)) return true;
    if (_subAt(name, "AECDH", i) && _wbBefore(name, i) && _wbAfter(name, i + 5)) return true;
  }
  return false;
}
function _assertConfidentialCipher(res) {
  if (!res || !res.tls || !res.tls.cipher) return;
  var c = res.tls.cipher;
  var name = (String(c.name || "") + " " + String(c.standardName || "")).toUpperCase();
  if (_hasWeakCipherToken(name)) throw E("est/weak-cipher", "the serverkeygen channel negotiated a NULL / anonymous / EXPORT cipher (" + (c.standardName || c.name) + "), which cannot protect the delivered private key (RFC 7030 sec. 4.4)");
}

function _ciHeaderList(headers, name) {
  headers = headers || {};
  var lname = name.toLowerCase(), keys = Object.keys(headers), parts = [];
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() !== lname) continue;
    var v = headers[keys[i]];
    if (v == null) continue;
    parts.push(Array.isArray(v) ? v.join(", ") : String(v));
  }
  return parts.length ? parts.join(", ") : null;
}

function _ciHeader(headers, name) {
  headers = headers || {};
  var lname = name.toLowerCase(), keys = Object.keys(headers), found = null, n = 0;
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() !== lname) continue;
    n += 1;
    if (n === 1) found = headers[keys[i]];
  }
  if (n > 1) {
    throw E("est/bad-content-type",
      "the response carries more than one " + lname + " header field, so what the body is cannot be told " +
      "from it (RFC 9110 sec. 5.1: field names are case-insensitive)");
  }
  return n === 0 ? null : found;
}

async function _serverkeygenResult(res, opts, derived) {
  var verdict = classifyResponse(res.status, res.headers, res.body, { op: "serverkeygen", now: opts.now });
  if (verdict.status === "retry") return { retry: true, retryAfterSeconds: verdict.retryAfterSeconds, retryAfterDate: verdict.retryAfterDate };
  if (verdict.status !== "ok") throw E("est/http-error", "an EST serverkeygen response must be HTTP 200 or 202 (RFC 7030 sec. 4.4.2), got " + res.status);
  var bodyLen = _bodyLen(res);
  if (bodyLen === 0) throw E("est/empty-body", "a 200 serverkeygen response carried an empty body (RFC 7030 sec. 4.4.2)");
  _assertConfidentialCipher(res);
  var out = parseServerKeygenResponse(res.body, _ciHeader(res.headers, "content-type"), {
    requestedEncryption: derived.requestedEncryption,
    expectedRecipientKeyId: derived.expectedRecipientKeyId,
    expectedRecipientKind: derived.expectedRecipientKind,
    expectedRecipientIssuerSerial: opts.expectedRecipientIssuerSerial,
  });
  if (out.privateKeyDer) {
    var spki;
    try { spki = await key.publicFromPrivate(out.privateKeyDer); }
    catch (e) { throw E("est/key-cert-mismatch", "the cleartext server-generated private key's public half could not be derived to bind it to a returned certificate (RFC 7030 sec. 4.4.2)", e); }
    var bound = findIssuedCert(out.certificates, spki);
    if (!bound) throw E("est/key-cert-mismatch", "the cleartext server-generated private key matches no returned certificate's public key (RFC 7030 sec. 4.4.2)");
    if (findIssuedCert(out.certificates.filter(function (c) { return c !== bound; }), spki)) throw E("est/ambiguous-issued-cert", "more than one returned certificate carries the server-generated key; the issued certificate is ambiguous (RFC 7030 sec. 4.4.2)");
    delete out.privateKeyDer;
  }
  return out;
}

/**
 * @primitive  pki.est.serverkeygen
 * @signature  pki.est.serverkeygen(baseUrl, csr, opts?) -> Promise<{ certificates, privateKey } | { certificates, encryptedKey } | { retry, retryAfterSeconds, retryAfterDate }>
 * @since      0.3.28
 * @status     stable
 * @spec       RFC 7030, RFC 8951
 * @related    pki.est.simpleenroll, pki.est.parseServerKeygenResponse
 *
 * Request a SERVER-GENERATED key pair + certificate: POST the CSR (base64 DER, `Content-Type:
 * application/pkcs10`, identical request encoding to `simpleenroll`) to
 * `<baseUrl>/.well-known/est/serverkeygen`. The two-part `multipart/mixed` response is surfaced as
 * `{ certificates, privateKey }` (a cleartext PKCS#8 `PrivateKeyInfo`) or `{ certificates,
 * encryptedKey }` (the CMS `EnvelopedData` the caller decrypts out-of-band with its key-encryption key;
 * the verb never decrypts, so it is not a decryption oracle), or `{ retry, retryAfterSeconds }` on a 202.
 * The certificates are raw and unordered: unlike `simpleenroll` no leaf is picked, because the CA generated
 * the key so the issued certificate's public key is the generated one, not the throwaway CSR key. A cleartext
 * key is bound to its certificate before it resolves: the delivered private key's public half MUST match
 * exactly one returned certificate (`est/key-cert-mismatch` on none, `est/ambiguous-issued-cert` on more than
 * one), so a mis-associated key is refused, never handed back unusable.
 * The encryption requirement + expected recipient are derived from the CSR's own DecryptKeyIdentifier /
 * AsymmetricDecryptKeyIdentifier attribute; an `opts` value that contradicts the CSR is `est/bad-input`
 * (a cleartext-key downgrade cannot slip past). The delivered key's channel is asserted confidentiality-
 * bearing (a NULL / anonymous / EXPORT cipher is `est/weak-cipher`). https-only, explicit-anchor, and the
 * whole redirect / auth / budget machinery of `simpleenroll` apply.
 *
 * @opts
 *   - `requestedEncryption` / `expectedRecipientKeyId` / `expectedRecipientIssuerSerial` -- OPTIONAL
 *     overrides of the CSR-derived recipient coherence; a value that contradicts the CSR is `est/bad-input`.
 *   - every option of pki.est.simpleenroll (transport, tls, label, budgets, credentials incl. `auth`).
 * @example
 *   var r = await pki.est.serverkeygen("https://ca.example", csrDer,
 *     { transport: function () { return Promise.resolve({ status: 202, headers: { "retry-after": "60" }, body: "" }); } });
 *   r.retry;   // true -- a 202 is surfaced, never slept
 */
function serverkeygen(baseUrl, csrInput, opts) {
  opts = opts || {};
  return Promise.resolve().then(function () {
    _knownOpts(opts, SERVERKEYGEN_OPTS, "serverkeygen");
    var csrDer = _csrDer(csrInput);
    var derived = _serverkeygenEncryptionFromCsr(csrDer);
    if (opts.requestedEncryption !== undefined && !!opts.requestedEncryption !== derived.requestedEncryption) throw E("est/bad-input", "opts.requestedEncryption (" + !!opts.requestedEncryption + ") contradicts the CSR's advertised key-encryption attribute (" + derived.requestedEncryption + ") (RFC 7030 sec. 4.4.1)");
    if (opts.expectedRecipientKeyId !== undefined) {
      if (!Buffer.isBuffer(opts.expectedRecipientKeyId)) throw E("est/bad-input", "opts.expectedRecipientKeyId must be a Buffer");
      if (derived.expectedRecipientKeyId && !opts.expectedRecipientKeyId.equals(derived.expectedRecipientKeyId)) throw E("est/bad-input", "opts.expectedRecipientKeyId contradicts the key identifier the CSR advertised (RFC 7030 sec. 4.4.1)");
    }
    if (opts.expectedRecipientIssuerSerial != null) {
      var eis = opts.expectedRecipientIssuerSerial;
      if (typeof eis !== "object" || Buffer.isBuffer(eis) || !Buffer.isBuffer(eis.issuer)) throw E("est/bad-input", "opts.expectedRecipientIssuerSerial must be { issuer: Buffer, serialNumber }");
      var s = eis.serialNumber;
      if (!((typeof s === "bigint" && s >= 0n) || (typeof s === "number" && Number.isSafeInteger(s) && s >= 0) || (typeof s === "string" && pkix.allCharsIn(s, _DIGITS_TABLE)))) throw E("est/bad-input", "opts.expectedRecipientIssuerSerial.serialNumber must be a NON-NEGATIVE bigint, a safe non-negative integer, or a decimal digit string (a certificate serial is non-negative, RFC 5280 sec. 4.1.2.2)");
    }
    if ((opts.expectedRecipientKeyId !== undefined || opts.expectedRecipientIssuerSerial != null) && !derived.requestedEncryption) {
      throw E("est/bad-input", "a recipient expectation (expectedRecipientKeyId / expectedRecipientIssuerSerial) implies an encrypted key, but the CSR advertised no DecryptKeyIdentifier / AsymmetricDecryptKeyIdentifier attribute (RFC 7030 sec. 4.4.1)");
    }
    return _client("serverkeygen", "POST", baseUrl, transferEncode(csrDer), { accept: "multipart/mixed", "content-type": "application/pkcs10" }, opts)
      .then(function (res) { return _serverkeygenResult(res, opts, derived); });
  });
}


function _csrattrsResult(res, opts) {
  var verdict = classifyResponse(res.status, res.headers, res.body, { op: "csrattrs", now: opts.now });
  if (verdict.status === "none-available") return { available: false, attrs: null };
  if (verdict.status === "retry") throw E("est/http-error", "a /csrattrs response must be HTTP 200, 204, or 404, not 202 (RFC 7030 sec. 4.5.2)");
  if (verdict.status !== "ok") throw E("est/http-error", "an EST csrattrs response must be HTTP 200 / 204 / 404 (RFC 7030 sec. 4.5.2), got " + res.status);
  var bodyLen = _bodyLen(res);
  if (bodyLen === 0) throw E("est/empty-body", "a 200 csrattrs response carried an empty body (RFC 7030 sec. 4.5.2)");
  var attrs = csrattrsFmt.parse(transferDecode(res.body));
  return { available: true, attrs: attrs, plan: buildEnrollAttributes(attrs) };
}

/**
 * @primitive  pki.est.csrattrs
 * @signature  pki.est.csrattrs(baseUrl, opts?) -> Promise<{ available: true, attrs, plan } | { available: false, attrs: null }>
 * @since      0.3.28
 * @status     stable
 * @spec       RFC 7030, RFC 8951, RFC 9908
 * @related    pki.est.simpleenroll, pki.est.buildEnrollAttributes
 *
 * Fetch the CA's CSR-attributes policy: GET `<baseUrl>/.well-known/est/csrattrs` (`Accept:
 * application/csrattrs`). A 200 body is base64-decoded, parsed as an RFC 9908 `CsrAttrs`, and returned
 * with a `plan` (`buildEnrollAttributes`) the caller applies to its next CSR; the verb never auto-applies
 * attributes to a CSR (single responsibility). A 204 or 404 is `{ available: false }` (a valid "no specific
 * attributes") and not an error; an empty SEQUENCE (`30 00`) is a complete empty policy (`attrs.items` empty),
 * distinct from an empty HTTP body (`est/empty-body`). Server auth is not required for this policy GET but a
 * 401 is tolerated (the shared auth path stays live). https-only + explicit-anchor as elsewhere.
 *
 * @opts
 *   - every transport / tls / label / budget / credential option of the other verbs.
 * @example
 *   var r = await pki.est.csrattrs("https://ca.example",
 *     { transport: function () { return Promise.resolve({ status: 404, headers: {}, body: "" }); } });
 *   r.available;   // false -- a 404 is "no CSR-attributes policy available"
 */
function csrattrs(baseUrl, opts) {
  opts = opts || {};
  return Promise.resolve().then(function () {
    _knownOpts(opts, CSRATTRS_OPTS, "csrattrs");
    return _client("csrattrs", "GET", baseUrl, null, { accept: "application/csrattrs" }, opts);
  }).then(function (res) { return _csrattrsResult(res, opts); });
}

module.exports = {
  cacerts: cacerts,
  simpleenroll: simpleenroll,
  simplereenroll: simplereenroll,
  serverkeygen: serverkeygen,
  csrattrs: csrattrs,
  transferDecode: transferDecode,
  transferEncode: transferEncode,
  splitMultipartMixed: splitMultipartMixed,
  parseCertsOnly: parseCertsOnly,
  findIssuedCert: findIssuedCert,
  parseServerKeygenResponse: parseServerKeygenResponse,
  classifyResponse: classifyResponse,
  paths: paths,
  challengePasswordFromTlsUnique: challengePasswordFromTlsUnique,
  decryptKeyIdentifierAttr: decryptKeyIdentifierAttr,
  asymmetricDecryptKeyIdentifierAttr: asymmetricDecryptKeyIdentifierAttr,
  smimeCapabilitiesAttr: smimeCapabilitiesAttr,
  buildEnrollAttributes: buildEnrollAttributes,
  reenrollGuard: reenrollGuard,
  fullcmc: fullcmc,
};
