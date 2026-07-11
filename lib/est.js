// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.est
 * @nav        Schema
 * @title      EST
 * @order      190
 * @slug       est
 *
 * @intro
 *   Enrollment over Secure Transport (RFC 7030, updated by RFC 8951 and
 *   RFC 9908) -- the transport-agnostic codecs, validators, and request builders
 *   an EST client composes over the shipped CMS / CSR / PKCS#8 / X.509 parsers.
 *   No socket is opened here: `transferDecode` / `transferEncode` are the RFC 8951
 *   sec. 3 base64 transfer codec (RFC 4648, and DELIBERATELY blind to any
 *   Content-Transfer-Encoding header -- errata 5904/5107); `splitMultipartMixed`
 *   is the /serverkeygen `multipart/mixed` splitter; `parseCertsOnly` validates a
 *   certs-only Simple PKI Response (RFC 5272 sec. 4.1) OVER `cms.parse` output;
 *   `parseServerKeygenResponse` dispatches the two-part key + certificate
 *   response with recipient-arm coherence; `classifyResponse` is the HTTP status
 *   / content-type / Retry-After state machine (202 accepted-not-ready surfaces
 *   `retryAfterSeconds` -- never an internal sleep; 204/404 on /csrattrs is a
 *   "none available" verdict, not an error). The builders assemble the CSR
 *   attributes EST adds -- a channel-binding challengePassword, the
 *   out-of-band-key identifiers, SMIMECapabilities, and the RFC 9908
 *   template-priority enroll plan.
 *
 *   Altitude MATCHES the toolkit: structural validation, no crypto verdicts.
 *   Certificates come back RAW and UNORDERED ("Clients MUST NOT assume the
 *   certificates are in any order", RFC 5272 sec. 4.1) -- `findIssuedCert` picks
 *   the issued certificate by a public-key match, never a positional guess. The
 *   serverkeygen encrypted-key part's EnvelopedData is surfaced structurally
 *   (ciphertext raw, decryption external). /fullcmc is recognized and rejected
 *   with a precise `est/fullcmc-not-supported` (deferred to the CMC format
 *   module). DER-only where DER, fail-closed everywhere.
 *
 * @card
 *   EST (RFC 7030 / 8951 / 9908) client codecs -- base64 transfer, multipart
 *   splitter, certs-only + serverkeygen validators over CMS, the enroll-attribute
 *   builders, and the HTTP response classifier. Transport-agnostic, fail-closed.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var constants = require("./constants");
var cms = require("./schema-cms");
var x509 = require("./schema-x509");
var crl = require("./schema-crl");
var pkcs8 = require("./schema-pkcs8");
var csr = require("./schema-csr");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");

var EstError = frameworkError.EstError;
function E(code, message, cause) { return new EstError(code, message, cause); }

var ID_DATA = oid.byName("data");
var ID_SIGNED_DATA = oid.byName("signedData");
var OID_CHALLENGE_PASSWORD = oid.byName("challengePassword");
var OID_DECRYPT_KEY_ID = oid.byName("decryptKeyID");
var OID_ASYMM_DECRYPT_KEY_ID = oid.byName("asymmDecryptKeyID");
var OID_SMIME_CAPABILITIES = oid.byName("smimeCapabilities");
var OID_TEMPLATE = oid.byName("certificationRequestInfoTemplate");

var OPERATIONS = ["cacerts", "simpleenroll", "simplereenroll", "fullcmc", "serverkeygen", "csrattrs"];

// The largest Retry-After delay this classifier will surface as a number: a
// generous one-year ceiling that keeps the value a safe integer and rejects an
// overflowing / nonsensical delay-seconds fail-closed rather than returning it.
var MAX_RETRY_AFTER_SECONDS = constants.TIME.days(365) / constants.TIME.seconds(1);

// The three HTTP-date forms (RFC 7231 sec. 7.1.1.1): IMF-fixdate (the required
// form), and the obsolete rfc850-date / asctime-date a recipient must still
// accept. Gating Date.parse on this grammar keeps its permissiveness (an ISO
// string like "2026-07-10") from passing as a valid Retry-After header.
var _MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(" ");
var _MONTH = "(?:" + _MONTHS.join("|") + ")";
var HTTP_DATE_FORMS = [
  new RegExp("^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \\d{2} " + _MONTH + " \\d{4} \\d{2}:\\d{2}:\\d{2} GMT$"),
  new RegExp("^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), \\d{2}-" + _MONTH + "-\\d{2} \\d{2}:\\d{2}:\\d{2} GMT$"),
  new RegExp("^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) " + _MONTH + " [ \\d]\\d \\d{2}:\\d{2}:\\d{2} \\d{4}$"),
];

// Parse an HTTP-date to epoch ms, or NaN when its grammar, calendar, or time is
// invalid. Built from the extracted fields via Date.UTC (never Date.parse): every
// HTTP-date is UTC -- the asctime form carries no GMT token, so delegating would
// parse it in LOCAL time -- and the round-trip check rejects an impossible date /
// time (Date.UTC normalizes Feb 31 -> Mar 2 just as Date.parse would).
function _httpDateMs(s) {
  if (!HTTP_DATE_FORMS.some(function (re) { return re.test(s); })) return NaN;
  var day, monName, year;
  var asc = /^\w{3} (\w{3}) ([ \d]\d) /.exec(s);                           // asctime: month then day
  if (asc) { monName = asc[1]; day = parseInt(asc[2], 10); year = parseInt(/(\d{4})$/.exec(s)[1], 10); }
  else {
    var dmy = /(\d{2})[ -](\w{3})[ -](\d{2,4})/.exec(s);                   // IMF / rfc850: day month year
    if (!dmy) return NaN;
    day = parseInt(dmy[1], 10); monName = dmy[2]; year = parseInt(dmy[3], 10);
    if (year < 100) year += (year < 70 ? 2000 : 1900);                    // rfc850 two-digit year
  }
  var t = /(\d{2}):(\d{2}):(\d{2})/.exec(s);
  var mon = _MONTHS.indexOf(monName);
  if (!t || mon < 0) return NaN;
  var hh = parseInt(t[1], 10), mi = parseInt(t[2], 10), ss = parseInt(t[3], 10);
  var when = Date.UTC(year, mon, day, hh, mi, ss);
  var d = new Date(when);
  if (d.getUTCDate() !== day || d.getUTCMonth() !== mon || d.getUTCFullYear() !== year ||
      d.getUTCHours() !== hh || d.getUTCMinutes() !== mi || d.getUTCSeconds() !== ss) return NaN;
  return when;
}

// ---- the RFC 8951 sec. 3/3.1 transfer codec (CTE-header-blind) -----------

/**
 * @primitive  pki.est.transferDecode
 * @signature  pki.est.transferDecode(body) -> Buffer
 * @since      0.1.24
 * @status     experimental
 * @spec       RFC 8951, RFC 4648
 * @related    pki.est.transferEncode
 *
 * Decode an EST payload body (a base64 string or Buffer) to DER. CR/LF/space/tab
 * are stripped anywhere (RFC 8951 sec. 3.1); any other non-alphabet byte fails
 * closed with `est/bad-base64`. A Content-Transfer-Encoding header is NEVER read
 * (errata 5904/5107). Bounded twice -- the raw length before decode and the
 * decoded DER against `DER_MAX_BYTES` (`est/too-large`).
 *
 * @example
 *   var roundTripped = pki.est.transferDecode(pki.est.transferEncode(der));
 */
function transferDecode(body) {
  // The pre-decode ceiling: the largest base64 that could yield a DER_MAX_BYTES
  // document, plus a generous line-wrapping allowance (CRLF at 64/76-char lines is
  // ~3%; 1/8 leaves ample margin) so a normally-wrapped near-limit body is not
  // rejected before the real DER_MAX_BYTES limit is enforced on the decode below.
  // guard.text.decode caps the raw byte length BEFORE the latin1 copy.
  var b64Len = Math.ceil(constants.LIMITS.DER_MAX_BYTES * 4 / 3);
  var cap = b64Len + Math.ceil(b64Len / 8) + constants.BYTES.kib(64);
  var s = guard.text.decode(body, cap, EstError, {
    charset: "latin1", tooLarge: "est/too-large", badInput: "est/bad-input", label: "the EST payload",
  });
  var stripped = s.replace(/[\r\n \t]/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(stripped)) throw E("est/bad-base64", "the EST payload is not RFC 4648 base64 (RFC 8951 sec. 3.1)");
  var der = Buffer.from(stripped, "base64");
  // Buffer.from silently truncates a non-canonical body (a length not a multiple
  // of 4, e.g. "A", or non-zero trailing bits). Re-encode and require an exact
  // round-trip so a malformed payload fails closed instead of decoding to a
  // different, shorter DER (the PEM decoder applies the same canonical check).
  if (der.toString("base64") !== stripped) throw E("est/bad-base64", "the EST payload is not canonical RFC 4648 base64 (RFC 8951 sec. 3.1)");
  if (der.length > constants.LIMITS.DER_MAX_BYTES) throw E("est/too-large", "the decoded EST DER exceeds the size cap");
  return der;
}

/**
 * @primitive  pki.est.transferEncode
 * @signature  pki.est.transferEncode(der) -> string
 * @since      0.1.24
 * @status     experimental
 * @spec       RFC 8951, RFC 4648
 * @related    pki.est.transferDecode
 *
 * Encode DER as an EST payload body: bare RFC 4648 base64, no line wrapping
 * (senders need not insert whitespace, RFC 8951 sec. 3.1).
 *
 * @example
 *   var body = pki.est.transferEncode(der);
 */
function transferEncode(der) {
  if (!Buffer.isBuffer(der)) throw E("est/bad-input", "transferEncode requires a DER Buffer");
  return der.toString("base64");
}

// ---- the multipart/mixed splitter (/serverkeygen) -----------------------

// Extract the boundary from a `multipart/mixed; boundary=...` content-type,
// tolerating whitespace before the semicolon (erratum 5779 REJECTED the ban).
function _multipartBoundary(contentType) {
  var ct = String(contentType || "");
  if (!/^multipart\/mixed\s*(;|$)/i.test(ct)) return null;
  var m = /;\s*boundary\s*=\s*("([^"]+)"|([^;\s]+))/i.exec(ct);
  return m ? (m[2] !== undefined ? m[2] : m[3]) : null;
}

// Split a multipart/mixed body into its parts, each { headers, contentType,
// body }. A boundary delimiter is `--boundary` only at the START OF A LINE (body
// start or after CRLF), optional transport-padding, then CRLF (a part) or `--`
// (the close delimiter) -- matching the raw substring would treat `--boundaryX`,
// which is NOT a delimiter (RFC 2046), as one. The preamble/epilogue are ignored.
function splitMultipartMixed(body, contentType) {
  var boundary = _multipartBoundary(contentType);
  if (!boundary) throw E("est/bad-multipart", "a serverkeygen response must be multipart/mixed with a boundary (RFC 7030 sec. 4.4.2)");
  var text = guard.text.decode(body, constants.LIMITS.DER_MAX_BYTES * 2, EstError, {
    charset: "latin1", tooLarge: "est/too-large", badInput: "est/bad-input", label: "the multipart body",
  });
  var esc = boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  var delimRe = new RegExp("(?:^|\\r?\\n)--" + esc + "(--)?[ \\t]*(?:\\r?\\n|$)", "g");
  var marks = [], m;
  while ((m = delimRe.exec(text)) !== null) {
    marks.push({ at: m.index, bodyStart: delimRe.lastIndex, close: m[1] === "--" });
    if (delimRe.lastIndex === m.index) delimRe.lastIndex += 1;   // guard a zero-length match
  }
  var closeAt = -1;
  for (var c = 0; c < marks.length; c++) { if (marks[c].close) { closeAt = c; break; } }
  if (closeAt === -1) throw E("est/bad-multipart", "the multipart body is missing its terminal boundary (RFC 2046)");
  var parts = [];
  for (var i = 0; i < closeAt; i++) {
    var seg = text.slice(marks[i].bodyStart, marks[i + 1].at);   // between this delimiter and the next
    var sep = seg.indexOf("\r\n\r\n");
    if (sep === -1) sep = seg.indexOf("\n\n");
    if (sep === -1) throw E("est/bad-multipart", "a multipart part is missing its header/body separator");
    var rawHeaders = seg.slice(0, sep);
    var partBody = seg.slice(sep).replace(/^(\r?\n){2}/, "").replace(/\r?\n$/, "");
    var headers = {};
    rawHeaders.split(/\r?\n/).forEach(function (line) {
      var col = line.indexOf(":");
      if (col > 0) headers[line.slice(0, col).trim().toLowerCase()] = line.slice(col + 1).trim();
    });
    var partCt = headers["content-type"] || "";
    if (/^multipart\//i.test(partCt)) throw E("est/bad-multipart", "a nested multipart part is not permitted");
    parts.push({ headers: headers, contentType: partCt, body: partBody });
  }
  return parts;
}

// ---- the certs-only Simple PKI Response validator -----------------------

/**
 * @primitive  pki.est.parseCertsOnly
 * @signature  pki.est.parseCertsOnly(der) -> { certificates, crls }
 * @since      0.1.24
 * @status     experimental
 * @spec       RFC 7030, RFC 5272, RFC 5652
 * @related    pki.est.findIssuedCert, pki.schema.cms.parse
 *
 * Validate a certs-only CMS Simple PKI Response (RFC 5272 sec. 4.1) over the
 * shipped `cms.parse` output: a SignedData with no eContent and EMPTY
 * signerInfos, carrying at least one plain X.509 certificate (a context-tagged
 * CertificateChoices alternative is rejected `est/bad-certificate-choice`). CRLs
 * MAY be present. Certificates come back RAW and in AS-RECEIVED order (never
 * sorted -- RFC 5272 sec. 4.1). A non-conformant response throws a typed
 * `EstError` (`est/not-certs-only`, `est/no-certificates`).
 *
 * @example
 *   var r = pki.est.parseCertsOnly(caCertsDer);
 *   r.certificates;   // -> [Buffer, ...] raw, unordered
 */
function parseCertsOnly(der) {
  var r;
  try { r = cms.parse(der); }
  catch (e) { if (e instanceof EstError) throw e; throw E("est/bad-response", "the EST response did not decode as CMS: " + ((e && e.message) || String(e)), e); }
  if (r.contentTypeName !== "signedData") throw E("est/not-certs-only", "an EST certs-only response must be a CMS SignedData (RFC 5272 sec. 4.1)");
  if (r.encapContentInfo.eContentType !== ID_DATA || r.encapContentInfo.eContent !== null) {
    throw E("est/not-certs-only", "a certs-only Simple PKI Response must carry id-data with no eContent (RFC 5272 sec. 4.1)");
  }
  if (r.signerInfos.length !== 0) throw E("est/not-certs-only", "a certs-only Simple PKI Response must have empty signerInfos (RFC 5272 sec. 4.1)");
  if (!r.certificates || r.certificates.length === 0) throw E("est/no-certificates", "an EST certs-only response must contain at least one certificate (RFC 7030 sec. 4.1.3)");
  for (var i = 0; i < r.certificates.length; i++) {
    if (r.certificates[i].tagClass !== "universal") throw E("est/bad-certificate-choice", "EST exchanges plain X.509 certificates; a tagged CertificateChoices alternative is not permitted (RFC 7030)");
    // A universal-SEQUENCE CertificateChoice must be a well-formed X.509
    // Certificate, not merely any SEQUENCE. Parse it structurally (still
    // returning the raw bytes below) so a malformed response fails closed.
    try { x509.parse(r.certificates[i].bytes); }
    catch (e) { if (e instanceof EstError) throw e; throw E("est/bad-certificate", "a certs-only response carried a non-certificate in its certificates field (RFC 5272 sec. 4.1)", e); }
  }
  var crls = r.crls || [];
  for (var j = 0; j < crls.length; j++) {
    // A RevocationInfoChoice is a plain X.509 CertificateList or a [1] otherRevInfo;
    // EST surfaces CRLs, so reject the tagged alternative and structurally validate
    // each universal entry as a CertificateList (mirrors the certificate path).
    if (crls[j].tagClass !== "universal") throw E("est/bad-crl", "an EST response CRL must be a plain X.509 CertificateList, not a tagged otherRevInfo alternative (RFC 5652 sec. 10.2.1)");
    try { crl.parse(crls[j].bytes); }
    catch (e) { if (e instanceof EstError) throw e; throw E("est/bad-crl", "a response carried a non-CRL in its crls field", e); }
  }
  return {
    certificates: r.certificates.map(function (c) { return c.bytes; }),
    crls: crls.map(function (c) { return c.bytes; }),
  };
}

// Pick the issued certificate from a certs-only response by matching its public
// key against the CSR / SPKI the client submitted -- the ONLY sanctioned
// identification (positional guessing is forbidden, RFC 5272 sec. 4.1). `target`
// is an SPKI object (with a `bytes` subjectPublicKey field) or a raw Buffer.
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

// ---- /serverkeygen ------------------------------------------------------

// Collect every key-identifier (subjectKeyIdentifier / KEKIdentifier) a set of
// RecipientInfos names, across the ktri / kari / kekri / kemri arms -- the
// byte identifiers a client's advertised decryptKeyID would match.
function _recipientKeyIds(recipientInfos) {
  var ids = [];
  function push(v) { if (Buffer.isBuffer(v)) ids.push(v); }
  (recipientInfos || []).forEach(function (r) {
    if (r.rid) push(r.rid.subjectKeyIdentifier);
    if (r.kemri && r.kemri.rid) push(r.kemri.rid.subjectKeyIdentifier);   // KEMRecipientInfo (RFC 9629, under the ori arm)
    if (r.kekid) push(r.kekid.keyIdentifier);
    (r.recipientEncryptedKeys || []).forEach(function (rek) { if (rek.rid) push(rek.rid.subjectKeyIdentifier); });
  });
  return ids;
}

// The { issuer (raw DN bytes), serialNumber } every issuerAndSerialNumber recipient
// arm names -- the form a server MAY use after mapping an AsymmetricDecryptKeyIdentifier
// to a certificate (RFC 7030 sec. 4.4.2), so a key-id-only match would miss it.
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

// The advertised recipient (a decryptKeyID / asymmDecryptKeyID key identifier
// and/or an issuer+serial) matches SOME RecipientInfo arm -- either identifier
// form the server may have used to name the same requested key.
function _recipientMatches(recipientInfos, opts) {
  if (Buffer.isBuffer(opts.expectedRecipientKeyId) &&
      _recipientKeyIds(recipientInfos).some(function (id) { return id.equals(opts.expectedRecipientKeyId); })) return true;
  var ias = opts.expectedRecipientIssuerSerial;
  if (ias && Buffer.isBuffer(ias.issuer) && ias.serialNumber != null) {
    var want = typeof ias.serialNumber === "bigint" ? ias.serialNumber : BigInt(ias.serialNumber);
    if (_recipientIssuerSerials(recipientInfos).some(function (r) { return r.issuer.equals(ias.issuer) && r.serialNumber === want; })) return true;
  }
  return false;
}

// Parse a /serverkeygen response: exactly two parts -- a private-key part
// (application/pkcs8 cleartext PrivateKeyInfo, or application/pkcs7-mime;
// smime-type=server-generated-key EnvelopedData) and a certificate part (the
// enroll-response shape). opts.requestedEncryption asserts the key part is
// encrypted (a cleartext part -> est/expected-encrypted-key). The advertised
// recipient may be given as opts.expectedRecipientKeyId (a Buffer, the
// decryptKeyID / asymmDecryptKeyID) and/or opts.expectedRecipientIssuerSerial
// ({ issuer: raw-DN Buffer, serialNumber }, the form a server MAY use after
// mapping that identifier to a certificate); when either is given, a RecipientInfo
// of the encrypted key must match one of them (else est/recipient-mismatch) -- so
// a response encrypted to a DIFFERENT recipient fails closed rather than passing.
// Split a content-type on `;` that are OUTSIDE a quoted-string (RFC 2045),
// so a `;` inside a parameter value does not create a spurious parameter.
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

// Split a part's content-type into its base media type (lowercased) and its
// smime-type parameter. The media type must be the EXACT token (a look-alike
// like application/pkcs8evil yields that literal, not application/pkcs8), and
// parameters are read token-by-token honoring quoted-strings so a smime-type-like
// substring inside another quoted parameter value is NOT taken as smime-type.
function _partMediaType(contentType) {
  var segs = _splitContentTypeParams(String(contentType || ""));
  var mediaMatch = /^\s*([a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*)\s*$/i.exec(segs[0]);
  var smimeType = null;
  for (var i = 1; i < segs.length; i++) {
    var eq = segs[i].indexOf("=");
    if (eq === -1) continue;
    if (segs[i].slice(0, eq).trim().toLowerCase() !== "smime-type") continue;
    var val = segs[i].slice(eq + 1).trim();
    if (val.length >= 2 && val.charAt(0) === '"' && val.charAt(val.length - 1) === '"') val = val.slice(1, -1);
    smimeType = val.toLowerCase();
    break;
  }
  return { media: mediaMatch ? mediaMatch[1].toLowerCase() : null, smimeType: smimeType };
}

function parseServerKeygenResponse(body, contentType, opts) {
  opts = opts || {};
  var parts = splitMultipartMixed(body, contentType);
  if (parts.length !== 2) throw E("est/bad-multipart", "a serverkeygen response must have exactly two parts (RFC 7030 sec. 4.4.2)");
  var keyPart = null, certPart = null, encrypted = false;
  for (var i = 0; i < parts.length; i++) {
    var pt = _partMediaType(parts[i].contentType);
    if (pt.media === "application/pkcs8") { keyPart = parts[i]; encrypted = false; }
    else if (pt.media === "application/pkcs7-mime" && pt.smimeType === "server-generated-key") { keyPart = parts[i]; encrypted = true; }
    // The certificate part exactly matches the /simpleenroll response
    // (RFC 7030 sec. 4.4.2), so it too MUST be smime-type=certs-only.
    else if (pt.media === "application/pkcs7-mime" && pt.smimeType === "certs-only") certPart = parts[i];
    else throw E("est/bad-multipart", "unrecognized serverkeygen part content-type " + JSON.stringify(parts[i].contentType));
  }
  if (!keyPart || !certPart) throw E("est/bad-multipart", "a serverkeygen response needs one key part and one certificate part");
  if (opts.requestedEncryption && !encrypted) throw E("est/expected-encrypted-key", "encryption was requested but the private-key part is cleartext (RFC 7030 sec. 4.4.2)");
  var out = { certificates: parseCertsOnly(transferDecode(certPart.body)).certificates };
  if (encrypted) {
    // The server-generated key MUST be a CMS EnvelopedData (RFC 7030 sec. 4.4.2);
    // a SignedData or any other CMS content type under the encrypted label is a
    // structurally invalid key part, not a success. The EnvelopedData is surfaced
    // structurally -- the ciphertext stays opaque and the RecipientInfo arms feed
    // the coherence check the caller makes.
    var parsedKey = cms.parse(transferDecode(keyPart.body));
    if (parsedKey.contentTypeName !== "envelopedData") throw E("est/bad-key-part", "a server-generated encrypted key part must be a CMS EnvelopedData (RFC 7030 sec. 4.4.2), got " + JSON.stringify(parsedKey.contentTypeName));
    // The EnvelopedData MUST encapsulate a CMS SignedData holding the private key
    // (RFC 7030 sec. 4.4.2) -- validate the inner encryptedContentInfo content type,
    // not just the outer ContentInfo, so a key wrapped around id-data or anything
    // else fails closed before the caller decrypts it.
    if (!parsedKey.encryptedContentInfo || parsedKey.encryptedContentInfo.contentType !== ID_SIGNED_DATA) throw E("est/bad-key-part", "a server-generated encrypted key's EnvelopedData must encapsulate a CMS SignedData (RFC 7030 sec. 4.4.2)");
    // A detached EnvelopedData (encryptedContent omitted) carries no ciphertext to
    // decrypt -- there is no key to recover, so it is not a valid key response.
    if (parsedKey.encryptedContentInfo.encryptedContent === null) throw E("est/bad-key-part", "a server-generated encrypted key's EnvelopedData must carry its encrypted content, not be detached (RFC 7030 sec. 4.4.2)");
    if (Buffer.isBuffer(opts.expectedRecipientKeyId) || opts.expectedRecipientIssuerSerial) {
      if (!_recipientMatches(parsedKey.recipientInfos, opts)) throw E("est/recipient-mismatch", "the server-generated key is not encrypted to the advertised recipient (RFC 7030 sec. 4.4.2)");
    }
    out.encryptedKey = parsedKey;
  } else {
    out.privateKey = pkcs8.parse(transferDecode(keyPart.body));
  }
  return out;
}

// ---- the HTTP response classifier --------------------------------------

// The required 200-response content-type per operation: the EXACT media-type
// token plus, where the RFC mandates it, the smime-type parameter. simpleenroll /
// simplereenroll require smime-type=certs-only (RFC 7030 sec. 4.2.3) so a different
// PKI message type (CMC-response, ...) is not accepted; cacerts mandates only the
// media type (sec. 4.1.3). Matched token-wise, not by prefix, so a look-alike like
// "application/pkcs7-mimeevil" is rejected.
var CONTENT_TYPE_BY_OP = {
  cacerts: { media: "application/pkcs7-mime" },
  simpleenroll: { media: "application/pkcs7-mime", smimeType: "certs-only" },
  simplereenroll: { media: "application/pkcs7-mime", smimeType: "certs-only" },
  serverkeygen: { media: "multipart/mixed" },
  csrattrs: { media: "application/csrattrs" },
};

// The operations whose responses this client classifies. /fullcmc is a real EST
// path (paths() emits its URL) but its CMC response is deferred to the CMC
// module, so classifying one is an explicit unsupported-operation fault rather
// than a silently-accepted 200 whose content-type went unchecked.
var CLASSIFIABLE_OPS = ["cacerts", "simpleenroll", "simplereenroll", "serverkeygen", "csrattrs"];

/**
 * @primitive  pki.est.classifyResponse
 * @signature  pki.est.classifyResponse(status, headers, body, opts?) -> verdict
 * @since      0.1.24
 * @status     experimental
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
  var op = opts.op;
  // Fail closed on an operation whose response this client cannot validate:
  // /fullcmc is recognized-but-deferred, and any other named op is a typo. An
  // absent op is the caller opting out of the content-type gate (generic
  // status handling) and stays permissive.
  if (op === "fullcmc") throw E("est/fullcmc-not-supported", "the /fullcmc operation is recognized but its CMC response is not supported by this client (RFC 7030 sec. 4.3)");
  if (op !== undefined && op !== null && CLASSIFIABLE_OPS.indexOf(op) === -1) throw E("est/unsupported-operation", "unrecognized EST operation " + JSON.stringify(op));
  var h = {};
  Object.keys(headers || {}).forEach(function (k) { h[k.toLowerCase()] = headers[k]; });
  if (status === 200) {
    var spec = CONTENT_TYPE_BY_OP[op];
    var ct = h["content-type"] || "";
    if (spec) {
      var pt = _partMediaType(ct);
      if (pt.media !== spec.media || (spec.smimeType && pt.smimeType !== spec.smimeType)) {
        throw E("est/bad-content-type", "a 200 " + op + " response must carry content-type " + spec.media + (spec.smimeType ? "; smime-type=" + spec.smimeType : "") + ", got " + JSON.stringify(ct));
      }
    }
    return { status: "ok", contentType: ct };
  }
  if (status === 202) {
    var ra = h["retry-after"];
    if (ra === undefined || ra === null || String(ra).trim() === "") throw E("est/missing-retry-after", "an HTTP 202 EST response must include Retry-After (RFC 8951 sec. 3.3)");
    var raStr = String(ra).trim();
    // Retry-After is delay-seconds OR an HTTP-date (RFC 7231 sec. 7.1.3). A
    // delay-seconds becomes retryAfterSeconds directly; an HTTP-date is surfaced
    // as an absolute retryAfterDate (epoch ms) -- and, when the caller passes its
    // receipt time as opts.now (epoch ms), also as a bounded retryAfterSeconds.
    // Neither form -> fail closed rather than a retry verdict with no delay.
    var out202 = { status: "retry", retryAfter: raStr, retryAfterSeconds: null, retryAfterDate: null };
    if (/^\d+$/.test(raStr)) {
      var n = parseInt(raStr, 10);
      if (!Number.isSafeInteger(n) || n > MAX_RETRY_AFTER_SECONDS) throw E("est/bad-retry-after", "the 202 Retry-After delay is out of the supported range (0.." + MAX_RETRY_AFTER_SECONDS + " seconds)");
      out202.retryAfterSeconds = n;
    } else {
      var when = _httpDateMs(raStr);
      if (isNaN(when)) throw E("est/bad-retry-after", "a 202 Retry-After must be delay-seconds or a valid HTTP-date (RFC 7231 sec. 7.1.1.1/7.1.3), got " + JSON.stringify(raStr));
      out202.retryAfterDate = when;
      if (typeof opts.now === "number" && isFinite(opts.now)) {
        var d = Math.max(0, Math.round((when - opts.now) / constants.TIME.seconds(1)));
        // The same one-year ceiling the delay-seconds form enforces (a date far in
        // the future would otherwise surface a huge numeric delay).
        if (d > MAX_RETRY_AFTER_SECONDS) throw E("est/bad-retry-after", "the 202 Retry-After date is beyond the supported horizon (" + MAX_RETRY_AFTER_SECONDS + " seconds)");
        out202.retryAfterSeconds = d;
      }
    }
    return out202;
  }
  if (status === 204 || status === 404) {
    if (op === "csrattrs") return { status: "none-available" };
    throw E("est/http-error", "HTTP " + status + " is not a valid " + op + " response");
  }
  if (status >= 300 && status < 400) return { status: "redirect", location: h["location"] || null };
  if (status >= 400) {
    // Decode only a bounded prefix for the message -- a huge error body must not
    // be materialized as a full string just to show its first 512 characters.
    var text = Buffer.isBuffer(body) ? body.subarray(0, 512).toString("utf8") : String(body || "").slice(0, 512);
    throw E("est/http-error", "EST server returned HTTP " + status + (text ? ": " + text : ""));
  }
  return { status: "unexpected", httpStatus: status };
}

// ---- operation-path builder ---------------------------------------------

/**
 * @primitive  pki.est.paths
 * @signature  pki.est.paths(baseUrl, opts?) -> { cacerts, simpleenroll, ... }
 * @since      0.1.24
 * @status     experimental
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
  var prefix = String(baseUrl).replace(/\/+$/, "") + "/.well-known/est";
  if (opts.label != null) {
    var label = String(opts.label);
    // A label is ONE URL path segment: unreserved characters only (RFC 3986),
    // never a dot-segment or an operation name. Rejecting rather than
    // percent-encoding keeps a reserved char (`/` `?` `#` `%`) or `..` from
    // silently retargeting the request to a different resource.
    if (label === "" || label === "." || label === ".." || !/^[A-Za-z0-9._~-]+$/.test(label) || OPERATIONS.indexOf(label) !== -1) {
      throw E("est/bad-label", "an EST CA label must be a single path segment of unreserved characters, not '.' / '..' or an operation name (RFC 7030 sec. 3.2.2)");
    }
    prefix += "/" + label;
  }
  var out = {};
  OPERATIONS.forEach(function (op) { out[op] = prefix + "/" + op; });
  return out;
}

// ---- builders: the CSR attributes EST adds ------------------------------

function _attr(typeOid, valueNodes) { return asn1.build.sequence([asn1.build.oid(typeOid), asn1.build.set(valueNodes)]); }

// the RFC 5929 tls-unique channel-binding bytes -> a challengePassword
// attribute whose value is their RFC 4648 base64 (SIZE 1..255). The builder
// takes caller-supplied binding bytes and never fakes one.
function challengePasswordFromTlsUnique(channelBinding) {
  if (!Buffer.isBuffer(channelBinding) || channelBinding.length === 0) throw E("est/bad-input", "challengePasswordFromTlsUnique requires the channel-binding bytes");
  var b64 = channelBinding.toString("base64");
  if (b64.length > 255) throw E("est/tls-unique-too-long", "the base64 tls-unique value exceeds 255 octets (RFC 7030 sec. 3.5)");
  return _attr(OID_CHALLENGE_PASSWORD, [asn1.build.printable(b64)]);
}

// the out-of-band key-encryption-key identifiers (OCTET STRING values).
function decryptKeyIdentifierAttr(keyId) {
  if (!Buffer.isBuffer(keyId)) throw E("est/bad-input", "decryptKeyIdentifierAttr requires the key-identifier bytes");
  return _attr(OID_DECRYPT_KEY_ID, [asn1.build.octetString(keyId)]);
}
function asymmetricDecryptKeyIdentifierAttr(keyId) {
  if (!Buffer.isBuffer(keyId)) throw E("est/bad-input", "asymmetricDecryptKeyIdentifierAttr requires the key-identifier bytes");
  return _attr(OID_ASYMM_DECRYPT_KEY_ID, [asn1.build.octetString(keyId)]);
}
// SMIMECapabilities ::= SEQUENCE OF SMIMECapability { capabilityID OID,
//   parameters ANY OPTIONAL }.
function smimeCapabilitiesAttr(capabilities) {
  if (!Array.isArray(capabilities) || capabilities.length === 0) throw E("est/bad-input", "smimeCapabilitiesAttr requires a non-empty capability list");
  var caps = capabilities.map(function (c) {
    var seq = [asn1.build.oid(c.capabilityID)];
    if (c.parameters !== undefined && c.parameters !== null) seq.push(Buffer.isBuffer(c.parameters) ? c.parameters : asn1.build.oid(c.parameters));
    return asn1.build.sequence(seq);
  });
  return _attr(OID_SMIME_CAPABILITIES, [asn1.build.sequence(caps)]);
}

// Derive the enroll-request attribute plan from a parsed CsrAttrs.
// When a template is present the plan derives from the TEMPLATE ONLY and ignores
// every other element (RFC 9908 sec. 4). The challengePassword OID is an
// INSTRUCTION ("include tls-unique") -> a channelBindingRequired flag, never a
// password value (the RFC 7030 example that echoed it is "NOT CORRECT",
// RFC 9908 sec. 4). Every item the plan does not model into a specific field --
// including a REGISTERED-but-unmodeled instruction like a bare signature-algorithm
// OID (RFC 8951) -- is surfaced on `unhandled` ({ kind, oid, name }) so the client
// never silently drops a server requirement.
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
      // EVERY key type the parser accepts is a key-type constraint (RSA / EC /
      // Ed25519 / ML-DSA / ...). The non-template form carries EXACTLY ONE key-type
      // attribute (RFC 9908 sec. 3.2); a second is an ambiguous server instruction,
      // not a last-one-wins override -- fail closed rather than pick one by order.
      if (plan.keyType) throw E("est/ambiguous-key-type", "a non-template CsrAttrs response must carry exactly one key-type attribute (RFC 9908 sec. 3.2)");
      // Surface the raw values too: a key type this planner does not decode into
      // curve / keySize (Ed25519, ML-DSA, ...) may still carry RFC 9908 parameters,
      // so never silently drop them.
      plan.keyType = { type: it.name, curve: it.curve || null, keySize: it.keySize || null, values: it.values || [] };
    }
    else plan.unhandled.push({ kind: it.kind, oid: it.oid, name: it.name });
  }
  return plan;
}

var SAN_OID = oid.byName("subjectAltName");

// Pull the SubjectAltName extension's raw extnValue (the DER GeneralNames) off a
// parsed extension list -- a certificate's `.extensions` or a CSR's
// extensionRequest `.extensions` -- as { critical, value }, or null when no SAN
// is present. Both fields matter: "identical" (RFC 7030 sec. 4.2.2) covers the
// criticality flag, not just the GeneralNames bytes.
function _san(extList) {
  if (!Array.isArray(extList)) return null;
  for (var i = 0; i < extList.length; i++) {
    if (extList[i].oid === SAN_OID) return { critical: !!extList[i].critical, value: extList[i].value };
  }
  return null;
}

// The requested extensions a CSR carries in its extensionRequest attribute
// (RFC 2985 sec. 5.4.2), decoded by the CSR parser, or null when absent. A CSR
// carrying more than one extensionRequest is structurally legal (no SET-OF
// uniqueness) but AMBIGUOUS for the re-enroll SAN comparison -- fail closed
// rather than trusting the DER-first one while a later one requests a different SAN.
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

// A re-enroll CSR MUST reuse the old certificate's Subject and SubjectAltName
// extension byte-identically (RFC 7030 sec. 4.2.2). Returns the old cert's
// subject + SAN for verbatim reuse in the new CSR; on a caller-supplied new CSR,
// compares both by raw DER (a rendered DN two different string encodings can
// share is NOT enough) and throws est/reenroll-subject-mismatch or
// est/reenroll-san-mismatch on any divergence (a SAN present on one side and
// absent on the other is a mismatch, not an accept).
function reenrollGuard(oldCertDer, newCsrDer) {
  var oldCert = x509.parse(oldCertDer);
  var oldSubject = oldCert.subject.rdns;   // the parsed subject; raw region surfaced below
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

module.exports = {
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
};
