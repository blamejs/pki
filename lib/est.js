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
 *   Enrollment over Secure Transport (RFC 7030, updated by RFC 8951 and RFC 9908).
 *   The network verbs -- `cacerts`, `simpleenroll`, `simplereenroll` -- run the thin
 *   RFC 7030 client: they compose the codecs below over the shared `pki.transport`
 *   (a caller MAY inject `opts.transport`; the default is a fail-closed
 *   `pki.transport.https`). This module opens no socket itself -- the sole socket
 *   choke point is `pki.transport` -- so the verbs stay a thin, fail-closed shell:
 *   https-only (`est/insecure-url`), an explicit trust anchor required
 *   (`est/no-trust-anchors`), same-origin redirects followed but a downgrade / loop
 *   refused, a 202 Retry-After SURFACED and never slept, HTTP Basic answered only
 *   after the transport authenticated the server, and the issued certificate chosen
 *   by public-key match. Under them sit the transport-agnostic codecs, validators, and
 *   request builders over the shipped CMS / CSR / PKCS#8 / X.509 parsers:
 *   `transferDecode` / `transferEncode` are the RFC 8951
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
 *   EST (RFC 7030 / 8951 / 9908) client -- the cacerts / simpleenroll / simplereenroll
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
var csrattrsFmt = require("./schema-csrattrs");   // aliased: the `csrattrs` name is the verb + the public export
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var httpTransport = require("./http-transport");
var httpDigest = require("./http-digest");
var retryAfter = require("./http-retry-after");

var EstError = frameworkError.EstError;
function E(code, message, cause) { return new EstError(code, message, cause); }
var ID_SIGNED_DATA = oid.byName("signedData");
var OID_CHALLENGE_PASSWORD = oid.byName("challengePassword");
var OID_DECRYPT_KEY_ID = oid.byName("decryptKeyID");
var OID_ASYMM_DECRYPT_KEY_ID = oid.byName("asymmDecryptKeyID");
var OID_SMIME_CAPABILITIES = oid.byName("smimeCapabilities");
var OID_TEMPLATE = oid.byName("certificationRequestInfoTemplate");

var OPERATIONS = ["cacerts", "simpleenroll", "simplereenroll", "fullcmc", "serverkeygen", "csrattrs"];

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
  // Strict canonical RFC 4648 base64 (RFC 8951 sec. 3.1) via the shared encoding
  // guard: the alphabet + whole-4-group + canonical round-trip fail a malformed
  // body closed instead of silently truncating to a shorter, different DER.
  var der = guard.encoding.base64(stripped, null, E, "est/bad-base64", "the EST payload");
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
  // Re-view: a detached-backed Buffer reads as zero-length and would encode "".
  der = guard.bytes.view(der, EstError, "est/bad-input", "transferEncode DER input");
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
  // The certs-only Simple PKI Response shape is a CMS concern shared with AIA path building; the reader lives
  // in schema-cms. The "est" prefix keeps the exact est/* codes (est/not-certs-only, est/no-certificates, ...).
  return cms.parseCertsOnly(der, E, "est");
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
// The key-identifier bytes each RecipientInfo arm names, filtered by MECHANISM (RFC 7030 sec. 4.4.1): an
// ASYMMETRIC decryption key (AsymmetricDecryptKeyIdentifier) is named by a subjectKeyIdentifier on a
// KeyTrans / KeyAgree / KEM arm, a SYMMETRIC key (DecryptKeyIdentifier) by the keyIdentifier of a KEK arm.
// Filtering keeps a symmetric KEK arm from satisfying an advertised asymmetric key (and vice-versa) merely
// because the identifier bytes coincide -- the returned key would be unusable with the mechanism requested.
// kind: "asymmetric" | "symmetric" | undefined (any, for a direct caller that did not state the mechanism).
function _recipientKeyIds(recipientInfos, kind) {
  var ids = [];
  function push(v) { if (Buffer.isBuffer(v)) ids.push(v); }
  (recipientInfos || []).forEach(function (r) {
    if (kind !== "symmetric") {
      if (r.rid) push(r.rid.subjectKeyIdentifier);
      if (r.kemri && r.kemri.rid) push(r.kemri.rid.subjectKeyIdentifier);   // KEMRecipientInfo (RFC 9629, under the ori arm)
      (r.recipientEncryptedKeys || []).forEach(function (rek) { if (rek.rid) push(rek.rid.subjectKeyIdentifier); });
    }
    if (kind !== "asymmetric") {
      if (r.kekid) push(r.kekid.keyIdentifier);
    }
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
      _recipientKeyIds(recipientInfos, opts.expectedRecipientKind).some(function (id) { return id.equals(opts.expectedRecipientKeyId); })) return true;
  var ias = opts.expectedRecipientIssuerSerial;
  if (ias && Buffer.isBuffer(ias.issuer) && ias.serialNumber != null) {
    // Validate the caller-supplied serial BEFORE BigInt() so a bad value is a typed est/bad-input, never a
    // raw SyntaxError / RangeError leaking from the codec (the single choke point for both the serverkeygen
    // verb and the public parseServerKeygenResponse).
    var sn = ias.serialNumber, want;
    if (typeof sn === "bigint" && sn >= 0n) want = sn;
    else if (typeof sn === "number" && Number.isSafeInteger(sn) && sn >= 0) want = BigInt(sn);
    else if (typeof sn === "string" && /^[0-9]+$/.test(sn)) want = BigInt(sn);
    else throw E("est/bad-input", "expectedRecipientIssuerSerial.serialNumber must be a NON-NEGATIVE bigint, a safe non-negative integer, or a decimal digit string (a certificate serial is non-negative, RFC 5280 sec. 4.1.2.2)");
    // An issuerAndSerialNumber names an ASYMMETRIC recipient -- a certificate identity the server derived from
    // an AsymmetricDecryptKeyIdentifier (RFC 7030 sec. 4.4.2); a symmetric KEK recipient has none. So a SYMMETRIC
    // request must NOT be satisfied by an asymmetric arm's issuer+serial, or the client would accept ciphertext
    // undecryptable with the symmetric key it requested. The key-id branch applies the same mechanism filter.
    if (opts.expectedRecipientKind !== "symmetric" &&
        _recipientIssuerSerials(recipientInfos).some(function (r) { return r.issuer.equals(ias.issuer) && r.serialNumber === want; })) return true;
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
    // A detached OR empty EnvelopedData carries no ciphertext to decrypt -- there is
    // no key to recover, so it is not a valid key response (the shared CMS assert
    // rejects both null and zero-length, matching the CRMF / PKCS#12 siblings).
    cms.assertAttachedCiphertext(parsedKey.encryptedContentInfo, E, "est/bad-key-part", "a server-generated encrypted key's EnvelopedData");
    if (Buffer.isBuffer(opts.expectedRecipientKeyId) || opts.expectedRecipientIssuerSerial) {
      if (!_recipientMatches(parsedKey.recipientInfos, opts)) throw E("est/recipient-mismatch", "the server-generated key is not encrypted to the advertised recipient (RFC 7030 sec. 4.4.2)");
    }
    out.encryptedKey = parsedKey;
  } else {
    var keyDer = transferDecode(keyPart.body);
    out.privateKey = pkcs8.parse(keyDer);
    // The raw cleartext PrivateKeyInfo DER is surfaced so a semantic layer can bind the key to its
    // certificate (the public-key coherence check the verb runs). Structural parsing itself never
    // does the crypto derivation -- mirroring parseCertsOnly, which splits certs while the enroll
    // verb picks the issued one by public-key match.
    out.privateKeyDer = keyDer;
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
    if (ra === undefined || ra === null || String(ra).trim() === "") throw E("est/missing-retry-after", "an HTTP 202 EST response must include Retry-After (RFC 7030 sec. 4.2.3)");
    var raStr = String(ra).trim();
    // Retry-After is delay-seconds OR an HTTP-date (RFC 7231 sec. 7.1.3), surfaced (never slept on)
    // as a bounded retryAfterSeconds and/or an absolute retryAfterDate via the shared parser; neither
    // form -> fail closed rather than a retry verdict with no delay.
    var parsed = retryAfter.parse(raStr, { now: opts.now, E: E, code: "est/bad-retry-after" });
    return { status: "retry", retryAfter: raStr, retryAfterSeconds: parsed.retryAfterSeconds, retryAfterDate: parsed.retryAfterDate };
  }
  if (status === 204 || status === 404) {
    if (op === "csrattrs") return { status: "none-available" };
    throw E("est/http-error", "HTTP " + status + " is not a valid " + op + " response");
  }
  if (status >= 300 && status < 400) return { status: "redirect", location: h["location"] || null };
  if (status >= 400) {
    // Decode only a bounded prefix for the message -- a huge error body must not
    // be materialized as a full string just to show its first 512 characters.
    // toString(enc, start, end) bounds the decode WITHOUT constructing a subarray
    // view, so a detached body reads as "" here rather than throwing a raw
    // TypeError that would mask the est/http-error verdict.
    var text = Buffer.isBuffer(body) ? body.toString("utf8", 0, 512) : String(body || "").slice(0, 512);
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

// ---- the thin RFC 7030 client: network verbs over the shared pki.transport ----

var DEFAULT_TIMEOUT = constants.TIME.seconds(30);
var MAX_TIMEOUT = constants.TIME.seconds(600);

// The DER of a caller-supplied CSR: a DER Buffer as-is, or a PEM "CERTIFICATE REQUEST"
// decoded. Any other input is a config-time est/bad-input.
function _csrDer(input) {
  if (Buffer.isBuffer(input)) return input;
  if (typeof input === "string") return csr.pemDecode(input);
  throw E("est/bad-input", "a CSR must be a DER Buffer or a PEM CERTIFICATE REQUEST string");
}

// Parse + validate the request URL BEFORE any transport is called: a URL that will not
// parse is est/bad-url, a non-https URL is est/insecure-url (RFC 7030 sec. 3.3). Runs
// even when a transport is injected, so an insecure URL never reaches the wire.
function _parseUrl(urlStr) {
  var url;
  try { url = new URL(String(urlStr)); }
  catch (e) { throw E("est/bad-url", "the EST server URL did not parse: " + String(urlStr), e); }
  if (url.protocol !== "https:") throw E("est/insecure-url", "EST requires https (RFC 7030 sec. 3.3), got " + url.protocol + " for " + urlStr);
  return url;
}

// Map opts.tls (operator-facing) to the transport request.tls shape (anchors -> ca).
// rejectUnauthorized is NOT here -- the transport forces it on unconditionally.
function _tlsForRequest(opts) {
  var t = opts.tls || {};
  return { anchors: t.anchors, useSystemStore: t.useSystemStore, cert: t.cert, key: t.key, minVersion: t.minVersion, servername: t.servername, checkServerIdentity: t.checkServerIdentity };
}

// Resolve a redirect target: reject a scheme downgrade (est/insecure-redirect) or a
// cross-origin redirect on a non-GET/HEAD method without opt-in
// (est/cross-origin-redirect); a Location that will not parse is est/bad-url. Same-origin
// (and cross-origin GET/HEAD) are followed -- the transport re-runs every TLS check on the
// new connection (RFC 7030 sec. 3.2.1).
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

// Does WWW-Authenticate advertise the given auth-scheme as a TOKEN? The quoted-string contents are blanked
// first (a quoted auth-param may contain a comma + the scheme name, e.g. `Digest realm="x, Basic required"`,
// which must NOT be read as a Basic challenge), then the scheme is matched at the start or after a
// comma-separated challenge, followed by whitespace / a comma / end -- never a substring, so `Digest
// realm="basic"` is not taken as Basic. `scheme` is always our own literal ("Basic" / "Digest").
function _offersScheme(www, scheme) {
  var s = String(www || "").replace(/"(?:[^"\\]|\\.)*"/g, "\"\"");
  return new RegExp("(?:^|,)\\s*" + scheme + "(?=[\\s,]|$)", "i").test(s);
}
// The chosen HTTP auth scheme: an explicit opts.auth.scheme wins; a legacy opts.username / opts.password
// WITHOUT opts.auth means Basic (backwards compatible); otherwise none. There is NO scheme:"auto" -- a
// Basic<->Digest downgrade is never silently chosen (a MITM stripping Digest to Basic must not succeed).
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
// Credentials present -- an EMPTY username is allowed (RFC 7030 sec. 3.2.3), so "defined" (not "truthy").
function _hasCreds(opts) { return _authUser(opts) !== undefined || _authPass(opts) !== undefined; }
var DIGEST_CODES = { unsupportedAlgorithm: "est/digest-unsupported-algorithm", weakAlgorithm: "est/digest-weak-algorithm", noQop: "est/digest-no-qop", badChallenge: "est/digest-bad-challenge" };
// The Digest answer policy, from opts.auth. The SAME object drives challenge SELECTION (parseChallenge) and
// the ANSWER (answer), so the client never selects a challenge under one policy then answers under another.
function _digestPolicy(opts) { return { allowMD5: !!(opts.auth && opts.auth.allowMD5), allowLegacyQop: !!(opts.auth && opts.auth.allowLegacyQop), codes: DIGEST_CODES }; }

// The redirect-follow + HTTP-auth-retry loop. Returns the terminal transport response
// ({status, headers, body}) -- a 2xx, a 202, or a non-401 4xx/5xx. A 3xx is followed
// (bounded by maxRedirects); a 401 is answered ONCE with Basic credentials, and ONLY when
// the caller supplied them and the challenge is Basic (RFC 7030 sec. 3.2.3) -- the server
// was authenticated by the transport's rejectUnauthorized TLS before any credential is
// transmitted (no credential ever precedes server authorization).
function _drive(method, url, body, headers, opts, transport, budgets) {
  var redirects = 0;
  var authTried = false;
  var staleRetries = 0;   // bounded re-answers to a Digest stale=true re-challenge (a fresh nonce), never an open loop
  var authSpaces = 0;     // distinct Digest protection spaces (realms) entered beyond the first -- bounded so a server cannot loop with an endless stream of new realms
  var lastDigestNonce = null;   // the nonce just answered -- a stale=true retry MUST carry a DIFFERENT (fresh) nonce
  var initialOrigin = url.origin;   // the origin the caller intended to authenticate to
  // The per-hop TLS: the origin-specific identity (mTLS cert/key + pinned SNI) is sent ONLY to the caller's
  // configured origin; a cross-origin hop gets a narrowed copy with those stripped (checkServerIdentity kept).
  // Derived FRESH from budgets.tls each hop (the ACME _tlsFor model) so a redirect back to the original origin
  // restores its identity rather than permanently losing the SNI at the first cross-origin boundary.
  function _tlsFor(u) {
    var t = budgets.tls;
    if (t && u.origin !== initialOrigin && (t.cert != null || t.key != null || t.servername != null)) {
      t = Object.assign({}, t);
      delete t.cert; delete t.key; delete t.servername;
    }
    return t;
  }
  // The per-hop Authorization, sent ONLY to the caller's origin (a cross-origin hop travels unauthenticated; a
  // redirect back to the origin restores it -- mirrors _tlsFor). A Basic credential is target-INDEPENDENT, so it
  // is cached whole in authValue. A Digest response is bound to the request method + target, so the CHALLENGE is
  // cached and the answer is (re)computed for the CURRENT method / uri on every hop -- a same-origin redirect (or
  // a 303 POST->GET) then gets a target-correct answer instead of a stale one the server would reject.
  var authValue = null;
  var digestChallenge = null;
  var digestNc = 0;   // requests answered under the CURRENT Digest nonce -- incremented per (re)send so a reused nonce never repeats an nc (RFC 7616 sec. 3.4); reset when a fresh nonce arrives
  var digestSent = false;   // whether the LAST request actually carried a Digest Authorization -- the DIRECT signal that a following 401 rejects a credential, vs. is a fresh challenge for a request sent unauthenticated
  function _headersFor(u) {
    digestSent = false;
    if (u.origin !== initialOrigin || (!authValue && !digestChallenge)) return headers;
    var hh = Object.assign({}, headers);
    if (digestChallenge) {
      // Preemptively reuse the cached answer only WITHIN the challenge's protection space (RFC 7616 sec. 3.5):
      // a same-origin redirect to a URI outside the challenge's `domain` is sent unauthenticated, so the target
      // resource's own challenge drives a fresh authentication instead of receiving an Authorization computed
      // for the wrong protection space.
      if (!httpDigest.inProtectionSpace(digestChallenge, u.origin, u.pathname)) return headers;
      digestNc += 1;
      hh.authorization = httpDigest.answer(digestChallenge, { method: method, uri: u.pathname + u.search, username: _authUser(opts), password: _authPass(opts), body: body, nc: digestNc, policy: _digestPolicy(opts) }, E);
      digestSent = true;
    } else { hh.authorization = authValue; }
    return hh;
  }
  function step() {
    return transport({ method: method, url: url.href, headers: _headersFor(url), body: body, tls: _tlsFor(url), timeout: budgets.timeout, maxResponseBytes: budgets.maxResponseBytes }).then(function (res) {
      res = res || {};
      // Measure an injected string body as UTF-8 -- the byte width the body is decoded/transfer-decoded at,
      // and what the real socket transport counts -- so a non-ASCII body (multi-byte chars are ~half the
      // count under latin1) cannot undercount past the DoS cap and reach body handling.
      var blen = Buffer.isBuffer(res.body) ? res.body.length : Buffer.byteLength(String(res.body == null ? "" : res.body), "utf8");
      if (blen > budgets.maxResponseBytes) throw E("est/response-too-large", "the response body (" + blen + " bytes) exceeds the " + budgets.maxResponseBytes + "-byte cap (RFC 7030 sec. 6)");
      // The transport contract returns lowercased headers, but the injectable seam only promises
      // { status, headers, body }; normalize here so a redirect Location / WWW-Authenticate from an
      // injected transport using ordinary HTTP casing is read correctly (never missed as absent).
      var h = {};
      Object.keys(res.headers || {}).forEach(function (k) { h[k.toLowerCase()] = res.headers[k]; });
      var status = res.status;
      if (status >= 300 && status < 400) {
        if (redirects >= budgets.maxRedirects) throw E("est/too-many-redirects", "the redirect chain exceeded maxRedirects=" + budgets.maxRedirects + " (RFC 7030 sec. 3.2.1)");
        // 303 See Other directs a non-GET/HEAD request to retrieve the target with GET and no body
        // (RFC 7231 sec. 6.4.4); drop the request body + its entity content-type before following, so
        // the CSR is not re-POSTed to the redirect target as a duplicate enrollment.
        if (status === 303 && method !== "GET" && method !== "HEAD") {
          method = "GET";
          body = null;
          if (headers["content-type"]) { headers = Object.assign({}, headers); delete headers["content-type"]; }
        }
        url = _redirectTarget(url, h.location, method, opts);
        // Credentials MUST NOT cross an origin boundary: the HTTP Basic Authorization header and the
        // ORIGIN-SPECIFIC TLS identity (mTLS cert/key + pinned SNI) are BOTH scoped per hop (_headersFor /
        // _tlsFor), so each is absent off-origin but restored on a hop back to the caller's configured origin.
        redirects += 1;
        return step();
      }
      if (status === 401) {
        // Answer a challenge ONLY on the origin the caller targeted: a 401 arriving after a cross-origin
        // redirect is a different server, and the client MUST NOT send its credentials there (RFC 7030 sec. 3.6).
        if (url.origin !== initialOrigin) throw E("est/auth-required", "refusing to send HTTP credentials to a redirected origin (RFC 7030 sec. 3.6)");
        var www = String(h["www-authenticate"] || "");
        // Bound the attacker-controlled challenge header BEFORE any scheme scan / copy (_offersScheme, the parser):
        // an injected transport without its own header limit must not cause unbounded allocation or work despite
        // the parser's own cap being applied later (CWE-400). The cap matches the Digest parser's.
        if (www.length > constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES) throw E("est/auth-required", "the WWW-Authenticate header exceeds the " + constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES + "-byte cap (RFC 7030 sec. 3.2.3)");
        var scheme = _authScheme(opts);
        if (scheme === null) throw E("est/auth-required", "the server requires HTTP authentication but no credentials were supplied (RFC 7030 sec. 3.2.3)");
        if (scheme === "digest") {
          if (!_offersScheme(www, "Digest")) throw E("est/auth-required", "opts.auth.scheme is \"digest\" but the server offered no Digest challenge: " + www);
          if (!_hasCreds(opts)) throw E("est/auth-required", "Digest authentication requires opts.auth.username / password (RFC 7030 sec. 3.2.3)");
          var ch = httpDigest.parseChallenge(www, E, "est/digest-bad-challenge", _digestPolicy(opts));
          if (!ch) throw E("est/auth-required", "the server offered no usable Digest challenge: " + www);
          // Whether this 401 REJECTS a credential turns on the DIRECT signal (RFC 7616 sec. 3.3 / 3.5): did the
          // request that received it actually CARRY a Digest answer for THIS protection space? A request sent
          // unauthenticated -- the first attempt, or one whose target lay outside the cached challenge's domain --
          // has not authenticated, so its 401 (even in the same realm) is a FRESH challenge to answer, never a
          // rejection. A credentialed request refused in the SAME realm IS a rejection of that credential: only a
          // stale=true re-challenge carrying a FRESH nonce may retry (a repeated nonce with stale=true is a
          // self-contradictory / hostile server -> terminate). Any fresh authentication -- the first, a newly
          // entered protection space, or an unauthenticated resource -- is bounded (maxRedirects) against a loop.
          if (digestSent && digestChallenge && ch.realm === digestChallenge.realm) {
            if (!(ch.stale && ch.nonce !== lastDigestNonce && staleRetries < budgets.maxStaleRetries)) throw E("est/auth-required", "the server rejected the credentialed Digest request (RFC 7030 sec. 3.2.3)");
            staleRetries += 1;
          } else {
            if (authTried && authSpaces >= budgets.maxRedirects) throw E("est/auth-required", "the server demanded Digest authentication for too many distinct protection spaces (RFC 7616 sec. 3.3)");
            if (authTried) authSpaces += 1;
            authTried = true;
            staleRetries = 0;   // a fresh authentication (new space / unauthenticated resource) restarts the stale budget
          }
          var nonceChanged = ch.nonce !== lastDigestNonce;
          lastDigestNonce = ch.nonce;
          // Cache the CHALLENGE, not a fixed answer: _headersFor computes the response for the CURRENT method /
          // request-target on each hop, so a same-origin redirect (or a 303 POST->GET) gets a target-correct answer
          // rather than a stale one. A policy fault (MD5 / no-qop / unsupported) surfaces from _headersFor on the
          // immediate re-send (the transport is not reached, so a rejected leg still proves calls did not advance).
          digestChallenge = ch;
          // Restart the nonce-count ONLY on a FRESH nonce. A challenge that REUSES the current nonce (a resource
          // reached unauthenticated after leaving the cached domain, answered with the same still-valid nonce)
          // keeps the count advancing, so a (nonce, nc) pair is never replayed -- resetting would resend nc=1 for
          // a nonce already counted and a server's replay detection would reject it (RFC 7616 sec. 3.4).
          if (nonceChanged) digestNc = 0;
          return step();
        }
        // Basic (default / explicit): the one-shot semantics unchanged.
        if (authTried) throw E("est/auth-required", "the server rejected the credentialed request (RFC 7030 sec. 3.2.3)");
        if (!_offersScheme(www, "Basic")) throw E("est/auth-required", "the server requires an unsupported HTTP authentication scheme (only Basic and Digest are supported): " + www);
        // An explicit auth.scheme:"basic" with no credentials must fail closed too (an empty username stays legal),
        // never transmit a "Basic Og==" (base64 of ":") the operator never supplied.
        if (!_hasCreds(opts)) throw E("est/auth-required", "the server requires HTTP authentication but no credentials were supplied (RFC 7030 sec. 3.2.3)");
        // Establish the credential as origin-scoped state (_headersFor attaches it only on the initial origin),
        // never a mutation of the shared headers that would leak across a cross-origin redirect.
        authValue = "Basic " + Buffer.from((_authUser(opts) || "") + ":" + (_authPass(opts) || ""), "utf8").toString("base64");
        authTried = true;
        return step();
      }
      return res;
    });
  }
  return step();
}

// The shared client entry: build the op URL, validate it + the trust config + the budgets
// (ALL before any transport call so a config fault proves the transport was never reached),
// then drive the request through the redirect/auth loop.
function _client(op, method, baseUrl, body, headers, opts) {
  // paths() concatenates onto the base string, so a query / fragment on the base URL would capture
  // the operation path (sending the request -- possibly an enrollment CSR -- to the wrong resource).
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
  _authScheme(opts);   // config-time: a bad opts.auth.scheme throws est/bad-input here, never deferred to a 401
  return _drive(method, url, body, Object.assign({}, headers), opts, transport, budgets);
}

// Turn a terminal response into the verb result: classifyResponse gates status +
// content-type (202 -> a surfaced retry, never slept; 4xx/5xx -> est/http-error), then an
// empty 200 is rejected and the certs-only body is decoded + validated. For an enroll, the
// issued certificate is the public-key match (findIssuedCert), never a positional guess;
// the remaining certificates are the chain.
function _certsResult(op, res, opts, csrSpki) {
  var verdict = classifyResponse(res.status, res.headers, res.body, { op: op, now: opts.now });
  if (verdict.status === "retry") {
    // 202 Retry-After is an ENROLLMENT response (RFC 7030 sec. 4.2.3); a successful /cacerts is 200
    // only (sec. 4.1.3), so a 202 there is a nonconforming server -> fail closed rather than "retry".
    if (op === "cacerts") throw E("est/http-error", "a /cacerts response must be HTTP 200, not 202 (RFC 7030 sec. 4.1.3)");
    return { retry: true, retryAfterSeconds: verdict.retryAfterSeconds, retryAfterDate: verdict.retryAfterDate };
  }
  // Only the RFC-defined success statuses are accepted: a non-standard 2xx (201, 206, ...) that the
  // classifier reports as "unexpected" must NOT have its body decoded and accepted as certificates.
  if (verdict.status !== "ok") throw E("est/http-error", "an EST " + op + " response must be HTTP 200 or 202 (RFC 7030 sec. 4.1.3 / 4.2.3), got " + res.status);
  // Measure the body as UTF-8 for parity with the transport cap above (this check only distinguishes empty
  // from non-empty, where the encoding is immaterial, but the shape is kept uniform so no site undercounts).
  var bodyLen = Buffer.isBuffer(res.body) ? res.body.length : Buffer.byteLength(String(res.body == null ? "" : res.body), "utf8");
  if (bodyLen === 0) throw E("est/empty-body", "a 200 " + op + " response carried an empty body (RFC 7030 sec. 4.1.3 / 4.2.3)");
  var parsed = parseCertsOnly(transferDecode(res.body));
  if (op === "cacerts") return { certificates: parsed.certificates, crls: parsed.crls };
  var issued = findIssuedCert(parsed.certificates, csrSpki);
  if (!issued) throw E("est/issued-cert-not-found", "no returned certificate matched the submitted CSR public key (RFC 5272 sec. 4.1)");
  // The chain is every OTHER response certificate (by reference, so a byte-identical duplicate is
  // NOT silently collapsed into the issued cert). Exactly one certificate may match the submitted
  // public key -- a second match (a renewed cert sharing the key, or a duplicate entry) makes the
  // issued certificate ambiguous, since the certs-only set has no issuance ordering (RFC 5272 sec. 4.1).
  var chain = parsed.certificates.filter(function (c) { return c !== issued; });
  if (findIssuedCert(chain, csrSpki)) throw E("est/ambiguous-issued-cert", "the enroll response carried more than one certificate matching the submitted CSR public key; the issued certificate is ambiguous (RFC 5272 sec. 4.1)");
  if (opts.strict && chain.length > 0) throw E("est/unexpected-certs", "strict: the enroll response carried " + parsed.certificates.length + " certificates, expected exactly the issued one");
  return { certificate: issued, chain: chain, certificates: parsed.certificates };
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
 * @status     experimental
 * @spec       RFC 7030, RFC 8951
 * @related    pki.est.simpleenroll, pki.transport.https
 *
 * Fetch a CA's certificates over the wire: GET `<baseUrl>/.well-known/est/cacerts` through
 * the shared `pki.transport` (inject `opts.transport`, else a fail-closed
 * `pki.transport.https`). Returns the raw, unordered certs-only set
 * (`{ certificates, crls }`), or `{ retry: true, retryAfterSeconds }` on a 202 (surfaced,
 * never slept). https-only (`est/insecure-url`); an explicit `opts.tls.anchors` (or an
 * `opts.tls.useSystemStore` opt-in) is required (`est/no-trust-anchors`); the returned CA
 * certificate is NOT auto-trusted -- the caller path-validates it and supplies the accepted
 * anchor on the next call.
 *
 * @opts
 *   - `transport` -- an injected transport(request) -> {status, headers, body}; default pki.transport.https.
 *   - `tls` -- { anchors, useSystemStore, cert, key, minVersion, servername, checkServerIdentity }.
 *   - `label` -- an OPTIONAL CA label path segment; `timeout` / `maxResponseBytes` / `maxRedirects` -- budgets.
 *   - `now` -- receipt time (epoch ms) to render a 202 Retry-After HTTP-date as seconds.
 * @example
 *   // a live CA uses the default pki.transport.https; here an injected transport returns a canned bag
 *   var r = await pki.est.cacerts("https://ca.example",
 *     { transport: function () { return Promise.resolve({ status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: caCertsDer.toString("base64") }); } });
 *   r.certificates;   // -> [Buffer, ...] raw, unordered
 */
function cacerts(baseUrl, opts) {
  opts = opts || {};
  return Promise.resolve().then(function () {
    return _client("cacerts", "GET", baseUrl, null, { accept: "application/pkcs7-mime" }, opts);
  }).then(function (res) { return _certsResult("cacerts", res, opts, null); });
}

/**
 * @primitive  pki.est.simpleenroll
 * @signature  pki.est.simpleenroll(baseUrl, csr, opts?) -> Promise<{ certificate, chain, certificates } | { retry, retryAfterSeconds }>
 * @since      0.3.16
 * @status     experimental
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
 * 401 is answered once with HTTP Basic ONLY when `opts.username`/`password` are supplied and
 * the transport already authenticated the server.
 *
 * @opts
 *   - `transport` / `tls` / `label` / `timeout` / `maxResponseBytes` / `maxRedirects` / `now` -- as pki.est.cacerts.
 *   - `strict` -- reject an enroll response that carries more than the single issued certificate.
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
  return Promise.resolve().then(function () { return _enroll("simpleenroll", baseUrl, csrInput, opts); });
}

/**
 * @primitive  pki.est.simplereenroll
 * @signature  pki.est.simplereenroll(baseUrl, csr, opts?) -> Promise<{ certificate, chain, certificates } | { retry, retryAfterSeconds }>
 * @since      0.3.16
 * @status     experimental
 * @spec       RFC 7030
 * @related    pki.est.simpleenroll, pki.est.reenrollGuard
 *
 * Renew / rekey a certificate: identical to `pki.est.simpleenroll` but POSTs to
 * `/.well-known/est/simplereenroll` and REQUIRES `opts.oldCert` (the certificate being
 * renewed). Before anything crosses the wire, `reenrollGuard` enforces that the CSR's
 * Subject and SubjectAltName (names and criticality) are byte-identical to `opts.oldCert`
 * (RFC 7030 sec. 4.2.2) -- a mismatch fails closed (`est/reenroll-subject-mismatch` /
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
    if (!opts.oldCert) throw E("est/bad-input", "simplereenroll requires opts.oldCert (the certificate being renewed, RFC 7030 sec. 4.2.2)");
    reenrollGuard(opts.oldCert, _csrDer(csrInput));   // est/reenroll-* on mismatch, BEFORE the POST
    return _enroll("simplereenroll", baseUrl, csrInput, opts);
  });
}

// ---- /serverkeygen (RFC 7030 sec. 4.4) ----------------------------------

// Derive the server-generated-key ENCRYPTION coherence from the CSR the caller actually POSTs (RFC 7030
// sec. 4.4.1): a DecryptKeyIdentifier / AsymmetricDecryptKeyIdentifier attribute names the key-encryption
// key the server must encrypt the generated private key to. Binding the expected recipient to the CSR (not a
// free-floating opts boolean) closes the drift where a cleartext key rides past a caller who forgot the flag.
function _serverkeygenEncryptionFromCsr(csrDer) {
  var attrs = csr.parse(csrDer).attributes || [];
  var keyId = null, kind = null;
  for (var i = 0; i < attrs.length; i++) {
    if (attrs[i].type !== OID_DECRYPT_KEY_ID && attrs[i].type !== OID_ASYMM_DECRYPT_KEY_ID) continue;
    // DecryptKeyIdentifier names a SYMMETRIC key-encryption key; AsymmetricDecryptKeyIdentifier an ASYMMETRIC
    // one (RFC 7030 sec. 4.4.1). The mechanism is preserved so the returned key part is matched to a compatible
    // RecipientInfo arm, not merely one whose identifier bytes coincide.
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

// The delivered private key rides TLS confidentiality alone: a NULL / anonymous / EXPORT suite MUST NOT be
// used to carry it (RFC 7030 sec. 4.4, sec. 6). Assert (never reconfigure) the negotiated cipher when the
// transport surfaces it; an injected transport that reports no cipher is trusted (the test/loopback channel).
function _assertConfidentialCipher(res) {
  if (!res || !res.tls || !res.tls.cipher) return;
  var c = res.tls.cipher;
  var name = (String(c.name || "") + " " + String(c.standardName || "")).toUpperCase();
  // EXPORT covers the RFC/IANA name; the OpenSSL short names use an EXP prefix followed by a separator OR a
  // digit run (EXP-RC4-MD5, EXP1024-RC4-SHA), so match EXP before either -- a bare `\bEXP\b` misses EXP1024.
  if (/NULL|ANON|EXPORT|\bEXP[-_0-9]|\bA(EC)?DH\b/.test(name)) throw E("est/weak-cipher", "the serverkeygen channel negotiated a NULL / anonymous / EXPORT cipher (" + (c.standardName || c.name) + "), which cannot protect the delivered private key (RFC 7030 sec. 4.4)");
}

// A case-insensitive header lookup: the injectable transport seam only promises { status, headers, body }, so a
// hostile / non-Node transport may deliver "Content-Type" in any casing -- read it case-insensitively (classifyResponse
// normalizes internally, but the multipart boundary is read from the header directly here).
function _ciHeader(headers, name) {
  headers = headers || {};
  if (headers[name] !== undefined) return headers[name];
  var lname = name.toLowerCase(), keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i++) { if (keys[i].toLowerCase() === lname) return headers[keys[i]]; }
  return null;
}

async function _serverkeygenResult(res, opts, derived) {
  var verdict = classifyResponse(res.status, res.headers, res.body, { op: "serverkeygen", now: opts.now });
  // A 202 is an enrollment posture (RFC 7030 sec. 4.4 treats /serverkeygen as an enroll): surfaced, never slept.
  if (verdict.status === "retry") return { retry: true, retryAfterSeconds: verdict.retryAfterSeconds, retryAfterDate: verdict.retryAfterDate };
  if (verdict.status !== "ok") throw E("est/http-error", "an EST serverkeygen response must be HTTP 200 or 202 (RFC 7030 sec. 4.4.2), got " + res.status);
  var bodyLen = Buffer.isBuffer(res.body) ? res.body.length : Buffer.byteLength(String(res.body == null ? "" : res.body), "utf8");
  if (bodyLen === 0) throw E("est/empty-body", "a 200 serverkeygen response carried an empty body (RFC 7030 sec. 4.4.2)");
  _assertConfidentialCipher(res);
  // parseServerKeygenResponse does the per-part transfer-decode; the recipient coherence is bound to the CSR.
  var out = parseServerKeygenResponse(res.body, _ciHeader(res.headers, "content-type"), {
    requestedEncryption: derived.requestedEncryption,
    expectedRecipientKeyId: derived.expectedRecipientKeyId,
    expectedRecipientKind: derived.expectedRecipientKind,
    expectedRecipientIssuerSerial: opts.expectedRecipientIssuerSerial,
  });
  // Bind a CLEARTEXT server-generated key to its certificate (RFC 7030 sec. 4.4.2): the CA generated
  // this pair and issued a certificate over its PUBLIC half, so the delivered PrivateKeyInfo's public key
  // MUST equal EXACTLY ONE returned certificate's SubjectPublicKeyInfo -- a key unrelated to every
  // certificate is an unusable / mis-associated credential, and a key matching more than one leaves the
  // issued certificate ambiguous. Mirrors simpleenroll's findIssuedCert public-key match; the encrypted
  // key stays opaque, so its recipient coherence is bound in the parser instead. The public half is
  // derived through the key engine (never re-serialized here); a key whose public half cannot be derived
  // is not bindable and fails closed.
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
 * @status     experimental
 * @spec       RFC 7030, RFC 8951
 * @related    pki.est.simpleenroll, pki.est.parseServerKeygenResponse
 *
 * Request a SERVER-GENERATED key pair + certificate: POST the CSR (base64 DER, `Content-Type:
 * application/pkcs10`, identical request encoding to `simpleenroll`) to
 * `<baseUrl>/.well-known/est/serverkeygen`. The two-part `multipart/mixed` response is surfaced as
 * `{ certificates, privateKey }` (a cleartext PKCS#8 `PrivateKeyInfo`) or `{ certificates,
 * encryptedKey }` (the CMS `EnvelopedData` the caller decrypts out-of-band with its key-encryption key --
 * the verb NEVER decrypts, so it is not a decryption oracle), or `{ retry, retryAfterSeconds }` on a 202.
 * The certificates are RAW/unordered -- unlike `simpleenroll` no leaf is picked, because the CA generated
 * the key so the issued certificate's public key is the generated one, not the throwaway CSR key. A CLEARTEXT
 * key is bound to its certificate before it resolves: the delivered private key's public half MUST match
 * EXACTLY ONE returned certificate (`est/key-cert-mismatch` on none, `est/ambiguous-issued-cert` on more than
 * one), so a mis-associated key is refused rather than handed back unusable.
 * The encryption requirement + expected recipient are DERIVED from the CSR's own DecryptKeyIdentifier /
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
      if (!((typeof s === "bigint" && s >= 0n) || (typeof s === "number" && Number.isSafeInteger(s) && s >= 0) || (typeof s === "string" && /^[0-9]+$/.test(s)))) throw E("est/bad-input", "opts.expectedRecipientIssuerSerial.serialNumber must be a NON-NEGATIVE bigint, a safe non-negative integer, or a decimal digit string (a certificate serial is non-negative, RFC 5280 sec. 4.1.2.2)");
    }
    // A recipient expectation implies the key part MUST be encrypted to that recipient; if the CSR advertised no
    // key-encryption attribute the coherence check below never runs, so a compromised CA could deliver the key
    // to a recipient IT controls (or cleartext) while the caller believes its pin was enforced. Refuse the
    // contradiction at config time (RFC 7030 sec. 4.4.1) -- the caller must advertise the KEK in the CSR.
    if ((opts.expectedRecipientKeyId !== undefined || opts.expectedRecipientIssuerSerial != null) && !derived.requestedEncryption) {
      throw E("est/bad-input", "a recipient expectation (expectedRecipientKeyId / expectedRecipientIssuerSerial) implies an encrypted key, but the CSR advertised no DecryptKeyIdentifier / AsymmetricDecryptKeyIdentifier attribute (RFC 7030 sec. 4.4.1)");
    }
    return _client("serverkeygen", "POST", baseUrl, transferEncode(csrDer), { accept: "multipart/mixed", "content-type": "application/pkcs10" }, opts)
      .then(function (res) { return _serverkeygenResult(res, opts, derived); });
  });
}

// ---- /csrattrs GET (RFC 7030 sec. 4.5, RFC 9908) ------------------------

function _csrattrsResult(res, opts) {
  var verdict = classifyResponse(res.status, res.headers, res.body, { op: "csrattrs", now: opts.now });
  // 204 / 404 = "CSR Attributes Response not available" -- a valid NONE outcome, not an error (RFC 7030 sec. 4.5.2).
  if (verdict.status === "none-available") return { available: false, attrs: null };
  // A 202 is nonconforming for a policy GET (sec. 4.5.2 lists only 200 / 204 / 404).
  if (verdict.status === "retry") throw E("est/http-error", "a /csrattrs response must be HTTP 200, 204, or 404, not 202 (RFC 7030 sec. 4.5.2)");
  if (verdict.status !== "ok") throw E("est/http-error", "an EST csrattrs response must be HTTP 200 / 204 / 404 (RFC 7030 sec. 4.5.2), got " + res.status);
  var bodyLen = Buffer.isBuffer(res.body) ? res.body.length : Buffer.byteLength(String(res.body == null ? "" : res.body), "utf8");
  // An empty HTTP body is distinct from a valid EMPTY CsrAttrs (`30 00` / base64 `MAA=`), which parses as {items:[]}.
  if (bodyLen === 0) throw E("est/empty-body", "a 200 csrattrs response carried an empty body (RFC 7030 sec. 4.5.2)");
  var attrs = csrattrsFmt.parse(transferDecode(res.body));
  return { available: true, attrs: attrs, plan: buildEnrollAttributes(attrs) };
}

/**
 * @primitive  pki.est.csrattrs
 * @signature  pki.est.csrattrs(baseUrl, opts?) -> Promise<{ available: true, attrs, plan } | { available: false, attrs: null }>
 * @since      0.3.28
 * @status     experimental
 * @spec       RFC 7030, RFC 8951, RFC 9908
 * @related    pki.est.simpleenroll, pki.est.buildEnrollAttributes
 *
 * Fetch the CA's CSR-attributes policy: GET `<baseUrl>/.well-known/est/csrattrs` (`Accept:
 * application/csrattrs`). A 200 body is base64-decoded, parsed as an RFC 9908 `CsrAttrs`, and returned
 * with a `plan` (`buildEnrollAttributes`) the caller applies to its NEXT CSR -- the verb NEVER auto-applies
 * attributes to a CSR (single responsibility). A 204 or 404 is `{ available: false }` (a valid "no specific
 * attributes"), NOT an error; an empty SEQUENCE (`30 00`) is a COMPLETE empty policy (`attrs.items` empty),
 * distinct from an empty HTTP body (`est/empty-body`). Server auth is NOT required for this policy GET but a
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
};
