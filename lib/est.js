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
var pkcs8 = require("./schema-pkcs8");
var csr = require("./schema-csr");
var frameworkError = require("./framework-error");

var EstError = frameworkError.EstError;
function E(code, message, cause) { return new EstError(code, message, cause); }

var ID_DATA = oid.byName("data");
var OID_CHALLENGE_PASSWORD = oid.byName("challengePassword");
var OID_DECRYPT_KEY_ID = oid.byName("decryptKeyID");
var OID_ASYMM_DECRYPT_KEY_ID = oid.byName("asymmDecryptKeyID");
var OID_SMIME_CAPABILITIES = oid.byName("smimeCapabilities");
var OID_TEMPLATE = oid.byName("certificationRequestInfoTemplate");
var OID_EC_PUBLIC_KEY = oid.byName("ecPublicKey");
var OID_RSA_ENCRYPTION = oid.byName("rsaEncryption");

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
  var s = Buffer.isBuffer(body) ? body.toString("latin1") : String(body);
  // The pre-decode ceiling: the largest base64 that could yield a DER_MAX_BYTES
  // document, plus whitespace slack. Reject an oversized body before decoding it.
  var cap = Math.ceil(constants.LIMITS.DER_MAX_BYTES * 4 / 3) + constants.BYTES.kib(64);
  if (s.length > cap) throw E("est/too-large", "the EST payload exceeds the transfer size cap");
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
// body }. RFC 2046: parts open with `--boundary` at a line start and the body
// ends with the terminal `--boundary--`; the preamble/epilogue are ignored.
function splitMultipartMixed(body, contentType) {
  var boundary = _multipartBoundary(contentType);
  if (!boundary) throw E("est/bad-multipart", "a serverkeygen response must be multipart/mixed with a boundary (RFC 7030 sec. 4.4.2)");
  var text = Buffer.isBuffer(body) ? body.toString("latin1") : String(body);
  if (text.length > constants.LIMITS.DER_MAX_BYTES * 2) throw E("est/too-large", "the multipart body exceeds the size cap");
  var delim = "--" + boundary;
  var terminal = delim + "--";
  var termIdx = text.indexOf(terminal);
  if (termIdx === -1) throw E("est/bad-multipart", "the multipart body is missing its terminal boundary (RFC 2046)");
  var head = text.slice(0, termIdx);
  var segments = head.split(delim).slice(1);   // drop the preamble
  var parts = [];
  for (var i = 0; i < segments.length; i++) {
    var seg = segments[i].replace(/^\r?\n/, "");
    var sep = seg.indexOf("\r\n\r\n");
    if (sep === -1) sep = seg.indexOf("\n\n");
    if (sep === -1) throw E("est/bad-multipart", "a multipart part is missing its header/body separator");
    var rawHeaders = seg.slice(0, sep);
    var partBody = seg.slice(sep).replace(/^(\r?\n){2}/, "").replace(/\r?\n$/, "");
    var headers = {};
    rawHeaders.split(/\r?\n/).forEach(function (line) {
      var c = line.indexOf(":");
      if (c > 0) headers[line.slice(0, c).trim().toLowerCase()] = line.slice(c + 1).trim();
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
  return {
    certificates: r.certificates.map(function (c) { return c.bytes; }),
    crls: (r.crls || []).map(function (c) { return c.bytes; }),
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

// Parse a /serverkeygen response: exactly two parts -- a private-key part
// (application/pkcs8 cleartext PrivateKeyInfo, or application/pkcs7-mime;
// smime-type=server-generated-key EnvelopedData) and a certificate part (the
// enroll-response shape). opts.requestedEncryption asserts the key part is
// encrypted (a cleartext part -> est/expected-encrypted-key). opts.expectedRecipientKeyId
// (a Buffer, the decryptKeyID / asymmDecryptKeyID the client advertised), when
// given, requires a RecipientInfo of the encrypted key to name that identifier
// (else est/recipient-mismatch) -- so a response encrypted to a DIFFERENT
// recipient fails closed instead of being surfaced as success.
function parseServerKeygenResponse(body, contentType, opts) {
  opts = opts || {};
  var parts = splitMultipartMixed(body, contentType);
  if (parts.length !== 2) throw E("est/bad-multipart", "a serverkeygen response must have exactly two parts (RFC 7030 sec. 4.4.2)");
  var keyPart = null, certPart = null;
  for (var i = 0; i < parts.length; i++) {
    var ct = parts[i].contentType.toLowerCase();
    if (/application\/pkcs8/.test(ct) || /server-generated-key/.test(ct)) keyPart = parts[i];
    else if (/application\/pkcs7-mime/.test(ct)) certPart = parts[i];
    else throw E("est/bad-multipart", "unrecognized serverkeygen part content-type " + JSON.stringify(parts[i].contentType));
  }
  if (!keyPart || !certPart) throw E("est/bad-multipart", "a serverkeygen response needs one key part and one certificate part");
  var encrypted = /server-generated-key/.test(keyPart.contentType.toLowerCase());
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
    if (Buffer.isBuffer(opts.expectedRecipientKeyId)) {
      var matched = _recipientKeyIds(parsedKey.recipientInfos).some(function (id) { return id.equals(opts.expectedRecipientKeyId); });
      if (!matched) throw E("est/recipient-mismatch", "the server-generated key is not encrypted to the advertised recipient key identifier (RFC 7030 sec. 4.4.2)");
    }
    out.encryptedKey = parsedKey;
  } else {
    out.privateKey = pkcs8.parse(transferDecode(keyPart.body));
  }
  return out;
}

// ---- the HTTP response classifier --------------------------------------

var CONTENT_TYPE_BY_OP = {
  cacerts: /^application\/pkcs7-mime/i,
  simpleenroll: /^application\/pkcs7-mime/i,
  simplereenroll: /^application\/pkcs7-mime/i,
  serverkeygen: /^multipart\/mixed/i,
  csrattrs: /^application\/csrattrs/i,
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
 * the operation's content-type (`est/bad-content-type`); a 202 requires a
 * Retry-After, surfaced as bounded `retryAfterSeconds` (never slept on -- an
 * absent one is `est/missing-retry-after`); 204/404 on `/csrattrs` is a
 * `none-available` verdict (an error on any other operation); 4xx/5xx surface
 * the capped diagnostic on `est/http-error`.
 *
 * @opts
 *   op: string   // the EST operation this response answers
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
    var re = CONTENT_TYPE_BY_OP[op];
    var ct = h["content-type"] || "";
    if (re && !re.test(ct)) throw E("est/bad-content-type", "a 200 " + op + " response must carry the expected content-type, got " + JSON.stringify(ct));
    return { status: "ok", contentType: ct };
  }
  if (status === 202) {
    var ra = h["retry-after"];
    if (ra === undefined || ra === null || String(ra).trim() === "") throw E("est/missing-retry-after", "an HTTP 202 EST response must include Retry-After (RFC 8951 sec. 3.3)");
    var secs = /^\d+$/.test(String(ra).trim()) ? parseInt(ra, 10) : null;
    return { status: "retry", retryAfterSeconds: secs, retryAfter: String(ra) };
  }
  if (status === 204 || status === 404) {
    if (op === "csrattrs") return { status: "none-available" };
    throw E("est/http-error", "HTTP " + status + " is not a valid " + op + " response");
  }
  if (status >= 300 && status < 400) return { status: "redirect", location: h["location"] || null };
  if (status >= 400) {
    var text = Buffer.isBuffer(body) ? body.toString("utf8") : String(body || "");
    throw E("est/http-error", "EST server returned HTTP " + status + (text ? ": " + text.slice(0, 512) : ""));
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
// RFC 9908 sec. 4). Unrecognized items are surfaced so an operator sees what was
// skipped.
function buildEnrollAttributes(csrattrsParsed) {
  var items = (csrattrsParsed && csrattrsParsed.items) || [];
  var template = null;
  for (var i = 0; i < items.length; i++) {
    if (items[i].kind === "attribute" && items[i].oid === OID_TEMPLATE) { template = items[i].template; break; }
  }
  if (template) return { fromTemplate: true, template: template, channelBindingRequired: false, unrecognized: [] };
  var plan = { fromTemplate: false, channelBindingRequired: false, keyType: null, extensions: null, unrecognized: [] };
  for (var j = 0; j < items.length; j++) {
    var it = items[j];
    if (it.oid === OID_CHALLENGE_PASSWORD) plan.channelBindingRequired = true;
    else if (it.kind === "attribute" && it.extensions) plan.extensions = it.extensions;
    else if (it.kind === "attribute" && (it.oid === OID_EC_PUBLIC_KEY || it.oid === OID_RSA_ENCRYPTION)) {
      // The non-template form carries EXACTLY ONE key-type attribute (RFC 9908
      // sec. 3.2); a second is an ambiguous server instruction, not a
      // last-one-wins override -- fail closed rather than pick a key type by order.
      if (plan.keyType) throw E("est/ambiguous-key-type", "a non-template CsrAttrs response must carry exactly one key-type attribute (RFC 9908 sec. 3.2)");
      plan.keyType = { type: it.name, curve: it.curve || null, keySize: it.keySize || null };
    }
    else if (it.name === null) plan.unrecognized.push(it.oid);
  }
  return plan;
}

var SAN_OID = oid.byName("subjectAltName");

// Pull the SubjectAltName extension's raw extnValue (the DER GeneralNames) off a
// parsed extension list -- a certificate's `.extensions` or a CSR's
// extensionRequest `.extensions` -- or null when no SAN is present.
function _sanValue(extList) {
  if (!Array.isArray(extList)) return null;
  for (var i = 0; i < extList.length; i++) {
    if (extList[i].oid === SAN_OID) return extList[i].value;
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
  var oldSan = _sanValue(oldCert.extensions);
  if (newCsrDer === undefined) return { subjectDn: oldSubjectDn, subject: oldSubject, subjectAltName: oldSan };
  var parsedCsr = csr.parse(newCsrDer);
  var subjectMatches = Buffer.isBuffer(oldSubjectBytes) && Buffer.isBuffer(parsedCsr.subject.bytes) && oldSubjectBytes.equals(parsedCsr.subject.bytes);
  if (!subjectMatches) throw E("est/reenroll-subject-mismatch", "a re-enroll CSR subject must be byte-identical to the certificate being renewed (RFC 7030 sec. 4.2.2)");
  var newSan = _sanValue(_csrRequestedExtensions(parsedCsr));
  var sanMatches = (oldSan === null && newSan === null) || (Buffer.isBuffer(oldSan) && Buffer.isBuffer(newSan) && oldSan.equals(newSan));
  if (!sanMatches) throw E("est/reenroll-san-mismatch", "a re-enroll CSR subjectAltName must be identical to the certificate being renewed (RFC 7030 sec. 4.2.2)");
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
