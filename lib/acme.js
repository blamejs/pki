// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.acme
 * @nav        Protocols
 * @title      ACME
 * @fullname   ACME (RFC 8555) certificate issuance
 * @order      20
 * @slug       acme
 *
 * @intro
 *   The RFC 8555 ACME message layer (updated by RFC 8737 tls-alpn-01, RFC 8738
 *   IP identifiers, and RFC 9773 ARI): object validators, request builders,
 *   challenge computations, and the ARI certID codec over the `pki.jose` JWS
 *   envelope. This is a MESSAGE LAYER, not an HTTP client: it owns the JWS
 *   construction/verification, the resource-object validation (closed status
 *   enums, conditional-required fields, immutable arrays), the three RFC 8555
 *   sec. 7.1.6 state machines, the challenge computations (key authorization,
 *   http-01, dns-01, tls-alpn-01), the identifier validators (`dns` / `ip` /
 *   wildcard), and the ARI certID, over an injectable transport.
 *
 *   Every resource object is validated by a declarative spec table (the JSON
 *   analog of the ASN.1 schema engine): one definition per surface drives both
 *   `validate(obj)` and the builders. Unknown fields are tolerated (ignored,
 *   never reflected); unknown challenge types are surfaced raw. Where ACME output
 *   re-enters the DER world (the finalize CSR, the downloaded certificate
 *   chain, the revokeCert payload, the ARI inputs), it routes through the shipped
 *   `pki.schema.csr` / `pki.schema.x509` parsers, so no new DER detector appears
 *   and the format-orchestrator's mutual-exclusion proof is untouched.
 *
 * @card
 *   RFC 8555 / 8737 / 8738 / 9773 ACME message layer: object validators, the
 *   three state machines, request builders, http-01 / dns-01 / tls-alpn-01
 *   challenge computations, and the ARI certID, over pki.jose, transport-injectable.
 */

var jose = require("./jose");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var csr = require("./schema-csr");
var pkix = require("./schema-pkix");
var constants = require("./constants");
var rfc3339 = require("./rfc3339");
var webcrypto = require("./webcrypto").webcrypto;
var subtle = webcrypto.subtle;
var frameworkError = require("./framework-error");
var httpTransport = require("./http-transport");
var retryAfter = require("./http-retry-after");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
// Membership is asked through an operation taken at load. Written out, the question reads two
// replaceable properties to answer one thing, and either answering wrongly changes whether a field
// counts as present in a document this client is deciding how to act on.
var _hasOwn = intrinsic.hasOwn;
// The operations the issued-certificate binding decides with, taken at load. That check runs on bytes
// a server chose, at a moment a caller controls, and it is the only thing standing between an
// enrollment and a certificate for someone else's name -- so what it decides with cannot be a property
// read when it runs. See guard-intrinsic for the whole captured set.
var _isBuffer = intrinsic.isBuffer;
var _isArrayI = intrinsic.isArray;
var _forEach = intrinsic.forEach;
var _mapI = intrinsic.map;
var _someI = intrinsic.some;
var _sortI = intrinsic.sort;
var _objectKeys = intrinsic.keys;
var _lower = intrinsic.toLowerCase;
var _StringI = intrinsic.String;
var _stringify = intrinsic.stringify;
var _push = intrinsic.push;
var _join = intrinsic.join;
var _concat = intrinsic.concat;
var _split = intrinsic.uncurry(String.prototype.split);
var _parseIntI = intrinsic.parseInt;
var _numToString = intrinsic.numberToString;
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var pkgVersion = require("../package.json").version;

// Charset tables + character-scan validators/trimmers replacing acme's rule-#11 regexes. The token / link-token
// tables feed pkix.allCharsIn (a NON-EMPTY string of only these characters); the rest scan by character code.
var _TOKEN_TABLE = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-");   // ^[A-Za-z0-9_-]
var _LINK_TOKEN_TABLE = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+.^_`|~-");   // RFC 7230 tchar
function _isHex1to4(s) {   // /^[0-9a-f]{1,4}$/
  var n = s.length;
  if (n < 1 || n > 4) return false;
  for (var i = 0; i < n; i++) { var c = _charCodeAt(s, i); if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102))) return false; }
  return true;
}
function _looksLikeIpv4(s) {   // /^\d{1,3}(\.\d{1,3}){3}$/ -- a loose dotted quad (octets are not range-checked)
  var n = s.length, i = 0, octet, d;
  for (octet = 0; octet < 4; octet++) {
    if (octet > 0) { if (i >= n || _charCodeAt(s, i) !== 0x2e) return false; i++; }
    for (d = 0; i < n && _charCodeAt(s, i) >= 48 && _charCodeAt(s, i) <= 57 && d < 3; d++) i++;
    if (d < 1) return false;
  }
  return i === n;
}
function _countAtSigns(s) { var c = 0; for (var i = 0; i < s.length; i++) { if (_charCodeAt(s, i) === 0x40) c++; } return c; }   // (s.match(/@/g)||[]).length
function _stripLeadingOWS(s, from) {   // s.slice(from).replace(/^[ \t]+/, "")
  var i = from;
  while (i < s.length && (_charCodeAt(s, i) === 0x20 || _charCodeAt(s, i) === 0x09)) i++;
  return _strSlice(s, i);
}
function _stripTrailingSlash(s) {   // s.replace(/\/+$/, "")
  var end = s.length;
  while (end > 0 && _charCodeAt(s, end - 1) === 0x2f) end--;
  return _strSlice(s, 0, end);
}
// /^(?:[^"\\]|\\.)*$/ : a valid quoted-string interior -- no unescaped '"', every '\' escapes a following
// NON-line-terminator character (the regex '.' matches no line terminator), and no dangling final '\'.
function _isValidQuotedInterior(s) {
  var i = 0, n = s.length;
  while (i < n) {
    var c = _charCodeAt(s, i);
    if (c === 0x22) return false;
    if (c === 0x5c) {
      if (i + 1 >= n) return false;
      var nx = _charCodeAt(s, i + 1);
      if (nx === 0x0a || nx === 0x0d || nx === 0x2028 || nx === 0x2029) return false;
      i += 2;
    } else i += 1;
  }
  return true;
}
// Shared character predicates for the scheme / label / URL scans below.
function _isAlpha(c) { return (c >= 65 && c <= 90) || (c >= 97 && c <= 122); }
function _isAlnumLower(c) { return (c >= 97 && c <= 122) || (c >= 48 && c <= 57); }
function _isSchemeChar(c) { return _isAlpha(c) || (c >= 48 && c <= 57) || c === 0x2b || c === 0x2e || c === 0x2d; }   // [A-Za-z0-9+.-]
// /^https?:\/\/[^\s]+$/ : lowercase http(s), "://", then >=1 non-whitespace character to the end.
function _isHttpUrlShape(v) {
  var n = v.length;
  if (!(_charCodeAt(v, 0) === 0x68 && _charCodeAt(v, 1) === 0x74 && _charCodeAt(v, 2) === 0x74 && _charCodeAt(v, 3) === 0x70)) return false;
  var i = 4;
  if (_charCodeAt(v, i) === 0x73) i++;
  if (_charCodeAt(v, i) !== 0x3a || _charCodeAt(v, i + 1) !== 0x2f || _charCodeAt(v, i + 2) !== 0x2f) return false;
  i += 3;
  if (i >= n) return false;
  for (; i < n; i++) { if (pkix.isJsWhitespace(_charCodeAt(v, i))) return false; }
  return true;
}
// /^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]+$/ : an RFC 3986 scheme, ":", then >=1 non-whitespace character to the end.
function _isUriShape(v) {
  var n = v.length;
  if (n === 0 || !_isAlpha(_charCodeAt(v, 0))) return false;
  var i = 1;
  while (i < n && _isSchemeChar(_charCodeAt(v, i))) i++;
  if (i >= n || _charCodeAt(v, i) !== 0x3a) return false;
  i++;
  if (i >= n) return false;
  for (; i < n; i++) { if (pkix.isJsWhitespace(_charCodeAt(v, i))) return false; }
  return true;
}
// /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/ : a DNS label -- first and last characters alphanumeric-lowercase, the
// interior characters additionally allowing '-'.
function _isLdhLabel(l) {
  var n = l.length;
  if (n === 0 || !_isAlnumLower(_charCodeAt(l, 0)) || !_isAlnumLower(_charCodeAt(l, n - 1))) return false;
  for (var i = 1; i < n - 1; i++) { var c = _charCodeAt(l, i); if (!(_isAlnumLower(c) || c === 0x2d)) return false; }
  return true;
}
// /^xn--[a-z0-9]+(-[a-z0-9]+)*$/ : an A-label -- "xn--" then hyphen-separated non-empty alphanumeric-lowercase runs.
function _isXnLabel(l) {
  var n = l.length;
  if (!(n >= 4 && _charCodeAt(l, 0) === 0x78 && _charCodeAt(l, 1) === 0x6e && _charCodeAt(l, 2) === 0x2d && _charCodeAt(l, 3) === 0x2d)) return false;
  var i = 4, g = 0;
  while (i < n && _isAlnumLower(_charCodeAt(l, i))) { i++; g++; }
  if (g < 1) return false;
  while (i < n) {
    if (_charCodeAt(l, i) !== 0x2d) return false;
    i++; var g2 = 0;
    while (i < n && _isAlnumLower(_charCodeAt(l, i))) { i++; g2++; }
    if (g2 < 1) return false;
  }
  return true;
}
// /^(0|[1-9]\d{0,2})$/ : a canonical decimal octet -- a single digit, or 2-3 digits with no leading zero.
function _isCanonicalOctet(s) {
  var n = s.length;
  if (n === 0 || n > 3) return false;
  if (n === 1) { var c0 = _charCodeAt(s, 0); return c0 >= 48 && c0 <= 57; }
  if (!(_charCodeAt(s, 0) >= 49 && _charCodeAt(s, 0) <= 57)) return false;
  for (var i = 1; i < n; i++) { var c = _charCodeAt(s, i); if (!(c >= 48 && c <= 57)) return false; }
  return true;
}
// /[\s\\]/ : contains a whitespace character or a backslash.
function _hasWsOrBackslash(s) {
  for (var i = 0; i < s.length; i++) { var c = _charCodeAt(s, i); if (c === 0x5c || pkix.isJsWhitespace(c)) return true; }
  return false;
}
// /^[A-Za-z][A-Za-z0-9+.-]*:/ : begins with an RFC 3986 scheme followed by ':' (a prefix test, not anchored at end).
function _hasSchemePrefix(uri) {
  var n = uri.length;
  if (n === 0 || !_isAlpha(_charCodeAt(uri, 0))) return false;
  var i = 1;
  while (i < n && _isSchemeChar(_charCodeAt(uri, i))) i++;
  return i < n && _charCodeAt(uri, i) === 0x3a;
}
// uri.split(/[/?#]/)[0] : the substring up to the first '/', '?', or '#' (the whole string if none).
function _uriFirstSegment(uri) {
  for (var i = 0; i < uri.length; i++) { var c = _charCodeAt(uri, i); if (c === 0x2f || c === 0x3f || c === 0x23) return _strSlice(uri, 0, i); }
  return uri;
}
// Does `s` end with the literal `suffix`? (/suffix$/ for a fixed suffix.)
function _endsWith(s, suffix) {
  var n = s.length, m = suffix.length;
  if (m > n) return false;
  for (var i = 0; i < m; i++) { if (_charCodeAt(s, n - m + i) !== _charCodeAt(suffix, i)) return false; }
  return true;
}

var AcmeError = frameworkError.AcmeError;
function E(code, message, cause) { return new AcmeError(code, message, cause); }

// ---- helpers -------------------------------------------------------------

function _isObject(v) { return v && typeof v === "object" && !Array.isArray(v); }
function _isString(v) { return typeof v === "string"; }
// RFC 3339 date-time validity (grammar + calendar) lives in the shared lib/rfc3339.js primitive so a
// downstream expiry / renewal-window comparison never runs on an impossible instant (month 13, a :60
// leap second, a rolled-over value). pki.ct's log-list window parse composes the same primitive.
function _isRfc3339(v) { return rfc3339.isValid(v); }
// A uniform random draw in [0, 1) from the platform CSPRNG (48 bits of entropy). Its only use is spreading
// the ARI renewal instant across the CA's suggested window (RFC 9773 sec. 4.2) so many clients do not
// stampede the same edge: a load-distribution measure, not a secret. Injectable via renewalWindow opts.random.
var _RANDOM_DENOM = Math.pow(2, 48);   // 6 bytes -> a uniform fraction in [0, 1)
function _defaultRandom() { return Buffer.from(webcrypto.getRandomValues(new Uint8Array(6))).readUIntBE(0, 6) / _RANDOM_DENOM; }
// RFC 9773 sec. 4.3.2: the ARI Retry-After bounds the re-poll cadence, so clamp it to [60s, 24h] and a
// hostile (or absent) value can neither hammer the CA nor defer the next check indefinitely. When the CA
// omits Retry-After (permitted), the decision helper still owes the caller a poll interval, so it returns a
// reasonable default in-range (sec. 4.3.2 "the client SHOULD use a reasonable default"), never null.
var RENEWAL_RETRY_MIN_SECONDS = 60;
var RENEWAL_RETRY_MAX_SECONDS = constants.TIME.days(1) / constants.TIME.seconds(1);
var RENEWAL_RETRY_DEFAULT_SECONDS = constants.TIME.hours(6) / constants.TIME.seconds(1);
// A URL string: an absolute http(s) URI with a real host (RFC 3986). ACME URLs are
// server-provided endpoints downstream transport will trust, so they are PARSED
// (not prefix-matched), so a malformed value like "https://[" or a hostless
// "http://" is rejected, not accepted by a loose regex.
function _isUrl(v) {
  // Prefilter the exact authority form with no whitespace before parsing: new URL()
  // silently repairs " https://.." (trim) and "https:host/.." (insert //), and the
  // original string is what gets copied into a protected `url` field, so a repaired
  // value must be rejected here, never accepted and mismatched at transport time.
  if (!_isString(v) || !_isHttpUrlShape(v)) return false;
  var u;
  // A parse failure is the "not a URL" verdict for this boolean predicate. There
  // is no PkiError here to thread a cause into, so the error is intentionally ignored.
  try { u = new URL(v); }
  catch (_e) { return false; }
  return (u.protocol === "http:" || u.protocol === "https:") && u.hostname.length > 0;
}
// A URI string with any RFC 3986 scheme (mailto:, tel:, http(s):, ...). An account
// `contact` is a URI, most commonly `mailto:` (RFC 8555 sec. 7.1.2 / RFC 6068), so
// it must not be narrowed to http(s); the strict mailto hygiene lives in the builder.
function _isUriString(v) { return _isString(v) && _isUriShape(v); }

// ---- resource object specs (RFC 8555 sec. 7.1.x) -------------------------

// Each field: { name, type, required?, requiredWhen?(obj), enum?, elemType? }.
// type: "string" | "url" | "rfc3339" | "boolean" | "object" | "array" | "any".
// The walker validates presence and shape only; unknown fields are ignored (never
// reflected). requiredWhen is the conditional-required rule (sec. 7.1.3 expires).
// The assigned RFC 5280 sec. 5.3.1 CRLReason values (0-6, 8-10). Value 7 is
// unassigned, so a revokeCert reason of 7 is rejected, never sent.
var CRL_REASONS = [0, 1, 2, 3, 4, 5, 6, 8, 9, 10];

// The registered challenge types (RFC 8555 sec. 8.3/8.4, RFC 8737). For these the
// `token` is a required, entropy-bearing base64url value; an unknown future type
// may define its own response fields, so `token` is only required for these.
var KNOWN_CHALLENGE_TYPES = { "http-01": 1, "dns-01": 1, "tls-alpn-01": 1 };

var STATUS = {
  account:       ["valid", "deactivated", "revoked"],
  order:         ["pending", "ready", "processing", "valid", "invalid"],
  authorization: ["pending", "valid", "invalid", "deactivated", "expired", "revoked"],
  challenge:     ["pending", "processing", "valid", "invalid"],
};

var SPECS = {
  directory: [
    { name: "newNonce", type: "url", required: true },
    { name: "newAccount", type: "url", required: true },
    { name: "newOrder", type: "url", required: true },
    { name: "revokeCert", type: "url", required: true },
    { name: "keyChange", type: "url", required: true },
    { name: "newAuthz", type: "url" },
    { name: "renewalInfo", type: "url" },
    { name: "meta", type: "object" },
  ],
  account: [
    { name: "status", type: "string", required: true, enum: STATUS.account },
    { name: "contact", type: "array", elemType: "contact" },
    { name: "termsOfServiceAgreed", type: "boolean" },
    { name: "externalAccountBinding", type: "object" },
    { name: "orders", type: "url" },   // required per RFC; lenient by default (OQ2)
  ],
  order: [
    { name: "status", type: "string", required: true, enum: STATUS.order },
    { name: "expires", type: "rfc3339", requiredWhen: function (o) { return o.status === "pending" || o.status === "valid"; } },
    { name: "identifiers", type: "array", required: true, minItems: 1, elemType: "orderIdentifier" },
    { name: "notBefore", type: "rfc3339" },
    { name: "notAfter", type: "rfc3339" },
    { name: "error", type: "object" },
    { name: "authorizations", type: "array", required: true, minItems: 1, elemType: "url" },
    { name: "finalize", type: "url", required: true },
    { name: "certificate", type: "url" },
    { name: "replaces", type: "string" },
  ],
  authorization: [
    { name: "identifier", type: "identifier", required: true },
    { name: "status", type: "string", required: true, enum: STATUS.authorization },
    { name: "expires", type: "rfc3339", requiredWhen: function (o) { return o.status === "valid"; } },
    // challenges is required (the key is present) but MAY be empty for an already-"valid" authorization the CA
    // granted out of band (RFC 8555 sec. 7.1.4 / 7.4.1, where no challenge was validated); a pending/other authz still
    // needs at least the one challenge the client fulfills.
    { name: "challenges", type: "array", required: true, minItems: function (o) { return o.status === "valid" ? 0 : 1; }, elemType: "challenge" },
    { name: "wildcard", type: "boolean" },
  ],
  challenge: [
    { name: "type", type: "string", required: true },
    { name: "url", type: "url", required: true },
    { name: "status", type: "string", required: true, enum: STATUS.challenge },
    { name: "validated", type: "rfc3339", requiredWhen: function (o) { return o.status === "valid"; } },
    { name: "token", type: "token", requiredWhen: function (o) { return KNOWN_CHALLENGE_TYPES[o.type] === 1; } },
    { name: "error", type: "object" },
  ],
  renewalInfo: [
    { name: "suggestedWindow", type: "object", required: true },
    { name: "explanationURL", type: "url" },
  ],
  ordersList: [
    { name: "orders", type: "array", required: true, elemType: "url" },   // RFC 8555 sec. 7.1.2.1 -- an array of order URLs
  ],
};

function _checkType(kind, field, value, obj) {
  switch (field.type) {
    case "string": if (!_isString(value)) return "must be a string"; break;
    case "url": if (!_isUrl(value)) return "must be a URL string"; break;
    case "rfc3339": if (!_isRfc3339(value)) return "must be an RFC 3339 date-time"; break;
    case "boolean": if (typeof value !== "boolean") return "must be a boolean"; break;
    case "token": _assertToken(value); break;   // >= 22 base64url chars, no padding (throws acme/bad-token)
    case "object": if (!_isObject(value)) return "must be an object"; break;
    case "identifier": _validateIdentifier(value); break;
    case "array":
      if (!Array.isArray(value)) return "must be an array";
      var minItems = typeof field.minItems === "function" ? field.minItems(obj) : field.minItems;   // conditional (sec. 7.1.4)
      if (minItems && value.length < minItems) return "must have at least " + minItems + " element(s)";
      for (var i = 0; i < value.length; i++) {
        if (field.elemType === "url" && !_isUrl(value[i])) return "element " + i + " must be a URL string";
        if (field.elemType === "contact" && !_isUriString(value[i])) return "element " + i + " must be a URI string";
        if (field.elemType === "identifier") _validateIdentifier(value[i]);
        if (field.elemType === "orderIdentifier") _validateOrderIdentifier(value[i]);
        if (field.elemType === "challenge") _validate("challenge", value[i]);
        if (field.elemType === "object" && !_isObject(value[i])) return "element " + i + " must be an object";
      }
      break;
    default: break; // "any"
  }
  return null;
}

// A kind name kebab-cased for use in an error code (the code shape is strict
// lowercase-kebab): a camelCase kind like "renewalInfo" must become
// "renewal-info", never leak "acme/bad-renewalInfo" (which the PkiError code
// validator rejects, turning a fault into a raw TypeError).
function _codeSlug(kind) {   // camelCase -> kebab-case: kind.replace(/([A-Z])/g, "-$1").toLowerCase()
  var out = "";
  for (var i = 0; i < kind.length; i++) { var c = _charCodeAt(kind, i); if (c >= 65 && c <= 90) out += "-"; out += _charAt(kind, i); }
  return _lower(out);
}

// Validate an object against a spec table. Returns the object; throws acme/*.
function _validate(kind, obj) {
  if (!_isObject(obj)) throw E("acme/bad-" + _codeSlug(kind), "an ACME " + kind + " must be a JSON object");
  var spec = SPECS[kind];
  for (var f = 0; f < spec.length; f++) {
    var field = spec[f];
    var present = _hasOwn(obj, field.name);
    var required = field.required || (field.requiredWhen && field.requiredWhen(obj));
    if (!present) {
      if (required) throw E("acme/missing-field", "an ACME " + kind + " is missing the required field " + JSON.stringify(field.name));
      continue;
    }
    if (field.enum && field.enum.indexOf(obj[field.name]) === -1) {
      throw E("acme/bad-status", "the " + kind + " " + field.name + " " + JSON.stringify(obj[field.name]) + " is not a recognized value");
    }
    var err = _checkType(kind, field, obj[field.name], obj);
    if (err) throw E("acme/bad-" + _codeSlug(kind), "the " + kind + " field " + JSON.stringify(field.name) + " " + err);
  }
  return obj;
}

// ---- identifiers (dns / ip; RFC 8555 sec. 7.1.4 / RFC 8738) --------------

// A dns identifier value: lowercase LDH ASCII labels (A-labels; a leading `*.`
// wildcard is validated by the ORDER path, never here). An ip identifier value:
// the RFC 5952 (IPv6) / RFC 1123 (IPv4) canonical textual form, byte-identical
// round-trip. `_validateIdentifier` rejects a value beginning `*.` (that is only
// legal in an order identifier, checked separately).
function _validateIdentifier(id) {
  if (!_isObject(id)) throw E("acme/bad-identifier", "an identifier must be { type, value } strings");
  var type = id.type, value = id.value;   // read each field ONCE (a getter-backed / inherited prop is captured here)
  if (!_isString(type) || !_isString(value)) throw E("acme/bad-identifier", "an identifier must be { type, value } strings");
  if (type === "dns") {
    if (value.indexOf("*.") === 0) throw E("acme/bad-identifier", "a wildcard *. value is not permitted in an authorization identifier (RFC 8555 sec. 7.1.4)");
    _assertDnsName(value);
  } else if (type === "ip") {
    _assertIpAddress(value);
  }
  // Return a canonical { type, value } built from the single read above; an unrecognized type is surfaced raw
  // (a server may add types). Callers serialize this object, not the caller's, so an inherited/getter-backed field
  // is not dropped by JSON.stringify and an enumerable extra property is not sent to the CA.
  return { type: type, value: value };
}

// A DNS name (each label lowercase letters/digits/hyphen, not leading/trailing
// hyphen; an xn-- A-label must be well-formed). Uppercase / non-ASCII rejected
// (the client sends A-labels only).
function _assertDnsName(name) {
  if (!_isString(name)) throw E("acme/bad-identifier", "a dns identifier value must be a string");
  if (name.length === 0 || name.length > 253) throw E("acme/bad-identifier", "a dns identifier value must be 1..253 characters");
  var labels = name.split(".");
  for (var i = 0; i < labels.length; i++) {
    var l = labels[i];
    if (l.length > 63) throw E("acme/bad-identifier", "a dns label must be 1..63 characters (RFC 1035 sec. 2.3.4): " + JSON.stringify(l));
    if (!_isLdhLabel(l)) throw E("acme/bad-identifier", "a dns label must be lowercase LDH ASCII (A-label): " + JSON.stringify(l));
    if (l.indexOf("xn--") === 0 && !_isXnLabel(l)) throw E("acme/bad-identifier", "a malformed xn-- A-label: " + JSON.stringify(l));
  }
}

// An IP address in canonical text (RFC 8738 sec. 3): IPv4 dotted-decimal with no
// leading zeros, or IPv6 in the RFC 5952 sec. 4 compressed lowercase form. The
// only accepted form is the one that round-trips byte-identically; an ambiguous
// value (leading zeros, uppercase hex, an uncompressed run) is rejected, never
// normalized-and-guessed.
function _assertIpAddress(value) {
  if (!_isString(value)) throw E("acme/bad-identifier", "an ip identifier value must be a string");
  if (_looksLikeIpv4(value)) {
    var parts = value.split(".");
    for (var i = 0; i < 4; i++) {
      if (!_isCanonicalOctet(parts[i]) || parseInt(parts[i], 10) > 255) throw E("acme/bad-identifier", "an ip identifier IPv4 octet is out of range or non-canonical: " + JSON.stringify(value));
    }
    return;
  }
  if (value.indexOf(":") !== -1) {
    if (value !== value.toLowerCase()) throw E("acme/bad-identifier", "an IPv6 ip identifier must be lowercase (RFC 5952)");
    var canon = _canonicalizeIpv6(value);
    if (canon === null || canon !== value) throw E("acme/bad-identifier", "an ip identifier must be the RFC 5952 canonical IPv6 form: " + JSON.stringify(value));
    return;
  }
  throw E("acme/bad-identifier", "an ip identifier value must be an IPv4 or IPv6 textual address (RFC 8738 sec. 3)");
}

// Parse an IPv6 address to its 8 groups then re-emit the RFC 5952 canonical form
// (lowercase, no leading zeros, the longest zero-run compressed with `::`, the
// leftmost when tied, never a single 0 group). Returns null on a malformed input.
function _canonicalizeIpv6(value) {
  var groups;
  if (value.indexOf("::") !== -1) {
    if (value.indexOf("::") !== value.lastIndexOf("::")) return null;   // only one ::
    var halves = _split(value, "::");
    var left = halves[0] ? _split(halves[0], ":") : [];
    var right = halves[1] ? _split(halves[1], ":") : [];
    var fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    var zeros = [];
    for (var z = 0; z < fill; z++) _push(zeros, "0");
    groups = _concat(_concat(left, zeros), right);
  } else {
    groups = _split(value, ":");
  }
  if (groups.length !== 8) return null;
  var nums = [];
  for (var i = 0; i < 8; i++) {
    if (!_isHex1to4(groups[i])) return null;
    _push(nums, _parseIntI(groups[i], 16));
  }
  var hex = _mapI(nums, function (n) { return _numToString(n, 16); });
  // Longest run of zero groups (>= 2) -> "::"; leftmost on a tie.
  var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (var g = 0; g < 8; g++) {
    if (nums[g] === 0) { if (curStart === -1) curStart = g; curLen++; if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; } }
    else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) return _join(hex, ":");
  var head = _join(intrinsic.arraySlice(hex, 0, bestStart), ":");
  var tail = _join(intrinsic.arraySlice(hex, bestStart + bestLen), ":");
  return head + "::" + tail;
}

// ---- state machines (RFC 8555 sec. 7.1.6) --------------------------------

// Legal transitions as data. An observed transition outside the set is an
// illegal server transition the client fails closed on (acme/bad-transition).
var TRANSITIONS = {
  challenge:     { pending: ["processing", "valid", "invalid"], processing: ["processing", "valid", "invalid"] },
  authorization: { pending: ["valid", "invalid", "deactivated"], valid: ["expired", "deactivated", "revoked"] },
  order:         { pending: ["ready", "invalid"], ready: ["processing", "valid", "invalid"], processing: ["valid", "invalid"] },
};

/**
 * @primitive  pki.acme.assertTransition
 * @signature  pki.acme.assertTransition(kind, from, to) -> void
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.validate
 *
 * Assert that a status transition of an ACME resource (`kind` =
 * `"challenge"|"authorization"|"order"`) from `from` to `to` is one of the
 * RFC 8555 sec. 7.1.6 legal edges. A same-status observation is allowed (a
 * server may re-report); any other edge throws `acme/bad-transition`.
 *
 * @example
 *   pki.acme.assertTransition("order", "pending", "ready");   // ok
 */
function assertTransition(kind, from, to) {
  var table = TRANSITIONS[kind];
  if (!table) throw E("acme/bad-input", "unknown resource kind " + JSON.stringify(kind));
  if (from === to) return;
  // The legal edges -- including every non-terminal state's edge to "invalid" -- are
  // the table. A terminal "valid" order/challenge has NO outgoing edge, so a
  // "valid" -> "invalid" regression is rejected (RFC 8555 sec. 7.1.6 makes valid
  // terminal; a client failing closed while polling must not accept it).
  var allowed = table[from];
  if (!allowed || allowed.indexOf(to) === -1) throw E("acme/bad-transition", "illegal " + kind + " transition " + JSON.stringify(from) + " -> " + JSON.stringify(to) + " (RFC 8555 sec. 7.1.6)");
}

// ---- problem documents (RFC 7807 / RFC 8555 sec. 6.7) --------------------

var ERROR_NAMESPACE = "urn:ietf:params:acme:error:";

/**
 * @primitive  pki.acme.validateProblem
 * @signature  pki.acme.validateProblem(obj) -> obj
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555, RFC 7807, RFC 9773
 * @related    pki.acme.validate
 *
 * Validate an ACME problem document (RFC 7807 + RFC 8555 sec. 6.7): a `type` in
 * the `urn:ietf:params:acme:error:` namespace, an optional `detail`, and
 * `subproblems` (each itself a problem document, optionally carrying an
 * `identifier`). A top-level `identifier` is forbidden (sec. 6.7.1) and throws
 * `acme/bad-problem`. Returns the object.
 *
 * @example
 *   pki.acme.validateProblem({ type: "urn:ietf:params:acme:error:malformed" });
 */
function validateProblem(obj) {
  if (!_isObject(obj)) throw E("acme/bad-problem", "a problem document must be a JSON object");
  if (_hasOwn(obj, "identifier")) throw E("acme/bad-problem", "a top-level problem document must not carry an identifier (RFC 8555 sec. 6.7.1)");
  if (!_isString(obj.type) || obj.type.indexOf(ERROR_NAMESPACE) !== 0) throw E("acme/bad-problem", "an ACME problem type must be in the " + ERROR_NAMESPACE + " namespace (RFC 8555 sec. 6.7)");
  if (_hasOwn(obj, "subproblems")) {
    if (!Array.isArray(obj.subproblems)) throw E("acme/bad-problem", "subproblems must be an array");
    for (var i = 0; i < obj.subproblems.length; i++) {
      var sub = obj.subproblems[i];
      if (!_isObject(sub) || !_isString(sub.type) || sub.type.indexOf(ERROR_NAMESPACE) !== 0) throw E("acme/bad-problem", "each subproblem must be an ACME problem document in the error namespace");
      // A subproblem identifier reflects a submitted order identifier, which MAY be a
      // wildcard (a rejectedIdentifier for a *.example.org order), so it is validated
      // with the order-identifier rule, not the stricter authorization one.
      if (_hasOwn(sub, "identifier")) _validateOrderIdentifier(sub.identifier);
    }
  }
  return obj;
}

// ---- object validators + identify ----------------------------------------

/**
 * @primitive  pki.acme.validate
 * @signature  pki.acme.validate(kind, obj) -> obj
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555, RFC 9773
 * @related    pki.acme.identify, pki.acme.validateProblem
 *
 * Validate an ACME resource object of a known `kind` (`"directory"` |
 * `"account"` | `"order"` | `"authorization"` | `"challenge"` | `"renewalInfo"`)
 * against its RFC 8555 / RFC 9773 spec: required and conditionally-required
 * fields, closed status enums, URL / RFC 3339 / identifier shapes, and array
 * minimums. Unknown fields are ignored (never reflected). Throws a typed
 * `acme/*` fault; returns the object.
 *
 * @example
 *   var orderObj = { status: "pending", expires: "2026-02-01T00:00:00Z",
 *     identifiers: [{ type: "dns", value: "example.org" }],
 *     authorizations: ["https://ca.example/authz/1"],
 *     finalize: "https://ca.example/order/1/finalize" };
 *   pki.acme.validate("order", orderObj).status;   // -> "pending"
 */
function validate(kind, obj) {
  if (kind === "problem") return validateProblem(obj);
  // renewalInfo carries an RFC 9773 window sanity check beyond the spec shape, so a
  // generic dispatch (identify -> validate) gets the SAME strictness as a direct
  // validateRenewalInfo call -- an inverted / malformed suggestedWindow is rejected.
  if (kind === "renewalInfo") return validateRenewalInfo(obj);
  if (!SPECS[kind]) throw E("acme/bad-input", "unknown ACME object kind " + JSON.stringify(kind));
  return _validate(kind, obj);
}

/**
 * @primitive  pki.acme.identify
 * @signature  pki.acme.identify(obj) -> string
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555, RFC 9773
 * @related    pki.acme.validate
 *
 * Classify an ACME JSON object into exactly one kind by its discriminating
 * member set -- `"jws"`, `"problem"`, `"directory"`, `"order"`, `"authorization"`,
 * `"challenge"`, `"account"`, `"renewalInfo"`, or `"unknown"`. The discriminators
 * are proven mutually exclusive; a DER structure identifies as `"unknown"`.
 *
 * @example
 *   var orderObj = { status: "pending", expires: "2026-02-01T00:00:00Z",
 *     identifiers: [{ type: "dns", value: "example.org" }],
 *     authorizations: ["https://ca.example/authz/1"],
 *     finalize: "https://ca.example/order/1/finalize" };
 *   pki.acme.identify(orderObj);   // -> "order"
 */
function identify(obj) {
  if (!_isObject(obj)) return "unknown";
  var has = function (k) { return _hasOwn(obj, k); };
  if (has("protected") && has("signature") && _isString(obj.protected) && _isString(obj.signature)) return "jws";
  if (_isString(obj.type) && obj.type.indexOf(ERROR_NAMESPACE) === 0) return "problem";
  if (has("newNonce") && has("newAccount")) return "directory";
  if (has("suggestedWindow")) return "renewalInfo";
  if (has("finalize") && has("authorizations")) return "order";
  if (has("identifier") && has("challenges")) return "authorization";
  if (has("type") && has("url") && has("token") && !has("identifier")) return "challenge";
  if (has("status") && (has("orders") || has("contact") || has("termsOfServiceAgreed"))) return "account";
  return "unknown";
}

// ---- challenge computations (RFC 8555 sec. 8 / 8737 / 8738) --------------

// A challenge token: >= 128 bits of entropy => >= 22 base64url chars, alphabet
// only, no `=` (RFC 8555 sec. 8, errata 6950). Validated BEFORE any use (also the
// http-01 reflection-XSS guard).
function _assertToken(token) {
  if (!_isString(token) || token.length < constants.LIMITS.ACME_TOKEN_MIN_CHARS || !pkix.allCharsIn(token, _TOKEN_TABLE)) throw E("acme/bad-token", "a challenge token must be >= " + constants.LIMITS.ACME_TOKEN_MIN_CHARS + " base64url characters with no padding (RFC 8555 sec. 8)");
}

async function _sha256(bytes) { return Buffer.from(await subtle.digest("SHA-256", bytes)); }

/**
 * @primitive  pki.acme.keyAuthorization
 * @signature  pki.acme.keyAuthorization(token, accountJwk) -> Promise<string>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555, RFC 7638
 * @related    pki.acme.http01, pki.acme.dns01, pki.acme.tlsAlpn01Extension
 *
 * The RFC 8555 sec. 8.1 key authorization: `token || '.' ||
 * base64url(SHA-256 JWK thumbprint of the account key)`. The token is validated
 * (entropy floor + alphabet) first; the thumbprint is the RFC 7638 canonical
 * digest, so changing the account key changes the key authorization.
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var accountJwk = await pki.webcrypto.subtle.exportKey("jwk", ec.publicKey);
 *   var token = "example-challenge-token-not-a-secret";   // the real one comes from the CA
 *   await pki.acme.keyAuthorization(token, accountJwk);   // -> "<token>.<thumbprint>"
 */
async function keyAuthorization(token, accountJwk) {
  _assertToken(token);
  var tp = await jose.thumbprint(accountJwk);
  return token + "." + tp;
}

/**
 * @primitive  pki.acme.http01
 * @signature  pki.acme.http01(token, accountJwk) -> Promise<{ path, body }>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.keyAuthorization
 *
 * The http-01 challenge computation (RFC 8555 sec. 8.3): the resource `path`
 * `/.well-known/acme-challenge/<token>` and the `body` (the ASCII key
 * authorization, no trailing newline). Validation reaches TCP port 80 over HTTP.
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var accountJwk = await pki.webcrypto.subtle.exportKey("jwk", ec.publicKey);
 *   var token = "example-challenge-token-not-a-secret";
 *   var c = await pki.acme.http01(token, accountJwk);
 *   c.path;   // -> "/.well-known/acme-challenge/<token>"
 */
async function http01(token, accountJwk) {
  var ka = await keyAuthorization(token, accountJwk);
  return { path: "/.well-known/acme-challenge/" + token, body: ka };
}

/**
 * @primitive  pki.acme.dns01
 * @signature  pki.acme.dns01(token, accountJwk, domain) -> Promise<{ name, value }>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.keyAuthorization
 *
 * The dns-01 challenge computation (RFC 8555 sec. 8.4): the TXT record `name`
 * `_acme-challenge.<domain>` (exactly one leading `*.` is stripped for a wildcard
 * order) and the `value` `base64url(SHA-256(keyAuthorization))`.
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var accountJwk = await pki.webcrypto.subtle.exportKey("jwk", ec.publicKey);
 *   var token = "example-challenge-token-not-a-secret";
 *   var r = await pki.acme.dns01(token, accountJwk, "example.org");
 *   r.name;   // -> "_acme-challenge.example.org"
 */
async function dns01(token, accountJwk, domain) {
  if (!_isString(domain)) throw E("acme/bad-identifier", "dns01 requires a domain string");
  var base = domain.indexOf("*.") === 0 ? domain.slice(2) : domain;
  _assertDnsName(base);
  var ka = await keyAuthorization(token, accountJwk);
  return { name: "_acme-challenge." + base, value: jose.base64url.encode(await _sha256(Buffer.from(ka, "ascii"))) };
}

var OID_ACME_IDENTIFIER = oid.byName("acmeIdentifier");
var OID_SAN = oid.byName("subjectAltName");
var OID_AKI = oid.byName("authorityKeyIdentifier");
var OID_CN = oid.byName("commonName");
var _extNs = pkix.makeNS("acme", AcmeError, oid);
var _extDecoders = pkix.certExtensionDecoders(_extNs);
var _extCtx = { E: function (c, m, cause) { return new AcmeError(c, m, cause); }, oid: oid };

/**
 * @primitive  pki.acme.tlsAlpn01Extension
 * @signature  pki.acme.tlsAlpn01Extension(token, accountJwk) -> Promise<Buffer>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8737
 * @related    pki.acme.verifyTlsAlpn01
 *
 * Build the DER of the critical `id-pe-acmeIdentifier` extension (RFC 8737
 * sec. 3): `SEQUENCE { extnID 1.3.6.1.5.5.7.1.31, critical TRUE, extnValue OCTET
 * STRING wrapping Authorization ::= OCTET STRING (SIZE 32) of the
 * SHA-256(keyAuthorization) }`. Placed in the validation certificate.
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var accountJwk = await pki.webcrypto.subtle.exportKey("jwk", ec.publicKey);
 *   var token = "example-challenge-token-not-a-secret";
 *   var extDer = await pki.acme.tlsAlpn01Extension(token, accountJwk);
 */
async function tlsAlpn01Extension(token, accountJwk) {
  var ka = await keyAuthorization(token, accountJwk);
  var digest = await _sha256(Buffer.from(ka, "ascii"));            // 32 bytes
  var authorization = asn1.build.octetString(digest);              // Authorization ::= OCTET STRING (SIZE 32)
  var extnValue = asn1.build.octetString(authorization);
  return asn1.build.sequence([asn1.build.oid(OID_ACME_IDENTIFIER), asn1.build.boolean(true), extnValue]);
}

// The 32-byte Authorization digest inside an acmeIdentifier extnValue, or throw.
function _readAcmeIdentifier(extnValue) {
  var auth;
  try { auth = asn1.read.octetString(asn1.decode(extnValue)); }
  catch (e) { throw E("acme/bad-tlsalpn", "the acmeIdentifier extnValue is not a well-formed Authorization OCTET STRING", e); }
  if (auth.length !== 32) throw E("acme/bad-tlsalpn", "the acmeIdentifier Authorization must be exactly 32 octets (RFC 8737 sec. 3)");
  return auth;
}

/**
 * @primitive  pki.acme.verifyTlsAlpn01
 * @signature  pki.acme.verifyTlsAlpn01(certDer, token, accountJwk, identifier) -> Promise<void>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8737, RFC 8738
 * @related    pki.acme.tlsAlpn01Extension
 *
 * Verify a tls-alpn-01 validation certificate (RFC 8737 sec. 3): a critical
 * `id-pe-acmeIdentifier` extension whose 32-octet Authorization equals
 * SHA-256(keyAuthorization), plus a SubjectAltName with exactly one entry, either a
 * dNSName equal to the `dns` identifier (case-insensitive) or a single iPAddress
 * for an `ip` identifier (RFC 8738 sec. 6). Any deviation throws `acme/bad-tlsalpn`.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var accountJwk = await pki.webcrypto.subtle.exportKey("jwk", ec.publicKey);
 *   var token = "example-challenge-token-not-a-secret";
 *   // the validation certificate carries exactly two extensions: the critical
 *   // acmeIdentifier, and a single-entry SAN naming the identifier being validated
 *   var acmeExt = await pki.acme.tlsAlpn01Extension(token, accountJwk);
 *   var sanExt = b.sequence([b.oid("2.5.29.17"),
 *     b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("example.org", "ascii"))]))]);
 *   var kp = await pki.key.generate("Ed25519");
 *   var certDer = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: [acmeExt, sanExt] }, { key: await pki.key.export(kp.privateKey) });
 *   await pki.acme.verifyTlsAlpn01(certDer, token, accountJwk, { type: "dns", value: "example.org" });
 */
async function verifyTlsAlpn01(certDer, token, accountJwk, identifier) {
  var cert = x509.parse(certDer);
  var exts = cert.extensions || [];
  var acmeExt = exts.filter(function (e) { return e.oid === OID_ACME_IDENTIFIER; })[0];
  if (!acmeExt) throw E("acme/bad-tlsalpn", "the validation certificate is missing the acmeIdentifier extension (RFC 8737 sec. 3)");
  if (!acmeExt.critical) throw E("acme/bad-tlsalpn", "the acmeIdentifier extension must be critical (RFC 8737 sec. 3)");
  var auth = _readAcmeIdentifier(acmeExt.value);
  var ka = await keyAuthorization(token, accountJwk);
  var expected = await _sha256(Buffer.from(ka, "ascii"));
  if (!auth.equals(expected)) throw E("acme/bad-tlsalpn", "the acmeIdentifier digest does not match the key authorization");
  // SAN: exactly one entry, of the identifier's type, equal to its value.
  var sanExt = exts.filter(function (e) { return e.oid === OID_SAN; })[0];
  if (!sanExt) throw E("acme/bad-tlsalpn", "the validation certificate is missing the SubjectAltName");
  var san = _extDecoders.byOid[OID_SAN](sanExt.value, _extCtx);
  if (!san.names || san.names.length !== 1) throw E("acme/bad-tlsalpn", "the SubjectAltName must carry EXACTLY ONE entry (RFC 8737 sec. 3)");
  var entry = san.names[0];
  if (!_isObject(identifier) || !_isString(identifier.type)) throw E("acme/bad-input", "an identifier { type, value } is required");
  if (identifier.type === "dns") {
    if (entry.tagNumber !== 2) throw E("acme/bad-tlsalpn", "a dns identifier requires a dNSName SAN");
    // Validate the identifier as a base dns name first (rejecting a wildcard *.
    // label or a malformed value), matching the ip branch and the rest of the
    // ACME path -- a tls-alpn-01 identifier must be a concrete, non-wildcard name.
    _assertDnsName(identifier.value);
    if (String(entry.value).toLowerCase() !== identifier.value) throw E("acme/bad-tlsalpn", "the SAN dNSName does not match the identifier");
  } else if (identifier.type === "ip") {
    if (entry.tagNumber !== 7) throw E("acme/bad-tlsalpn", "an ip identifier requires a single iPAddress SAN (RFC 8738 sec. 6)");
    // Reject a NON-canonical identifier (leading-zero octets, uppercase IPv6, an
    // uncompressed run) rather than normalizing-and-guessing it -- the same
    // fail-closed rule the rest of the ACME identifier path applies. After this the
    // identifier value is its own canonical form, so the SAN's canonical text must equal it.
    _assertIpAddress(identifier.value);
    var sanIp = _ipBytesToText(entry.value);
    if (sanIp === null || sanIp !== identifier.value) throw E("acme/bad-tlsalpn", "the iPAddress SAN does not match the ip identifier (RFC 8738 sec. 6)");
  } else {
    throw E("acme/bad-tlsalpn", "unsupported tls-alpn-01 identifier type " + JSON.stringify(identifier.type));
  }
}

// ---- request builders (RFC 8555 sec. 7.x) --------------------------------

// The signed outer request is a Flattened JWS under the acme-outer profile: alg
// + nonce + url + EXACTLY ONE of kid/jwk (jose enforces one-of, nonce, url). The
// payload is a raw Buffer -- POST-as-GET is an empty Buffer (encodes to ""), a
// resource POST is the UTF-8 JSON of the payload object. `o` carries the signing
// key (`key`, a private CryptoKey), its `alg`, the fresh `nonce`, the target
// `url`, and either `kid` (an account URL) or `jwk` (an embedded public JWK).
function _outerHeader(o) {
  var h = { alg: o.alg, nonce: o.nonce, url: o.url };
  if (_hasOwn(o, "kid")) h.kid = o.kid;
  if (_hasOwn(o, "jwk")) h.jwk = o.jwk;
  return h;
}
function _payloadBuf(obj) {
  if (obj === undefined) return Buffer.alloc(0);                 // POST-as-GET
  return Buffer.from(JSON.stringify(obj), "utf8");
}
// A verb documented `-> Promise` refuses by REJECTING, never by throwing (guard-async).
//
// The validation stays SYNCHRONOUS: these verbs read a caller's options object -- the key, the
// nonce, the identifiers -- and resolving those before any turn passes is what stops a value being
// swapped between the check and the use. Only the exit changes.
var _promised = guard.async.deferred;
function _signOuter(o, payloadObj) {
  if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
  if (!o.key) throw E("acme/bad-input", "a signing key (opts.key) is required");
  // The header carries the account jwk in jwk mode and the kid in kid mode, so the public JWK is
  // already there whenever there is one to name; jose.sign reads its own opts.jwk in kid mode only.
  return jose.sign({ protected: _outerHeader(o), payload: _payloadBuf(payloadObj), key: o.key, profile: "acme-outer" });
}

/**
 * @primitive  pki.acme.postAsGet
 * @signature  pki.acme.postAsGet(opts) -> Promise<object>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.newOrder
 *
 * Build a POST-as-GET request (RFC 8555 sec. 6.3): a JWS whose payload is the
 * EMPTY octet string (`payload: ""`), distinct from a POST of an empty object
 * (`{}`). `opts` carries `{ key, alg, nonce, url, kid }` (an authenticated read
 * is always kid-signed). Returns the flattened JWS.
 *
 * @example
 *   await pki.acme.postAsGet({ key, alg: "ES256", nonce, url: orderUrl, kid });
 */
function postAsGet(o) {
  return _promised(function () {
    if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
    // An authenticated read is ALWAYS kid-signed; copy only the kid-mode fields so a
    // leftover jwk (e.g. reused from a newAccount options object) cannot embed a key.
    return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, undefined);
  });
}

// A contact URL (RFC 8555 sec. 7.3): a `mailto:` addr-spec carries no header
// fields (`?` hfields) and exactly one address (no comma-list) -- fail closed on
// ambiguity (never send to a guessed recipient). Other URL schemes pass through
// as opaque strings (the server decides support via unsupportedContact).
function _assertContacts(contacts) {
  if (!Array.isArray(contacts)) throw E("acme/bad-contact", "contact must be an array of URL strings");
  contacts.forEach(function (c) {
    if (!_isUriString(c)) throw E("acme/bad-contact", "each contact must be a URI string (RFC 8555 sec. 7.1.2)");
    // URI schemes are case-insensitive (RFC 3986), so detect mailto regardless of
    // case -- "MAILTO:a@b?..." must still hit the RFC 6068 header-field guards.
    if (c.slice(0, "mailto:".length).toLowerCase() === "mailto:") {
      var addr = c.slice("mailto:".length);
      if (addr.indexOf("?") !== -1) throw E("acme/bad-contact", "a mailto contact must not carry header fields (RFC 8555 sec. 7.3 / RFC 6068)");
      if (addr.indexOf(",") !== -1) throw E("acme/bad-contact", "a mailto contact must be a single addr-spec, not a comma list (RFC 8555 sec. 7.3)");
      if (_countAtSigns(addr) !== 1) throw E("acme/bad-contact", "a mailto contact must be exactly one addr-spec");
    }
  });
}

/**
 * @primitive  pki.acme.newAccount
 * @signature  pki.acme.newAccount(opts) -> Promise<object>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.externalAccountBinding
 *
 * Build a newAccount request (RFC 8555 sec. 7.3): a jwk-signed JWS (a new account
 * has no kid yet) whose payload MAY carry `contact` (mailto validated fail-closed),
 * `termsOfServiceAgreed`, `onlyReturnExisting`, and an `externalAccountBinding`
 * (an EAB inner JWS from `externalAccountBinding`). `opts` = `{ key, alg, nonce,
 * url, jwk, contact?, termsOfServiceAgreed?, onlyReturnExisting?, externalAccountBinding? }`.
 *
 * @example
 *   await pki.acme.newAccount({ key, alg: "ES256", nonce, url, jwk, termsOfServiceAgreed: true });
 */
function newAccount(o) {
  return _promised(function () {
  if (!_isObject(o) || !_isObject(o.jwk)) throw E("acme/bad-input", "newAccount must embed the account public jwk (RFC 8555 sec. 7.3)");
  var payload = {};
  if (o.contact !== undefined) { _assertContacts(o.contact); payload.contact = o.contact; }
  // Require actual booleans -- never coerce a string like "false"/"0", which `!!`
  // would serialize as `true`, silently agreeing to Terms of Service or forcing
  // onlyReturnExisting.
  if (o.termsOfServiceAgreed !== undefined) {
    if (typeof o.termsOfServiceAgreed !== "boolean") throw E("acme/bad-input", "termsOfServiceAgreed must be a boolean");
    payload.termsOfServiceAgreed = o.termsOfServiceAgreed;
  }
  if (o.onlyReturnExisting !== undefined) {
    if (typeof o.onlyReturnExisting !== "boolean") throw E("acme/bad-input", "onlyReturnExisting must be a boolean");
    payload.onlyReturnExisting = o.onlyReturnExisting;
  }
  if (o.externalAccountBinding !== undefined) {
    if (!_isObject(o.externalAccountBinding)) throw E("acme/bad-input", "externalAccountBinding must be an EAB inner JWS object");
    payload.externalAccountBinding = o.externalAccountBinding;
  }
  return jose.sign({ protected: { alg: o.alg, nonce: o.nonce, url: o.url, jwk: o.jwk }, payload: _payloadBuf(payload), key: o.key, profile: "acme-outer" });
  });
}

var _HMAC_HASH = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" };

/**
 * @primitive  pki.acme.externalAccountBinding
 * @signature  pki.acme.externalAccountBinding(opts) -> Promise<object>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.newAccount
 *
 * Build the External Account Binding inner JWS (RFC 8555 sec. 7.3.4): a MAC-only
 * (`HS256`/`HS384`/`HS512`) JWS over the account public JWK, keyed by the CA-issued
 * `kid` + symmetric `macKey` (a raw `Buffer` or an HMAC `CryptoKey`), `url` equal to
 * the newAccount URL, NO nonce. `opts` = `{ macKey, kid, url, accountJwk, alg? }`
 * (alg default `HS256`). The result is embedded as newAccount's `externalAccountBinding`.
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var accountJwk = await pki.webcrypto.subtle.exportKey("jwk", ec.publicKey);
 *   var macKey = Buffer.alloc(32, 7);          // the HMAC key the CA issued out of band
 *   var url = "https://ca.example/acme/new-acct";
 *   var eab = await pki.acme.externalAccountBinding({ macKey, kid: "abc123", url, accountJwk });
 */
async function externalAccountBinding(o) {
  if (!_isObject(o) || !_isObject(o.accountJwk)) throw E("acme/bad-input", "externalAccountBinding requires the account public jwk (sec. 7.3.4)");
  jose.assertPublicJwk(o.accountJwk);   // the account JWK is published in the EAB payload -> public-only
  if (!_isString(o.kid)) throw E("acme/bad-input", "externalAccountBinding requires the CA-issued kid");
  var alg = o.alg || "HS256";
  if (!_HMAC_HASH[alg]) throw E("acme/bad-input", "an EAB inner JWS must use an HS* MAC algorithm (sec. 7.3.4), not " + JSON.stringify(alg));
  var key = o.macKey;
  if (Buffer.isBuffer(key)) {
    try { key = await subtle.importKey("raw", key, { name: "HMAC", hash: _HMAC_HASH[alg] }, false, ["sign"]); }
    catch (e) { throw E("acme/bad-input", "the EAB macKey could not be imported as an HMAC key", e); }
  } else if (!key || typeof key !== "object" || key.type !== "secret") {
    // Anything that is neither a raw Buffer nor a secret-key CryptoKey would reach
    // subtle.sign and throw a bare TypeError; fail closed with a typed fault instead.
    throw E("acme/bad-input", "the EAB macKey must be a raw Buffer or an HMAC (secret) CryptoKey");
  }
  return jose.sign({ protected: { alg: alg, kid: o.kid, url: o.url }, payload: _payloadBuf(o.accountJwk), key: key, profile: "eab-inner" });
}

// An order identifier MAY carry a wildcard: EXACTLY ONE leading `*.` label, `dns`
// only (sec. 7.1.3). An `ip` identifier has no wildcard form. Everything else is
// the shared _validateIdentifier syntax on the base name.
function _validateOrderIdentifier(id) {
  if (!_isObject(id)) throw E("acme/bad-identifier", "an order identifier must be { type, value } strings");
  var type = id.type, value = id.value;   // read each field ONCE (a getter-backed / inherited prop is captured here)
  if (!_isString(type) || !_isString(value)) throw E("acme/bad-identifier", "an order identifier must be { type, value } strings");
  if (type === "dns") {
    var v = value;
    if (v.indexOf("*.") === 0) {
      v = v.slice(2);
      if (v.indexOf("*") !== -1) throw E("acme/bad-identifier", "a wildcard order identifier permits exactly one leading *. label (RFC 8555 sec. 7.1.3)");
    } else if (v.indexOf("*") !== -1) {
      throw E("acme/bad-identifier", "a wildcard must be a single leading *. label (RFC 8555 sec. 7.1.3)");
    }
    _assertDnsName(v);
  } else if (type === "ip") {
    if (value.indexOf("*") !== -1) throw E("acme/bad-identifier", "an ip identifier has no wildcard form (RFC 8738)");
    _assertIpAddress(value);
  }
  // Canonical { type, value } from the single read (the ORIGINAL value, wildcard `*.` included) -- see
  // _validateIdentifier: callers serialize THIS, so the wire payload cannot diverge from what was validated.
  return { type: type, value: value };
}

/**
 * @primitive  pki.acme.newOrder
 * @signature  pki.acme.newOrder(opts) -> Promise<object>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555, RFC 9773
 * @related    pki.acme.finalize, pki.acme.ariCertId
 *
 * Build a newOrder request (RFC 8555 sec. 7.4): a kid-signed JWS whose payload
 * carries a non-empty validated `identifiers` array (each `dns`/`ip`, one leading
 * `*.` wildcard permitted for `dns`), optional `notBefore`/`notAfter`, and an
 * optional RFC 9773 `replaces` (the ARI certID of the certificate being renewed).
 * `opts` = `{ key, alg, nonce, url, kid, identifiers, notBefore?, notAfter?, replaces? }`.
 *
 * @example
 *   await pki.acme.newOrder({ key, alg: "ES256", nonce, url, kid, identifiers: [{ type: "dns", value: "example.org" }] });
 */
function newOrder(o) {
  return _promised(function () {
  if (!_isObject(o) || !Array.isArray(o.identifiers) || o.identifiers.length === 0) throw E("acme/bad-order", "newOrder requires a non-empty identifiers array (RFC 8555 sec. 7.4)");
  // Serialize the CANONICAL { type, value } each validator returns, never the caller's objects (which may carry
  // getter-backed / inherited fields JSON.stringify would drop, or extra enumerable fields it would send).
  var payload = { identifiers: o.identifiers.map(_validateOrderIdentifier) };
  if (o.notBefore !== undefined) { if (!_isRfc3339(o.notBefore)) throw E("acme/bad-order", "notBefore must be an RFC 3339 date-time"); payload.notBefore = o.notBefore; }
  if (o.notAfter !== undefined) { if (!_isRfc3339(o.notAfter)) throw E("acme/bad-order", "notAfter must be an RFC 3339 date-time"); payload.notAfter = o.notAfter; }
  if (o.replaces !== undefined) { if (!_isString(o.replaces)) throw E("acme/bad-order", "replaces must be an ARI certID string (RFC 9773 sec. 5)"); payload.replaces = o.replaces; }
  return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, payload);
  });
}

/**
 * @primitive  pki.acme.newAuthz
 * @signature  pki.acme.newAuthz(opts) -> flattened JWS
 * @since      0.3.29
 * @status     stable
 * @spec       RFC 8555, RFC 8555 sec. 7.4.1
 * @related    pki.acme.newOrder, pki.acme.client
 *
 * Build a kid-signed pre-authorization request (RFC 8555 sec. 7.4.1): a Flattened JWS over exactly
 * `{ identifier: { type, value } }`, a single identifier object and not an array. The identifier is validated as
 * an authorization identifier, which rejects a wildcard `*.` value (pre-authorization cannot authorize a
 * wildcard name); a bad type / value is `acme/bad-identifier`. `opts` = `{ key, alg, nonce, url, kid, identifier }`.
 * The `client.newAuthz(identifier)` verb composes this, POSTs it to the directory `newAuthz` resource, and
 * returns the validated authorization bound to the requested identifier.
 *
 * @example
 *   await pki.acme.newAuthz({ key, alg: "ES256", nonce, url, kid, identifier: { type: "dns", value: "example.org" } });
 */
function newAuthz(o) {
  if (!_isObject(o) || !_isObject(o.identifier)) throw E("acme/bad-identifier", "newAuthz requires a single identifier object (RFC 8555 sec. 7.4.1)");
  // Serialize the canonical { type, value } the validator returns, never the caller's object (see _validateIdentifier).
  return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, { identifier: _validateIdentifier(o.identifier) });
}

// The account key's SubjectPublicKeyInfo DER, imported from its public JWK, so a
// finalize CSR carrying that same key is caught (sec. 11.1). The DER is canonical
// (node emits canonical SPKI), matched byte-for-byte against the CSR's strict-DER SPKI.
async function _jwkToSpki(jwk) {
  var importAlg;
  if (jwk.kty === "EC") importAlg = { name: "ECDSA", namedCurve: jwk.crv };
  else if (jwk.kty === "RSA") importAlg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  else if (jwk.kty === "OKP") importAlg = { name: jwk.crv };
  else if (jwk.kty === "AKP") importAlg = { name: jwk.alg };
  else throw E("acme/bad-key", "unsupported account key type " + JSON.stringify(jwk && jwk.kty));
  var key;
  try { key = await subtle.importKey("jwk", jwk, importAlg, true, []); }
  catch (e) { throw E("acme/bad-key", "the account key JWK could not be imported to derive its SubjectPublicKeyInfo", e); }
  return Buffer.from(await subtle.exportKey("spki", key));
}

// EVERY common name in the subject (a DN may carry more than one CN RDN) -- taking
// only the first would let a second CN smuggle an identifier past the order-set match.
// Walked through the captured operations, because this feeds the issued-certificate binding: the set
// it builds is what says the certificate names what the order asked for, and it is built after the
// download returns. A replaced traversal could present a name the certificate does not carry, and the
// comparison would agree that the two sets are equal.
function _subjectCommonNames(subject) {
  var names = [];
  if (!subject || !_isArrayI(subject.rdns)) return names;
  _forEach(subject.rdns, function (atvs) {
    if (!_isArrayI(atvs)) return;
    _forEach(atvs, function (atv) {
      if ((atv.name === "commonName" || atv.type === OID_CN) && _isString(atv.value)) _push(names, atv.value);
    });
  });
  return names;
}

// An iPAddress SAN octet string (4 = IPv4, 16 = IPv6) to its RFC 8738 canonical
// text -- the same form an order ip identifier carries -- or null on a bad length.
function _ipBytesToText(buf) {
  if (!_isBuffer(buf)) return null;
  if (buf.length === 4) return buf[0] + "." + buf[1] + "." + buf[2] + "." + buf[3];
  if (buf.length === 16) {
    var groups = [];
    for (var i = 0; i < 16; i += 2) _push(groups, _numToString((buf[i] << 8) | buf[i + 1], 16));
    return _canonicalizeIpv6(_join(groups, ":"));
  }
  return null;
}

// The set of identifiers a CSR requests: the subject CN (counted as dns) plus the
// SAN dNSName / iPAddress entries in the extensionRequest attribute, keyed
// "dns:<lower>" / "ip:<canonical>" for an order-insensitive compare.
function _csrIdentifierSet(parsedCsr) {
  // Null prototype: membership below is asked as `set[k]`, and against an ordinary object that question
  // reaches Object.prototype, so a name planted there would read as an identifier the request carried.
  var set = intrinsic.create(null);
  // PKCS#10 permits duplicate attribute types, so aggregate EVERY extensionRequest
  // attribute and EVERY subjectAltName within each -- taking only the first would let
  // a second extensionRequest smuggle identifiers past the order-set comparison.
  _forEach(parsedCsr.attributes || [], function (a) {
    if (a.type !== oid.byName("extensionRequest") || !_isArrayI(a.extensions)) return;
    _forEach(a.extensions, function (e) {
      if (e.oid !== OID_SAN) return;
      var dec = _extDecoders.byOid[OID_SAN](e.value, _extCtx);
      _forEach(dec.names || [], function (n) { _addSanName(set, n, "the finalize CSR"); });
    });
  });
  // EVERY common name, alternative names present or not -- which is where this side parts from the
  // issued-certificate set, because the two answer different questions. That set asks what a
  // certificate authenticates, and no matcher reads a common name for that. This one asks what the
  // request is ASKING to have certified, and a CA may carry a common name through into the issued
  // certificate, so a CSR naming the order's name in a SAN and an unauthorized one in its subject is
  // a request for a name the order does not cover.
  _forEach(_subjectCommonNames(parsedCsr.subject), function (cn) { _addCommonName(set, cn, "the finalize CSR"); });
  return set;
}

// One subjectAltName entry folded into an identifier set, for the CSR and the issued certificate
// alike. A dNSName or iPAddress maps to an ACME order identifier; anything else -- rfc822Name,
// otherName, directoryName, uniformResourceIdentifier, registeredID -- does not, and is REFUSED
// rather than skipped. Skipping it would leave a name in the certificate that the set-equality
// comparison never saw, so a certificate additionally naming a mailbox or a URI would compare equal
// to an order covering neither. A malformed iPAddress is the same case: unmappable, so unbindable.
// One subject common name folded into an identifier set. A CN holding an IP literal is an IP
// identifier, not a dns one: CABF TLS BR 7.1.4.2.2 lets a commonName match either a dNSName or an
// iPAddress SAN, so an IP certificate routinely carries the address in both places while the order
// carries it once as `ip`. Counting the CN as `dns:` there would make a correct issuance compare as
// two identifiers against the order's one. A CN that looks like an address but is not the canonical
// RFC 5952 / RFC 8738 form is neither a usable dns name nor a canonical ip identifier, and it is
// refused rather than normalized -- the same rule the ip identifier validator applies.
function _addCommonName(set, cn, what) {
  var looksIp = _looksLikeIpv4(cn) || intrinsic.stringIndexOf(cn, ":") !== -1;
  // An address in a common name adds no identity of its own. Address matching reads the iPAddress
  // subjectAltName and never falls back to the common name, so a subject naming the ordered address
  // only there cannot authenticate it. What the ordinary IP certificate does -- CABF TLS BR
  // 7.1.4.2.2 permits a common name to match an iPAddress SAN, and issuers write the address in both
  // places -- is repeat an address the alternative names ALREADY carry, and that is a duplicate of an
  // authorized name rather than a new one. So: accepted where the set already holds it, refused
  // otherwise, which covers the address carried only in the subject and the one naming a DIFFERENT
  // address than the alternative names do. The alternative names are folded in before the common
  // names on both sides, so the set is complete by the time this reads it.
  if (looksIp) {
    var canonical = true;
    try { _assertIpAddress(cn); }
    catch (_e) {
      canonical = false;
    }
    if (canonical && set["ip:" + cn] === true) return;
    throw _unmappableName(what, cn, null);
  }
  // ASCII case folding, never the Unicode mapping. A DirectoryString common name may hold characters
  // whose Unicode lowercase IS ASCII -- U+212A KELVIN SIGN folds to "k" -- so a full fold turns a name
  // the certificate does not carry as a DNS label into one that compares equal to an order identifier.
  var folded = _asciiLower(cn);
  // A single leading `*.` is a wildcard name, which an order identifier carries verbatim (sec. 7.1.3)
  // and a certificate carries as a SAN, so it is validated the way the order validator validates one:
  // strip the one wildcard label, then hold the rest to the A-label rule.
  var base = intrinsic.stringIndexOf(folded, "*.") === 0 ? _strSlice(folded, 2) : folded;
  if (intrinsic.stringIndexOf(base, "*") !== -1) throw _unmappableName(what, cn, null);
  try { _assertDnsName(base); }
  catch (e2) {
    throw _unmappableName(what, cn, e2);
  }
  set["dns:" + folded] = true;
}

// A name the comparison cannot express, refused rather than left out. Dropping it is unsafe even
// though a smaller certificate set can only fail equality: a certificate may carry SEVERAL common
// names, and dropping the unmappable one while another supplies the match reports the set as bound
// while the certificate still names something the order never covered -- `CN=example.org,
// CN=victim.example.`, where the trailing-dot spelling is one a hostname matcher will accept.
function _unmappableName(what, name, cause) {
  return E("acme/unsupported-identifier-type",
    what + " carries the name " + _stringify(name) + " in its subject, which maps to no ACME order " +
    "identifier (only a dns name or a canonical IP address does), so the identifier set cannot be " +
    "compared", cause || undefined);
}

// A-Z to a-z and nothing else, through the toolkit's one definition of that fold. String.prototype
// .toLowerCase applies the full Unicode mapping, under which several non-ASCII characters fold INTO
// ASCII, and a name folded that way is one the certificate does not carry.
var _asciiLower = guard.name.lowerAscii;

function _addSanName(set, n, what) {
  // ASCII case folding on both sides of the comparison, never the Unicode mapping: a character whose
  // Unicode lowercase IS ASCII would otherwise fold into a name the certificate does not carry.
  if (n.tagNumber === 2) { set["dns:" + _asciiLower(_StringI(n.value))] = true; return; }
  if (n.tagNumber === 7) {
    var t = _ipBytesToText(n.value);
    if (t === null) throw E("acme/unsupported-identifier-type", what + " carries an iPAddress subjectAltName that is neither 4 nor 16 octets, so it maps to no order identifier");
    set["ip:" + t] = true;
    return;
  }
  throw E("acme/unsupported-identifier-type",
    what + " carries a subjectAltName of GeneralName type [" + n.tagNumber + "], which maps to no ACME " +
    "order identifier (only dNSName and iPAddress do), so the identifier set cannot be compared");
}

// The order's own identifiers as the same keyed set. Built through the captured operations and with a
// null prototype for the same two reasons its siblings are: this set is computed AFTER the certificate
// download returns, so what walks the array and folds each name must not be replaceable in between,
// and membership is asked as `set[k]`, which against an ordinary object would answer for a name planted
// on Object.prototype rather than one the order carried.
function _orderIdentifierSet(identifiers) {
  var set = intrinsic.create(null);
  _forEach(identifiers, function (id) {
    if (id.type === "dns") set["dns:" + _asciiLower(id.value)] = true;
    else if (id.type === "ip") set["ip:" + id.value] = true;
    // A registered identifier type this comparison cannot map to a certificate name is REFUSED, not
    // dropped. Dropping it would leave the comparison answering about the identifiers it happens to
    // understand while reporting a check of the whole set: an order for a dns name and one other type
    // would be satisfied by a certificate naming only the dns name. The ACME identifier registry
    // (RFC 8555 sec. 9.7.7) is open, so this is the shape a new type arrives in.
    else throw E("acme/unsupported-identifier-type",
      "this build cannot bind a certificate to an order identifier of type " + _stringify(id.type) +
      " (only dns and ip map to a certificate name), so it cannot report the identifier set as checked");
  });
  return set;
}

// The set of identifiers an ISSUED certificate carries, keyed the same way as the CSR and order sets
// so the three are comparable. The subjectAltName entries are the names a certificate asserts; the
// subject common name is consulted ONLY when there is no such entry. Where a SAN is present the
// common name is not an additional identity -- name matching has read the SAN and ignored the common
// name for many years, and CABF TLS BR 7.1.4.2.2 requires any common name to appear among the SAN
// values anyway, so counting it again would make a certificate whose SAN set is exactly the order's
// compare unequal because of a legacy or organizational common name beside it.
//
// A certificate may carry several SAN extensions in a non-conformant encoding, so every one is
// aggregated rather than the first -- taking one would let a second smuggle a name past the
// comparison.
function _certIdentifierSet(parsedCert) {
  var set = intrinsic.create(null);
  _forEach(parsedCert.extensions || [], function (e) {
    if (e.oid !== OID_SAN) return;
    var dec = _extDecoders.byOid[OID_SAN](e.value, _extCtx);
    _forEach(dec.names || [], function (n) { _addSanName(set, n, "the downloaded certificate"); });
  });
  if (_objectKeys(set).length === 0) {
    _forEach(_subjectCommonNames(parsedCert.subject), function (cn) { _addCommonName(set, cn, "the downloaded certificate"); });
  }
  return set;
}

function _assertCsrIdentifiers(parsedCsr, identifiers) {
  var have = _csrIdentifierSet(parsedCsr);
  var want = _orderIdentifierSet(identifiers);
  var haveKeys = _objectKeys(have), wantKeys = _objectKeys(want);
  var mismatch = haveKeys.length !== wantKeys.length ||
    _someI(wantKeys, function (k) { return !have[k]; }) ||
    _someI(haveKeys, function (k) { return !want[k]; });
  if (mismatch) {
    throw E("acme/csr-identifier-mismatch", "the finalize CSR identifier set " + _stringify(_sortI(haveKeys)) +
      " does not equal the order identifiers " + _stringify(_sortI(wantKeys)) + " (RFC 8555 sec. 7.4)");
  }
}

/**
 * @primitive  pki.acme.finalize
 * @signature  pki.acme.finalize(opts) -> Promise<object>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.newOrder
 *
 * Build a finalize request (RFC 8555 sec. 7.4): a kid-signed JWS whose payload
 * `csr` is the base64url of the DER PKCS#10 (never PEM). The CSR is parsed with
 * `pki.schema.csr.parse`; its requested identifier set (SAN + CN) MUST equal the
 * order identifiers (`acme/csr-identifier-mismatch`), and its public key MUST NOT
 * be the account key (`acme/key-reuse`, sec. 11.1). `opts` = `{ key, alg, nonce,
 * url, kid, csr (DER Buffer), identifiers?, accountJwk? }`.
 *
 * @example
 *   await pki.acme.finalize({ key, alg: "ES256", nonce, url, kid, csr: csrDer, identifiers, accountJwk });
 */
async function finalize(o) {
  if (!_isObject(o) || !guard.bytes.isByteSource(o.csr)) throw E("acme/bad-input", "finalize requires a DER CSR BufferSource (opts.csr)");
  var csrBuf = guard.bytes.snapshotSource(o.csr, E, "acme/bad-input", "the finalize CSR");
  var parsed = csr.parse(csrBuf);                         // strict DER; rejects PEM/garbage
  if (o.accountJwk !== undefined) {
    var accountSpki = await _jwkToSpki(o.accountJwk);
    if (parsed.subjectPublicKeyInfo && Buffer.isBuffer(parsed.subjectPublicKeyInfo.bytes) &&
        parsed.subjectPublicKeyInfo.bytes.equals(accountSpki)) {
      throw E("acme/key-reuse", "the finalize CSR public key must not be the account key (RFC 8555 sec. 11.1)");
    }
  }
  if (o.identifiers !== undefined) {
    if (!Array.isArray(o.identifiers) || o.identifiers.length === 0) throw E("acme/bad-input", "finalize identifiers must be the non-empty order identifier array");
    o.identifiers.forEach(_validateOrderIdentifier);   // caller-supplied -> validate before comparing (no raw TypeError)
    _assertCsrIdentifiers(parsed, o.identifiers);
  }
  var payload = { csr: jose.base64url.encode(csrBuf) };
  return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, payload);
}

/**
 * @primitive  pki.acme.challengeResponse
 * @signature  pki.acme.challengeResponse(opts) -> Promise<object>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.http01, pki.acme.dns01
 *
 * Build a challenge-response POST (RFC 8555 sec. 7.5.1): a kid-signed JWS whose
 * payload is the type-defined response object -- `{}` for the three registered
 * challenge types (http-01 / dns-01 / tls-alpn-01), which is DISTINCT from a
 * POST-as-GET empty payload. `opts` = `{ key, alg, nonce, url, kid, payload? }`
 * (payload default `{}`; pass a custom object for a future challenge type).
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var key = ec.privateKey;
 *   var nonce = "oFvnlFP1wIhRlYS2jTaXbA";                 // from the CA's Replay-Nonce header
 *   var kid = "https://ca.example/acct/1", challUrl = "https://ca.example/chall/1";
 *   await pki.acme.challengeResponse({ key, alg: "ES256", nonce, url: challUrl, kid });
 */
function challengeResponse(o) {
  return _promised(function () {
    if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
    var payload = o.payload !== undefined ? o.payload : {};
    if (!_isObject(payload)) throw E("acme/bad-input", "a challenge response payload must be a JSON object (RFC 8555 sec. 7.5.1)");
    return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, payload);
  });
}

/**
 * @primitive  pki.acme.deactivate
 * @signature  pki.acme.deactivate(opts) -> Promise<object>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.validate
 *
 * Build a deactivation POST (RFC 8555 sec. 7.3.6 account / sec. 7.5.2
 * authorization): a kid-signed JWS with the payload `{"status":"deactivated"}` --
 * the only client-settable status. `opts` = `{ key, alg, nonce, url, kid }`.
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var key = ec.privateKey;
 *   var nonce = "oFvnlFP1wIhRlYS2jTaXbA";
 *   var kid = "https://ca.example/acct/1", authzUrl = "https://ca.example/authz/1";
 *   await pki.acme.deactivate({ key, alg: "ES256", nonce, url: authzUrl, kid });
 */
function deactivate(o) {
  return _promised(function () {
    if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
    return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, { status: "deactivated" });
  });
}

/**
 * @primitive  pki.acme.updateAccount
 * @signature  pki.acme.updateAccount(opts) -> Promise<object>
 * @since      0.6.4
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.client, pki.acme.newAccount, pki.acme.deactivate
 *
 * Build an account-update POST (RFC 8555 sec. 7.3.2): a kid-signed JWS whose payload carries the
 * account fields a client may set. `contact` is that field (RFC 6068 mailto hygiene applies; an empty
 * array clears all contacts). `opts` = `{ key, alg, nonce, url, kid, contact }`. The server ignores
 * updates to `status`, `termsOfServiceAgreed`, `orders`, and unrecognized fields (sec. 7.3.2), so the
 * `pki.acme.client` wrapper refuses those at the door rather than emit a silently-discarded payload.
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var key = ec.privateKey;
 *   var nonce = "oFvnlFP1wIhRlYS2jTaXbA";
 *   var kid = "https://ca.example/acct/1";
 *   await pki.acme.updateAccount({ key, alg: "ES256", nonce, url: kid, kid, contact: ["mailto:admin@example.org"] });
 */
function updateAccount(o) {
  return _promised(function () {
    if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
    _assertContacts(o.contact);   // RFC 6068 mailto hygiene; an empty array clears all contacts
    return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, { contact: o.contact });
  });
}

/**
 * @primitive  pki.acme.revokeCert
 * @signature  pki.acme.revokeCert(opts) -> Promise<object>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555, RFC 5280
 * @related    pki.acme.ariCertId
 *
 * Build a revokeCert request (RFC 8555 sec. 7.6): a JWS whose payload `certificate`
 * is the base64url of the DER certificate and optional `reason` is an assigned
 * RFC 5280 CRLReason (0-6, 8-10; 7 is unassigned). Signed EITHER by the account key (`kid` mode) OR by the
 * certificate key (`jwk` mode) -- pass exactly one. `opts` = `{ key, alg, nonce,
 * url, certificate (DER Buffer), reason?, kid? | jwk? }`.
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var key = ec.privateKey;
 *   var nonce = "oFvnlFP1wIhRlYS2jTaXbA";
 *   var kid = "https://ca.example/acct/1", url = "https://ca.example/acme/revoke-cert";
 *   var kp = await pki.key.generate("Ed25519");
 *   var certDer = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(kp.privateKey) });
 *   await pki.acme.revokeCert({ key, alg: "ES256", nonce, url, kid, certificate: certDer, reason: 1 });
 */
function revokeCert(o) {
  return _promised(function () {
  if (!_isObject(o) || !guard.bytes.isByteSource(o.certificate)) throw E("acme/bad-input", "revokeCert requires a DER certificate BufferSource (opts.certificate)");
  var certBuf = guard.bytes.snapshotSource(o.certificate, E, "acme/bad-input", "the revokeCert certificate");
  x509.parse(certBuf);                                    // structural validation of the target
  var hasKid = _hasOwn(o, "kid");
  var hasJwk = _hasOwn(o, "jwk");
  if (hasKid === hasJwk) throw E("acme/bad-input", "revokeCert must be signed with EXACTLY ONE of the account kid or the certificate jwk (RFC 8555 sec. 7.6)");
  var payload = { certificate: jose.base64url.encode(certBuf) };
  if (o.reason !== undefined) {
    if (typeof o.reason !== "number" || !isFinite(o.reason) || Math.floor(o.reason) !== o.reason || CRL_REASONS.indexOf(o.reason) === -1) {
      throw E("acme/bad-revocation-reason", "reason must be an assigned RFC 5280 CRLReason (0-6, 8-10; value 7 is unassigned)");
    }
    payload.reason = o.reason;
  }
  var header = { alg: o.alg, nonce: o.nonce, url: o.url };
  if (hasKid) header.kid = o.kid; else header.jwk = o.jwk;
  return jose.sign({ protected: header, payload: _payloadBuf(payload), key: o.key, profile: "acme-outer" });
  });
}

/**
 * @primitive  pki.acme.keyChange
 * @signature  pki.acme.keyChange(opts) -> Promise<object>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 8555
 * @related    pki.acme.newAccount
 *
 * Build a key-change request (RFC 8555 sec. 7.3.5): a nested JWS. The INNER JWS is
 * signed by the NEW account key (embedded `jwk`, no nonce, `url` == the keyChange
 * URL) over `{ account, oldKey }`; the OUTER JWS is the account (`kid`, `oldKey`)
 * signing that inner object. `opts` = `{ key (old private), alg (old), kid
 * (account URL), account (account URL), oldKey (old public JWK), newKey (new
 * private), newJwk (new public JWK), newAlg, nonce, url }`.
 *
 * @example
 *   var subtle = pki.webcrypto.subtle;
 *   var oldPair = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var newPair = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var oldKey = oldPair.privateKey, newKey = newPair.privateKey;
 *   var oldJwk = await subtle.exportKey("jwk", oldPair.publicKey);
 *   var newJwk = await subtle.exportKey("jwk", newPair.publicKey);
 *   var nonce = "oFvnlFP1wIhRlYS2jTaXbA";
 *   var kid = "https://ca.example/acct/1", url = "https://ca.example/acme/key-change";
 *   await pki.acme.keyChange({ key: oldKey, alg: "ES256", kid, account: kid, oldKey: oldJwk, newKey, newJwk, newAlg: "ES256", nonce, url });
 */
async function keyChange(o) {
  if (!_isObject(o)) throw E("acme/bad-input", "a keyChange options object is required");
  if (!_isString(o.account)) throw E("acme/bad-input", "keyChange requires the account URL (payload account)");
  if (!_isObject(o.oldKey)) throw E("acme/bad-input", "keyChange requires the old account public jwk (payload oldKey)");
  if (!_isObject(o.newJwk)) throw E("acme/bad-input", "keyChange requires the new account public jwk (inner header jwk)");
  // oldKey is published in the inner payload and newJwk in the inner header -> both public-only.
  jose.assertPublicJwk(o.oldKey);
  jose.assertPublicJwk(o.newJwk);
  var inner = await jose.sign({
    protected: { alg: o.newAlg, url: o.url, jwk: o.newJwk },
    payload: _payloadBuf({ account: o.account, oldKey: o.oldKey }),
    key: o.newKey, profile: "keychange-inner",
  });
  return jose.sign({ protected: { alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, payload: _payloadBuf(inner), key: o.key, profile: "acme-outer" });
}

// ---- ARI (RFC 9773 renewal information) ----------------------------------

/**
 * @primitive  pki.acme.ariCertId
 * @signature  pki.acme.ariCertId(certDer) -> string
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 9773
 * @related    pki.acme.parseAriCertId, pki.acme.newOrder
 *
 * The RFC 9773 sec. 4.1 ARI certificate identifier of a DER certificate:
 * `base64url(AKI keyIdentifier) || '.' || base64url(serial content octets)`. The
 * serial is the raw DER INTEGER content, and its leading `00` sign-padding byte is
 * preserved (dropping it is the documented mass-404 client bug). Throws
 * `acme/bad-certid` if the certificate lacks an AKI keyIdentifier.
 *
 * @example
 *   // the certificate must carry an authorityKeyIdentifier -- ARI keys off it
 *   var ca = await pki.key.generate("Ed25519");
 *   var caKey = await pki.key.export(ca.privateKey);
 *   var caDer = await pki.x509.sign({ subject: "Example CA", subjectPublicKey: await pki.key.export(ca.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } }, { key: caKey });
 *   var kp = await pki.key.generate("Ed25519");
 *   var certDer = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     serialNumber: 0x87654321n, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { authorityKeyIdentifier: true } }, { cert: caDer, key: caKey });
 *   pki.acme.ariCertId(certDer);   // -> "<b64u-aki>.<b64u-serial>"
 */
function ariCertId(certDer) {
  if (!guard.bytes.isByteSource(certDer)) throw E("acme/bad-input", "ariCertId requires a DER certificate BufferSource");
  var cert = x509.parse(certDer);
  var akiExt = (cert.extensions || []).filter(function (e) { return e.oid === OID_AKI; })[0];
  if (!akiExt) throw E("acme/bad-certid", "the certificate has no authorityKeyIdentifier extension (RFC 9773 sec. 4.1)");
  var aki = _extDecoders.byOid[OID_AKI](akiExt.value, _extCtx);
  if (!aki || !Buffer.isBuffer(aki.keyIdentifier)) throw E("acme/bad-certid", "the authorityKeyIdentifier has no keyIdentifier field (RFC 9773 sec. 4.1)");
  var serialBytes = Buffer.from(cert.serialNumberHex, "hex");   // DER INTEGER content; sign-pad preserved
  return jose.base64url.encode(aki.keyIdentifier) + "." + jose.base64url.encode(serialBytes);
}

/**
 * @primitive  pki.acme.parseAriCertId
 * @signature  pki.acme.parseAriCertId(certId) -> { keyIdentifier, serial }
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 9773
 * @related    pki.acme.ariCertId
 *
 * Parse an ARI certID string (RFC 9773 sec. 4.1) into `{ keyIdentifier, serial }`
 * Buffers. The two dot-joined halves are each strict base64url (padding /
 * non-alphabet rejected); anything but exactly two parts throws `acme/bad-certid`.
 *
 * @example
 *   // the two halves are base64url(authorityKeyIdentifier) and base64url(serialNumber)
 *   pki.acme.parseAriCertId("aYhfK4oaay8.AIdlQyE").serial;   // -> Buffer 00 87 65 43 21
 */
function parseAriCertId(certId) {
  if (!_isString(certId)) throw E("acme/bad-certid", "an ARI certID must be a string");
  var parts = certId.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw E("acme/bad-certid", "an ARI certID must be two base64url halves joined by '.' (RFC 9773 sec. 4.1)");
  var keyIdentifier, serial;
  try { keyIdentifier = jose.base64url.decode(parts[0]); serial = jose.base64url.decode(parts[1]); }
  catch (e) { throw E("acme/bad-certid", "an ARI certID half is not strict base64url (RFC 9773 sec. 4.1)", e); }
  return { keyIdentifier: keyIdentifier, serial: serial };
}

/**
 * @primitive  pki.acme.validateRenewalInfo
 * @signature  pki.acme.validateRenewalInfo(obj) -> obj
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 9773
 * @related    pki.acme.validate
 *
 * Validate an ARI RenewalInfo object (RFC 9773 sec. 4.2): a `suggestedWindow` with
 * RFC 3339 `start` and `end`, `end` strictly after `start` (an inverted or
 * zero-width window throws `acme/bad-renewal-window` -- the client treats it as no
 * response, defusing a renewal stampede), and an optional `explanationURL`.
 * Returns the object.
 *
 * @example
 *   pki.acme.validateRenewalInfo({ suggestedWindow: { start: "2026-01-01T00:00:00Z", end: "2026-01-08T00:00:00Z" } });
 */
function validateRenewalInfo(obj) {
  _validate("renewalInfo", obj);
  var w = obj.suggestedWindow;
  if (!_isObject(w) || !_isRfc3339(w.start) || !_isRfc3339(w.end)) throw E("acme/bad-renewal-window", "a renewalInfo suggestedWindow must carry RFC 3339 start and end (RFC 9773 sec. 4.2)");
  // The line above already rejected any w.start/w.end that is not a grammar+calendar-valid
  // RFC 3339 string, so neither Date.parse can be NaN here -- the comparison is source-validated.
  // allow:nan-date-comparison-unguarded -- source-validated by the rfc3339.isValid check above.
  if (Date.parse(w.end) <= Date.parse(w.start)) throw E("acme/bad-renewal-window", "the renewal window end must be strictly after start (RFC 9773 sec. 4.2)");
  return obj;
}

// ---- the thin RFC 8555 client: a stateful session over the shared pki.transport ----

var CLIENT_DEFAULT_TIMEOUT = constants.TIME.seconds(30);
var CLIENT_MAX_TIMEOUT = constants.TIME.seconds(600);
// The RFC 8555 sec. 6.1 REQUIRED User-Agent, sent on every request (caller-overridable per request).
var CLIENT_USER_AGENT = "blamejs-pki/" + pkgVersion + " node/" + process.versions.node;
// A hard cap on the single-use nonce pool so a server that attaches a Replay-Nonce to every response
// (permitted, RFC 8555 sec. 6.5) -- including the unauthenticated, poll-scheduled renewalInfo GET --
// cannot grow it without bound; the oldest (least fresh) nonce is evicted first (CWE-770).
var CLIENT_MAX_NONCE_POOL = 32;

// Parse + validate a URL BEFORE any request: not-parseable -> acme/bad-url, non-https -> acme/insecure-url
// (RFC 8555 sec. 6.1 -- HTTPS is REQUIRED; the message-layer _isUrl accepts http, the client does not).
// The validated string is returned VERBATIM (never url.href): the JWS protected `url` and the account
// `kid` must be the exact server-provided value (RFC 8555 sec. 6.4/7.3), which URL normalization -- a
// dropped :443, an added trailing slash -- would otherwise change, breaking the server's match.
function _clientUrl(urlStr) {
  var s = String(urlStr);
  var url;
  try { url = new URL(s); }
  catch (e) { throw E("acme/bad-url", "the ACME URL did not parse: " + s, e); }
  if (url.protocol !== "https:") throw E("acme/insecure-url", "ACME requires https (RFC 8555 sec. 6.1), got " + url.protocol + " for " + s);
  // An ACME URL never carries userinfo. The transport connects to the host and does NOT put userinfo in the
  // request target, so a signed JWS `url` with userinfo would not match the URL the request is directed to
  // (RFC 8555 sec. 6.4); refuse it rather than sign a credential-bearing URL that steers nothing. Test the RAW
  // authority for a literal "@", not url.username/password: an EMPTY userinfo ("https://@host", "https://:@host")
  // leaves both empty while the verbatim URL still carries the "@" the transport drops.
  var _uAuth = _uriAuthority(s, true);
  if (intrinsic.stringIndexOf(_uAuth ? _uAuth.authority : "", "@") !== -1) throw E("acme/bad-url", "an ACME URL must not contain userinfo: " + JSON.stringify(s));
  // Reject a spelling the transport would REPAIR into a different path -- whitespace (WHATWG percent-
  // encodes or trims it) or a backslash (rewritten to `/`). The transport re-parses the URL to the
  // normalized path while the JWS `url` keeps the original, so the signed and requested URLs would differ.
  if (_hasWsOrBackslash(s)) throw E("acme/bad-url", "an ACME URL must not contain whitespace or a backslash: " + JSON.stringify(s));
  // The path/query round-trip checks below cover only pathname+search; apply the shared structural authority
  // guard too, so a repaired AUTHORITY (a bracket in userinfo -- "a[b@host" -> "a%5Bb@host", a double "@") is
  // rejected on THIS direct path (a directory / Location / caller URL) exactly as the Link-alternate path
  // already rejects it. Otherwise the verbatim URL would be signed (sec. 6.4) while the transport connects to a
  // different authority. (An uppercase host / explicit :443 is NOT a repair here -- it is normalized, not
  // rewritten to a different authority -- and is deliberately honored below, so it is not flagged.)
  if (_uriStructurallyInvalid(s)) throw E("acme/bad-url", "an ACME URL authority is not canonical (the transport would repair it): " + JSON.stringify(s));
  // Reject a HOST the transport would rewrite to a DIFFERENT authority. WHATWG's special-scheme parser coerces an
  // IPv4-address form -- hex ("0x7f.1"), octal ("0177.0.0.1"), decimal ("2130706433"), shorthand ("127.1") -- into
  // a dotted-quad ("127.0.0.1"), so the JWS `url` would be signed over the raw host while the transport connects to
  // a different (often loopback / internal, an SSRF-adjacent) address. Compare the raw host (ASCII-lowercased, the
  // only tolerated normalization) to the parsed hostname: uppercase-host and a default :443 still match, an IPv4
  // coercion or a non-canonical IPv6 literal does not. (path/query/fragment are checked separately below.)
  var _auth = _uriAuthority(s, true);
  if (_auth) {
    var _hp = _auth.authority.slice(_auth.authority.lastIndexOf("@") + 1);   // strip any userinfo (does not route the request)
    var _rawHost = _hp.charAt(0) === "[" ? _hp.slice(0, _hp.indexOf("]") + 1) : _hp.split(":")[0];   // strip the port
    if (_rawHost.toLowerCase() !== url.hostname) throw E("acme/bad-url", "an ACME URL host is not canonical (the transport would rewrite it): " + JSON.stringify(s));
  }
  // Reject any path the transport would NORMALIZE differently -- literal OR percent-encoded dot-segments
  // (`/..`, `/%2e%2e/`), or an authority-only URL with NO path (`https://ca.example`, where the transport
  // inserts a `/`) -- by comparing the raw path in `s` to the WHATWG-parsed pathname the transport sends as
  // the request target; a mismatch means the signed JWS `url` would keep a path the request never used. The
  // empty raw path is deliberately NOT coerced to `/`: that coercion would mask the authority-only case,
  // whose verbatim `s` (no slash) differs from the `/` the transport requests. (The authority may still
  // normalize -- a default :443 port, an uppercase host -- as that does not change the path; an encoded char
  // like `%41` or a dot inside a segment name round-trips unchanged.)
  var _pathStart = _rawPathStart(s);
  var rawPath = _strSlice(s, _pathStart, _firstDelim(s, _pathStart, 0x3f, 0x23, -1));
  if (rawPath !== url.pathname) throw E("acme/bad-url", "an ACME URL path is not canonical (the transport would normalize it): " + JSON.stringify(s));
  // The query round-trips too (the transport sends pathname+search): an EMPTY query ("...?") -- which WHATWG
  // drops (url.search === "") while the verbatim URL keeps the "?" -- or any query the parser would rewrite
  // signs a JWS `url` differing from the request target. A non-empty canonical query (`?a=b`) round-trips and
  // is honored. (The fragment is rejected below, so the first raw "?" is the query delimiter.)
  var qi = s.indexOf("?");
  var rawQuery = qi === -1 ? "" : s.slice(qi).split("#")[0];
  if (rawQuery !== url.search) throw E("acme/bad-url", "an ACME URL query is not canonical (the transport would normalize it): " + JSON.stringify(s));
  // Reject a fragment: the transport builds the request target from pathname+search only, so a `#frag`
  // would sign a JWS `url` (sec. 6.4) that differs from the URL actually requested, failing at the CA. Test
  // the RAW `#` delimiter, not `url.hash`: an EMPTY fragment ("...alt#") leaves url.hash === "" (falsy) while
  // the verbatim URL still carries the `#`. A literal `#` is always the fragment delimiter (a `#` in a path is
  // %23), so its mere presence is the fragment.
  if (s.indexOf("#") !== -1) throw E("acme/bad-url", "an ACME URL must not contain a fragment: " + JSON.stringify(s));
  // Return the value VERBATIM (the server's exact spelling for the sec. 6.4/7.3 JWS match) -- a conforming
  // CA may emit a form WHATWG would normalize (a default :443 port, an uppercase host); the transport
  // re-parses it for the connection, so such a URL is honored rather than rejected as non-canonical.
  return s;
}
// Turn a server `Location` (which MAY be a relative URI-reference -- valid HTTP, common behind a proxy)
// into the account/order URL: an absolute Location is used verbatim, a relative one is resolved against
// the request URL, and the result is https-gated. A caller URL uses _clientUrl directly.
function _resolveLocation(loc, base) {
  // An ABSOLUTE Location is used VERBATIM (its exact spelling -- an uppercase host, an explicit :443 --
  // for the sec. 6.4/7.3 JWS match, via _clientUrl). Only a RELATIVE reference is resolved against the
  // request URL first (the resolved href is then https-gated).
  var isAbsolute = true;
  try { new URL(loc); }
  catch (_e) { isAbsolute = false; }
  if (isAbsolute) return _clientUrl(loc);
  var u;
  try { u = new URL(loc, base); }
  catch (e) { throw E("acme/bad-url", "the Location header did not resolve to a valid URL: " + JSON.stringify(loc), e); }
  // A relative reference whose QUERY WHATWG re-encoded on resolution (an RFC 3986 reserved char the special-scheme
  // query set percent-encodes -- an apostrophe -> %27) is non-canonical: the signed+requested URL would differ from
  // the raw advertised query (RFC 8555 sec. 6.4). _clientUrl makes this check for an absolute URL, which a relative
  // reference would otherwise bypass.
  if (_queryRepaired(loc, u)) throw E("acme/bad-url", "a relative Link/Location query is not canonical (resolution re-encoded it): " + JSON.stringify(loc));
  return _clientUrl(u.href);
}
// Did resolving `rawRef` re-encode its query (a reserved char like "'" -> %27)? RFC 3986 sec. 6.2.2.2 does NOT make
// a reserved char equivalent to its percent-escape, so a raw query that differs from the resolved search is a
// non-canonical reference -- used to reject a repaired target AND to skip a repaired anchor whose context match
// would otherwise be SPOOFED (a "?x='" anchor byte-matching a base carrying "?x=%27").
function _queryRepaired(rawRef, resolvedUrl) {
  var qi = rawRef.indexOf("?");
  return qi !== -1 && rawRef.slice(qi).split("#")[0] !== resolvedUrl.search;
}
// The default poll sleeper is the shared bounded sleeper (lib/sleep.js): it chunks a delay above Node's
// 32-bit setTimeout ceiling so a large (parser-bounded, up to a year) Retry-After is honored rather than
// silently clamped to 1 ms and rapidly re-polled. pki.cmp.session composes the SAME home.
var _defaultSleep = require("./sleep").sleep;
function _clientTls(o) {
  var t = o.tls || {};
  return { anchors: t.anchors, useSystemStore: t.useSystemStore, cert: t.cert, key: t.key, minVersion: t.minVersion, servername: t.servername, checkServerIdentity: t.checkServerIdentity };
}
// Split a PEM certificate chain (RFC 8555 sec. 7.4.2 application/pem-certificate-chain) into its DER certs.
var PEM_CERT_BEGIN = "-----BEGIN CERTIFICATE-----";
var PEM_CERT_END = "-----END CERTIFICATE-----";
function _splitPemChain(text) {
  var out = [];
  var lastEnd = 0, from = 0, begin, end;
  // Each block is the shortest BEGIN..END span (the lazy /BEGIN[\s\S]*?END/g scan by literal index).
  while ((begin = intrinsic.stringIndexOf(text, PEM_CERT_BEGIN, from)) !== -1 &&
         (end = intrinsic.stringIndexOf(text, PEM_CERT_END, begin + PEM_CERT_BEGIN.length)) !== -1) {
    var blockEnd = end + PEM_CERT_END.length;
    // application/pem-certificate-chain is ONLY PEM blocks separated by whitespace (RFC 8555 sec. 7.4.2) --
    // no explanatory text before, between, or after; reject any non-whitespace outside a block.
    if (text.slice(lastEnd, begin).trim() !== "") throw E("acme/bad-certificate-chain", "the certificate chain contained non-whitespace text outside a PEM block (RFC 8555 sec. 7.4.2)");
    var der;
    // Decode the armor AND structurally parse it: valid PEM armor can wrap arbitrary base64, so without
    // the strict X.509 parse the download could return non-certificate bytes as the issued certificate.
    try { der = x509.pemDecode(_strSlice(text, begin, blockEnd), "CERTIFICATE"); x509.parse(der); }
    catch (e) { throw E("acme/bad-certificate-chain", "a downloaded certificate did not decode as a valid X.509 certificate (RFC 8555 sec. 7.4.2)", e); }
    out.push(der);
    lastEnd = blockEnd;
    from = blockEnd;
  }
  if (text.slice(lastEnd).trim() !== "") throw E("acme/bad-certificate-chain", "the certificate chain contained trailing non-whitespace text outside a PEM block (RFC 8555 sec. 7.4.2)");
  if (!out.length) throw E("acme/bad-certificate-chain", "the certificate download carried no PEM certificate (RFC 8555 sec. 7.4.2)");
  return out;
}

// The default and hard ceilings on the alternate-chain fetch (RFC 8555 sec. 7.4.2). A Link header is an
// UNTRUSTED server field: cap its length before the walk, and cap how many extra signed POSTs it can drive
// (CWE-770 fetch amplification), the same posture as maxRedirects.
var LINK_HEADER_MAX_BYTES = constants.BYTES.kib(8);
var DEFAULT_MAX_ALTERNATES = 8;
// Trim only HTTP OWS -- SP (0x20) and HTAB (0x09) -- NOT arbitrary Unicode whitespace. String.prototype.trim
// would strip an NBSP (obs-text) and other Unicode spaces, letting them masquerade as field whitespace.
function _trimOWS(s) {   // s.replace(/^[ \t]+/, "").replace(/[ \t]+$/, "")
  var a = 0, b = s.length;
  while (a < b && (_charCodeAt(s, a) === 0x20 || _charCodeAt(s, a) === 0x09)) a++;
  while (b > a && (_charCodeAt(s, b - 1) === 0x20 || _charCodeAt(s, b - 1) === 0x09)) b--;
  return _strSlice(s, a, b);
}
// ---- URI / percent / Link character-scan helpers (rule #11: no regex) ----
var _URIREF_TBL = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~:/?#[]@!$&'()*+,;=%-");   // RFC 3986 URI-Reference allowed set
var _UNRES_TBL = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-");   // RFC 3986 unreserved
var _IPVF_TBL = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!$&'()*+,;=:-");   // IPvFuture tail chars
var _HEX_TBL = pkix.charTable("0123456789ABCDEFabcdef");   // hex digit, by table lookup (not an OR-chain)
function _hexVal(c) { if (c >= 48 && c <= 57) return c - 48; if (c >= 65 && c <= 70) return c - 55; return c - 87; }
function _upperHexChar(c) { return (c >= 97 && c <= 102) ? c - 32 : c; }
// The RFC 3986 authority front-half shared by every authority check: an optional (or, when schemeRequired,
// mandatory) scheme, "//", then the authority up to the first "/?#". Returns null when there is no "//".
function _uriAuthority(uri, schemeRequired) {
  var n = uri.length, i = 0, schemeEnd = -1, j;
  if (n > 0 && _isAlpha(_charCodeAt(uri, 0))) {
    j = 1;
    while (j < n && _isSchemeChar(_charCodeAt(uri, j))) j++;
    if (j < n && _charCodeAt(uri, j) === 0x3a) schemeEnd = j;
  }
  if (schemeEnd !== -1) {
    if (_charCodeAt(uri, schemeEnd + 1) === 0x2f && _charCodeAt(uri, schemeEnd + 2) === 0x2f) i = schemeEnd + 1;
    else if (schemeRequired) return null;
    else { schemeEnd = -1; i = 0; }
  }
  if (schemeRequired && schemeEnd === -1) return null;
  if (_charCodeAt(uri, i) !== 0x2f || _charCodeAt(uri, i + 1) !== 0x2f) return null;
  var authStart = i + 2, authEnd = authStart;
  while (authEnd < n) { var c = _charCodeAt(uri, authEnd); if (c === 0x2f || c === 0x3f || c === 0x23) break; authEnd++; }
  return { scheme: schemeEnd === -1 ? "" : _strSlice(uri, 0, schemeEnd + 1), authorityStart: authStart, authorityEnd: authEnd, authority: _strSlice(uri, authStart, authEnd) };
}
// The first index at/after `from` whose code is one of the (up to three) delimiters, else the string length.
function _firstDelim(s, from, d0, d1, d2) { for (var i = from; i < s.length; i++) { var c = _charCodeAt(s, i); if (c === d0 || c === d1 || c === d2) return i; } return s.length; }
// /^:[0-9]*$/ : ":" then zero or more digits (an empty port ":" passes).
function _isNumericPort(s) { if (s.length === 0 || _charCodeAt(s, 0) !== 0x3a) return false; for (var i = 1; i < s.length; i++) { var c = _charCodeAt(s, i); if (c < 48 || c > 57) return false; } return true; }
// /^[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+$/ : a valid RFC 3986 IPvFuture literal interior.
function _isIpvFuture(s) {
  var n = s.length, i = 1, h = 0, g = 0;
  if (n === 0 || (_charCodeAt(s, 0) !== 0x76 && _charCodeAt(s, 0) !== 0x56)) return false;
  while (i < n) { if (_HEX_TBL[_charCodeAt(s, i)]) { i++; h++; } else break; }
  if (h < 1 || i >= n || _charCodeAt(s, i) !== 0x2e) return false;
  i++;
  while (i < n) { if (_IPVF_TBL[_charCodeAt(s, i)]) { i++; g++; } else break; }
  return g >= 1 && i === n;
}
// The prefix ^(?:scheme:)?//(?:[^/?#@[\]]*@)?\[[^[\]]*\] : optional scheme, "//", optional BRACKET-EXCLUDING
// userinfo, then an IP-literal host. Returns the index past "]" (the match length from 0) or -1.
function _matchBracketAuthPrefix(uri) {
  var a = _uriAuthority(uri, false);
  if (!a) return -1;
  var n = uri.length, i = a.authorityStart, save = i, k = i, uiOk = true, c;
  while (k < n) { c = _charCodeAt(uri, k); if (c === 0x40) break; if (c === 0x2f || c === 0x3f || c === 0x23 || c === 0x5b || c === 0x5d) { uiOk = false; break; } k++; }
  if (uiOk && k < n && _charCodeAt(uri, k) === 0x40) i = k + 1; else i = save;
  if (_charCodeAt(uri, i) !== 0x5b) return -1;
  i++;
  while (i < n) { c = _charCodeAt(uri, i); if (c === 0x5b || c === 0x5d) break; i++; }
  if (i >= n || _charCodeAt(uri, i) !== 0x5d) return -1;
  return i + 1;
}
// The prefix ^(?:scheme:)?//(?:[^/?#@]*@)?\[([^\]]*)\] : optional scheme, "//", optional BRACKET-PERMITTING
// userinfo, then an IP-literal host. Returns the interior (between "[" and "]") or null.
function _ipLiteralInterior(uri) {
  var a = _uriAuthority(uri, false);
  if (!a) return null;
  var n = uri.length, save = a.authorityStart, k = save, c, bracketAt;
  while (k < n) { c = _charCodeAt(uri, k); if (c === 0x2f || c === 0x3f || c === 0x23 || c === 0x40) break; k++; }
  if (k < n && _charCodeAt(uri, k) === 0x40 && _charCodeAt(uri, k + 1) === 0x5b) bracketAt = k + 1;
  else if (_charCodeAt(uri, save) === 0x5b) bracketAt = save;
  else return null;
  var start = bracketAt + 1, p = start;
  while (p < n && _charCodeAt(uri, p) !== 0x5d) p++;
  if (p >= n) return null;
  return _strSlice(uri, start, p);
}
// s.replace(/^[a-z]+:\/\/[^/?#]*/i, "") -> the index where the path begins (0 if there is no scheme+"//").
function _rawPathStart(s) {
  var n = s.length, i = 0;
  while (i < n && _isAlpha(_charCodeAt(s, i))) i++;
  if (i === 0) return 0;
  if (_charCodeAt(s, i) !== 0x3a || _charCodeAt(s, i + 1) !== 0x2f || _charCodeAt(s, i + 2) !== 0x2f) return 0;
  i += 3;
  while (i < n) { var c = _charCodeAt(s, i); if (c === 0x2f || c === 0x3f || c === 0x23) break; i++; }
  return i;
}
// Does `s` contain a character NOT in `table`? (A bespoke false-on-empty scan: !pkix.allCharsIn would wrongly
// report an empty string as carrying a bad character.)
function _hasCharOutside(s, table) { for (var i = 0; i < s.length; i++) { if (!table[_charCodeAt(s, i)]) return true; } return false; }
// /%(?![0-9A-Fa-f]{2})/ : a "%" NOT introducing a valid pct-escape (two hex digits).
function _hasBadPct(s) { for (var i = 0; i < s.length; i++) { if (_charCodeAt(s, i) === 0x25 && !(_HEX_TBL[_charCodeAt(s, i + 1)] && _HEX_TBL[_charCodeAt(s, i + 2)])) return true; } return false; }
// /^[A-Za-z][A-Za-z0-9.-]*$/ : an RFC 8288 reg-rel-type (a letter then letters / digits / "." / "-").
function _isRegRelType(t) { var n = t.length; if (n === 0 || !_isAlpha(_charCodeAt(t, 0))) return false; for (var i = 1; i < n; i++) { var c = _charCodeAt(t, i); if (!(_isAlpha(c) || (c >= 48 && c <= 57) || c === 0x2e || c === 0x2d)) return false; } return true; }
// Fold every "%2e"/"%2E" in a path segment to "." (that specific dot escape, NOT a general pct-decode); records
// whether any fold occurred (the /%2e/i prefilter). Returns { decoded, folded }.
function _foldPct2e(seg) { var out = "", i = 0, n = seg.length, folded = false; while (i < n) { if (_charCodeAt(seg, i) === 0x25 && _charCodeAt(seg, i + 1) === 0x32 && (_charCodeAt(seg, i + 2) === 0x65 || _charCodeAt(seg, i + 2) === 0x45)) { out += "."; folded = true; i += 3; } else { out += _charAt(seg, i); i += 1; } } return { decoded: out, folded: folded }; }
// inner.replace(/\\(.)/g, "$1") : unescape RFC 7230 quoted-pairs ("\x" -> "x"). "\" + a line terminator is left
// intact (the regex "." matches no line terminator), as is a dangling final "\".
function _unescapeQuotedPair(inner) {
  var out = "", i = 0, n = inner.length;
  while (i < n) {
    if (_charCodeAt(inner, i) === 0x5c && i + 1 < n) {
      var nx = _charCodeAt(inner, i + 1);
      if (nx === 0x0a || nx === 0x0d || nx === 0x2028 || nx === 0x2029) { out += _charAt(inner, i); i += 1; }
      else { out += _charAt(inner, i + 1); i += 2; }
    } else { out += _charAt(inner, i); i += 1; }
  }
  return out;
}
// Is `t` a valid RFC 8288 sec. 3.3 relation-type -- a reg-rel-type (a letter then LDH, compared case-
// insensitively) OR an ext-rel-type (an absolute URI: a scheme then ':', AND a canonical RFC 3986 reference so
// a scheme prefix alone is not enough, e.g. "http:%ZZ" is rejected for its malformed pct-escape)? "@" is neither.
function _validRelType(t) {
  if (_isRegRelType(t)) return true;   // reg-rel-type
  // ext-rel-type: a full absolute URI. A relation type is an identifier, never resolved, so a percent-encoded dot
  // (%2e) is a legal char (not a dot-segment); other than that its structure must be a valid absolute URI.
  if (_hasCharOutside(t, _URIREF_TBL)) return false;
  return _validAbsoluteUri(t);
}
// Is `t` a valid RFC 3986 ABSOLUTE URI (a relation-type identifier, never connected to)? A scheme, valid pct-
// escapes, and a structurally valid authority/path. The characters are already validated (LINK_URI_BADCHAR above);
// _uriStructurallyInvalid enforces the rest by RFC 3986 GRAMMAR -- brackets only in an authority IP-literal whose
// content is a valid IPv6/IPvFuture, a non-empty authority, at most one "@", at most one "#", a numeric port. NO
// URL.canParse on the whole URI: its special-scheme quirks wrongly reject valid identifiers (an IPv4 coercion of a
// numeric reg-name "1.2.3.4.5", a 16-bit port cap, IPvFuture, an empty reg-name "foo://user@/"); WHATWG is used
// only inside _badIpLiteral to validate an IPv6 literal, the one place it is correct.
function _validAbsoluteUri(t) {
  return _hasSchemePrefix(t) && !_hasBadPct(t) && !_uriStructurallyInvalid(t);
}
// A URI carries at most ONE "#" (the fragment delimiter); a fragment cannot itself contain "#" (RFC 3986 sec.
// 3.5), so a second literal "#" is invalid, which WHATWG ACCEPTS by folding the rest into the fragment. A pct-
// encoded "%23" is a literal char, not counted.
function _multiFragment(uri) { return uri.split("#").length > 2; }
// The authority (after "//", optionally after a scheme, up to the next "/?#") carries at most one "@" (userinfo
// "@" host); a second literal "@" is invalid RFC 3986, which WHATWG ACCEPTS while rewriting the first "@".
function _authorityMultiAt(uri) {
  var a = _uriAuthority(uri, false);
  if (!a) return false;
  var cnt = 0;
  for (var i = 0; i < a.authority.length; i++) { if (_charCodeAt(a.authority, i) === 0x40) cnt++; }
  return cnt >= 2;
}
// A URI whose scheme REQUIRES an authority (or a scheme-relative reference, which inherits one -- always https
// here) must have a NON-EMPTY authority. A "//" immediately followed by "/", "?", "#", or end is an empty
// authority WHATWG silently REPAIRS by promoting the next path segment to the host ("///cert/alt" -> host "cert";
// "////acme.example/p" -> host "acme.example"; "http:///relations" -> host "relations"). A scheme that legitimately
// allows an empty authority (file:///path, or any non-authority scheme) is NOT flagged.
function _hasEmptyAuthority(uri) {
  var a = _uriAuthority(uri, false);
  if (!a) return false;
  var scheme = a.scheme === "" ? "" : a.scheme.slice(0, -1).toLowerCase();   // "" == scheme-relative (inherits the https base)
  if (scheme !== "" && scheme !== "http" && scheme !== "https" && scheme !== "ws" && scheme !== "wss" && scheme !== "ftp") return false;
  // The HOST itself (the authority with any userinfo and port stripped) must be non-empty -- not only the char
  // right after "//": "https://user@/x" and "https://:443/x" have an empty host after the userinfo / before the
  // port, which WHATWG rejects (or repairs) for a special scheme.
  var host = a.authority.slice(a.authority.lastIndexOf("@") + 1);
  if (host.charAt(0) !== "[") { var ci = host.indexOf(":"); if (ci !== -1) host = host.slice(0, ci); }
  return host === "";
}
// Are any brackets in `uri` confined to a single authority IP-literal (`scheme://[...]`, scheme optional for a
// network-path reference, RFC 3986 sec. 4.2)? RFC 3986 permits `[`/`]` ONLY there; anywhere else -- a path
// ("/cert/[alt]") or an opaque scheme part ("urn:[") -- they are invalid, yet WHATWG's lenient parse accepts them.
function _bracketsOnlyInAuthority(uri) {
  if (uri.indexOf("[") === -1 && uri.indexOf("]") === -1) return true;
  // Optional userinfo may precede the IP-literal host (RFC 3986: authority = [ userinfo "@" ] host [ ":" port ]).
  // A raw "[" / "]" is NOT permitted in userinfo (RFC 3986 sec. 3.2.1/3.2.2 -- the IP-literal host is the ONLY place
  // square brackets are allowed), so the userinfo class excludes them; otherwise "a[b@[::1]" (which WHATWG repairs
  // to "a%5Bb@[::1]") would anchor on the real host and slip.
  var mlen = _matchBracketAuthPrefix(uri);
  if (mlen === -1) return false;
  var rest = _strSlice(uri, mlen);
  if (rest.indexOf("[") !== -1 || rest.indexOf("]") !== -1) return false;   // no bracket past the authority
  // After the IP-literal HOST "]", the rest of the authority (up to the next "/?#") may be ONLY an optional numeric
  // ":port". Anything else -- an "@" ("[::1]:80@host" / "[::1]@host", where "[::1]" is a bracketed userinfo, invalid
  // RFC 3986), a non-numeric port, or trailing host text -- means the literal sits in an invalid position, which
  // WHATWG would re-parse to a DIFFERENT host.
  var afterHost = _strSlice(rest, 0, _firstDelim(rest, 0, 0x2f, 0x3f, 0x23));
  return afterHost === "" || _isNumericPort(afterHost);
}
// A relative-PATH reference (no scheme, no "//" authority) whose FIRST path segment contains a ":" is a
// path-noscheme violation (RFC 3986 sec. 3.3 / 4.2: the first segment "cannot contain a colon (':') character",
// as it would be mistaken for a scheme). ":foo" or "1x:y" is such a case, which WHATWG resolves against the base
// (same-origin) rather than rejecting. A real scheme ("foo:bar") is handled by the scheme/https gates, not here.
function _relFirstSegHasColon(uri) {
  if (_hasSchemePrefix(uri) || uri.indexOf("//") === 0) return false;
  return _uriFirstSegment(uri).indexOf(":") !== -1;
}
// The authority port (":" after the host, before the next "/?#") must be *DIGIT (RFC 3986 sec. 3.2.3). A
// non-numeric port ("host:bad") is malformed -- the character + structural checks otherwise miss it, and WHATWG
// rejects it only on connect (so a fetched target would be skipped rather than failing closed). An empty port
// (":") and a missing port are fine.
function _badPort(uri) {
  var a = _uriAuthority(uri, false);
  if (!a) return false;
  var auth = a.authority, n = auth.length, i = 0, at = -1, hostEnd, e;
  for (var u = 0; u < n; u++) { if (_charCodeAt(auth, u) === 0x40) { at = u; break; } }   // userinfo up to first "@"
  if (at !== -1) i = at + 1;
  if (i < n && _charCodeAt(auth, i) === 0x5b) {   // IP-literal host "[...]"
    e = i + 1;
    while (e < n && _charCodeAt(auth, e) !== 0x5d) e++;
    if (e < n) hostEnd = e + 1;
    else { hostEnd = i; while (hostEnd < n && _charCodeAt(auth, hostEnd) !== 0x3a) hostEnd++; }
  } else { hostEnd = i; while (hostEnd < n && _charCodeAt(auth, hostEnd) !== 0x3a) hostEnd++; }   // reg-name up to ":"
  if (hostEnd >= n || _charCodeAt(auth, hostEnd) !== 0x3a) return false;   // no port
  return !_isNumericPort(_strSlice(auth, hostEnd));
}
// An IP-literal host "[...]" must CONTAIN a valid IPv6 address or IPvFuture (RFC 3986 sec. 3.2.2) -- "[not-ip]",
// "[]", "[garbage]" are malformed, which the bracket-placement check alone accepts (it only confirms the brackets
// are in the authority) and WHATWG rejects only on connect (so a fetched target would be skipped rather than
// failing closed). IPvFuture is checked by grammar; an IPv6 by WHATWG (which parses it correctly). `URL.canParse`
// never throws, so no swallow.
function _badIpLiteral(uri) {
  var interior = _ipLiteralInterior(uri);
  if (interior === null) return false;
  if (_isIpvFuture(interior)) return false;   // valid IPvFuture
  return !URL.canParse("http://[" + interior + "]/");
}
// The RFC 3986 STRUCTURAL rules a URI-reference must satisfy that WHATWG would otherwise silently REPAIR (accept
// while rewriting) or reject only on connect: brackets only in an authority IP-literal, a non-empty authority, at
// most one "@" in the authority, at most one "#", a numeric port, no colon in a relative-path first segment.
// SHARED by the fetched-target/anchor check (_linkUriInvalid) AND the ext-rel-type check (_validAbsoluteUri) so the
// two can NEVER diverge -- a new structural rule added here binds both at once.
function _uriStructurallyInvalid(uri) {
  return !_bracketsOnlyInAuthority(uri) || _hasEmptyAuthority(uri) || _authorityMultiAt(uri) || _multiFragment(uri) || _relFirstSegHasColon(uri) || _badPort(uri) || _badIpLiteral(uri);
}
// RFC 3986 sec. 6.2.2 syntax-based normalization for an alternate DEDUP key (the verbatim URL is still what is
// fetched + signed, sec. 6.4). The WHATWG-normalized href already lowercases scheme+host, drops a default port,
// and removes dot-segments; on top of that, DECODE a percent-escape of an unreserved char (sec. 6.2.2.2 --
// "%61" == "a") and UPPERCASE the hex of any other escape (sec. 6.2.2.1), so equivalent spellings collapse to one
// signed fetch (CWE-770). fromCharCode keeps the source pure-ASCII while matching a runtime byte.
function _dedupKey(href) {
  var out = "", i = 0, n = href.length;
  while (i < n) {
    if (_charCodeAt(href, i) === 0x25 && _HEX_TBL[_charCodeAt(href, i + 1)] && _HEX_TBL[_charCodeAt(href, i + 2)]) {
      var h1 = _charCodeAt(href, i + 1), h2 = _charCodeAt(href, i + 2), v = (_hexVal(h1) << 4) | _hexVal(h2);
      if (_UNRES_TBL[v]) out += String.fromCharCode(v);                                          // decode an unreserved escape
      else out += "%" + String.fromCharCode(_upperHexChar(h1)) + String.fromCharCode(_upperHexChar(h2));   // else uppercase the hex
      i += 3;
    } else { out += _charAt(href, i); i += 1; }
  }
  return out;
}
// A path SEGMENT that decodes to "." or ".." via a percent-encoded dot (`%2e`): URL resolution decodes `%2e`
// to `.` for dot-segment removal, so an encoded `..` silently becomes a path traversal that changes the
// resolved target. Reject only such an encoded dot-SEGMENT -- an encoded dot elsewhere (a filename `0%2ex` ->
// `0.x`) is a valid target, and a LITERAL `.`/`..` segment resolves transparently. Path only (before ?/#).
function _hasEncodedDotSegment(uri) {
  var segs = _split(_strSlice(uri, 0, _firstDelim(uri, 0, 0x3f, 0x23, -1)), "/");
  for (var _si = 0; _si < segs.length; _si++) {
    var r = _foldPct2e(segs[_si]);
    if (!r.folded) continue;
    if (r.decoded === "." || r.decoded === "..") return true;
  }
  return false;
}
// Is a Link URI-Reference (a target OR an anchor) NOT a canonical RFC 3986 reference -- i.e. one URL parsing
// would repair (a disallowed char, a malformed pct-escape, an encoded dot-segment) on resolution?
function _linkUriInvalid(uri) {
  // A bracket in a resolved target/anchor is valid only in an authority IP-literal (a same-origin IPv6/IPvFuture
  // cert URL is legal); in a path it is invalid and WHATWG would repair it by percent-encoding.
  return _hasCharOutside(uri, _URIREF_TBL) || _hasBadPct(uri) || _hasEncodedDotSegment(uri) || _uriStructurallyInvalid(uri);
}
// A control octet forbidden in an HTTP field-value (RFC 9110): any C0 control except HTAB, plus DEL. Checked
// by code point (not a control-char regex) to keep the source pure ASCII and clear of eslint no-control-regex.
function _hasCtlOctet(s) {
  for (var _ci = 0; _ci < s.length; _ci++) { var _cc = s.charCodeAt(_ci); if (_cc === 0x7F || (_cc < 0x20 && _cc !== 0x09)) return true; }
  return false;
}

// Split an RFC 8288 Link field into its comma-separated link-values, respecting <...> and "..." context so
// a comma inside a URI or a quoted parameter value is not a separator. An unterminated quote fails closed.
function _splitLinkValues(s) {
  var out = [], start = 0, inAngle = false, inQuote = false;
  for (var i = 0; i < s.length; i++) {
    var ch = s.charAt(i);
    if (inQuote) { if (ch === "\\") { i++; continue; } if (ch === "\"") inQuote = false; continue; }
    if (ch === "\"") { inQuote = true; continue; }
    if (ch === "<") inAngle = true;
    else if (ch === ">") inAngle = false;
    else if (ch === "," && !inAngle) { out.push(s.slice(start, i)); start = i + 1; }
  }
  if (inQuote || inAngle) throw E("acme/bad-link", "the Link header has an unterminated quote or angle bracket (RFC 8288)");
  out.push(s.slice(start));
  return out;
}
// Split a link-value's parameter tail (everything after `<URI>`) into `;`-separated name=value params,
// quote-aware; a quoted value is unescaped. Returns [{ name (lower-cased), value }].
function _splitLinkParams(rest) {
  var parts = [], start = 0, inQuote = false;
  for (var i = 0; i < rest.length; i++) {
    var ch = rest.charAt(i);
    if (inQuote) { if (ch === "\\") { i++; continue; } if (ch === "\"") inQuote = false; continue; }
    if (ch === "\"") inQuote = true;
    else if (ch === ";") { parts.push(rest.slice(start, i)); start = i + 1; }
  }
  parts.push(rest.slice(start));
  var out = [];
  for (var j = 0; j < parts.length; j++) {
    var p = _trimOWS(parts[j]);
    // `rest` starts with the first `;`, so parts[0] is an expected empty slot before the first parameter. Any
    // OTHER empty part is a `;` with no parameter after it (`;;` or a trailing `;`) -- malformed (RFC 8288).
    if (p === "") { if (j === 0) continue; throw E("acme/bad-link", "an empty Link parameter (a ';' with no parameter) is malformed (RFC 8288): " + JSON.stringify(rest)); }
    var eq = p.indexOf("=");
    var name = (eq === -1 ? p : _trimOWS(p.slice(0, eq))).toLowerCase();
    // A parameter NAME is a token (RFC 8288 / RFC 7230): reject whitespace / specials rather than accept a
    // malformed "bad name=x" as a silently-ignored parameter that masks the value grammar below.
    if (!pkix.allCharsIn(name, _LINK_TOKEN_TABLE)) throw E("acme/bad-link", "a Link parameter name must be a token (RFC 8288 / RFC 7230): " + JSON.stringify(p));
    // A valueless token parameter is VALID: RFC 8288 link-param = token BWS [ "=" BWS ( token / quoted-string ) ]
    // -- the value is OPTIONAL. Keep it as an empty-valued extension param (it is never `rel`, so it is ignored).
    // (An EMPTY part -- a `;` with no token at all, e.g. `;;` -- was already rejected above.)
    if (eq === -1) { out.push({ name: name, value: "", hasValue: false }); continue; }
    var v = _trimOWS(p.slice(eq + 1));
    if (v.length >= 2 && v.charAt(0) === "\"" && v.charAt(v.length - 1) === "\"") {
      var inner = v.slice(1, -1);   // a quoted-string may hold a space-separated list (RFC 8288)
      if (!_isValidQuotedInterior(inner)) throw E("acme/bad-link", "a quoted Link parameter value is malformed (an unescaped quote or dangling backslash, RFC 7230): " + JSON.stringify(p));
      v = _unescapeQuotedPair(inner);
    } else if (!pkix.allCharsIn(v, _LINK_TOKEN_TABLE)) {
      // An UNQUOTED value is a single NON-EMPTY RFC 7230 token -- no whitespace/specials, and an empty value
      // (`foo=`) is not a token (an empty value must be quoted, `foo=""`). Reject a malformed one rather than
      // split-and-match it as if it were a quoted relation list.
      throw E("acme/bad-link", "an unquoted Link parameter value must be a non-empty token (RFC 8288 / RFC 7230): " + JSON.stringify(p));
    }
    out.push({ name: name, value: v, hasValue: true });
  }
  return out;
}
// Does an RFC 8288 rel value (a space-separated relation-type list) contain "alternate" as a WHOLE token,
// case-insensitively (RFC 8288 sec. 3.3)? Never a substring -- "alternateX" / "xalternate" do not match.
function _relHas(rel, relName) {
  // The rel value is a SPACE-separated relation-type list (RFC 8288 sec. 3.3) -- split on SP only, NOT a tab
  // or other whitespace, so "next<TAB>index" is a single (non-matching) relation-type, not a false match.
  var toks = String(rel).split(" ");
  for (var i = 0; i < toks.length; i++) { if (toks[i].toLowerCase() === relName) return true; }
  return false;
}
// Parse one link-value `"<" URI-Reference ">" *( ";" link-param )` -> { uri, rel } (rel "" if absent);
// a blank segment (a trailing comma) -> null (skip); anything not starting with <...> -> acme/bad-link.
function _parseLinkValue(raw) {
  var s = _trimOWS(raw);
  if (s === "") return null;
  var gt = s.indexOf(">");
  if (s.charAt(0) !== "<" || gt === -1) throw E("acme/bad-link", "a Link value must be <URI-Reference> with parameters (RFC 8288): " + JSON.stringify(raw));
  // After the "<URI>" the remainder is *( OWS ";" OWS link-param ) -- so, past any leading whitespace, it is
  // empty or begins with ';'. Any other trailing text (a param not introduced by ';', e.g. "<uri>rel=...") is
  // malformed and MUST NOT be leniently read as a parameter.
  var rest = _stripLeadingOWS(s, gt + 1);
  if (rest !== "" && rest.charAt(0) !== ";") throw E("acme/bad-link", "a Link value's parameters must be introduced by ';' (RFC 8288): " + JSON.stringify(raw));
  var uri = s.slice(1, gt);
  // A URI-Reference carries only RFC 3986 characters; WHATWG URL parsing would silently REPAIR anything else
  // (trim whitespace, percent-encode a brace/control char, rewrite a backslash) when the target is later
  // resolved -- masking a malformed / off-path value. Reject it up front, the same canonicality posture the
  // client applies to every server-provided URL (a relative target skips _clientUrl's raw-vs-parsed check).
  if (_linkUriInvalid(uri)) throw E("acme/bad-link", "a Link URI-Reference contains a character, percent-escape, or encoded dot-segment not permitted by RFC 3986: " + JSON.stringify(raw));
  var params = _splitLinkParams(rest), rel = "", relSeen = false, anchor = null, anchorSeen = false;
  for (var i = 0; i < params.length; i++) {
    // The FIRST occurrence of rel wins; later ones are ignored (RFC 8288 sec. 3.3, a singleton) -- take the first
    // even when its value is empty, so `rel="";rel=alternate` keeps the empty first value (the caller then fails
    // closed on the empty rel, rather than falling through to the later alternate).
    if (params[i].name === "rel" && !relSeen) { rel = params[i].value; relSeen = true; }
    else if (params[i].name === "anchor") {
      // anchor is NOT in the RFC 8288 sec. 3.3 singleton set (rel/media/title/title*/type), so it has no "ignore
      // after the first" rule. A DUPLICATE anchor is ambiguous, and anchor is security-relevant (it overrides the
      // link CONTEXT), so it fails closed rather than silently taking one. A VALUELESS anchor (no `=`) is malformed;
      // an explicit value -- even an empty quoted one (`anchor=""`, resolving to the context) -- is valid.
      if (anchorSeen) throw E("acme/bad-link", "a Link value must not carry more than one anchor parameter (RFC 8288 sec. 3.2, ambiguous context): " + JSON.stringify(raw));
      anchorSeen = true;
      if (!params[i].hasValue) throw E("acme/bad-link", "a Link anchor parameter requires a URI value (RFC 8288 sec. 3.2): " + JSON.stringify(raw));
      anchor = params[i].value;
    }
  }
  return { uri: uri, rel: rel, anchor: anchor, relSeen: relSeen };
}
// Parse an RFC 8288 Link response header for the targets of ONE relation type -- the sec. 7.4.2
// `alternate` certificate chains and the sec. 7.1.2.1 `next` orders page share every byte-cap /
// control-octet / rel-well-formedness / anchor-context / resolve / https-gate / origin-gate / dedupe
// rule, and only the matched relation and the singleton rule vary. Read the (case-insensitive,
// node-lower-cased) `link` field -- a combined string OR an array -- bound its length, split into
// link-values, keep the `relName`-rel ones, resolve each against `base`, https-gate, origin-gate to
// `base`'s origin, and dedupe by resolved URL. An UNTRUSTED header: every malformed shape or non-https /
// off-origin / unresolvable target fails closed as acme/bad-link. opts.singleton (RFC 8288 sec. 3.3)
// makes >1 DISTINCT target ambiguous -> acme/bad-link, for a singleton relation such as `next`.
function _parseLinkRelation(headers, base, relName, opts) {
  opts = opts || {};
  var raw = null;
  for (var k in headers) { if (_hasOwn(headers, k) && k.toLowerCase() === "link") { raw = headers[k]; break; } }
  if (raw == null) return [];
  var baseUrl = new URL(base), baseOrigin = baseUrl.origin, baseHref = baseUrl.href;   // the download URL
  var fields = Array.isArray(raw) ? raw : [raw], out = [], seen = Object.create(null), totalBytes = 0;
  // Seed the dedup set with the PRIMARY download URL: a CA that advertises the certificate URL itself as a
  // rel="alternate" (it is not an alternate of itself, RFC 8555 sec. 7.4.2) must not cause a redundant re-fetch.
  seen[_dedupKey(baseHref)] = true;
  for (var fi = 0; fi < fields.length; fi++) {
    var field = String(fields[fi]);
    // Cap the AGGREGATE across every Link field (CWE-770): an injected transport / duplicate-Link array can
    // hand back many fields, each under a per-field size, that together are unbounded -- bound the sum so the
    // parse work (and the collected alternate set) cannot amplify regardless of the header's shape. Charge a
    // per-field overhead so a flood of EMPTY fields (each 0 bytes) still counts toward the cap.
    totalBytes += field.length + 1;
    if (totalBytes > LINK_HEADER_MAX_BYTES) throw E("acme/bad-link", "the Link header(s) exceed the " + LINK_HEADER_MAX_BYTES + "-byte aggregate cap (RFC 8288, CWE-770)");
    if (_hasCtlOctet(field)) throw E("acme/bad-link", "a Link header must not contain control octets (RFC 9110 field-value)");
    var values = _splitLinkValues(field);
    for (var vi = 0; vi < values.length; vi++) {
      var lv = _parseLinkValue(values[vi]);
      if (lv === null) continue;
      // A rel that is PRESENT but empty (`rel=""`) is a zero-length relation-type list, which is malformed (RFC
      // 8288 sec. 3.3 requires >=1 type). Fail closed rather than silently skip it -- otherwise a malformed value
      // could shadow a later valid one. (A link-value with NO rel at all is simply not one of ours -> skipped.)
      if (lv.relSeen && lv.rel === "") throw E("acme/bad-link", "a Link rel parameter must name at least one relation-type (RFC 8288 sec. 3.3)");
      // The rel value is a space-separated relation-type list with 1*SP separators (RFC 8288 sec. 3.3): multiple
      // spaces BETWEEN types are allowed, but a LEADING or TRAILING space is malformed (so "alternate " is not
      // split-and-matched as containing "alternate", while "alternate  index" is a valid two-type list).
      if (lv.rel !== "" && (lv.rel.charAt(0) === " " || lv.rel.charAt(lv.rel.length - 1) === " ")) throw E("acme/bad-link", "a Link rel value has a leading or trailing space (RFC 8288 sec. 3.3): " + JSON.stringify(lv.rel));
      // EVERY relation-type in the list must be well-formed (RFC 8288 sec. 3.3): a bad token (e.g. "@") makes the
      // list malformed, even if another token is "alternate". (Empty tokens are internal 1*SP -- skip them.)
      var relToks = lv.rel === "" ? [] : lv.rel.split(" ");
      for (var ri = 0; ri < relToks.length; ri++) { if (relToks[ri] !== "" && !_validRelType(relToks[ri])) throw E("acme/bad-link", "a Link rel value contains a token that is not a valid relation-type (RFC 8288 sec. 3.3): " + JSON.stringify(lv.rel)); }
      if (!_relHas(lv.rel, relName)) continue;
      // RFC 8288 sec. 3.2: an `anchor` overrides the link's CONTEXT. A certificate alternate's context is the
      // certificate itself (the download URL); a link anchored to another resource is an alternate of THAT
      // resource, not this certificate -- skip it. No anchor, or one resolving to the download URL, is ours.
      if (lv.anchor != null) {
        // Validate the RAW anchor with the same RFC 3986 rules as a target BEFORE resolving: otherwise a
        // repairable anchor (an encoded dot-segment) could traverse to the certificate URL and SPOOF a context
        // match. A non-canonical anchor is not a reliable context -> skip.
        if (_linkUriInvalid(lv.anchor)) continue;
        var au;
        try { au = new URL(lv.anchor, base); } catch (_ae) { continue; }
        // A repaired anchor query ("?x='" re-encoded to "?x=%27") must not byte-match a base carrying "?x=%27":
        // "'" is a reserved sub-delim, not equivalent to its escape (RFC 3986 sec. 6.2.2.2), so a resolution that
        // re-encoded it is a non-canonical anchor -> unreliable context, skip.
        if (_queryRepaired(lv.anchor, au)) continue;
        if (au.href !== baseHref) continue;
      }
      var resolved;
      try { resolved = _resolveLocation(lv.uri, base); }   // resolves a relative ref + enforces the https gate
      catch (e) {
        // A non-https alternate is a security-relevant anomaly -> fail the whole header closed. A target that is a
        // valid RFC 3986 reference but not a canonical ACME request URL (literal dot-segments, or a sub-delim
        // WHATWG would re-encode in a special-scheme query) cannot be signed AND requested byte-identically
        // (RFC 8555 sec. 6.4), so it is merely UNUSABLE -> skip THIS alternate and keep the others (sec. 7.4.2
        // permits several), rather than discarding every valid alternate over one non-canonical spelling.
        if (e && e.code === "acme/insecure-url") throw E("acme/bad-link", "a rel=\"" + relName + "\" Link target is not an https URL: " + JSON.stringify(lv.uri), e);
        continue;
      }
      // Origin-gate: an alternate is fetched with the ACCOUNT-KEY-signed POST-as-GET, so an untrusted (TLS-
      // delivered but unsigned) Link header MUST NOT steer that authenticated request to a different origin
      // (SSRF). Confine alternates to the certificate download's own origin -- the same "possibly compromised
      // directory" threat the cross-origin mTLS-credential strip already defends (RFC 8555 sec. 7.4.2
      // alternates are the CA's own chains, served alongside the certificate).
      var parsed = new URL(resolved);
      if (parsed.origin !== baseOrigin) throw E("acme/bad-link", "a rel=\"" + relName + "\" Link target is not on the request URL's origin (SSRF guard): " + JSON.stringify(lv.uri));
      // Dedup by the RFC 3986 sec. 6.2.2-normalized href (lowercased scheme+host, no default :443, no dot-segments,
      // unreserved pct-escapes decoded), so equivalent spellings ("acme.example" vs "ACME.EXAMPLE:443", "/alt" vs
      // "/%61lt") collapse to one fetch (CWE-770 amplification) -- while the VERBATIM resolved string is what is
      // fetched + signed (RFC 8555 sec. 6.4 exact-URL match).
      var key = _dedupKey(parsed.href);
      if (!seen[key]) { seen[key] = true; out.push(resolved); }
    }
  }
  // RFC 8288 sec. 3.3: `next` is a singleton relation-type, so more than one DISTINCT target is ambiguous.
  // The deduped set already collapses equivalent spellings, so this fires only on genuinely different URLs.
  if (opts.singleton && out.length > 1) throw E("acme/bad-link", "the Link header names more than one distinct rel=\"" + relName + "\" target (RFC 8288 sec. 3.3, a singleton relation)");
  return out;
}

function _parseLinkAlternates(headers, base) { return _parseLinkRelation(headers, base, "alternate", {}); }
// The single sec. 7.1.2.1 `next` orders-page target resolved against `base`, or null when the header names none.
function _parseLinkNext(headers, base) { var m = _parseLinkRelation(headers, base, "next", { singleton: true }); return m.length ? m[0] : null; }

/**
 * @primitive  pki.acme.client
 * @signature  pki.acme.client(directoryUrl, opts) -> client
 * @since      0.3.18
 * @status     stable
 * @spec       RFC 8555, RFC 8737, RFC 8738, RFC 9773
 * @related    pki.acme.newOrder, pki.transport.https
 *
 * A stateful RFC 8555 ACME client that drives the live directory flow over the shared `pki.transport`
 * (inject `opts.transport`, else a fail-closed `pki.transport.https`). It composes the shipped message
 * layer (the JWS builders + object validators + state machines) and owns only session state: the
 * fetched directory, the single-use nonce pool (a fresh anti-replay nonce per JWS, badNonce bounded-
 * retried with the error's Replay-Nonce), and the account URL captured as the `kid`. `opts.accountKey`
 * (a private CryptoKey) + `opts.accountJwk` (its public JWK) + `opts.alg` sign every request. Every
 * request is https-only (`acme/insecure-url`); reads are POST-as-GET; a problem+json response is a
 * typed `acme/server-problem`; a poll sleeps on a bounded Retry-After via an injectable sleeper and is
 * capped by a poll count and a total-wait budget. Returns a client
 * object: `directory`, `newAccount`, `newOrder`, `newAuthz`, `getOrder` / `getAuthorization` / `getChallenge`,
 * `respondToChallenge`, `finalize`, `pollOrder` / `pollAuthorization`, `downloadCertificate`,
 * `revokeCert`, `deactivateAccount` / `deactivateAuthorization`, `keyChange`, `renewalInfo`, `renewalWindow`.
 *
 * @opts
 *   - `accountKey` / `accountJwk` / `alg` -- REQUIRED: the account private key, its public JWK, and the JWS alg.
 *   - `transport` -- injectable transport(request) -> {status, headers, body}; default pki.transport.https.
 *   - `tls` -- { anchors, useSystemStore, cert, key, minVersion, servername, checkServerIdentity } for the default transport.
 *   - `timeout` / `maxResponseBytes` / `maxRedirects` -- transport budgets; `maxNonceRetries` -- badNonce retry cap (default 1).
 *   - `maxPolls` / `maxTotalWait` / `sleep` -- poll-loop budgets + an injectable sleeper; `clock` -- an injectable receipt clock (default Date.now) for a Retry-After HTTP-date.
 *   - `newAuthz(identifier)` -- pre-authorize a single identifier (RFC 8555 sec. 7.4.1) -> { authorization, url }.
 *   - `downloadCertificate(url, { expectedSpki, identifiers, requireBinding, selectChain, maxAlternates })` -- bind the issued certificate to this order, then pick among RFC 8555 sec. 7.4.2 alternate chains. `expectedSpki` (the DER SubjectPublicKeyInfo this order's CSR asked to have certified) and `identifiers` (the order's own identifier array) are what the returned end-entity certificate is checked against: a different key is `acme/certificate-key-mismatch`, a different identifier set `acme/certificate-identifier-mismatch`. Only `dns` and `ip` identifiers map to a name a certificate carries, so an order identifier of another registered type, a certificate `subjectAltName` that is neither a dNSName nor an iPAddress, and a subject common name that is neither a dns name nor a canonical IP address, are each refused as `acme/unsupported-identifier-type` rather than dropped from the comparison. The certificate's alternative names are its identity; its common name is read only where it asserts none. At least one is required (`acme/binding-required`) unless `requireBinding: false`, which waives the requirement to supply material and never the check on material that is supplied. The result reports `boundToKey` / `boundToIdentifiers`. `selectChain({certificate, chain, certificates})` returns the first truthy candidate (primary first, then bounded `Link rel="alternate"` chains, confined to the download's own origin); the result adds `alternates` (the resolved alternate URLs).
 *   - `renewalWindow(certDer, { random, clock, replaced, previous })` -- the RFC 9773 ARI renewal decision: composes `renewalInfo`, selects a uniform-random instant in the suggested window -> { suggestedWindow, selectedTime, renewNow, retryAfterSeconds, explanationURL }. Pass a prior result back as `previous` to REUSE its selectedTime while the CA's window is unchanged (RFC 9773 sec. 4.2), so repeated refreshes keep one stable renewal instant.
 * @example
 *   var acme = pki.acme.client("https://acme.example/directory", { accountKey, accountJwk, alg: "ES256", transport });
 *   var acct = await acme.newAccount({ termsOfServiceAgreed: true });
 *   var ord = await acme.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
 */
// The options pki.acme.client reads at construction. A near-miss spelling (a plural, a sibling verb's
// word, a dropped letter) must be refused with a message naming it, not read as undefined and silently
// defaulted -- a mistyped `maxRedirects` or `transport` would otherwise change the client's behavior with
// no error. The per-request options each returned method takes are checked in those methods, not here.
var _CLIENT_OPTS = {
  accountKey: 1, accountJwk: 1, alg: 1, transport: 1, tls: 1, timeout: 1, maxResponseBytes: 1,
  maxRedirects: 1, maxNonceRetries: 1, maxPolls: 1, maxTotalWait: 1, sleep: 1, clock: 1,
};
// The per-request options each client method reads. A near-miss spelling in a method's own bag is
// refused the same way the constructor refuses one, rather than read as undefined and silently
// defaulted -- a mistyped `requireBinding` or `reason` would otherwise change the request with no error.
// finalize accepts `identifiers` but NEVER lets it override the order's own set (RFC 8555 sec. 7.4), so
// it is recognized here though the binding ignores it.
var _METHOD_OPTS = {
  finalize: { csr: 1, identifiers: 1 },
  poll: { maxPolls: 1, maxTotalWait: 1, onRetryAfter: 1 },
  download: { expectedSpki: 1, identifiers: 1, requireBinding: 1, selectChain: 1, maxAlternates: 1 },
  revoke: { certAlg: 1, certJwk: 1, certKey: 1, certificate: 1, reason: 1 },
  keyChange: { newAlg: 1, newJwk: 1, newKey: 1 },
  renewalWindow: { random: 1, clock: 1, replaced: 1, previous: 1 },
  updateAccount: { contact: 1 },
  listOrders: { maxPages: 1 },
};
// Settle a per-method options bag the way the constructor settles its own: guard.identifier.optionsObject
// snapshots the bag and refuses one a getter rewrites mid-read (a `requireBinding` getter that grows a
// misspelled key after the check would otherwise slip past assertKnownKeys), THEN reject any unknown key.
// Returns the settled bag so the method reads the frozen copy, never the live object a getter could rewrite.
function _gateOpts(bag, whitelist, name) {
  bag = guard.identifier.optionsObject(bag, E, "acme/bad-input", "pki.acme " + name + " options");
  guard.identifier.assertKnownKeys(bag, whitelist, E, "acme/bad-input", "unknown " + name + " option ");
  return bag;
}
function client(directoryUrl, opts) {
  opts = guard.identifier.optionsObject(opts, E, "acme/bad-input", "pki.acme.client options");
  guard.identifier.assertKnownKeys(opts, _CLIENT_OPTS, E, "acme/bad-input", "unknown pki.acme.client option ");
  if (!opts.accountKey) throw E("acme/bad-input", "client requires opts.accountKey (the account private key)");
  if (!_isObject(opts.accountJwk)) throw E("acme/bad-input", "client requires opts.accountJwk (the account public JWK)");
  if (!_isString(opts.alg)) throw E("acme/bad-input", "client requires opts.alg (the account-key JWS alg)");
  jose.assertPublicJwk(opts.accountJwk);
  var dirUrl = _clientUrl(directoryUrl);
  var accountKey = opts.accountKey, accountJwk = opts.accountJwk, alg = opts.alg;

  var transport = opts.transport;
  if (!transport) {
    var t0 = opts.tls || {};
    var hasAnchors = t0.anchors !== undefined && t0.anchors !== null && !(Array.isArray(t0.anchors) && t0.anchors.length === 0);
    if (!hasAnchors && t0.useSystemStore !== true) throw E("acme/no-trust-anchors", "no explicit trust anchor and tls.useSystemStore not set to true (RFC 8555 sec. 6.1)");
    transport = httpTransport.https({ E: E, errPrefix: "acme" });
  }
  var budgets = {
    tls: _clientTls(opts),
    timeout: guard.limits.cap(opts.timeout, "timeout", CLIENT_DEFAULT_TIMEOUT, { E: E, code: "acme/bad-input", min: 1, max: CLIENT_MAX_TIMEOUT }),
    maxResponseBytes: guard.limits.cap(opts.maxResponseBytes, "maxResponseBytes", constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, { E: E, code: "acme/bad-input", min: 1, max: constants.LIMITS.HTTP_MAX_RESPONSE_BYTES }),
    maxRedirects: guard.limits.cap(opts.maxRedirects, "maxRedirects", 5, { E: E, code: "acme/bad-input", min: 0, max: 32 }),
  };
  var maxNonceRetries = guard.limits.cap(opts.maxNonceRetries, "maxNonceRetries", 1, { E: E, code: "acme/bad-input", min: 0, max: 8 });
  var maxPolls = guard.limits.cap(opts.maxPolls, "maxPolls", 20, { E: E, code: "acme/bad-input", min: 1, max: 1000 });
  var maxTotalWait = guard.limits.cap(opts.maxTotalWait, "maxTotalWait", retryAfter.MAX_RETRY_AFTER_SECONDS, { E: E, code: "acme/bad-input", min: 0, max: retryAfter.MAX_RETRY_AFTER_SECONDS });
  var sleep = typeof opts.sleep === "function" ? opts.sleep : _defaultSleep;
  // The receipt clock for a Retry-After HTTP-date: read FRESH per response (a fixed value would go stale
  // across polls, and a missing one would collapse every HTTP-date to a 1s delay). Injectable for tests.
  var clock = typeof opts.clock === "function" ? opts.clock : function () { return Date.now(); };

  // session state
  var dirCache = null;
  var nonces = [];
  var kid = null;
  // The mTLS client credential is bound to the CONFIGURED directory origin: it is presented ONLY to that
  // origin, never to a different one reached via a redirect or advertised by a (possibly compromised)
  // directory. A CA that legitimately spans origins uses JWS auth, not a transport client certificate.
  var trustedOrigin = new URL(dirUrl).origin;
  function _tlsFor(url) {
    var t = budgets.tls;
    // Cross-origin, strip the ORIGIN-SPECIFIC identity: the client certificate/key (credential leak) and the
    // pinned `servername` (SNI, which selects the trusted host's certificate). The caller's
    // `checkServerIdentity` is RETAINED -- it is an ADDITIONAL tightening constraint (a certificate / SPKI
    // pin, or a stricter host check) that node re-evaluates against the actual host, so a pin keeps applying
    // and a host-pinned check fails the wrong host closed; dropping it would accept the cross-origin host
    // under only the default hostname validation, bypassing the pin.
    if (new URL(url).origin !== trustedOrigin && (t.cert != null || t.key != null || t.servername != null)) {
      t = Object.assign({}, t);
      delete t.cert; delete t.key; delete t.servername;
    }
    return t;
  }

  function _bodyText(res) { return Buffer.isBuffer(res.body) ? res.body.toString("utf8") : String(res.body || ""); }
  // The RAW bytes for jose.parseJson, so its FATAL UTF-8 validation runs on the wire body -- _bodyText's
  // lossy utf8 decode (replacement chars) would let a malformed RFC 8259 response slip through. A string
  // body (an injected test transport) carries no malformed UTF-8, so encoding it is lossless.
  function _jsonInput(res) { return Buffer.isBuffer(res.body) ? res.body : Buffer.from(String(res.body == null ? "" : res.body), "utf8"); }
  function _requireKid() { if (!kid) throw E("acme/no-account", "no account is set -- call newAccount before an authenticated request (RFC 8555 sec. 6.2)"); return kid; }
  function _harvestNonce(v) {
    if (typeof v !== "string" || v === "") return;
    try { jose.base64url.decode(v); }
    catch (_e) { return; }   // ignore an invalid Replay-Nonce (RFC 8555 sec. 6.5.1)
    while (nonces.length >= CLIENT_MAX_NONCE_POOL) nonces.shift();   // evict the oldest, bound the pool (CWE-770)
    nonces.push(v);
  }
  function _isProblem(res) { return intrinsic.stringIndexOf(_lower(String(res.headers["content-type"] || "")), "application/problem+json") !== -1; }   // ci substring (ASCII content-type)
  function _serverProblem(res) {
    var prob = null;
    try { prob = jose.parseJson(_jsonInput(res)); if (_isObject(prob)) validateProblem(prob); }
    catch (_e) { /* allow:swallow-unverified an unparseable / schema-invalid problem doc; the typed acme/server-problem is surfaced from the HTTP status regardless */ }
    var type = (prob && prob.type) || "", detail = (prob && prob.detail) || "";
    var err = E("acme/server-problem", "the ACME server returned a problem (HTTP " + res.status + ")" + (type ? " " + type : "") + (detail ? ": " + detail : ""));
    err.problem = prob; err.httpStatus = res.status;
    return err;
  }
  function _json(res) {
    try { return jose.parseJson(_jsonInput(res)); }
    catch (e) { throw E("acme/bad-response", "the response body was not valid JSON: " + ((e && e.message) || String(e)), e); }
  }

  // One request over the transport; lowercases headers, caps the body, harvests a Replay-Nonce off every
  // FINAL response (validated base64url, RFC 8555 sec. 6.5.1). A redirect on a SAFE method (GET/HEAD --
  // the unauthenticated directory / newNonce / renewalInfo reads) is followed to its https Location, up to
  // the maxRedirects budget; an authenticated POST is bound to its JWS `url` (sec. 6.4), so its redirect
  // is surfaced unchanged for the verb to reject. Every request carries the sec. 6.1 REQUIRED User-Agent.
  function _send(method, url, headers, body) { return _sendFollowing(method, url, headers, body, 0); }
  function _sendFollowing(method, url, headers, body, redirects) {
    var reqHeaders = Object.assign({ "user-agent": CLIENT_USER_AGENT }, headers || {});
    // _tlsFor binds the mTLS credential to the trusted origin, so EVERY request (this one, a redirect
    // target, or a directory-advertised URL on another host) presents the client certificate only there.
    return transport({ method: method, url: url, headers: reqHeaders, body: body, tls: _tlsFor(url), timeout: budgets.timeout, maxResponseBytes: budgets.maxResponseBytes }).then(function (res) {
      res = res || {};
      var h = {};
      Object.keys(res.headers || {}).forEach(function (k) { h[k.toLowerCase()] = res.headers[k]; });
      // Measure an injected string body as UTF-8 -- the exact bytes _jsonInput re-encodes it to before the
      // decoder sees it -- so a non-ASCII body (e.g. multi-byte emoji, ~half the byte count under latin1)
      // cannot slip past the cap and reach the JSON parser.
      var blen = Buffer.isBuffer(res.body) ? guard.bytes.lengthOf(res.body) : Buffer.byteLength(String(res.body == null ? "" : res.body), "utf8");
      if (blen > budgets.maxResponseBytes) throw E("acme/response-too-large", "the response body (" + blen + " bytes) exceeds the " + budgets.maxResponseBytes + "-byte cap");
      if ((method === "GET" || method === "HEAD") && res.status >= 300 && res.status < 400) {
        if (redirects >= budgets.maxRedirects) throw E("acme/too-many-redirects", "the redirect budget of " + budgets.maxRedirects + " was exceeded");
        if (!_isString(h["location"])) throw E("acme/bad-redirect", "a " + res.status + " redirect carried no Location header (RFC 7231 sec. 6.4)");
        // A Location may be relative (common behind a reverse proxy) -- resolve it against the request URL
        // before the https gate, so `/v2/directory` follows rather than failing the URL parse.
        var next;
        try { next = new URL(h["location"], url).href; }
        catch (e) { throw E("acme/bad-redirect", "the redirect Location did not resolve to a valid URL", e); }
        return _sendFollowing(method, _clientUrl(next), headers, body, redirects + 1);
      }
      _harvestNonce(h["replay-nonce"]);
      return { status: res.status, headers: h, body: res.body == null ? "" : res.body };
    });
  }

  function _getDirectory() {
    if (dirCache) return Promise.resolve(dirCache);
    return _send("GET", dirUrl, { accept: "application/json" }, null).then(function (res) {
      if (res.status !== 200) throw E("acme/bad-directory", "the ACME directory request returned HTTP " + res.status);
      var obj = _json(res);
      validate("directory", obj);
      dirCache = obj;
      return obj;
    });
  }
  function _resource(name) {
    return _getDirectory().then(function (dir) {
      if (!_isString(dir[name])) throw E("acme/resource-unavailable", "the directory does not advertise the '" + name + "' resource (RFC 8555 sec. 7.1.1)");
      return _clientUrl(dir[name]);   // the client is the sole https gate -- a directory advertising an http resource fails closed (RFC 8555 sec. 6.1)
    });
  }
  // Take the FRESHEST pooled nonce (LIFO): every response's Replay-Nonce is appended, so on a badNonce
  // the error response's fresh nonce is the last harvested and is the one the retry consumes (RFC 8555
  // sec. 6.5) -- never a staler pooled nonce (e.g. one an unauthenticated read left behind).
  function _takeNonce() {
    if (nonces.length) return Promise.resolve(nonces.pop());
    var before = nonces.length;
    return _resource("newNonce").then(function (nn) { return _send("HEAD", nn, {}, null); }).then(function (res) {
      // newNonce must succeed (RFC 8555 sec. 7.2: 200/204). An ERROR response (a 4xx/5xx rate limit) also
      // carries a Replay-Nonce, but using it would silently proceed past the server's error -- discard the
      // harvested nonce and surface the problem instead.
      if (res.status !== 200 && res.status !== 204) { nonces.length = before; throw _serverProblem(res); }
      if (!nonces.length) throw E("acme/no-nonce", "the server did not provide a usable Replay-Nonce (RFC 8555 sec. 7.2)");
      return nonces.pop();
    });
  }

  // POST a JWS built by makeJws(nonce) as application/jose+json, and on a badNonce error retry (bounded)
  // with the error response's fresh nonce (RFC 8555 sec. 6.5 -- _takeNonce's LIFO pool surfaces it).
  // `accept` is the media type the request advertises (default application/json). This is the single
  // home of the badNonce retry, so every signed POST -- account-key or certificate-key -- inherits it.
  function _postJws(url, makeJws, accept, okStatuses) {
    var ok = okStatuses || [200];
    var attempt = 0;
    function once() {
      return _takeNonce().then(makeJws).then(function (jws) {
        return _send("POST", url, { "content-type": "application/jose+json", "accept": accept || "application/json" }, JSON.stringify(jws));
      }).then(function (res) {
        // An application/problem+json body is an ERROR regardless of the HTTP status -- a CA / proxy
        // returning a problem with an erroneous 2xx must NOT be accepted as success (RFC 7807 / RFC 8555).
        if (res.status >= 300 || _isProblem(res)) {
          if (_isProblem(res)) {
            var prob = null;
            try { prob = jose.parseJson(_jsonInput(res)); }
            catch (_e) { /* allow:swallow-unverified a non-JSON problem body is not a badNonce; prob stays null, falling through to the typed acme/server-problem throw */ }
            if (prob && typeof prob.type === "string" && _endsWith(prob.type, ":badNonce") && attempt < maxNonceRetries) { attempt++; return once(); }
          }
          throw _serverProblem(res);
        }
        // Enforce the PER-OPERATION success status (RFC 8555): only newAccount/newOrder may return 201
        // (created); every other verb requires 200, so a verb never acts on an incomplete result -- e.g.
        // keyChange rotating the session key or revokeCert reporting success on a 201/202.
        if (ok.indexOf(res.status) === -1) throw E("acme/unexpected-status", "an ACME POST returned an unexpected status " + res.status + " (expected " + ok.join("/") + ", RFC 8555)");
        return res;
      });
    }
    return once();
  }
  // Build an account-key JWS (kid or jwk mode) with a fresh nonce and POST it through the retrying _postJws.
  function _post(url, builder, extra, mode, accept, okStatuses) {
    return _postJws(url, function (nonce) {
      // The client-owned JWS session fields (signing key, alg, single-use nonce, protected url) are applied
      // AFTER the caller's payload options, so a payload carrying key/alg/nonce/url cannot override them and
      // desynchronize the protected header from the actual request (or reuse a nonce).
      var base = Object.assign({}, extra || {}, { key: accountKey, alg: alg, nonce: nonce, url: url });
      if (mode === "jwk") base.jwk = accountJwk; else base.kid = _requireKid();
      return builder(base);
    }, accept, okStatuses);
  }
  function _postAsGet(url) { return _post(url, postAsGet, null, "kid"); }

  // ---- verbs (internal _-prefixed to avoid shadowing the module builders) ----
  function _directory() { return _getDirectory(); }

  function _newAccount(payloadOpts) {
    return _resource("newAccount").then(function (url) {
      // newAccount is 201 (created) for a new account or 200 for an existing one (RFC 8555 sec. 7.3).
      return _post(url, newAccount, payloadOpts || {}, "jwk", undefined, [200, 201]).then(function (res) {
        var loc = res.headers["location"];
        if (!_isString(loc)) throw E("acme/no-account-url", "newAccount did not return an account URL in a Location header (RFC 8555 sec. 7.3)");
        // Validate the account object BEFORE committing the kid, so a malformed account (no status,
        // an unknown status) fails closed rather than enabling authenticated operations under a bad kid.
        var account = validate("account", _json(res));
        kid = _resolveLocation(loc, url);
        return { account: account, url: kid };
      });
    });
  }
  function _newOrder(payloadOpts) {
    return _resource("newOrder").then(function (url) {
      // newOrder returns 201 Created ONLY (RFC 8555 sec. 7.4) -- a 200 is a non-conforming server / proxy.
      return _post(url, newOrder, payloadOpts || {}, "kid", undefined, [201]).then(function (res) {
        var loc = res.headers["location"];
        if (!_isString(loc)) throw E("acme/no-order-url", "newOrder did not return an order URL in a Location header (RFC 8555 sec. 7.4)");
        return { order: validate("order", _json(res)), url: _resolveLocation(loc, url) };
      });
    });
  }
  function _newAuthz(identifier) {
    return Promise.resolve().then(function () {
    // Reject a wildcard / bad AUTHORIZATION identifier BEFORE any network (sec. 7.4.1); the builder re-checks. Bind
    // to the CANONICAL { type, value } (a single validated read), so the wire body, the sent identifier, and the
    // returned-authz comparison below all use the same values -- never a getter that could re-read differently.
    var canon = _validateIdentifier(identifier);
    return _resource("newAuthz").then(function (url) {
      // 201 (Created) is the norm (RFC 8555 sec. 7.4.1), but a CA that returns an already-existing authorization
      // (the out-of-band valid case) MAY answer 200 (OK) -- the authz was not newly created -- just as newAccount
      // accepts 200 for an existing account. Accept both; the Location + object are validated below regardless.
      return _post(url, newAuthz, { identifier: canon }, "kid", undefined, [200, 201]).then(function (res) {
        var loc = res.headers["location"];
        if (!_isString(loc)) throw E("acme/no-authorization-url", "newAuthz did not return an authorization URL in a Location header (RFC 8555 sec. 7.4.1)");
        var authz = validate("authorization", _json(res));
        // Bind the returned authorization to the SUBMITTED identifier (sec. 7.4.1): a server returning an authz
        // for a different identifier is not silently accepted. The submitted identifier is always non-wildcard
        // (_validateIdentifier rejects a leading *.), so an authz the CA marks wildcard:true (sec. 7.1.4 -- it
        // authorizes *.<value>, a BROADER grant than requested) is a mismatch, not the authorization asked for.
        if (!authz.identifier || authz.identifier.type !== canon.type || authz.identifier.value !== canon.value || authz.wildcard === true) throw E("acme/identifier-mismatch", "the returned authorization does not match the requested identifier (RFC 8555 sec. 7.4.1)");
        // A pre-authorization's status "MUST be 'pending' unless the server has out-of-band information about the
        // client's authorization status" (sec. 7.4.1): the normal case is a fresh "pending" authz the caller then
        // fulfills, but the CA MAY instead return an already-"valid" authz (the identifier is already authorized for
        // this account -- no challenge to answer). Both are usable; only a terminal failed state ("invalid"/
        // "deactivated"/"expired"/"revoked") is not the authorization the pre-auth flow can proceed with.
        if (authz.status !== "pending" && authz.status !== "valid") throw E("acme/unexpected-authorization-status", "newAuthz returned an authorization that is neither pending nor already valid (status " + JSON.stringify(authz.status) + "); RFC 8555 sec. 7.4.1");
        return { authorization: authz, url: _resolveLocation(loc, url) };
      });
    });
    });
  }
  // A bad URL leaves as a REJECTION, like every other verb on this client. It is not only a caller
  // typo that reaches here: the message layer deliberately accepts http as well as https, so an
  // order whose `authorizations` array carries an http URL validates, and the very next step --
  // getAuthorization(order.authorizations[0]) -- threw out of the middle of an async ACME loop
  // rather than rejecting into the handler already wrapped around it.
  function _getOrder(url) { return _promised(function () { return _postAsGet(_clientUrl(url)).then(function (res) { return validate("order", _json(res)); }); }); }
  function _getAuthorization(url) { return _promised(function () { return _postAsGet(_clientUrl(url)).then(function (res) { return validate("authorization", _json(res)); }); }); }
  function _getChallenge(url) { return _promised(function () { return _postAsGet(_clientUrl(url)).then(function (res) { return validate("challenge", _json(res)); }); }); }
  function _respondToChallenge(url) { return _promised(function () { return _post(_clientUrl(url), challengeResponse, null, "kid").then(function (res) { return validate("challenge", _json(res)); }); }); }

  function _finalize(order, o) { return _promised(function () { return _finalizeBody(order, o); }); }
  function _finalizeBody(order, o) {
    o = _gateOpts(o, _METHOD_OPTS.finalize, "finalize");
    if (!_isObject(order) || !_isString(order.finalize)) throw E("acme/bad-input", "finalize requires the order object with its finalize URL");
    if (!Array.isArray(order.identifiers)) throw E("acme/bad-input", "finalize requires the order's identifiers to enforce the RFC 8555 sec. 7.4 CSR-set match");
    // The sec. 7.4 CSR-vs-order check is ALWAYS bound to the order's OWN authoritative identifiers (the
    // client holds the validated order) -- never a caller-supplied set, which could otherwise loosen the
    // check so a CSR matching the replacement passes locally only to be rejected by the CA.
    return _post(_clientUrl(order.finalize), finalize, { csr: o.csr, identifiers: order.identifiers, accountJwk: accountJwk }, "kid").then(function (res) { return validate("order", _json(res)); });
  }

  // Poll a resource by POST-as-GET until it reaches a terminal state, honoring Retry-After (surfaced +
  // slept via the injectable sleep), bounded by maxPolls + maxTotalWait; each observed pair runs
  // assertTransition. A terminal `invalid` surfaces the object (the caller inspects .status).
  function _poll(kind, url, budget) {
    // A per-call poll override is validated through the SAME bounds as the constructor budget, so an
    // Infinity / NaN / over-ceiling value cannot turn a non-terminal resource into an unbounded loop.
    // Surface a bad override (or url) as a REJECTION, not a sync throw, so this async verb is uniform.
    var capPolls, capWait;
    try {
      budget = _gateOpts(budget, _METHOD_OPTS.poll, "poll");
      capPolls = budget.maxPolls != null ? guard.limits.cap(budget.maxPolls, "maxPolls", maxPolls, { E: E, code: "acme/bad-input", min: 1, max: 1000 }) : maxPolls;
      capWait = budget.maxTotalWait != null ? guard.limits.cap(budget.maxTotalWait, "maxTotalWait", maxTotalWait, { E: E, code: "acme/bad-input", min: 0, max: retryAfter.MAX_RETRY_AFTER_SECONDS }) : maxTotalWait;
      url = _clientUrl(url);
    } catch (e) { return Promise.reject(e); }
    // An order poll terminates on every STABLE state (RFC 8555 sec. 7.1.6): `ready` (all authorizations
    // met -- the signal to finalize) and `valid` / `invalid`, not just valid/invalid -- otherwise a poll
    // run before finalize spins on the stable `ready` until the budget is exhausted.
    var terminal = kind === "order" ? { ready: true, valid: true, invalid: true } : { valid: true, invalid: true, deactivated: true, expired: true, revoked: true };
    var last = null, count = 0, waited = 0;
    function step() {
      count++;
      return _postAsGet(url).then(function (res) {
        var obj = validate(kind, _json(res));
        if (last && last !== obj.status) assertTransition(kind, last, obj.status);
        last = obj.status;
        if (terminal[obj.status]) return obj;
        if (count >= capPolls) throw E("acme/poll-exhausted", "the " + kind + " did not reach a terminal state within " + capPolls + " polls (RFC 8555 sec. 7.5.1)");
        var ra = res.headers["retry-after"];
        var delaySec = 1;
        if (typeof ra === "string" && ra.trim() !== "") { delaySec = retryAfter.parse(ra, { now: clock(), E: E, code: "acme/bad-retry-after" }).retryAfterSeconds; if (delaySec == null) delaySec = 1; }
        waited += delaySec;
        if (waited > capWait) throw E("acme/poll-exhausted", "the " + kind + " poll exceeded the total wait budget of " + capWait + " seconds");
        if (typeof budget.onRetryAfter === "function") budget.onRetryAfter(delaySec);
        return Promise.resolve(sleep(delaySec * constants.TIME.seconds(1))).then(step);
      });
    }
    return step();
  }
  function _pollOrder(url, budget) { return _poll("order", url, budget); }
  function _pollAuthorization(url, budget) { return _poll("authorization", url, budget); }

  // Read + strictly validate a downloaded chain response into { certificate, chain, certificates }. The caller
  // routes through _post (okStatuses [200]), so a non-200 has already thrown _serverProblem before this runs.
  function _readCertChain(res) {
    // The certificate representation is bound to application/pem-certificate-chain (RFC 8555 sec. 7.4.2):
    // a 200 with a wrong media type (a proxy error, a misrouted response) fails closed even if its body
    // happens to contain parseable PEM. Match the media-type TOKEN exactly (before any ;-parameters), so
    // a lookalike like application/pem-certificate-chain-evil does not slip through a substring test.
    var ctToken = String(res.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (ctToken !== "application/pem-certificate-chain") throw E("acme/bad-certificate-chain", "the certificate download returned an unexpected media type " + JSON.stringify(ctToken) + " (expected application/pem-certificate-chain, RFC 8555 sec. 7.4.2)");
    var chain = _splitPemChain(_bodyText(res));
    return { certificate: chain[0], chain: chain.slice(1), certificates: chain };
  }
  function _fetchCertChain(url) { return _post(url, postAsGet, null, "kid", "application/pem-certificate-chain").then(_readCertChain); }

  // The material that says which certificate this download is allowed to be, reduced ONCE at the
  // door: the caller's options object is read here and never again, so a value that changes between
  // the check and the use cannot be what the check ran on. Returns { spki, ids, require }.
  function _bindingSpec(opts) {
    var spki = opts.expectedSpki, ids = opts.identifiers, req = opts.requireBinding;
    if (spki !== undefined) {
      if (!guard.bytes.isByteSource(spki)) throw E("acme/bad-input", "downloadCertificate opts.expectedSpki must be a DER SubjectPublicKeyInfo BufferSource");
      // SNAPSHOT: the comparison happens after a network round trip, so a retained reference would let
      // the caller rewrite the key the certificate is checked against once the request had gone out --
      // rejecting the right certificate, or accepting one minted for the replacement bytes.
      spki = guard.bytes.snapshotSource(spki, AcmeError, "acme/bad-input", "downloadCertificate expectedSpki");
    }
    if (ids !== undefined) {
      if (!_isArrayI(ids) || ids.length === 0) throw E("acme/bad-input", "downloadCertificate opts.identifiers must be the non-empty order identifier array");
      // Reduced to this module's OWN validated copy at the door: the array and its entries are the
      // caller's, and the comparison below happens after a network round trip.
      ids = _mapI(ids, _validateOrderIdentifier);
    }
    if (req !== undefined && typeof req !== "boolean") throw E("acme/bad-input", "downloadCertificate opts.requireBinding must be a boolean");
    var require_ = req === undefined ? true : req;
    // Required by default, because a download nobody checked is the one an operator installs. The
    // waiver is explicit and it waives only the REQUIREMENT to supply material: anything supplied is
    // still checked below, so the waiver cannot become the place a mismatch hides.
    if (require_ && spki === undefined && ids === undefined) {
      throw E("acme/binding-required",
        "downloadCertificate needs the material that binds the issued certificate to this order -- " +
        "opts.expectedSpki (the DER SubjectPublicKeyInfo the CSR asked to have certified) and/or " +
        "opts.identifiers (the order's identifiers). Pass opts.requireBinding false to download without " +
        "either, in which case the result reports boundToKey and boundToIdentifiers false");
    }
    return { spki: spki, ids: ids, require: require_ };
  }

  // Bind the certificate that came back to the request that was made. RFC 8555 sec. 7.4.2 says nothing
  // about what the certificate resource may return, so nothing on the wire stops a CA -- or anything
  // that can answer that URL -- from handing back a certificate for another key or another name. The
  // OUTBOUND direction already refuses a CSR whose identifier set is not the order's (sec. 7.4); this
  // is the same relation read back off the issued certificate. The sibling enrollment client makes the
  // same check: pki.est picks the issued certificate by public-key match against the submitted CSR.
  function _assertCertBinding(leafDer, spec) {
    var leaf;
    try { leaf = x509.parse(leafDer); }
    catch (e) { throw E("acme/bad-certificate-chain", "the downloaded end-entity certificate did not parse (RFC 8555 sec. 7.4.2)", e); }
    if (spec.spki !== undefined) {
      var got = leaf.subjectPublicKeyInfo && leaf.subjectPublicKeyInfo.bytes;
      if (!_isBuffer(got) || !guard.crypto.constantTimeEqual(got, spec.spki)) {
        throw E("acme/certificate-key-mismatch",
          "the downloaded certificate certifies a different public key than the one this order's CSR asked " +
          "to have certified, so it cannot be used with the private key held here (RFC 8555 sec. 7.4)");
      }
    }
    if (spec.ids !== undefined) {
      var have = _certIdentifierSet(leaf), want = _orderIdentifierSet(spec.ids);
      var haveKeys = _objectKeys(have), wantKeys = _objectKeys(want);
      var mismatch = haveKeys.length !== wantKeys.length ||
        _someI(wantKeys, function (k) { return !have[k]; }) ||
        _someI(haveKeys, function (k) { return !want[k]; });
      if (mismatch) {
        throw E("acme/certificate-identifier-mismatch",
          "the downloaded certificate's identifier set " + _stringify(_sortI(haveKeys)) +
          " is not the order's " + _stringify(_sortI(wantKeys)) + " (RFC 8555 sec. 7.4)");
      }
    }
  }

  function _downloadCertificate(url, opts) {
    // Prelude in a resolved-promise .then so a bad opt / URL is a REJECTION, uniform for a .catch caller.
    return Promise.resolve().then(function () {
      opts = _gateOpts(opts, _METHOD_OPTS.download, "downloadCertificate");
      var select = opts.selectChain;
      if (select !== undefined && typeof select !== "function") throw E("acme/bad-input", "downloadCertificate opts.selectChain must be a function");
      var maxAlt = guard.limits.cap(opts.maxAlternates, "maxAlternates", DEFAULT_MAX_ALTERNATES, { E: E, code: "acme/bad-input", min: 0, max: 64 });
      var binding = _bindingSpec(opts);
      var dlUrl = _clientUrl(url);
      return _post(dlUrl, postAsGet, null, "kid", "application/pem-certificate-chain").then(function (res) {
        var primary = _readCertChain(res);
        // The Link header is UNTRUSTED. Parse it now but DEFER any malformed-header error: a malformed Link is
        // fatal only if the alternates are actually needed (the primary itself is rejected below). So a broken
        // or hostile Link can never deny a valid primary download -- whether the caller is selecting or not.
        var alternates = [], linkError = null;
        try { alternates = _parseLinkAlternates(res.headers, dlUrl); }
        catch (e) { linkError = e; }
        // Bind the primary leaf NOW, before a rejected primary can drive alternate fetches: an
        // unbindable certificate fails on the response that carried it rather than after up to
        // maxAlternates further signed POSTs.
        _assertCertBinding(primary.certificate, binding);
        // The same assertion again on whatever is actually returned. Every candidate must carry the
        // primary's own end-entity certificate (sec. 7.4.2, enforced below), so today this can only
        // re-confirm what the line above settled; it is here because `result` is the one door every
        // return passes through, and a candidate that stopped sharing that leaf would still be bound.
        function result(cand) {
          _assertCertBinding(cand.certificate, binding);
          return { certificate: cand.certificate, chain: cand.chain, certificates: cand.certificates, alternates: alternates,
            boundToKey: binding.spki !== undefined, boundToIdentifiers: binding.ids !== undefined };
        }
        if (!select) return result(primary);
        // Selection: consider the PRIMARY first, then each alternate in header order, bounded by maxAlt
        // (CWE-770 fetch amplification). selectChain MAY be async -- await its result (Promise.resolve wraps a
        // sync return too) so a returned Promise is never treated as always-truthy. The first truthy wins. An
        // alternate whose end-entity certificate differs from the primary's violates sec. 7.4.2 ("starting with
        // the same end-entity certificate") -- fail closed rather than accept a substituted leaf. A predicate
        // throw / rejection propagates unswallowed. Exhausting the budget with alternates left unfetched is
        // acme/too-many-alternates; fetching every alternate with no match is acme/no-matching-chain.
        return Promise.resolve(select(primary)).then(function (primaryMatch) {
          if (primaryMatch) return result(primary);
          // The primary was rejected, so the alternates ARE needed now -- a malformed Link finally fails closed.
          if (linkError) throw linkError;
          var leaf = primary.certificate, toFetch = alternates.slice(0, maxAlt), overBudget = alternates.length > maxAlt, idx = 0;
          function next() {
            if (idx >= toFetch.length) {
              if (overBudget) throw E("acme/too-many-alternates", "no acceptable chain within the maxAlternates=" + maxAlt + " fetch budget (RFC 8555 sec. 7.4.2, CWE-770)");
              throw E("acme/no-matching-chain", "no downloaded chain satisfied selectChain (RFC 8555 sec. 7.4.2)");
            }
            return _fetchCertChain(toFetch[idx++]).then(function (cand) {
              if (!cand.certificate.equals(leaf)) throw E("acme/bad-alternate", "an alternate chain did not start with the same end-entity certificate (RFC 8555 sec. 7.4.2)");
              return Promise.resolve(select(cand)).then(function (m) { return m ? result(cand) : next(); });
            });
          }
          return next();
        });
      });
    });
  }

  function _revokeCert(o) {
    // Bad input surfaces as a REJECTION -- _promised turns a throw into one -- so this async verb stays
    // uniform for a .catch caller rather than throwing synchronously.
    return _promised(function () {
      o = _gateOpts(o, _METHOD_OPTS.revoke, "revokeCert");
      if (!guard.bytes.isByteSource(o.certificate)) throw E("acme/bad-input", "revokeCert requires a DER certificate BufferSource (opts.certificate)");
      // Certificate-key mode (RFC 8555 sec. 7.6) needs the COMPLETE triple certKey + certJwk + certAlg: an
      // incomplete set must NOT fall through to the account-key path (wrong credential), and certAlg must be
      // explicit -- inheriting the account alg would sign a different-family certificate key under the wrong
      // JWS algorithm (an ES256 account revoking with an RSA certificate key), which JOSE then rejects.
      var certKeyMode = o.certKey != null || _isObject(o.certJwk) || o.certAlg != null;
      if (certKeyMode && !(o.certKey != null && _isObject(o.certJwk) && _isString(o.certAlg))) throw E("acme/bad-input", "revokeCert certificate-key mode requires certKey, certJwk, AND certAlg together, or none (RFC 8555 sec. 7.6)");
      var extra = { certificate: o.certificate };
      if (o.reason !== undefined) extra.reason = o.reason;
      return _resource("revokeCert").then(function (url) {
        if (certKeyMode) {
          // sign with the certificate key (jwk mode) rather than the account (RFC 8555 sec. 7.6), through
          // the same _postJws so it inherits the badNonce bounded retry the kid path has.
          return _postJws(url, function (nonce) {
            return revokeCert(Object.assign({}, extra, { key: o.certKey, alg: o.certAlg, nonce: nonce, url: url, jwk: o.certJwk }));
          }).then(function () { return true; });
        }
        return _post(url, revokeCert, extra, "kid").then(function () { return true; });
      });
    });
  }

  function _deactivateAccount() { return _promised(function () { return _post(_requireKid(), deactivate, null, "kid").then(function (res) { return validate("account", _json(res)); }); }); }
  function _deactivateAuthorization(url) { return _promised(function () { return _post(_clientUrl(url), deactivate, null, "kid").then(function (res) { return validate("authorization", _json(res)); }); }); }

  // updateAccount (RFC 8555 sec. 7.3.2): a kid-signed POST to the account URL updating the caller's
  // contact set. The options bag is snapshotted FIRST (a getter that grows a key after the check cannot
  // slip past), then the fields the server MUST ignore are refused with guidance -- a caller that sends
  // one has silently not done what they asked, so the client will not emit a payload the CA discards.
  function _updateAccount(o) {
    return _promised(function () {
      o = guard.identifier.optionsObject(o, E, "acme/bad-input", "pki.acme updateAccount options");
      if (o.status !== undefined) throw E("acme/bad-input", "updateAccount cannot change the account status; use deactivateAccount (RFC 8555 sec. 7.3.6 is the only client-settable status)");
      if (o.termsOfServiceAgreed !== undefined) throw E("acme/bad-input", "termsOfServiceAgreed cannot be updated by the client (RFC 8555 sec. 7.1.2 / 7.3.3); a changed-terms CA answers a request with a userActionRequired problem");
      if (o.orders !== undefined) throw E("acme/bad-input", "the account orders URL is server-assigned and cannot be updated (RFC 8555 sec. 7.3.2)");
      if (o.externalAccountBinding !== undefined) throw E("acme/bad-input", "externalAccountBinding is not updateable by the client (RFC 8555 sec. 7.1.2 / 7.3.4)");
      guard.identifier.assertKnownKeys(o, _METHOD_OPTS.updateAccount, E, "acme/bad-input", "unknown updateAccount option ");
      var account = _requireKid();
      return _post(account, updateAccount, { contact: o.contact }, "kid").then(function (res) { return validate("account", _json(res)); });
    });
  }

  // listOrders (RFC 8555 sec. 7.1.2.1): a POST-as-GET to the account's orders URL, aggregating the
  // sec. 7.1.2.1 `Link: rel="next"` pages. The `next` header is untrusted (TLS-delivered, unsigned) and
  // steers the next account-key-signed POST-as-GET, so it is https-gated, confined to the request URL's
  // origin (SSRF), deduped against a visited-page loop, and bounded by maxPages (CWE-770 amplification).
  function _listOrders(ordersUrl, o) {
    return _promised(function () {
      o = _gateOpts(o, _METHOD_OPTS.listOrders, "listOrders");
      var maxPages = guard.limits.cap(o.maxPages, "maxPages", 50, { E: E, code: "acme/bad-input", min: 1 });
      var out = [], seen = intrinsic.create(null), pages = 0, truncated = false;
      function fetchPage(pageUrl) {
        seen[_dedupKey(pageUrl)] = true;   // pageUrl is a canonical _clientUrl output, so the dedup key is consistent
        return _postAsGet(pageUrl).then(function (res) {
          pages += 1;
          var body = validate("ordersList", _json(res));
          for (var i = 0; i < body.orders.length; i++) _push(out, body.orders[i]);
          var next = _parseLinkNext(res.headers, pageUrl);   // resolved against this page, https + origin-gated, singleton
          if (next == null) return;
          if (pages >= maxPages) { truncated = true; return; }
          var nextUrl = _clientUrl(next);   // re-affirm the https gate on the followed target
          if (seen[_dedupKey(nextUrl)]) return;   // loop guard: a next to an already-visited page
          return fetchPage(nextUrl);
        });
      }
      return fetchPage(_clientUrl(ordersUrl)).then(function () { return { orders: out, pages: pages, truncated: truncated }; });
    });
  }

  function _keyChange(o) { return _promised(function () { return _keyChangeBody(o); }); }
  function _keyChangeBody(o) {
    o = _gateOpts(o, _METHOD_OPTS.keyChange, "keyChange");
    if (!o.newKey || !_isObject(o.newJwk) || !_isString(o.newAlg)) throw E("acme/bad-input", "keyChange requires newKey, newJwk, and newAlg");
    var account = _requireKid();
    return _resource("keyChange").then(function (url) {
      return _post(url, keyChange, { account: account, oldKey: accountJwk, newKey: o.newKey, newJwk: o.newJwk, newAlg: o.newAlg }, "kid").then(function (res) {
        // RFC 8555 sec. 7.3.5: a 200 means the server has COMMITTED the rollover (the status is gated to 200
        // by _post; a problem+json is already rejected). Rotate the session key FIRST so the client stays in
        // sync -- a bodyless or malformed account body must NOT leave the client on the old key while the
        // server holds the new one. The account object is optional + informational: parse it best-effort.
        accountKey = o.newKey; accountJwk = o.newJwk; alg = o.newAlg;
        var acct = null;
        if (_bodyText(res).trim() !== "") {
          try { acct = validate("account", _json(res)); }
          catch (_e) { acct = null; }
        }
        return { account: acct, url: account };
      });
    });
  }

  // ARI RenewalInfo (RFC 9773 sec. 4.1) -- the SOLE UNAUTHENTICATED GET (no JWS, no nonce).
  function _renewalInfo(certDer, clockFn, retryAfterCapSeconds) {
    return _promised(function () { return _renewalInfoBody(certDer, clockFn, retryAfterCapSeconds); });
  }
  function _renewalInfoBody(certDer, clockFn, retryAfterCapSeconds) {
    if (!guard.bytes.isByteSource(certDer)) throw E("acme/bad-input", "renewalInfo requires a DER certificate BufferSource");
    var _rawClk = typeof clockFn === "function" ? clockFn : clock;   // renewalWindow may pass a per-call clock
    // The clock MUST return finite epoch ms: a NaN / Infinity would make the expiry comparison below silently
    // false and bypass the RFC 9773 sec. 4.3 gate, so the validating wrapper fails closed on a non-finite value.
    function clk() { var t = _rawClk(); if (typeof t !== "number" || !isFinite(t)) throw E("acme/bad-input", "the renewalInfo clock returned a non-finite value"); return t; }
    // RFC 9773 sec. 4.3: a client MUST NOT check a certificate's RenewalInfo after it has expired. Gate BEFORE the
    // unauthenticated GET -- the same expiry test renewalWindow applies -- so the raw verb cannot query a dead cert.
    var notAfterMs = guard.time.instantOf(x509.parse(certDer).validity.notAfter);
    // allow:nan-date-comparison-unguarded -- notAfter is a codec-parsed cert date (asn1 readTime rejects a NaN instant).
    if (clk() > notAfterMs) throw E("acme/certificate-expired", "the certificate is already past its notAfter; a client MUST NOT check RenewalInfo after it has expired (RFC 9773 sec. 4.3)");
    var certId = ariCertId(certDer);
    return _resource("renewalInfo").then(function (base) {
      // Re-check expiry immediately BEFORE the GET: the directory fetch above (uncached) can take long enough that a
      // certificate close to notAfter crosses it in between, and RFC 9773 sec. 4.3 forbids the query after expiry.
      // allow:nan-date-comparison-unguarded -- notAfterMs is a codec-parsed cert date; clk() is validated finite.
      if (clk() > notAfterMs) throw E("acme/certificate-expired", "the certificate expired before the RenewalInfo request could be issued; a client MUST NOT check RenewalInfo after expiry (RFC 9773 sec. 4.3)");
      // Append the certID to the PATH, before any query string (RFC 9773): a directory renewalInfo URL may
      // carry a query, so string concatenation would push the certID into the query rather than the path.
      var u = new URL(base);
      u.pathname = _stripTrailingSlash(u.pathname) + "/" + certId;
      var url = _clientUrl(u.href);
      return _send("GET", url, { accept: "application/json" }, null).then(function (res) {
        if (res.status !== 200) throw _serverProblem(res);
        var obj = validateRenewalInfo(_json(res));
        var ra = res.headers["retry-after"];
        var retryAfterSeconds = null;
        if (typeof ra === "string" && ra.trim() !== "") {
          // renewalWindow passes a cap: the Retry-After is ADVISORY there and is clamped anyway, so a huge or
          // unparseable value must clamp / drop to null (renewalWindow then defaults) rather than discard the
          // validated window. The raw renewalInfo verb (no cap) stays strict -- a bad Retry-After fails closed.
          var raOpts = { now: clk(), E: E, code: "acme/bad-retry-after" };
          if (typeof retryAfterCapSeconds === "number") { raOpts.cap = retryAfterCapSeconds; raOpts.lenient = true; }
          retryAfterSeconds = retryAfter.parse(ra, raOpts).retryAfterSeconds;
        }
        return { renewalInfo: obj, retryAfterSeconds: retryAfterSeconds };
      });
    });
  }

  // ARI renewal-window decision (RFC 9773 sec. 4.2 / 4.3) -- a pure, timer-less helper that composes the
  // unauthenticated renewalInfo GET, picks a uniform-random instant in the CA's suggested window, and
  // returns the decision as DATA. It never sleeps or schedules: an auto-renewing daemon is an explicit
  // future opt-in, not a hidden timer inside the thin client.
  function _renewalWindow(certDer, o) {
    return Promise.resolve().then(function () {
      o = _gateOpts(o, _METHOD_OPTS.renewalWindow, "renewalWindow");
      if (!guard.bytes.isByteSource(certDer)) throw E("acme/bad-input", "renewalWindow requires a DER certificate BufferSource");
      if (o.random !== undefined && typeof o.random !== "function") throw E("acme/bad-input", "renewalWindow opts.random must be a function returning a number in [0, 1]");
      if (o.clock !== undefined && typeof o.clock !== "function") throw E("acme/bad-input", "renewalWindow opts.clock must be a function returning epoch milliseconds");
      // replaced is the sec. 4.3 "MUST NOT act on a replaced certificate" signal: require a real boolean so a
      // truthy non-boolean (a caller storing replacement state as a timestamp/object) cannot fail OPEN past
      // the gate below (=== true would let it through) and issue the RenewalInfo GET the RFC forbids.
      if (o.replaced !== undefined && typeof o.replaced !== "boolean") throw E("acme/bad-input", "renewalWindow opts.replaced must be a boolean");
      // opts.previous is a prior renewalWindow RESULT the caller stored: RFC 9773 sec. 4.2 says the client SHOULD
      // store the selected time and reuse it, so refreshing ARI (a later call after retryAfterSeconds) keeps the
      // SAME renewal instant while the CA's window is unchanged rather than re-randomizing and jittering it.
      if (o.previous !== undefined && !_isObject(o.previous)) throw E("acme/bad-input", "renewalWindow opts.previous must be a prior renewalWindow result object");
      // A per-call clock (documented opt) overrides the client's receipt clock for the WHOLE decision -- the
      // expiry gate, the renew-now comparison, and the RenewalInfo Retry-After parse -- so a caller can ask
      // "should I renew as of time T?" deterministically without reconfiguring the client. Every READING must
      // be a finite epoch ms: a NaN / Infinity would make each relational comparison silently false and bypass
      // the expiry gate, so the validating wrapper fails closed on a non-finite value.
      var _clk = typeof o.clock === "function" ? o.clock : clock;
      function clk() { var t = _clk(); if (typeof t !== "number" || !isFinite(t)) throw E("acme/bad-input", "the renewalWindow clock returned a non-finite value"); return t; }
      // RFC 9773 sec. 4.3: a client MUST NOT act on renewal info for a certificate it can no longer use --
      // one already past its notAfter (nothing to renew) or one the caller knows has been replaced. Gate
      // BEFORE the fetch so a decommissioned certificate never even reaches the CA.
      var notAfter = x509.parse(certDer).validity.notAfter;
      var now = clk();
      // Exclusive of notAfter: X.509 validity is inclusive of notAfter (a cert is still valid AT it), matching
      // path-validate's `t > notAfter` expiry test -- only a cert strictly past notAfter has nothing to renew.
      // allow:nan-date-comparison-unguarded -- notAfter is a codec-parsed cert date (asn1 readTime rejects a NaN
      // instant) and the window start/end below are rfc3339-validated by validateRenewalInfo; neither is NaN.
      if (now > guard.time.instantOf(notAfter)) throw E("acme/certificate-expired", "the certificate is already past its notAfter; there is nothing to renew (RFC 9773 sec. 4.3)");
      if (o.replaced === true) throw E("acme/certificate-replaced", "the caller asserts this certificate has already been replaced (RFC 9773 sec. 4.3)");
      return _renewalInfo(certDer, clk, RENEWAL_RETRY_MAX_SECONDS).then(function (ri) {
        var w = ri.renewalInfo.suggestedWindow;
        // start/end are grammar+calendar-validated RFC 3339 by validateRenewalInfo (an inverted window has
        // already thrown acme/bad-renewal-window), so neither Date.parse is NaN and end > start here.
        var startMs = Date.parse(w.start), endMs = Date.parse(w.end);
        // Bound the window by the certificate's own expiry: a renewal instant AFTER notAfter is useless (you
        // must renew BEFORE the cert dies), so a CA suggestedWindow that extends past notAfter is clamped to it
        // -- selection stays uniform within the still-valid sub-window. If the whole window is past notAfter,
        // effStart collapses to effEnd (renew at the last valid instant).
        var notAfterMs = guard.time.instantOf(notAfter);
        var effEnd = Math.min(endMs, notAfterMs), effStart = Math.min(startMs, effEnd);
        // RFC 9773 sec. 4.2: if the caller passed a prior result (opts.previous) whose suggestedWindow is UNCHANGED,
        // REUSE its selectedTime (clamped to the still-valid, notAfter-bounded window) instead of drawing again, so
        // repeated ARI refreshes converge on one stable renewal instant. A changed window (or no prior) draws fresh.
        var pw = o.previous && _isObject(o.previous.suggestedWindow) ? o.previous.suggestedWindow : null;
        var selectedMs;
        if (pw && pw.start === w.start && pw.end === w.end && _isString(o.previous.selectedTime)) {
          var prevMs = Date.parse(o.previous.selectedTime);
          if (!isFinite(prevMs)) throw E("acme/bad-input", "renewalWindow opts.previous.selectedTime must be an RFC 3339 date-time");
          selectedMs = Math.max(effStart, Math.min(effEnd, prevMs));
        } else {
          // Validate the draw's TYPE, never coerce: Number(null)/Number(false) -> 0, Number("0.5") -> 0.5 would
          // silently accept a non-number callback return. Require an actual number in [0, 1].
          var draw = o.random ? o.random() : _defaultRandom();
          if (typeof draw !== "number" || !(draw >= 0 && draw <= 1)) throw E("acme/bad-input", "renewalWindow opts.random must return a number in [0, 1]");
          // select a uniform-random instant across the (validity-bounded) window to spread renewals; if it is
          // already in the past, the caller should renew immediately.
          selectedMs = Math.round(effStart + draw * (effEnd - effStart));
        }
        var retryAfterSeconds = ri.retryAfterSeconds == null ? RENEWAL_RETRY_DEFAULT_SECONDS :
          Math.max(RENEWAL_RETRY_MIN_SECONDS, Math.min(RENEWAL_RETRY_MAX_SECONDS, ri.retryAfterSeconds));
        return {
          suggestedWindow: w,
          selectedTime: new Date(selectedMs).toISOString(),
          // Decide renew-now against a FRESH clock read: the RenewalInfo GET may itself span the selected
          // instant, so the pre-fetch `now` (used above only for the expiry gate) could be stale here. Also
          // renew now when the SELECTED instant lands at or past notAfter -- whether the whole window opened
          // after expiry or a straddling window's draw hit the clamp endpoint, there is no margin left, so
          // waiting for the (clamped) time would leave the cert to expire unrenewed.
          renewNow: selectedMs <= clk() || selectedMs >= notAfterMs,
          retryAfterSeconds: retryAfterSeconds,
          explanationURL: _isString(ri.renewalInfo.explanationURL) ? ri.renewalInfo.explanationURL : null,
        };
      });
    });
  }

  return {
    directory: _directory,
    newAccount: _newAccount,
    newOrder: _newOrder,
    newAuthz: _newAuthz,
    getOrder: _getOrder,
    getAuthorization: _getAuthorization,
    getChallenge: _getChallenge,
    respondToChallenge: _respondToChallenge,
    finalize: _finalize,
    pollOrder: _pollOrder,
    pollAuthorization: _pollAuthorization,
    downloadCertificate: _downloadCertificate,
    revokeCert: _revokeCert,
    deactivateAccount: _deactivateAccount,
    deactivateAuthorization: _deactivateAuthorization,
    updateAccount: _updateAccount,
    listOrders: _listOrders,
    keyChange: _keyChange,
    renewalInfo: _renewalInfo,
    renewalWindow: _renewalWindow,
  };
}

module.exports = {
  client: client,
  validate: validate,
  validateProblem: validateProblem,
  validateRenewalInfo: validateRenewalInfo,
  identify: identify,
  assertTransition: assertTransition,
  keyAuthorization: keyAuthorization,
  http01: http01,
  dns01: dns01,
  tlsAlpn01Extension: tlsAlpn01Extension,
  verifyTlsAlpn01: verifyTlsAlpn01,
  // request builders
  postAsGet: postAsGet,
  newAccount: newAccount,
  externalAccountBinding: externalAccountBinding,
  newOrder: newOrder,
  newAuthz: newAuthz,
  finalize: finalize,
  challengeResponse: challengeResponse,
  deactivate: deactivate,
  updateAccount: updateAccount,
  revokeCert: revokeCert,
  keyChange: keyChange,
  // ARI (RFC 9773)
  ariCertId: ariCertId,
  parseAriCertId: parseAriCertId,
  // re-exported for the ACME consumer / test surface
  jose: jose,
};
