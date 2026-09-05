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
var wcEngine = require("./webcrypto");
var webcrypto = wcEngine.webcrypto;
var subtle = webcrypto.subtle;
var frameworkError = require("./framework-error");
var httpTransport = require("./http-transport");
var retryAfter = require("./http-retry-after");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _resolve = intrinsic.uncurry(intrinsic.promiseResolve);
var _hasOwn = intrinsic.hasOwn;
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

var _TOKEN_TABLE = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-");
var _LINK_TOKEN_TABLE = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+.^_`|~-");
function _isHex1to4(s) {
  var n = s.length;
  if (n < 1 || n > 4) return false;
  for (var i = 0; i < n; i++) { var c = _charCodeAt(s, i); if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102))) return false; }
  return true;
}
function _looksLikeIpv4(s) {
  var n = s.length, i = 0, octet, d;
  for (octet = 0; octet < 4; octet++) {
    if (octet > 0) { if (i >= n || _charCodeAt(s, i) !== 0x2e) return false; i++; }
    for (d = 0; i < n && _charCodeAt(s, i) >= 48 && _charCodeAt(s, i) <= 57 && d < 3; d++) i++;
    if (d < 1) return false;
  }
  return i === n;
}
function _countAtSigns(s) { var c = 0; for (var i = 0; i < s.length; i++) { if (_charCodeAt(s, i) === 0x40) c++; } return c; }
function _stripLeadingOWS(s, from) {
  var i = from;
  while (i < s.length && (_charCodeAt(s, i) === 0x20 || _charCodeAt(s, i) === 0x09)) i++;
  return _strSlice(s, i);
}
function _stripTrailingSlash(s) {
  var end = s.length;
  while (end > 0 && _charCodeAt(s, end - 1) === 0x2f) end--;
  return _strSlice(s, 0, end);
}
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
function _isAlpha(c) { return (c >= 65 && c <= 90) || (c >= 97 && c <= 122); }
function _isAlnumLower(c) { return (c >= 97 && c <= 122) || (c >= 48 && c <= 57); }
function _isSchemeChar(c) { return _isAlpha(c) || (c >= 48 && c <= 57) || c === 0x2b || c === 0x2e || c === 0x2d; }
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
function _isLdhLabel(l) {
  var n = l.length;
  if (n === 0 || !_isAlnumLower(_charCodeAt(l, 0)) || !_isAlnumLower(_charCodeAt(l, n - 1))) return false;
  for (var i = 1; i < n - 1; i++) { var c = _charCodeAt(l, i); if (!(_isAlnumLower(c) || c === 0x2d)) return false; }
  return true;
}
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
function _isCanonicalOctet(s) {
  var n = s.length;
  if (n === 0 || n > 3) return false;
  if (n === 1) { var c0 = _charCodeAt(s, 0); return c0 >= 48 && c0 <= 57; }
  if (!(_charCodeAt(s, 0) >= 49 && _charCodeAt(s, 0) <= 57)) return false;
  for (var i = 1; i < n; i++) { var c = _charCodeAt(s, i); if (!(c >= 48 && c <= 57)) return false; }
  return true;
}
function _hasWsOrBackslash(s) {
  for (var i = 0; i < s.length; i++) { var c = _charCodeAt(s, i); if (c === 0x5c || pkix.isJsWhitespace(c)) return true; }
  return false;
}
function _hasSchemePrefix(uri) {
  var n = uri.length;
  if (n === 0 || !_isAlpha(_charCodeAt(uri, 0))) return false;
  var i = 1;
  while (i < n && _isSchemeChar(_charCodeAt(uri, i))) i++;
  return i < n && _charCodeAt(uri, i) === 0x3a;
}
function _uriFirstSegment(uri) {
  for (var i = 0; i < uri.length; i++) { var c = _charCodeAt(uri, i); if (c === 0x2f || c === 0x3f || c === 0x23) return _strSlice(uri, 0, i); }
  return uri;
}
function _endsWith(s, suffix) {
  var n = s.length, m = suffix.length;
  if (m > n) return false;
  for (var i = 0; i < m; i++) { if (_charCodeAt(s, n - m + i) !== _charCodeAt(suffix, i)) return false; }
  return true;
}

var AcmeError = frameworkError.AcmeError;
function E(code, message, cause) { return new AcmeError(code, message, cause); }


function _isObject(v) { return v && typeof v === "object" && !Array.isArray(v); }
function _isString(v) { return typeof v === "string"; }
function _isRfc3339(v) { return rfc3339.isValid(v); }
var _RANDOM_DENOM = Math.pow(2, 48);
function _defaultRandom() { return Buffer.from(webcrypto.getRandomValues(new Uint8Array(6))).readUIntBE(0, 6) / _RANDOM_DENOM; }
var RENEWAL_RETRY_MIN_SECONDS = 60;
var RENEWAL_RETRY_MAX_SECONDS = constants.TIME.days(1) / constants.TIME.seconds(1);
var RENEWAL_RETRY_DEFAULT_SECONDS = constants.TIME.hours(6) / constants.TIME.seconds(1);
function _isUrl(v) {
  if (!_isString(v) || !_isHttpUrlShape(v)) return false;
  var u;
  try { u = new URL(v); }
  catch (_e) { return false; }
  return (u.protocol === "http:" || u.protocol === "https:") && u.hostname.length > 0;
}
function _isUriString(v) { return _isString(v) && _isUriShape(v); }


var CRL_REASONS = [0, 1, 2, 3, 4, 5, 6, 8, 9, 10];

var KNOWN_CHALLENGE_TYPES = intrinsic.assign(intrinsic.create(null), { "http-01": 1, "dns-01": 1, "tls-alpn-01": 1 });

var STATUS = {
  account:       ["valid", "deactivated", "revoked"],
  order:         ["pending", "ready", "processing", "valid", "invalid"],
  authorization: ["pending", "valid", "invalid", "deactivated", "expired", "revoked"],
  challenge:     ["pending", "processing", "valid", "invalid"],
};

var SPECS = intrinsic.assign(intrinsic.create(null), {
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
    { name: "orders", type: "url" },
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
    { name: "orders", type: "array", required: true, elemType: "url" },
  ],
});

function _checkType(kind, field, value, obj) {
  switch (field.type) {
    case "string": if (!_isString(value)) return "must be a string"; break;
    case "url": if (!_isUrl(value)) return "must be a URL string"; break;
    case "rfc3339": if (!_isRfc3339(value)) return "must be an RFC 3339 date-time"; break;
    case "boolean": if (typeof value !== "boolean") return "must be a boolean"; break;
    case "token": _assertToken(value); break;
    case "object": if (!_isObject(value)) return "must be an object"; break;
    case "identifier": _validateIdentifier(value); break;
    case "array":
      if (!Array.isArray(value)) return "must be an array";
      var minItems = typeof field.minItems === "function" ? field.minItems(obj) : field.minItems;
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
    default: break;
  }
  return null;
}

function _codeSlug(kind) {
  var out = "";
  for (var i = 0; i < kind.length; i++) { var c = _charCodeAt(kind, i); if (c >= 65 && c <= 90) out += "-"; out += _charAt(kind, i); }
  return _lower(out);
}

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


function _validateIdentifier(id) {
  if (!_isObject(id)) throw E("acme/bad-identifier", "an identifier must be { type, value } strings");
  var type = id.type, value = id.value;
  if (!_isString(type) || !_isString(value)) throw E("acme/bad-identifier", "an identifier must be { type, value } strings");
  if (type === "dns") {
    if (value.indexOf("*.") === 0) throw E("acme/bad-identifier", "a wildcard *. value is not permitted in an authorization identifier (RFC 8555 sec. 7.1.4)");
    _assertDnsName(value);
  } else if (type === "ip") {
    _assertIpAddress(value);
  }
  return { type: type, value: value };
}

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

function _canonicalizeIpv6(value) {
  var groups;
  if (value.indexOf("::") !== -1) {
    if (value.indexOf("::") !== value.lastIndexOf("::")) return null;
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


var TRANSITIONS = intrinsic.assign(intrinsic.create(null), {
  challenge:     { pending: ["processing", "valid", "invalid"], processing: ["processing", "valid", "invalid"] },
  authorization: { pending: ["valid", "invalid", "deactivated"], valid: ["expired", "deactivated", "revoked"] },
  order:         { pending: ["ready", "invalid"], ready: ["processing", "valid", "invalid"], processing: ["valid", "invalid"] },
});

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
  var table = TRANSITIONS[guard.text.keyOf(kind)];
  if (!table) throw E("acme/bad-input", "unknown resource kind " + guard.text.showValue(kind));
  if (from === to) return;
  var allowed = _hasOwn(table, guard.text.keyOf(from)) ? table[guard.text.keyOf(from)] : null;
  if (!allowed || allowed.indexOf(to) === -1) throw E("acme/bad-transition", "illegal " + kind + " transition " + guard.text.showValue(from) + " -> " + guard.text.showValue(to) + " (RFC 8555 sec. 7.1.6)");
}


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
      if (_hasOwn(sub, "identifier")) _validateOrderIdentifier(sub.identifier);
    }
  }
  return obj;
}


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
  if (kind === "renewalInfo") return validateRenewalInfo(obj);
  if (!SPECS[guard.text.keyOf(kind)]) throw E("acme/bad-input", "unknown ACME object kind " + guard.text.showValue(kind));
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
 * member set: `"jws"`, `"problem"`, `"directory"`, `"order"`, `"authorization"`,
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
  var digest = await _sha256(Buffer.from(ka, "ascii"));
  var authorization = asn1.build.octetString(digest);
  var extnValue = asn1.build.octetString(authorization);
  return asn1.build.sequence([asn1.build.oid(OID_ACME_IDENTIFIER), asn1.build.boolean(true), extnValue]);
}

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
  var sanExt = exts.filter(function (e) { return e.oid === OID_SAN; })[0];
  if (!sanExt) throw E("acme/bad-tlsalpn", "the validation certificate is missing the SubjectAltName");
  var san = _extDecoders.byOid[OID_SAN](sanExt.value, _extCtx);
  if (!san.names || san.names.length !== 1) throw E("acme/bad-tlsalpn", "the SubjectAltName must carry EXACTLY ONE entry (RFC 8737 sec. 3)");
  var entry = san.names[0];
  if (!_isObject(identifier) || !_isString(identifier.type)) throw E("acme/bad-input", "an identifier { type, value } is required");
  if (identifier.type === "dns") {
    if (entry.tagNumber !== 2) throw E("acme/bad-tlsalpn", "a dns identifier requires a dNSName SAN");
    _assertDnsName(identifier.value);
    if (String(entry.value).toLowerCase() !== identifier.value) throw E("acme/bad-tlsalpn", "the SAN dNSName does not match the identifier");
  } else if (identifier.type === "ip") {
    if (entry.tagNumber !== 7) throw E("acme/bad-tlsalpn", "an ip identifier requires a single iPAddress SAN (RFC 8738 sec. 6)");
    _assertIpAddress(identifier.value);
    var sanIp = _ipBytesToText(entry.value);
    if (sanIp === null || sanIp !== identifier.value) throw E("acme/bad-tlsalpn", "the iPAddress SAN does not match the ip identifier (RFC 8738 sec. 6)");
  } else {
    throw E("acme/bad-tlsalpn", "unsupported tls-alpn-01 identifier type " + guard.text.showValue(identifier.type));
  }
}


function _outerHeader(o) {
  var h = { alg: o.alg, nonce: o.nonce, url: o.url };
  if (_hasOwn(o, "kid")) h.kid = o.kid;
  if (_hasOwn(o, "jwk")) h.jwk = o.jwk;
  return h;
}
function _payloadBuf(obj) {
  if (obj === undefined) return Buffer.alloc(0);
  return Buffer.from(JSON.stringify(obj), "utf8");
}
var _promised = guard.async.deferred;
function _signOuter(o, payloadObj) {
  if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
  if (!o.key) throw E("acme/bad-input", "a signing key (opts.key) is required");
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
    return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, undefined);
  });
}

function _assertContacts(contacts) {
  if (!Array.isArray(contacts)) throw E("acme/bad-contact", "contact must be an array of URL strings");
  for (var i = 0; i < contacts.length; i++) {
    if (!_hasOwn(contacts, i)) throw E("acme/bad-contact", "contact[" + i + "] is missing (a sparse array is not allowed)");
    var c = contacts[i];
    if (!_isUriString(c)) throw E("acme/bad-contact", "each contact must be a URI string (RFC 8555 sec. 7.1.2)");
    if (c.slice(0, "mailto:".length).toLowerCase() === "mailto:") {
      var addr = c.slice("mailto:".length);
      if (addr.indexOf("?") !== -1) throw E("acme/bad-contact", "a mailto contact must not carry header fields (RFC 8555 sec. 7.3 / RFC 6068)");
      if (addr.indexOf(",") !== -1) throw E("acme/bad-contact", "a mailto contact must be a single addr-spec, not a comma list (RFC 8555 sec. 7.3)");
      if (_countAtSigns(addr) !== 1) throw E("acme/bad-contact", "a mailto contact must be exactly one addr-spec");
    }
  }
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

var _HMAC_HASH = intrinsic.assign(intrinsic.create(null), { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" });

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
  jose.assertPublicJwk(o.accountJwk);
  if (!_isString(o.kid)) throw E("acme/bad-input", "externalAccountBinding requires the CA-issued kid");
  var alg = o.alg || "HS256";
  if (!_HMAC_HASH[guard.text.keyOf(alg)]) throw E("acme/bad-input", "an EAB inner JWS must use an HS* MAC algorithm (sec. 7.3.4), not " + guard.text.showValue(alg));
  var key = o.macKey;
  if (Buffer.isBuffer(key)) {
    try { key = await subtle.importKey("raw", key, { name: "HMAC", hash: _HMAC_HASH[alg] }, false, ["sign"]); }
    catch (e) { throw E("acme/bad-input", "the EAB macKey could not be imported as an HMAC key", e); }
  } else if (!key || typeof key !== "object" || key.type !== "secret") {
    throw E("acme/bad-input", "the EAB macKey must be a raw Buffer or an HMAC (secret) CryptoKey");
  }
  return jose.sign({ protected: { alg: alg, kid: o.kid, url: o.url }, payload: _payloadBuf(o.accountJwk), key: key, profile: "eab-inner" });
}

function _validateOrderIdentifier(id) {
  if (!_isObject(id)) throw E("acme/bad-identifier", "an order identifier must be { type, value } strings");
  var type = id.type, value = id.value;
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
  return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, { identifier: _validateIdentifier(o.identifier) });
}

async function _jwkToSpki(jwk) {
  var importAlg;
  if (jwk.kty === "EC") importAlg = { name: "ECDSA", namedCurve: jwk.crv };
  else if (jwk.kty === "RSA") importAlg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  else if (jwk.kty === "OKP") importAlg = { name: jwk.crv };
  else if (jwk.kty === "AKP") importAlg = { name: jwk.alg };
  else throw E("acme/bad-key", "unsupported account key type " + guard.text.showValue(jwk && jwk.kty));
  var key;
  try { key = await subtle.importKey("jwk", jwk, importAlg, true, []); }
  catch (e) { throw E("acme/bad-key", "the account key JWK could not be imported to derive its SubjectPublicKeyInfo", e); }
  return Buffer.from(await subtle.exportKey("spki", key));
}

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

function _csrIdentifierSet(parsedCsr) {
  var set = intrinsic.create(null);
  _forEach(parsedCsr.attributes || [], function (a) {
    if (a.type !== oid.byName("extensionRequest") || !_isArrayI(a.extensions)) return;
    _forEach(a.extensions, function (e) {
      if (e.oid !== OID_SAN) return;
      var dec = _extDecoders.byOid[OID_SAN](e.value, _extCtx);
      _forEach(dec.names || [], function (n) { _addSanName(set, n, "the finalize CSR"); });
    });
  });
  _forEach(_subjectCommonNames(parsedCsr.subject), function (cn) { _addCommonName(set, cn, "the finalize CSR"); });
  return set;
}

function _addCommonName(set, cn, what) {
  var looksIp = _looksLikeIpv4(cn) || intrinsic.stringIndexOf(cn, ":") !== -1;
  if (looksIp) {
    var canonical = true;
    try { _assertIpAddress(cn); }
    catch (_e) {
      canonical = false;
    }
    if (canonical && set["ip:" + cn] === true) return;
    throw _unmappableName(what, cn, null);
  }
  var folded = _asciiLower(cn);
  var base = intrinsic.stringIndexOf(folded, "*.") === 0 ? _strSlice(folded, 2) : folded;
  if (intrinsic.stringIndexOf(base, "*") !== -1) throw _unmappableName(what, cn, null);
  try { _assertDnsName(base); }
  catch (e2) {
    throw _unmappableName(what, cn, e2);
  }
  set["dns:" + folded] = true;
}

function _unmappableName(what, name, cause) {
  return E("acme/unsupported-identifier-type",
    what + " carries the name " + _stringify(name) + " in its subject, which maps to no ACME order " +
    "identifier (only a dns name or a canonical IP address does), so the identifier set cannot be " +
    "compared", cause || undefined);
}

var _asciiLower = guard.name.lowerAscii;

function _addSanName(set, n, what) {
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

function _orderIdentifierSet(identifiers) {
  var set = intrinsic.create(null);
  _forEach(identifiers, function (id) {
    if (id.type === "dns") set["dns:" + _asciiLower(id.value)] = true;
    else if (id.type === "ip") set["ip:" + id.value] = true;
    else throw E("acme/unsupported-identifier-type",
      "this build cannot bind a certificate to an order identifier of type " + _stringify(id.type) +
      " (only dns and ip map to a certificate name), so it cannot report the identifier set as checked");
  });
  return set;
}

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
  var parsed = csr.parse(csrBuf);
  if (o.accountJwk !== undefined) {
    var accountSpki = await _jwkToSpki(o.accountJwk);
    if (parsed.subjectPublicKeyInfo && Buffer.isBuffer(parsed.subjectPublicKeyInfo.bytes) &&
        parsed.subjectPublicKeyInfo.bytes.equals(accountSpki)) {
      throw E("acme/key-reuse", "the finalize CSR public key must not be the account key (RFC 8555 sec. 11.1)");
    }
  }
  if (o.identifiers !== undefined) {
    if (!Array.isArray(o.identifiers) || o.identifiers.length === 0) throw E("acme/bad-input", "finalize identifiers must be the non-empty order identifier array");
    for (var ii = 0; ii < o.identifiers.length; ii++) {
      if (!_hasOwn(o.identifiers, ii)) throw E("acme/bad-input", "finalize identifiers[" + ii + "] is missing (a sparse array is not allowed)");
      _validateOrderIdentifier(o.identifiers[ii]);
    }
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
 * payload is the type-defined response object: `{}` for the three registered
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
 * authorization): a kid-signed JWS with the payload `{"status":"deactivated"}`,
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
    _assertContacts(o.contact);
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
 * certificate key (`jwk` mode). Pass exactly one. `opts` = `{ key, alg, nonce,
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
  x509.parse(certBuf);
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
  jose.assertPublicJwk(o.oldKey);
  jose.assertPublicJwk(o.newJwk);
  var inner = await jose.sign({
    protected: { alg: o.newAlg, url: o.url, jwk: o.newJwk },
    payload: _payloadBuf({ account: o.account, oldKey: o.oldKey }),
    key: o.newKey, profile: "keychange-inner",
  });
  return jose.sign({ protected: { alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, payload: _payloadBuf(inner), key: o.key, profile: "acme-outer" });
}


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
  var serialBytes = Buffer.from(cert.serialNumberHex, "hex");
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
 * zero-width window throws `acme/bad-renewal-window`: the client treats it as no
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
  // allow:nan-date-comparison-unguarded -- source-validated by the rfc3339.isValid check above.
  if (Date.parse(w.end) <= Date.parse(w.start)) throw E("acme/bad-renewal-window", "the renewal window end must be strictly after start (RFC 9773 sec. 4.2)");
  return obj;
}


var CLIENT_DEFAULT_TIMEOUT = constants.TIME.seconds(30);
var CLIENT_MAX_TIMEOUT = constants.TIME.seconds(600);
var CLIENT_USER_AGENT = "blamejs-pki/" + pkgVersion + " node/" + process.versions.node;
var CLIENT_MAX_NONCE_POOL = 32;

function _clientUrl(urlStr) {
  var s = String(urlStr);
  var url;
  try { url = new URL(s); }
  catch (e) { throw E("acme/bad-url", "the ACME URL did not parse: " + s, e); }
  if (url.protocol !== "https:") throw E("acme/insecure-url", "ACME requires https (RFC 8555 sec. 6.1), got " + url.protocol + " for " + s);
  var _uAuth = _uriAuthority(s, true);
  if (intrinsic.stringIndexOf(_uAuth ? _uAuth.authority : "", "@") !== -1) throw E("acme/bad-url", "an ACME URL must not contain userinfo: " + JSON.stringify(s));
  if (_hasWsOrBackslash(s)) throw E("acme/bad-url", "an ACME URL must not contain whitespace or a backslash: " + JSON.stringify(s));
  if (_uriStructurallyInvalid(s)) throw E("acme/bad-url", "an ACME URL authority is not canonical (the transport would repair it): " + JSON.stringify(s));
  var _auth = _uriAuthority(s, true);
  if (_auth) {
    var _hp = _auth.authority.slice(_auth.authority.lastIndexOf("@") + 1);
    var _rawHost = _hp.charAt(0) === "[" ? _hp.slice(0, _hp.indexOf("]") + 1) : _hp.split(":")[0];
    if (_rawHost.toLowerCase() !== url.hostname) throw E("acme/bad-url", "an ACME URL host is not canonical (the transport would rewrite it): " + JSON.stringify(s));
  }
  var _pathStart = _rawPathStart(s);
  var rawPath = _strSlice(s, _pathStart, _firstDelim(s, _pathStart, 0x3f, 0x23, -1));
  if (rawPath !== url.pathname) throw E("acme/bad-url", "an ACME URL path is not canonical (the transport would normalize it): " + JSON.stringify(s));
  var qi = s.indexOf("?");
  var rawQuery = qi === -1 ? "" : s.slice(qi).split("#")[0];
  if (rawQuery !== url.search) throw E("acme/bad-url", "an ACME URL query is not canonical (the transport would normalize it): " + JSON.stringify(s));
  if (s.indexOf("#") !== -1) throw E("acme/bad-url", "an ACME URL must not contain a fragment: " + JSON.stringify(s));
  return s;
}
function _resolveLocation(loc, base) {
  var isAbsolute = true;
  try { new URL(loc); }
  catch (_e) { isAbsolute = false; }
  if (isAbsolute) return _clientUrl(loc);
  var u;
  try { u = new URL(loc, base); }
  catch (e) { throw E("acme/bad-url", "the Location header did not resolve to a valid URL: " + JSON.stringify(loc), e); }
  if (_queryRepaired(loc, u)) throw E("acme/bad-url", "a relative Link/Location query is not canonical (resolution re-encoded it): " + JSON.stringify(loc));
  return _clientUrl(u.href);
}
function _queryRepaired(rawRef, resolvedUrl) {
  var qi = rawRef.indexOf("?");
  return qi !== -1 && rawRef.slice(qi).split("#")[0] !== resolvedUrl.search;
}
var _defaultSleep = require("./sleep").sleep;
function _clientTls(o) {
  var t = o.tls || {};
  return { anchors: t.anchors, useSystemStore: t.useSystemStore, cert: t.cert, key: t.key, minVersion: t.minVersion, servername: t.servername, checkServerIdentity: t.checkServerIdentity };
}
var PEM_CERT_BEGIN = "-----BEGIN CERTIFICATE-----";
var PEM_CERT_END = "-----END CERTIFICATE-----";
function _splitPemChain(text) {
  var out = [];
  var lastEnd = 0, from = 0, begin, end;
  while ((begin = intrinsic.stringIndexOf(text, PEM_CERT_BEGIN, from)) !== -1 &&
         (end = intrinsic.stringIndexOf(text, PEM_CERT_END, begin + PEM_CERT_BEGIN.length)) !== -1) {
    var blockEnd = end + PEM_CERT_END.length;
    if (text.slice(lastEnd, begin).trim() !== "") throw E("acme/bad-certificate-chain", "the certificate chain contained non-whitespace text outside a PEM block (RFC 8555 sec. 7.4.2)");
    var der;
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

var LINK_HEADER_MAX_BYTES = constants.BYTES.kib(8);
var DEFAULT_MAX_ALTERNATES = 8;
function _trimOWS(s) {
  var a = 0, b = s.length;
  while (a < b && (_charCodeAt(s, a) === 0x20 || _charCodeAt(s, a) === 0x09)) a++;
  while (b > a && (_charCodeAt(s, b - 1) === 0x20 || _charCodeAt(s, b - 1) === 0x09)) b--;
  return _strSlice(s, a, b);
}
var _URIREF_TBL = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~:/?#[]@!$&'()*+,;=%-");
var _UNRES_TBL = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-");
var _IPVF_TBL = pkix.charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!$&'()*+,;=:-");
var _HEX_TBL = pkix.charTable("0123456789ABCDEFabcdef");
function _hexVal(c) { if (c >= 48 && c <= 57) return c - 48; if (c >= 65 && c <= 70) return c - 55; return c - 87; }
function _upperHexChar(c) { return (c >= 97 && c <= 102) ? c - 32 : c; }
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
function _firstDelim(s, from, d0, d1, d2) { for (var i = from; i < s.length; i++) { var c = _charCodeAt(s, i); if (c === d0 || c === d1 || c === d2) return i; } return s.length; }
function _isNumericPort(s) { if (s.length === 0 || _charCodeAt(s, 0) !== 0x3a) return false; for (var i = 1; i < s.length; i++) { var c = _charCodeAt(s, i); if (c < 48 || c > 57) return false; } return true; }
function _isIpvFuture(s) {
  var n = s.length, i = 1, h = 0, g = 0;
  if (n === 0 || (_charCodeAt(s, 0) !== 0x76 && _charCodeAt(s, 0) !== 0x56)) return false;
  while (i < n) { if (_HEX_TBL[_charCodeAt(s, i)]) { i++; h++; } else break; }
  if (h < 1 || i >= n || _charCodeAt(s, i) !== 0x2e) return false;
  i++;
  while (i < n) { if (_IPVF_TBL[_charCodeAt(s, i)]) { i++; g++; } else break; }
  return g >= 1 && i === n;
}
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
function _rawPathStart(s) {
  var n = s.length, i = 0;
  while (i < n && _isAlpha(_charCodeAt(s, i))) i++;
  if (i === 0) return 0;
  if (_charCodeAt(s, i) !== 0x3a || _charCodeAt(s, i + 1) !== 0x2f || _charCodeAt(s, i + 2) !== 0x2f) return 0;
  i += 3;
  while (i < n) { var c = _charCodeAt(s, i); if (c === 0x2f || c === 0x3f || c === 0x23) break; i++; }
  return i;
}
function _hasCharOutside(s, table) { for (var i = 0; i < s.length; i++) { if (!table[_charCodeAt(s, i)]) return true; } return false; }
function _hasBadPct(s) { for (var i = 0; i < s.length; i++) { if (_charCodeAt(s, i) === 0x25 && !(_HEX_TBL[_charCodeAt(s, i + 1)] && _HEX_TBL[_charCodeAt(s, i + 2)])) return true; } return false; }
function _isRegRelType(t) { var n = t.length; if (n === 0 || !_isAlpha(_charCodeAt(t, 0))) return false; for (var i = 1; i < n; i++) { var c = _charCodeAt(t, i); if (!(_isAlpha(c) || (c >= 48 && c <= 57) || c === 0x2e || c === 0x2d)) return false; } return true; }
function _foldPct2e(seg) { var out = "", i = 0, n = seg.length, folded = false; while (i < n) { if (_charCodeAt(seg, i) === 0x25 && _charCodeAt(seg, i + 1) === 0x32 && (_charCodeAt(seg, i + 2) === 0x65 || _charCodeAt(seg, i + 2) === 0x45)) { out += "."; folded = true; i += 3; } else { out += _charAt(seg, i); i += 1; } } return { decoded: out, folded: folded }; }
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
function _validRelType(t) {
  if (_isRegRelType(t)) return true;
  if (_hasCharOutside(t, _URIREF_TBL)) return false;
  return _validAbsoluteUri(t);
}
function _validAbsoluteUri(t) {
  return _hasSchemePrefix(t) && !_hasBadPct(t) && !_uriStructurallyInvalid(t);
}
function _multiFragment(uri) { return uri.split("#").length > 2; }
function _authorityMultiAt(uri) {
  var a = _uriAuthority(uri, false);
  if (!a) return false;
  var cnt = 0;
  for (var i = 0; i < a.authority.length; i++) { if (_charCodeAt(a.authority, i) === 0x40) cnt++; }
  return cnt >= 2;
}
function _hasEmptyAuthority(uri) {
  var a = _uriAuthority(uri, false);
  if (!a) return false;
  var scheme = a.scheme === "" ? "" : a.scheme.slice(0, -1).toLowerCase();
  if (scheme !== "" && scheme !== "http" && scheme !== "https" && scheme !== "ws" && scheme !== "wss" && scheme !== "ftp") return false;
  var host = a.authority.slice(a.authority.lastIndexOf("@") + 1);
  if (host.charAt(0) !== "[") { var ci = host.indexOf(":"); if (ci !== -1) host = host.slice(0, ci); }
  return host === "";
}
function _bracketsOnlyInAuthority(uri) {
  if (uri.indexOf("[") === -1 && uri.indexOf("]") === -1) return true;
  var mlen = _matchBracketAuthPrefix(uri);
  if (mlen === -1) return false;
  var rest = _strSlice(uri, mlen);
  if (rest.indexOf("[") !== -1 || rest.indexOf("]") !== -1) return false;
  var afterHost = _strSlice(rest, 0, _firstDelim(rest, 0, 0x2f, 0x3f, 0x23));
  return afterHost === "" || _isNumericPort(afterHost);
}
function _relFirstSegHasColon(uri) {
  if (_hasSchemePrefix(uri) || uri.indexOf("//") === 0) return false;
  return _uriFirstSegment(uri).indexOf(":") !== -1;
}
function _badPort(uri) {
  var a = _uriAuthority(uri, false);
  if (!a) return false;
  var auth = a.authority, n = auth.length, i = 0, at = -1, hostEnd, e;
  for (var u = 0; u < n; u++) { if (_charCodeAt(auth, u) === 0x40) { at = u; break; } }
  if (at !== -1) i = at + 1;
  if (i < n && _charCodeAt(auth, i) === 0x5b) {
    e = i + 1;
    while (e < n && _charCodeAt(auth, e) !== 0x5d) e++;
    if (e < n) hostEnd = e + 1;
    else { hostEnd = i; while (hostEnd < n && _charCodeAt(auth, hostEnd) !== 0x3a) hostEnd++; }
  } else { hostEnd = i; while (hostEnd < n && _charCodeAt(auth, hostEnd) !== 0x3a) hostEnd++; }
  if (hostEnd >= n || _charCodeAt(auth, hostEnd) !== 0x3a) return false;
  return !_isNumericPort(_strSlice(auth, hostEnd));
}
function _badIpLiteral(uri) {
  var interior = _ipLiteralInterior(uri);
  if (interior === null) return false;
  if (_isIpvFuture(interior)) return false;
  return !URL.canParse("http://[" + interior + "]/");
}
function _uriStructurallyInvalid(uri) {
  return !_bracketsOnlyInAuthority(uri) || _hasEmptyAuthority(uri) || _authorityMultiAt(uri) || _multiFragment(uri) || _relFirstSegHasColon(uri) || _badPort(uri) || _badIpLiteral(uri);
}
function _dedupKey(href) {
  var out = "", i = 0, n = href.length;
  while (i < n) {
    if (_charCodeAt(href, i) === 0x25 && _HEX_TBL[_charCodeAt(href, i + 1)] && _HEX_TBL[_charCodeAt(href, i + 2)]) {
      var h1 = _charCodeAt(href, i + 1), h2 = _charCodeAt(href, i + 2), v = (_hexVal(h1) << 4) | _hexVal(h2);
      if (_UNRES_TBL[v]) out += String.fromCharCode(v);
      else out += "%" + String.fromCharCode(_upperHexChar(h1)) + String.fromCharCode(_upperHexChar(h2));
      i += 3;
    } else { out += _charAt(href, i); i += 1; }
  }
  return out;
}
function _hasEncodedDotSegment(uri) {
  var segs = _split(_strSlice(uri, 0, _firstDelim(uri, 0, 0x3f, 0x23, -1)), "/");
  for (var _si = 0; _si < segs.length; _si++) {
    var r = _foldPct2e(segs[_si]);
    if (!r.folded) continue;
    if (r.decoded === "." || r.decoded === "..") return true;
  }
  return false;
}
function _linkUriInvalid(uri) {
  return _hasCharOutside(uri, _URIREF_TBL) || _hasBadPct(uri) || _hasEncodedDotSegment(uri) || _uriStructurallyInvalid(uri);
}
function _hasCtlOctet(s) {
  for (var _ci = 0; _ci < s.length; _ci++) { var _cc = s.charCodeAt(_ci); if (_cc === 0x7F || (_cc < 0x20 && _cc !== 0x09)) return true; }
  return false;
}

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
    if (p === "") { if (j === 0) continue; throw E("acme/bad-link", "an empty Link parameter (a ';' with no parameter) is malformed (RFC 8288): " + JSON.stringify(rest)); }
    var eq = p.indexOf("=");
    var name = (eq === -1 ? p : _trimOWS(p.slice(0, eq))).toLowerCase();
    if (!pkix.allCharsIn(name, _LINK_TOKEN_TABLE)) throw E("acme/bad-link", "a Link parameter name must be a token (RFC 8288 / RFC 7230): " + JSON.stringify(p));
    if (eq === -1) { out.push({ name: name, value: "", hasValue: false }); continue; }
    var v = _trimOWS(p.slice(eq + 1));
    if (v.length >= 2 && v.charAt(0) === "\"" && v.charAt(v.length - 1) === "\"") {
      var inner = v.slice(1, -1);
      if (!_isValidQuotedInterior(inner)) throw E("acme/bad-link", "a quoted Link parameter value is malformed (an unescaped quote or dangling backslash, RFC 7230): " + JSON.stringify(p));
      v = _unescapeQuotedPair(inner);
    } else if (!pkix.allCharsIn(v, _LINK_TOKEN_TABLE)) {
      throw E("acme/bad-link", "an unquoted Link parameter value must be a non-empty token (RFC 8288 / RFC 7230): " + JSON.stringify(p));
    }
    out.push({ name: name, value: v, hasValue: true });
  }
  return out;
}
function _relHas(rel, relName) {
  var toks = String(rel).split(" ");
  for (var i = 0; i < toks.length; i++) { if (toks[i].toLowerCase() === relName) return true; }
  return false;
}
function _parseLinkValue(raw) {
  var s = _trimOWS(raw);
  if (s === "") return null;
  var gt = s.indexOf(">");
  if (s.charAt(0) !== "<" || gt === -1) throw E("acme/bad-link", "a Link value must be <URI-Reference> with parameters (RFC 8288): " + JSON.stringify(raw));
  var rest = _stripLeadingOWS(s, gt + 1);
  if (rest !== "" && rest.charAt(0) !== ";") throw E("acme/bad-link", "a Link value's parameters must be introduced by ';' (RFC 8288): " + JSON.stringify(raw));
  var uri = s.slice(1, gt);
  if (_linkUriInvalid(uri)) throw E("acme/bad-link", "a Link URI-Reference contains a character, percent-escape, or encoded dot-segment not permitted by RFC 3986: " + JSON.stringify(raw));
  var params = _splitLinkParams(rest), rel = "", relSeen = false, anchor = null, anchorSeen = false;
  for (var i = 0; i < params.length; i++) {
    if (params[i].name === "rel" && !relSeen) { rel = params[i].value; relSeen = true; }
    else if (params[i].name === "anchor") {
      if (anchorSeen) throw E("acme/bad-link", "a Link value must not carry more than one anchor parameter (RFC 8288 sec. 3.2, ambiguous context): " + JSON.stringify(raw));
      anchorSeen = true;
      if (!params[i].hasValue) throw E("acme/bad-link", "a Link anchor parameter requires a URI value (RFC 8288 sec. 3.2): " + JSON.stringify(raw));
      anchor = params[i].value;
    }
  }
  return { uri: uri, rel: rel, anchor: anchor, relSeen: relSeen };
}
function _parseLinkRelation(headers, base, relName, opts) {
  opts = opts || {};
  var raw = null;
  for (var k in headers) { if (_hasOwn(headers, k) && k.toLowerCase() === "link") { raw = headers[k]; break; } }
  if (raw == null) return [];
  var baseUrl = new URL(base), baseOrigin = baseUrl.origin, baseHref = baseUrl.href;
  var baseKey = _dedupKey(baseHref);
  var fields = Array.isArray(raw) ? raw : [raw], out = [], seen = Object.create(null), distinctCount = 0, totalBytes = 0;
  for (var fi = 0; fi < fields.length; fi++) {
    var field = String(fields[fi]);
    totalBytes += field.length + 1;
    if (totalBytes > LINK_HEADER_MAX_BYTES) throw E("acme/bad-link", "the Link header(s) exceed the " + LINK_HEADER_MAX_BYTES + "-byte aggregate cap (RFC 8288, CWE-770)");
    if (_hasCtlOctet(field)) throw E("acme/bad-link", "a Link header must not contain control octets (RFC 9110 field-value)");
    var values = _splitLinkValues(field);
    for (var vi = 0; vi < values.length; vi++) {
      var lv = _parseLinkValue(values[vi]);
      if (lv === null) continue;
      if (lv.relSeen && lv.rel === "") throw E("acme/bad-link", "a Link rel parameter must name at least one relation-type (RFC 8288 sec. 3.3)");
      if (lv.rel !== "" && (lv.rel.charAt(0) === " " || lv.rel.charAt(lv.rel.length - 1) === " ")) throw E("acme/bad-link", "a Link rel value has a leading or trailing space (RFC 8288 sec. 3.3): " + JSON.stringify(lv.rel));
      var relToks = lv.rel === "" ? [] : lv.rel.split(" ");
      for (var ri = 0; ri < relToks.length; ri++) { if (relToks[ri] !== "" && !_validRelType(relToks[ri])) throw E("acme/bad-link", "a Link rel value contains a token that is not a valid relation-type (RFC 8288 sec. 3.3): " + JSON.stringify(lv.rel)); }
      if (!_relHas(lv.rel, relName)) continue;
      if (lv.anchor != null) {
        if (_linkUriInvalid(lv.anchor)) continue;
        var au;
        try { au = new URL(lv.anchor, base); }
        catch (_ae) { continue; }
        if (_queryRepaired(lv.anchor, au)) continue;
        if (au.href !== baseHref) continue;
      }
      var resolved;
      try { resolved = _resolveLocation(lv.uri, base); }
      catch (e) {
        if (e && e.code === "acme/insecure-url") throw E("acme/bad-link", "a rel=\"" + relName + "\" Link target is not an https URL: " + JSON.stringify(lv.uri), e);
        if (opts.singleton) throw E("acme/bad-link", "a rel=\"" + relName + "\" Link target is not a usable ACME request URL: " + _stringify(lv.uri), e);
        continue;
      }
      var parsed = new URL(resolved);
      if (parsed.origin !== baseOrigin) throw E("acme/bad-link", "a rel=\"" + relName + "\" Link target is not on the request URL's origin (SSRF guard): " + JSON.stringify(lv.uri));
      var key = _dedupKey(parsed.href);
      if (seen[key]) continue;
      seen[key] = true;
      distinctCount += 1;
      if (key !== baseKey) out.push(resolved);
    }
  }
  if (opts.singleton && distinctCount > 1) throw E("acme/bad-link", "the Link header names more than one distinct rel=\"" + relName + "\" target (RFC 8288 sec. 3.3, a singleton relation)");
  return out;
}

function _parseLinkAlternates(headers, base) { return _parseLinkRelation(headers, base, "alternate", {}); }
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
 * `revokeCert`, `deactivateAccount` / `deactivateAuthorization`, `updateAccount`, `listOrders`, `keyChange`, `renewalInfo`, `renewalWindow`, `scheduleRenewal`.
 *
 * @opts
 *   - `accountKey` / `accountJwk` / `alg` -- REQUIRED: the account private key, its public JWK, and the JWS alg.
 *   - `transport` -- injectable `transport(request) -> Promise<{status, headers, body}>`; default pki.transport.https. It must return a promise of the response; anything else is `acme/bad-input`.
 *   - `tls` -- { anchors, useSystemStore, cert, key, minVersion, servername, checkServerIdentity } for the default transport.
 *   - `timeout` / `maxResponseBytes` / `maxRedirects` -- transport budgets; `maxNonceRetries` -- badNonce retry cap (default 1).
 *   - `proxy` -- reach the ACME server through a forward HTTP proxy (`{ url, auth?, tls? }`; see pki.transport).
 *   - `maxPolls` / `maxTotalWait` / `sleep` -- poll-loop budgets + an injectable sleeper; `clock` -- an injectable receipt clock (default Date.now) for a Retry-After HTTP-date.
 *   - `resignKeys` -- optional ordered `[{ alg, key }]` enabling the RFC 8555 sec. 6.2 badSignatureAlgorithm re-sign. When a CA rejects the account `alg` and advertises the algs it supports, the first entry whose `alg` the CA advertised re-signs the request once and retries. Each `key` is a CryptoKey for the SAME account key material under that `alg`: an RSA account key signs RS256 and PS256 from one key, and its registered public JWK verifies either. The caller's order selects and the CA's list only filters, so a spoofed badSignatureAlgorithm cannot force a weaker alg (sec. 10). Absent, or with no advertised match, the badSignatureAlgorithm surfaces unchanged.
 *   - `newAuthz(identifier)` -- pre-authorize a single identifier (RFC 8555 sec. 7.4.1) -> { authorization, url }.
 *   - `downloadCertificate(url, { expectedSpki, identifiers, requireBinding, selectChain, maxAlternates })` -- bind the issued certificate to this order, then pick among RFC 8555 sec. 7.4.2 alternate chains. `expectedSpki` (the DER SubjectPublicKeyInfo this order's CSR asked to have certified) and `identifiers` (the order's own identifier array) are what the returned end-entity certificate is checked against: a different key is `acme/certificate-key-mismatch`, a different identifier set `acme/certificate-identifier-mismatch`. Only `dns` and `ip` identifiers map to a name a certificate carries, so an order identifier of another registered type, a certificate `subjectAltName` that is neither a dNSName nor an iPAddress, and a subject common name that is neither a dns name nor a canonical IP address, are each refused as `acme/unsupported-identifier-type` rather than dropped from the comparison. The certificate's alternative names are its identity; its common name is read only where it asserts none. At least one is required (`acme/binding-required`) unless `requireBinding: false`, which waives the requirement to supply material and never the check on material that is supplied. The result reports `boundToKey` / `boundToIdentifiers`. `selectChain({certificate, chain, certificates})` returns the first truthy candidate (primary first, then bounded `Link rel="alternate"` chains, confined to the download's own origin); the result adds `alternates` (the resolved alternate URLs).
 *   - `renewalWindow(certDer, { random, clock, replaced, previous })` -- the RFC 9773 ARI renewal decision: composes `renewalInfo`, selects a uniform-random instant in the suggested window -> { suggestedWindow, selectedTime, renewNow, retryAfterSeconds, explanationURL }. Pass a prior result back as `previous` to REUSE its selectedTime while the CA's window is unchanged (RFC 9773 sec. 4.2), so repeated refreshes keep one stable renewal instant.
 *   - `scheduleRenewal(certDer, { random, shouldStop, renew, maxChecks, maxWait, longTermRetrySeconds, temporaryBaseSeconds })` -- the RFC 9773 sec. 4.1 auto-sleeping renewal loop over `renewalWindow`. It fetches the ARI decision, sleeps via the client `sleep` until the sooner of the selected instant and the Retry-After, and refetches until the window says renew now, resolving `{ reason: "renew-now", decision }`. It stops early with `{ reason: "expired" }` once the certificate passes its notAfter (a client MUST NOT check RenewalInfo after expiry, sec. 4.3), `{ reason: "stopped" }` when `shouldStop()` returns true (the caller's certificate-replaced signal, sec. 4.3), and `{ reason: "budget" }` when the optional `maxChecks` or `maxWait` (seconds) bound is reached. A transient server or transport error retries on the sec. 4.3.3 schedule: a 5xx backs off exponentially from `temporaryBaseSeconds`, and every other transient error waits `longTermRetrySeconds` (default six hours). A caller or certificate error, including a certificate that carries no authorityKeyIdentifier and so cannot produce an ARI certID, rejects. When `renew(decision)` is supplied it is awaited at renew now instead of resolving; returning a new certificate DER reschedules on it, returning nothing resolves `{ reason: "renewed", decision }`.
 * @example
 *   var acme = pki.acme.client("https://acme.example/directory", { accountKey, accountJwk, alg: "ES256", transport });
 *   var acct = await acme.newAccount({ termsOfServiceAgreed: true });
 *   var ord = await acme.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
 */
var _CLIENT_OPTS = {
  accountKey: 1, accountJwk: 1, alg: 1, resignKeys: 1, transport: 1, tls: 1, timeout: 1, maxResponseBytes: 1,
  maxRedirects: 1, maxNonceRetries: 1, maxPolls: 1, maxTotalWait: 1, sleep: 1, clock: 1, proxy: 1,
};
var _METHOD_OPTS = {
  finalize: { csr: 1, identifiers: 1 },
  poll: { maxPolls: 1, maxTotalWait: 1, onRetryAfter: 1 },
  download: { expectedSpki: 1, identifiers: 1, requireBinding: 1, selectChain: 1, maxAlternates: 1 },
  revoke: { certAlg: 1, certJwk: 1, certKey: 1, certificate: 1, reason: 1 },
  keyChange: { newAlg: 1, newJwk: 1, newKey: 1 },
  renewalWindow: { random: 1, clock: 1, replaced: 1, previous: 1 },
  scheduleRenewal: { random: 1, shouldStop: 1, renew: 1, maxChecks: 1, maxWait: 1, longTermRetrySeconds: 1, temporaryBaseSeconds: 1 },
  updateAccount: { contact: 1 },
  listOrders: { maxPages: 1 },
};
function _gateOpts(bag, whitelist, name) {
  bag = guard.identifier.optionsObject(bag, E, "acme/bad-input", "pki.acme " + name + " options");
  guard.identifier.assertKnownKeys(bag, whitelist, E, "acme/bad-input", "unknown " + name + " option ");
  return bag;
}
function _resignKeysOf(raw) {
  if (raw == null) return null;
  if (!_isArrayI(raw) || raw.length === 0) throw E("acme/bad-input", "resignKeys, when set, must be a non-empty array of { alg, key } (RFC 8555 sec. 6.2)");
  var out = [];
  for (var i = 0; i < raw.length; i++) {
    var e = raw[i];
    if (!_isObject(e)) throw E("acme/bad-input", "each resignKeys entry must be { alg: string, key: CryptoKey } (RFC 8555 sec. 6.2); entry " + i + " is not");
    var a = e.alg, k = e.key;
    if (!_isString(a) || !wcEngine.isCryptoKeyLike(k)) throw E("acme/bad-input", "each resignKeys entry must be { alg: string, key: CryptoKey } (RFC 8555 sec. 6.2); entry " + i + " is not");
    out[i] = intrinsic.freeze({ alg: a, key: k });
  }
  return intrinsic.freeze(out);
}
function _chooseResign(resignKeys, serverAlgs) {
  if (!resignKeys || !_isArrayI(serverAlgs)) return null;
  for (var i = 0; i < resignKeys.length; i++) {
    for (var j = 0; j < serverAlgs.length; j++) {
      if (serverAlgs[j] === resignKeys[i].alg) return resignKeys[i];
    }
  }
  return null;
}
function _jwkForAlg(jwk, alg) {
  var out = {};
  var keys = intrinsic.ownKeys(jwk);
  for (var i = 0; i < keys.length; i++) { out[keys[i]] = jwk[keys[i]]; }
  out.alg = alg;
  return out;
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
  var resignKeys = _resignKeysOf(opts.resignKeys);

  var transport = opts.transport;
  if (!transport) {
    var t0 = opts.tls || {};
    var hasAnchors = t0.anchors !== undefined && t0.anchors !== null && !(Array.isArray(t0.anchors) && t0.anchors.length === 0);
    if (!hasAnchors && t0.useSystemStore !== true) throw E("acme/no-trust-anchors", "no explicit trust anchor and tls.useSystemStore not set to true (RFC 8555 sec. 6.1)");
    transport = httpTransport.https({ E: E, errPrefix: "acme" });
  }
  var budgets = {
    tls: _clientTls(opts),
    proxy: httpTransport.snapshotProxy(opts.proxy),
    timeout: guard.limits.cap(opts.timeout, "timeout", CLIENT_DEFAULT_TIMEOUT, { E: E, code: "acme/bad-input", min: 1, max: CLIENT_MAX_TIMEOUT }),
    maxResponseBytes: guard.limits.cap(opts.maxResponseBytes, "maxResponseBytes", constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, { E: E, code: "acme/bad-input", min: 1, max: constants.LIMITS.HTTP_MAX_RESPONSE_BYTES }),
    maxRedirects: guard.limits.cap(opts.maxRedirects, "maxRedirects", 5, { E: E, code: "acme/bad-input", min: 0, max: 32 }),
  };
  var maxNonceRetries = guard.limits.cap(opts.maxNonceRetries, "maxNonceRetries", 1, { E: E, code: "acme/bad-input", min: 0, max: 8 });
  var maxPolls = guard.limits.cap(opts.maxPolls, "maxPolls", 20, { E: E, code: "acme/bad-input", min: 1, max: 1000 });
  var maxTotalWait = guard.limits.cap(opts.maxTotalWait, "maxTotalWait", retryAfter.MAX_RETRY_AFTER_SECONDS, { E: E, code: "acme/bad-input", min: 0, max: retryAfter.MAX_RETRY_AFTER_SECONDS });
  var sleep = typeof opts.sleep === "function" ? opts.sleep : _defaultSleep;
  var clock = typeof opts.clock === "function" ? opts.clock : function () { return Date.now(); };

  var dirCache = null;
  var nonces = [];
  var kid = null;
  var trustedOrigin = new URL(dirUrl).origin;
  function _tlsFor(url) {
    var t = budgets.tls;
    if (new URL(url).origin !== trustedOrigin) {
      t = Object.assign({}, t);
      t.cert = null; t.key = null; t.servername = null;
    }
    return t;
  }

  function _bodyText(res) {
    var b = res.body;
    if (Buffer.isBuffer(b)) return b.toString("utf8");
    if (b == null) return "";
    if (typeof b === "string") return b;
    return guard.bytes.snapshotSource(b, E, "acme/bad-response", "the response body").toString("utf8");
  }
  function _jsonInput(res) {
    var b = res.body;
    if (Buffer.isBuffer(b)) return b;
    if (b == null) return Buffer.alloc(0);
    if (typeof b === "string") return Buffer.from(b, "utf8");
    return guard.bytes.snapshotSource(b, E, "acme/bad-response", "the response body");
  }
  function _requireKid() { if (!kid) throw E("acme/no-account", "no account is set -- call newAccount before an authenticated request (RFC 8555 sec. 6.2)"); return kid; }
  function _harvestNonce(v) {
    if (typeof v !== "string" || v === "") return;
    try { jose.base64url.decode(v); }
    catch (_e) { return; }
    while (nonces.length >= CLIENT_MAX_NONCE_POOL) nonces.shift();
    nonces.push(v);
  }
  function _isProblem(res) { return intrinsic.stringIndexOf(_lower(String(res.headers["content-type"] || "")), "application/problem+json") !== -1; }
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

  function _send(method, url, headers, body) { return _sendFollowing(method, url, headers, body, 0); }
  function _sendFollowing(method, url, headers, body, redirects) {
    var reqHeaders = Object.assign({ "user-agent": CLIENT_USER_AGENT }, headers || {});
    return guard.async.deferred(function () {
      return guard.async.awaited(transport({ method: method, url: url, headers: reqHeaders, body: body, tls: _tlsFor(url), proxy: budgets.proxy, timeout: budgets.timeout, maxResponseBytes: budgets.maxResponseBytes }), E, "acme/bad-input", "opts.transport");
    }).then(function (res) {
      res = res || {};
      var h = {};
      Object.keys(res.headers || {}).forEach(function (k) { h[k.toLowerCase()] = res.headers[k]; });
      var blen = res.body == null ? 0 : (typeof res.body === "string" ? Buffer.byteLength(res.body, "utf8")
        : (Buffer.isBuffer(res.body) ? guard.bytes.lengthOf(res.body) : guard.bytes.lengthOf(guard.bytes.source(res.body, E, "acme/bad-response", "the response body"))));
      if (blen > budgets.maxResponseBytes) throw E("acme/response-too-large", "the response body (" + blen + " bytes) exceeds the " + budgets.maxResponseBytes + "-byte cap");
      if ((method === "GET" || method === "HEAD") && res.status >= 300 && res.status < 400) {
        if (redirects >= budgets.maxRedirects) throw E("acme/too-many-redirects", "the redirect budget of " + budgets.maxRedirects + " was exceeded");
        if (!_isString(h["location"])) throw E("acme/bad-redirect", "a " + res.status + " redirect carried no Location header (RFC 7231 sec. 6.4)");
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
      return _clientUrl(dir[name]);
    });
  }
  function _takeNonce() {
    if (nonces.length) return Promise.resolve(nonces.pop());
    var before = nonces.length;
    return _resource("newNonce").then(function (nn) { return _send("HEAD", nn, {}, null); }).then(function (res) {
      if (res.status !== 200 && res.status !== 204) { nonces.length = before; throw _serverProblem(res); }
      if (!nonces.length) throw E("acme/no-nonce", "the server did not provide a usable Replay-Nonce (RFC 8555 sec. 7.2)");
      return nonces.pop();
    });
  }

  function _postJws(url, makeJws, accept, okStatuses, allowResign) {
    var ok = okStatuses || [200];
    var attempt = 0;
    var resignAttempt = 0;
    function once(override) {
      return _takeNonce().then(function (nonce) { return makeJws(nonce, override); }).then(function (jws) {
        return _send("POST", url, { "content-type": "application/jose+json", "accept": accept || "application/json" }, JSON.stringify(jws));
      }).then(function (res) {
        if (res.status >= 300 || _isProblem(res)) {
          if (_isProblem(res)) {
            var prob = null;
            try { prob = jose.parseJson(_jsonInput(res)); }
            catch (_e) { /* allow:swallow-unverified a non-JSON problem body is not a badNonce; prob stays null, falling through to the typed acme/server-problem throw */ }
            if (prob && typeof prob.type === "string" && _endsWith(prob.type, ":badNonce") && attempt < maxNonceRetries) { attempt++; return once(override); }
            if (allowResign && resignKeys && prob && typeof prob.type === "string" && _endsWith(prob.type, ":badSignatureAlgorithm") && resignAttempt < 1) {
              var pick = _chooseResign(resignKeys, prob.algorithms);
              if (pick) { resignAttempt++; return once(pick); }
            }
          }
          throw _serverProblem(res);
        }
        if (ok.indexOf(res.status) === -1) throw E("acme/unexpected-status", "an ACME POST returned an unexpected status " + res.status + " (expected " + ok.join("/") + ", RFC 8555)");
        return res;
      });
    }
    return once();
  }
  function _post(url, builder, extra, mode, accept, okStatuses) {
    return _postJws(url, function (nonce, override) {
      var base = Object.assign({}, extra || {}, { key: override ? override.key : accountKey, alg: override ? override.alg : alg, nonce: nonce, url: url });
      if (mode === "jwk") base.jwk = override ? _jwkForAlg(accountJwk, override.alg) : accountJwk; else base.kid = _requireKid();
      return builder(base);
    }, accept, okStatuses, true);
  }
  function _postAsGet(url) { return _post(url, postAsGet, null, "kid"); }

  function _directory() { return _getDirectory(); }

  function _newAccount(payloadOpts) {
    return _resource("newAccount").then(function (url) {
      return _post(url, newAccount, payloadOpts || {}, "jwk", undefined, [200, 201]).then(function (res) {
        var loc = res.headers["location"];
        if (!_isString(loc)) throw E("acme/no-account-url", "newAccount did not return an account URL in a Location header (RFC 8555 sec. 7.3)");
        var account = validate("account", _json(res));
        kid = _resolveLocation(loc, url);
        return { account: account, url: kid };
      });
    });
  }
  function _newOrder(payloadOpts) {
    return _resource("newOrder").then(function (url) {
      return _post(url, newOrder, payloadOpts || {}, "kid", undefined, [201]).then(function (res) {
        var loc = res.headers["location"];
        if (!_isString(loc)) throw E("acme/no-order-url", "newOrder did not return an order URL in a Location header (RFC 8555 sec. 7.4)");
        return { order: validate("order", _json(res)), url: _resolveLocation(loc, url) };
      });
    });
  }
  function _newAuthz(identifier) {
    return Promise.resolve().then(function () {
    var canon = _validateIdentifier(identifier);
    return _resource("newAuthz").then(function (url) {
      return _post(url, newAuthz, { identifier: canon }, "kid", undefined, [200, 201]).then(function (res) {
        var loc = res.headers["location"];
        if (!_isString(loc)) throw E("acme/no-authorization-url", "newAuthz did not return an authorization URL in a Location header (RFC 8555 sec. 7.4.1)");
        var authz = validate("authorization", _json(res));
        if (!authz.identifier || authz.identifier.type !== canon.type || authz.identifier.value !== canon.value || authz.wildcard === true) throw E("acme/identifier-mismatch", "the returned authorization does not match the requested identifier (RFC 8555 sec. 7.4.1)");
        if (authz.status !== "pending" && authz.status !== "valid") throw E("acme/unexpected-authorization-status", "newAuthz returned an authorization that is neither pending nor already valid (status " + JSON.stringify(authz.status) + "); RFC 8555 sec. 7.4.1");
        return { authorization: authz, url: _resolveLocation(loc, url) };
      });
    });
    });
  }
  function _getOrder(url) { return _promised(function () { return _postAsGet(_clientUrl(url)).then(function (res) { return validate("order", _json(res)); }); }); }
  function _getAuthorization(url) { return _promised(function () { return _postAsGet(_clientUrl(url)).then(function (res) { return validate("authorization", _json(res)); }); }); }
  function _getChallenge(url) { return _promised(function () { return _postAsGet(_clientUrl(url)).then(function (res) { return validate("challenge", _json(res)); }); }); }
  function _respondToChallenge(url) { return _promised(function () { return _post(_clientUrl(url), challengeResponse, null, "kid").then(function (res) { return validate("challenge", _json(res)); }); }); }

  function _finalize(order, o) { return _promised(function () { return _finalizeBody(order, o); }); }
  function _finalizeBody(order, o) {
    o = _gateOpts(o, _METHOD_OPTS.finalize, "finalize");
    if (!_isObject(order) || !_isString(order.finalize)) throw E("acme/bad-input", "finalize requires the order object with its finalize URL");
    if (!Array.isArray(order.identifiers)) throw E("acme/bad-input", "finalize requires the order's identifiers to enforce the RFC 8555 sec. 7.4 CSR-set match");
    return _post(_clientUrl(order.finalize), finalize, { csr: o.csr, identifiers: order.identifiers, accountJwk: accountJwk }, "kid").then(function (res) { return validate("order", _json(res)); });
  }

  function _poll(kind, url, budget) {
    var capPolls, capWait;
    try {
      budget = _gateOpts(budget, _METHOD_OPTS.poll, "poll");
      capPolls = budget.maxPolls != null ? guard.limits.cap(budget.maxPolls, "maxPolls", maxPolls, { E: E, code: "acme/bad-input", min: 1, max: 1000 }) : maxPolls;
      capWait = budget.maxTotalWait != null ? guard.limits.cap(budget.maxTotalWait, "maxTotalWait", maxTotalWait, { E: E, code: "acme/bad-input", min: 0, max: retryAfter.MAX_RETRY_AFTER_SECONDS }) : maxTotalWait;
      url = _clientUrl(url);
    } catch (e) { return Promise.reject(e); }
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

  function _readCertChain(res) {
    var ctToken = String(res.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (ctToken !== "application/pem-certificate-chain") throw E("acme/bad-certificate-chain", "the certificate download returned an unexpected media type " + JSON.stringify(ctToken) + " (expected application/pem-certificate-chain, RFC 8555 sec. 7.4.2)");
    var chain = _splitPemChain(_bodyText(res));
    return { certificate: chain[0], chain: chain.slice(1), certificates: chain };
  }
  function _fetchCertChain(url) { return _post(url, postAsGet, null, "kid", "application/pem-certificate-chain").then(_readCertChain); }

  function _bindingSpec(opts) {
    var spki = opts.expectedSpki, ids = opts.identifiers, req = opts.requireBinding;
    if (spki !== undefined) {
      if (!guard.bytes.isByteSource(spki)) throw E("acme/bad-input", "downloadCertificate opts.expectedSpki must be a DER SubjectPublicKeyInfo BufferSource");
      spki = guard.bytes.snapshotSource(spki, AcmeError, "acme/bad-input", "downloadCertificate expectedSpki");
    }
    if (ids !== undefined) {
      if (!_isArrayI(ids) || ids.length === 0) throw E("acme/bad-input", "downloadCertificate opts.identifiers must be the non-empty order identifier array");
      ids = _mapI(ids, _validateOrderIdentifier);
    }
    if (req !== undefined && typeof req !== "boolean") throw E("acme/bad-input", "downloadCertificate opts.requireBinding must be a boolean");
    var require_ = req === undefined ? true : req;
    if (require_ && spki === undefined && ids === undefined) {
      throw E("acme/binding-required",
        "downloadCertificate needs the material that binds the issued certificate to this order -- " +
        "opts.expectedSpki (the DER SubjectPublicKeyInfo the CSR asked to have certified) and/or " +
        "opts.identifiers (the order's identifiers). Pass opts.requireBinding false to download without " +
        "either, in which case the result reports boundToKey and boundToIdentifiers false");
    }
    return { spki: spki, ids: ids, require: require_ };
  }

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
    return Promise.resolve().then(function () {
      opts = _gateOpts(opts, _METHOD_OPTS.download, "downloadCertificate");
      var select = opts.selectChain;
      if (select !== undefined && typeof select !== "function") throw E("acme/bad-input", "downloadCertificate opts.selectChain must be a function");
      var maxAlt = guard.limits.cap(opts.maxAlternates, "maxAlternates", DEFAULT_MAX_ALTERNATES, { E: E, code: "acme/bad-input", min: 0, max: 64 });
      var binding = _bindingSpec(opts);
      var dlUrl = _clientUrl(url);
      return _post(dlUrl, postAsGet, null, "kid", "application/pem-certificate-chain").then(function (res) {
        var primary = _readCertChain(res);
        var alternates = [], linkError = null;
        try { alternates = _parseLinkAlternates(res.headers, dlUrl); }
        catch (e) { linkError = e; }
        _assertCertBinding(primary.certificate, binding);
        function result(cand) {
          _assertCertBinding(cand.certificate, binding);
          return { certificate: cand.certificate, chain: cand.chain, certificates: cand.certificates, alternates: alternates,
            boundToKey: binding.spki !== undefined, boundToIdentifiers: binding.ids !== undefined };
        }
        if (!select) return result(primary);
        return Promise.resolve(select(primary)).then(function (primaryMatch) {
          if (primaryMatch) return result(primary);
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
    return _promised(function () {
      o = _gateOpts(o, _METHOD_OPTS.revoke, "revokeCert");
      if (!guard.bytes.isByteSource(o.certificate)) throw E("acme/bad-input", "revokeCert requires a DER certificate BufferSource (opts.certificate)");
      var certKeyMode = o.certKey != null || _isObject(o.certJwk) || o.certAlg != null;
      if (certKeyMode && !(o.certKey != null && _isObject(o.certJwk) && _isString(o.certAlg))) throw E("acme/bad-input", "revokeCert certificate-key mode requires certKey, certJwk, AND certAlg together, or none (RFC 8555 sec. 7.6)");
      var extra = { certificate: o.certificate };
      if (o.reason !== undefined) extra.reason = o.reason;
      return _resource("revokeCert").then(function (url) {
        if (certKeyMode) {
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

  function _updateAccount(o) {
    return _promised(function () {
      o = guard.identifier.optionsObject(o, E, "acme/bad-input", "pki.acme updateAccount options");
      if (o.status !== undefined) throw E("acme/bad-input", "updateAccount cannot change the account status; use deactivateAccount (RFC 8555 sec. 7.3.6 is the only client-settable status)");
      if (o.termsOfServiceAgreed !== undefined) throw E("acme/bad-input", "the server MUST ignore a termsOfServiceAgreed update to the account (RFC 8555 sec. 7.3.2); it is set at account creation, and a changed-terms CA answers with a userActionRequired problem (sec. 7.3.3) directing a human to the terms URL");
      if (o.orders !== undefined) throw E("acme/bad-input", "the account orders URL is server-assigned and cannot be updated (RFC 8555 sec. 7.3.2)");
      if (o.externalAccountBinding !== undefined) throw E("acme/bad-input", "externalAccountBinding is not updateable by the client (RFC 8555 sec. 7.1.2 / 7.3.4)");
      guard.identifier.assertKnownKeys(o, _METHOD_OPTS.updateAccount, E, "acme/bad-input", "unknown updateAccount option ");
      var account = _requireKid();
      return _post(account, updateAccount, { contact: o.contact }, "kid").then(function (res) { return validate("account", _json(res)); });
    });
  }

  function _listOrders(ordersUrl, o) {
    return _promised(function () {
      o = _gateOpts(o, _METHOD_OPTS.listOrders, "listOrders");
      var maxPages = guard.limits.cap(o.maxPages, "maxPages", 50, { E: E, code: "acme/bad-input", min: 1 });
      var out = [], seen = intrinsic.create(null), pages = 0, truncated = false;
      function fetchPage(pageUrl) {
        seen[_dedupKey(pageUrl)] = true;
        return _postAsGet(pageUrl).then(function (res) {
          pages += 1;
          var body = validate("ordersList", _json(res));
          for (var i = 0; i < body.orders.length; i++) _push(out, body.orders[i]);
          var next = _parseLinkNext(res.headers, pageUrl);
          if (next == null) return;
          var nextUrl = _clientUrl(next);
          if (seen[_dedupKey(nextUrl)]) return;
          if (pages >= maxPages) { truncated = true; return; }
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
        accountKey = o.newKey; accountJwk = o.newJwk; alg = o.newAlg;
        resignKeys = null;
        var acct = null;
        if (_bodyText(res).trim() !== "") {
          try { acct = validate("account", _json(res)); }
          catch (_e) { acct = null; }
        }
        return { account: acct, url: account };
      });
    });
  }

  function _renewalInfo(certDer, clockFn, retryAfterCapSeconds) {
    return _promised(function () { return _renewalInfoBody(certDer, clockFn, retryAfterCapSeconds); });
  }
  function _renewalInfoBody(certDer, clockFn, retryAfterCapSeconds) {
    if (!guard.bytes.isByteSource(certDer)) throw E("acme/bad-input", "renewalInfo requires a DER certificate BufferSource");
    var _rawClk = typeof clockFn === "function" ? clockFn : clock;
    function clk() { var t = _rawClk(); if (typeof t !== "number" || !isFinite(t)) throw E("acme/bad-input", "the renewalInfo clock returned a non-finite value"); return t; }
    var notAfterMs = guard.time.instantOf(x509.parse(certDer).validity.notAfter);
    // allow:nan-date-comparison-unguarded -- notAfter is a codec-parsed cert date (asn1 readTime rejects a NaN instant).
    if (clk() > notAfterMs) throw E("acme/certificate-expired", "the certificate is already past its notAfter; a client MUST NOT check RenewalInfo after it has expired (RFC 9773 sec. 4.3)");
    var certId = ariCertId(certDer);
    return _resource("renewalInfo").then(function (base) {
      // allow:nan-date-comparison-unguarded -- notAfterMs is a codec-parsed cert date; clk() is validated finite.
      if (clk() > notAfterMs) throw E("acme/certificate-expired", "the certificate expired before the RenewalInfo request could be issued; a client MUST NOT check RenewalInfo after expiry (RFC 9773 sec. 4.3)");
      var u = new URL(base);
      u.pathname = _stripTrailingSlash(u.pathname) + "/" + certId;
      var url = _clientUrl(u.href);
      return _send("GET", url, { accept: "application/json" }, null).then(function (res) {
        if (res.status !== 200) throw _serverProblem(res);
        var obj = validateRenewalInfo(_json(res));
        var ra = res.headers["retry-after"];
        var retryAfterSeconds = null;
        if (typeof ra === "string" && ra.trim() !== "") {
          var raOpts = { now: clk(), E: E, code: "acme/bad-retry-after" };
          if (typeof retryAfterCapSeconds === "number") { raOpts.cap = retryAfterCapSeconds; raOpts.lenient = true; }
          retryAfterSeconds = retryAfter.parse(ra, raOpts).retryAfterSeconds;
        }
        return { renewalInfo: obj, retryAfterSeconds: retryAfterSeconds };
      });
    });
  }

  function _renewalWindow(certDer, o) {
    return Promise.resolve().then(function () {
      o = _gateOpts(o, _METHOD_OPTS.renewalWindow, "renewalWindow");
      if (!guard.bytes.isByteSource(certDer)) throw E("acme/bad-input", "renewalWindow requires a DER certificate BufferSource");
      if (o.random !== undefined && typeof o.random !== "function") throw E("acme/bad-input", "renewalWindow opts.random must be a function returning a number in [0, 1]");
      if (o.clock !== undefined && typeof o.clock !== "function") throw E("acme/bad-input", "renewalWindow opts.clock must be a function returning epoch milliseconds");
      if (o.replaced !== undefined && typeof o.replaced !== "boolean") throw E("acme/bad-input", "renewalWindow opts.replaced must be a boolean");
      if (o.previous !== undefined && !_isObject(o.previous)) throw E("acme/bad-input", "renewalWindow opts.previous must be a prior renewalWindow result object");
      var _clk = typeof o.clock === "function" ? o.clock : clock;
      function clk() { var t = _clk(); if (typeof t !== "number" || !isFinite(t)) throw E("acme/bad-input", "the renewalWindow clock returned a non-finite value"); return t; }
      var notAfter = x509.parse(certDer).validity.notAfter;
      var now = clk();
      // allow:nan-date-comparison-unguarded -- notAfter is a codec-parsed cert date (asn1 readTime rejects a NaN
      if (now > guard.time.instantOf(notAfter)) throw E("acme/certificate-expired", "the certificate is already past its notAfter; there is nothing to renew (RFC 9773 sec. 4.3)");
      if (o.replaced === true) throw E("acme/certificate-replaced", "the caller asserts this certificate has already been replaced (RFC 9773 sec. 4.3)");
      return _renewalInfo(certDer, clk, RENEWAL_RETRY_MAX_SECONDS).then(function (ri) {
        var w = ri.renewalInfo.suggestedWindow;
        var startMs = Date.parse(w.start), endMs = Date.parse(w.end);
        var notAfterMs = guard.time.instantOf(notAfter);
        var effEnd = Math.min(endMs, notAfterMs), effStart = Math.min(startMs, effEnd);
        var pw = o.previous && _isObject(o.previous.suggestedWindow) ? o.previous.suggestedWindow : null;
        var selectedMs;
        if (pw && pw.start === w.start && pw.end === w.end && _isString(o.previous.selectedTime)) {
          var prevMs = Date.parse(o.previous.selectedTime);
          if (!isFinite(prevMs)) throw E("acme/bad-input", "renewalWindow opts.previous.selectedTime must be an RFC 3339 date-time");
          selectedMs = Math.max(effStart, Math.min(effEnd, prevMs));
        } else {
          var draw;
          if (o.random) { try { draw = o.random(); } catch (e) { throw E("acme/bad-input", "the renewalWindow random callback threw", e); } }
          else { draw = _defaultRandom(); }
          if (typeof draw !== "number" || !(draw >= 0 && draw <= 1)) throw E("acme/bad-input", "renewalWindow opts.random must return a number in [0, 1]");
          selectedMs = Math.round(effStart + draw * (effEnd - effStart));
        }
        var retryAfterSeconds = ri.retryAfterSeconds == null ? RENEWAL_RETRY_DEFAULT_SECONDS :
          Math.max(RENEWAL_RETRY_MIN_SECONDS, Math.min(RENEWAL_RETRY_MAX_SECONDS, ri.retryAfterSeconds));
        return {
          suggestedWindow: w,
          selectedTime: new Date(selectedMs).toISOString(),
          renewNow: selectedMs <= clk() || selectedMs >= notAfterMs,
          retryAfterSeconds: retryAfterSeconds,
          explanationURL: _isString(ri.renewalInfo.explanationURL) ? ri.renewalInfo.explanationURL : null,
        };
      });
    });
  }

  function _scheduleRenewal(certDer, o) {
    return _resolve(Promise).then(function () {
      o = _gateOpts(o, _METHOD_OPTS.scheduleRenewal, "scheduleRenewal");
      if (!guard.bytes.isByteSource(certDer)) throw E("acme/bad-input", "scheduleRenewal requires a DER certificate BufferSource");
      if (o.random !== undefined && typeof o.random !== "function") throw E("acme/bad-input", "scheduleRenewal opts.random must be a function returning a number in [0, 1]");
      if (o.shouldStop !== undefined && typeof o.shouldStop !== "function") throw E("acme/bad-input", "scheduleRenewal opts.shouldStop must be a function returning a boolean");
      if (o.renew !== undefined && typeof o.renew !== "function") throw E("acme/bad-input", "scheduleRenewal opts.renew must be an async function (decision) -> newCertDer | void");
      function optCount(v, name) {
        if (v === undefined) return null;
        if (typeof v !== "number" || !intrinsic.isFinite(v) || v < 1 || intrinsic.floor(v) !== v) throw E("acme/bad-input", "scheduleRenewal opts." + name + " must be a positive integer");
        return v;
      }
      var maxChecks = optCount(o.maxChecks, "maxChecks");
      var _mw = optCount(o.maxWait, "maxWait");
      var maxWaitMs = _mw == null ? null : constants.TIME.seconds(_mw);
      var longTermMs = constants.TIME.seconds(guard.limits.cap(o.longTermRetrySeconds, "longTermRetrySeconds", RENEWAL_RETRY_DEFAULT_SECONDS, { E: E, code: "acme/bad-input", min: RENEWAL_RETRY_MIN_SECONDS, max: RENEWAL_RETRY_MAX_SECONDS }));
      var tempBaseMs = constants.TIME.seconds(guard.limits.cap(o.temporaryBaseSeconds, "temporaryBaseSeconds", RENEWAL_RETRY_MIN_SECONDS, { E: E, code: "acme/bad-input", min: 1, max: RENEWAL_RETRY_MAX_SECONDS }));
      function _clk() { var t = clock(); if (typeof t !== "number" || !intrinsic.isFinite(t)) throw E("acme/bad-input", "the scheduleRenewal clock returned a non-finite value"); return t; }
      var startMs = _clk(), checks = 0, tempBackoffMs = tempBaseMs, previous = null;
      var cert = guard.bytes.snapshotSource(certDer, AcmeError, "acme/bad-input", "the scheduleRenewal certificate");
      function _boundedSleep(ms) { if (maxWaitMs != null) { ms = intrinsic.min(ms, intrinsic.max(0, maxWaitMs - (_clk() - startMs))); } return _resolve(Promise, sleep(ms)); }
      function _sleepThenLoop(ms) { return (maxChecks != null && checks >= maxChecks) ? { reason: "budget" } : _boundedSleep(ms).then(loop); }
      function _stop() {
        if (!o.shouldStop) return false;
        var s;
        try { s = o.shouldStop(); }
        catch (e) { throw E("acme/bad-input", "the scheduleRenewal shouldStop callback threw", e); }
        if (typeof s !== "boolean") throw E("acme/bad-input", "the scheduleRenewal shouldStop callback must return a boolean");
        return s;
      }

      function loop() {
        if (_stop()) return { reason: "stopped" };
        if (maxChecks != null && checks >= maxChecks) return { reason: "budget" };
        if (maxWaitMs != null && (_clk() - startMs) >= maxWaitMs) return { reason: "budget" };
        checks += 1;
        return _renewalWindow(cert, { random: o.random, clock: clock, previous: previous == null ? undefined : previous }).then(function (decision) {
          if (_stop()) return { reason: "stopped" };
          if (maxWaitMs != null && (_clk() - startMs) >= maxWaitMs) return { reason: "budget" };
          tempBackoffMs = tempBaseMs;
          if (decision.renewNow) {
            if (o.renew) {
              var _rc;
              try { _rc = o.renew(decision); }
              catch (e) { throw E("acme/bad-input", "the scheduleRenewal renew callback threw", e); }
              return _resolve(Promise, _rc).then(function (next) {
                if (next == null) return { reason: "renewed", decision: decision };
                if (!guard.bytes.isByteSource(next)) throw E("acme/bad-input", "scheduleRenewal opts.renew must return a DER certificate BufferSource or a nullish value");
                cert = guard.bytes.snapshotSource(next, AcmeError, "acme/bad-input", "the scheduleRenewal renewed certificate"); previous = null; return loop();
              }, function (e) { throw E("acme/bad-input", "the scheduleRenewal renew callback rejected", e); });
            }
            return { reason: "renew-now", decision: decision };
          }
          previous = decision;
          var untilSelected = guard.time.instantOf(rfc3339.parse(decision.selectedTime, E, "acme/bad-input", "the renewalWindow selected time")) - _clk();
          var retryMs = constants.TIME.seconds(decision.retryAfterSeconds);
          return _sleepThenLoop(intrinsic.max(0, intrinsic.min(untilSelected, retryMs)));
        }, function (err) {
          var code = err && err.code;
          if (code === "acme/certificate-expired") return { reason: "expired" };
          if (code === "acme/certificate-replaced") return { reason: "replaced" };
          if (code === "acme/bad-input" || code === "acme/bad-certid" || code === "acme/resource-unavailable" || (typeof code === "string" && intrinsic.stringIndexOf(code, "x509/") === 0)) throw err;
          var temporary = code === "acme/server-problem" && typeof err.httpStatus === "number" && err.httpStatus >= 500;
          var waitMs;
          if (temporary) { waitMs = intrinsic.min(tempBackoffMs, longTermMs); tempBackoffMs = tempBackoffMs * 2; }
          else { tempBackoffMs = tempBaseMs; waitMs = longTermMs; }
          return _sleepThenLoop(waitMs);
        });
      }
      return loop();
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
    scheduleRenewal: _scheduleRenewal,
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
  ariCertId: ariCertId,
  parseAriCertId: parseAriCertId,
  jose: jose,
};
