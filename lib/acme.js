// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.acme
 * @nav        Protocols
 * @title      ACME
 * @order      20
 * @slug       acme
 *
 * @intro
 *   The RFC 8555 ACME message layer (updated by RFC 8737 tls-alpn-01, RFC 8738
 *   IP identifiers, and RFC 9773 ARI) -- object validators, request builders,
 *   challenge computations, and the ARI certID codec over the `pki.jose` JWS
 *   envelope. This is a MESSAGE LAYER, not an HTTP client: it owns the JWS
 *   construction/verification, the resource-object validation (closed status
 *   enums, conditional-required fields, immutable arrays), the three RFC 8555
 *   sec. 7.1.6 state machines, the challenge computations (key authorization,
 *   http-01, dns-01, tls-alpn-01), the identifier validators (`dns` / `ip` /
 *   wildcard), and the ARI certID -- over an injectable transport.
 *
 *   Every resource object is validated by a declarative spec table (the JSON
 *   analog of the ASN.1 schema engine): one definition per surface drives both
 *   `validate(obj)` and the builders. Unknown fields are tolerated (ignored,
 *   never reflected); unknown challenge types are surfaced raw. Where ACME output
 *   re-enters the DER world -- the finalize CSR, the downloaded certificate
 *   chain, the revokeCert payload, the ARI inputs -- it routes through the shipped
 *   `pki.schema.csr` / `pki.schema.x509` parsers, so no new DER detector appears
 *   and the format-orchestrator's mutual-exclusion proof is untouched.
 *
 * @card
 *   RFC 8555 / 8737 / 8738 / 9773 ACME message layer: object validators, the
 *   three state machines, request builders, http-01 / dns-01 / tls-alpn-01
 *   challenge computations, and the ARI certID -- over pki.jose, transport-injectable.
 */

var jose = require("./jose");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var csr = require("./schema-csr");
var pkix = require("./schema-pkix");
var constants = require("./constants");
var rfc3339 = require("./rfc3339");
var subtle = require("./webcrypto").webcrypto.subtle;
var frameworkError = require("./framework-error");

var AcmeError = frameworkError.AcmeError;
function E(code, message, cause) { return new AcmeError(code, message, cause); }

// ---- helpers -------------------------------------------------------------

function _isObject(v) { return v && typeof v === "object" && !Array.isArray(v); }
function _isString(v) { return typeof v === "string"; }
// RFC 3339 date-time validity (grammar + calendar) lives in the shared lib/rfc3339.js primitive so a
// downstream expiry / renewal-window comparison never runs on an impossible instant (month 13, a :60
// leap second, a rolled-over value). pki.ct's log-list window parse composes the same primitive.
function _isRfc3339(v) { return rfc3339.isValid(v); }
// A URL string: an absolute http(s) URI with a real host (RFC 3986). ACME URLs are
// server-provided endpoints downstream transport will trust, so they are PARSED
// (not prefix-matched) -- a malformed value like "https://[" or a hostless
// "http://" is rejected, not accepted by a loose regex.
function _isUrl(v) {
  // Prefilter the exact authority form with no whitespace BEFORE parsing: new URL()
  // silently repairs " https://.." (trim) and "https:host/.." (insert //), and the
  // ORIGINAL string is what gets copied into a protected `url` field, so a repaired
  // value must be rejected here rather than accepted and mismatched at transport time.
  if (!_isString(v) || !/^https?:\/\/[^\s]+$/.test(v)) return false;
  var u;
  // A parse failure IS the "not a URL" verdict for this boolean predicate -- there
  // is no PkiError here to thread a cause into, so the error is intentionally ignored.
  try { u = new URL(v); }
  catch (_e) { return false; }
  return (u.protocol === "http:" || u.protocol === "https:") && u.hostname.length > 0;
}
// A URI string with any RFC 3986 scheme (mailto:, tel:, http(s):, ...). An account
// `contact` is a URI, most commonly `mailto:` (RFC 8555 sec. 7.1.2 / RFC 6068), so
// it must NOT be narrowed to http(s); the strict mailto hygiene lives in the builder.
function _isUriString(v) { return _isString(v) && /^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]+$/.test(v); }

// ---- resource object specs (RFC 8555 sec. 7.1.x) -------------------------

// Each field: { name, type, required?, requiredWhen?(obj), enum?, elemType? }.
// type: "string" | "url" | "rfc3339" | "boolean" | "object" | "array" | "any".
// The walker validates presence/shape ONLY; unknown fields are ignored (never
// reflected). requiredWhen is the conditional-required rule (sec. 7.1.3 expires).
// The assigned RFC 5280 sec. 5.3.1 CRLReason values (0-6, 8-10). Value 7 is
// unassigned, so a revokeCert reason of 7 is rejected rather than sent.
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
    { name: "challenges", type: "array", required: true, minItems: 1, elemType: "challenge" },
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
};

function _checkType(kind, field, value) {
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
      if (field.minItems && value.length < field.minItems) return "must have at least " + field.minItems + " element(s)";
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
function _codeSlug(kind) { return kind.replace(/([A-Z])/g, "-$1").toLowerCase(); }

// Validate an object against a spec table. Returns the object; throws acme/*.
function _validate(kind, obj) {
  if (!_isObject(obj)) throw E("acme/bad-" + _codeSlug(kind), "an ACME " + kind + " must be a JSON object");
  var spec = SPECS[kind];
  for (var f = 0; f < spec.length; f++) {
    var field = spec[f];
    var present = Object.prototype.hasOwnProperty.call(obj, field.name);
    var required = field.required || (field.requiredWhen && field.requiredWhen(obj));
    if (!present) {
      if (required) throw E("acme/missing-field", "an ACME " + kind + " is missing the required field " + JSON.stringify(field.name));
      continue;
    }
    if (field.enum && field.enum.indexOf(obj[field.name]) === -1) {
      throw E("acme/bad-status", "the " + kind + " " + field.name + " " + JSON.stringify(obj[field.name]) + " is not a recognized value");
    }
    var err = _checkType(kind, field, obj[field.name]);
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
  if (!_isObject(id) || !_isString(id.type) || !_isString(id.value)) throw E("acme/bad-identifier", "an identifier must be { type, value } strings");
  if (id.type === "dns") {
    if (id.value.indexOf("*.") === 0) throw E("acme/bad-identifier", "a wildcard *. value is not permitted in an authorization identifier (RFC 8555 sec. 7.1.4)");
    _assertDnsName(id.value);
  } else if (id.type === "ip") {
    _assertIpAddress(id.value);
  }
  // An unrecognized identifier type is surfaced raw (a server may add types).
  return id;
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
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(l)) throw E("acme/bad-identifier", "a dns label must be lowercase LDH ASCII (A-label): " + JSON.stringify(l));
    if (l.indexOf("xn--") === 0 && !/^xn--[a-z0-9]+(-[a-z0-9]+)*$/.test(l)) throw E("acme/bad-identifier", "a malformed xn-- A-label: " + JSON.stringify(l));
  }
}

// An IP address in canonical text (RFC 8738 sec. 3): IPv4 dotted-decimal with no
// leading zeros, or IPv6 in the RFC 5952 sec. 4 compressed lowercase form. The
// only accepted form is the one that round-trips byte-identically -- an ambiguous
// value (leading zeros, uppercase hex, an uncompressed run) is rejected, never
// normalized-and-guessed.
function _assertIpAddress(value) {
  if (!_isString(value)) throw E("acme/bad-identifier", "an ip identifier value must be a string");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    var parts = value.split(".");
    for (var i = 0; i < 4; i++) {
      if (!/^(0|[1-9]\d{0,2})$/.test(parts[i]) || parseInt(parts[i], 10) > 255) throw E("acme/bad-identifier", "an ip identifier IPv4 octet is out of range or non-canonical: " + JSON.stringify(value));
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
// (lowercase, no leading zeros, the longest zero-run compressed with `::` -- the
// leftmost when tied, never a single 0 group). Returns null on a malformed input.
function _canonicalizeIpv6(value) {
  var groups;
  if (value.indexOf("::") !== -1) {
    if (value.indexOf("::") !== value.lastIndexOf("::")) return null;   // only one ::
    var halves = value.split("::");
    var left = halves[0] ? halves[0].split(":") : [];
    var right = halves[1] ? halves[1].split(":") : [];
    var fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    groups = left.concat(new Array(fill).fill("0")).concat(right);
  } else {
    groups = value.split(":");
  }
  if (groups.length !== 8) return null;
  var nums = [];
  for (var i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/.test(groups[i])) return null;
    nums.push(parseInt(groups[i], 16));
  }
  var hex = nums.map(function (n) { return n.toString(16); });
  // Longest run of zero groups (>= 2) -> "::"; leftmost on a tie.
  var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (var g = 0; g < 8; g++) {
    if (nums[g] === 0) { if (curStart === -1) curStart = g; curLen++; if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; } }
    else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) return hex.join(":");
  var head = hex.slice(0, bestStart).join(":");
  var tail = hex.slice(bestStart + bestLen).join(":");
  return head + "::" + tail;
}

// ---- state machines (RFC 8555 sec. 7.1.6) --------------------------------

// Legal transitions as data. An observed transition outside the set is an
// illegal server transition the client fails closed on (acme/bad-transition).
var TRANSITIONS = {
  challenge:     { pending: ["processing", "valid", "invalid"], processing: ["processing", "valid", "invalid"] },
  authorization: { pending: ["valid", "invalid"], valid: ["expired", "deactivated", "revoked"] },
  order:         { pending: ["ready", "invalid"], ready: ["processing", "valid", "invalid"], processing: ["valid", "invalid"] },
};

/**
 * @primitive  pki.acme.assertTransition
 * @signature  pki.acme.assertTransition(kind, from, to) -> void
 * @since      0.1.25
 * @status     experimental
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
 * @status     experimental
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
  if (Object.prototype.hasOwnProperty.call(obj, "identifier")) throw E("acme/bad-problem", "a top-level problem document must not carry an identifier (RFC 8555 sec. 6.7.1)");
  if (!_isString(obj.type) || obj.type.indexOf(ERROR_NAMESPACE) !== 0) throw E("acme/bad-problem", "an ACME problem type must be in the " + ERROR_NAMESPACE + " namespace (RFC 8555 sec. 6.7)");
  if (Object.prototype.hasOwnProperty.call(obj, "subproblems")) {
    if (!Array.isArray(obj.subproblems)) throw E("acme/bad-problem", "subproblems must be an array");
    for (var i = 0; i < obj.subproblems.length; i++) {
      var sub = obj.subproblems[i];
      if (!_isObject(sub) || !_isString(sub.type) || sub.type.indexOf(ERROR_NAMESPACE) !== 0) throw E("acme/bad-problem", "each subproblem must be an ACME problem document in the error namespace");
      // A subproblem identifier reflects a submitted order identifier, which MAY be a
      // wildcard (a rejectedIdentifier for a *.example.org order), so it is validated
      // with the order-identifier rule, not the stricter authorization one.
      if (Object.prototype.hasOwnProperty.call(sub, "identifier")) _validateOrderIdentifier(sub.identifier);
    }
  }
  return obj;
}

// ---- object validators + identify ----------------------------------------

/**
 * @primitive  pki.acme.validate
 * @signature  pki.acme.validate(kind, obj) -> obj
 * @since      0.1.25
 * @status     experimental
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
 * @status     experimental
 * @spec       RFC 8555, RFC 9773
 * @related    pki.acme.validate
 *
 * Classify an ACME JSON object into exactly one kind by its discriminating
 * member set -- `"jws"`, `"problem"`, `"directory"`, `"order"`, `"authorization"`,
 * `"challenge"`, `"account"`, `"renewalInfo"`, or `"unknown"`. The discriminators
 * are proven mutually exclusive; a DER structure identifies as `"unknown"`.
 *
 * @example
 *   pki.acme.identify(orderObj);   // -> "order"
 */
function identify(obj) {
  if (!_isObject(obj)) return "unknown";
  var has = function (k) { return Object.prototype.hasOwnProperty.call(obj, k); };
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
var TOKEN_RE = new RegExp("^[A-Za-z0-9_-]{" + constants.LIMITS.ACME_TOKEN_MIN_CHARS + ",}$");
function _assertToken(token) {
  if (!_isString(token) || !TOKEN_RE.test(token)) throw E("acme/bad-token", "a challenge token must be >= " + constants.LIMITS.ACME_TOKEN_MIN_CHARS + " base64url characters with no padding (RFC 8555 sec. 8)");
}

async function _sha256(bytes) { return Buffer.from(await subtle.digest("SHA-256", bytes)); }

/**
 * @primitive  pki.acme.keyAuthorization
 * @signature  pki.acme.keyAuthorization(token, accountJwk) -> Promise<string>
 * @since      0.1.25
 * @status     experimental
 * @spec       RFC 8555, RFC 7638
 * @related    pki.acme.http01, pki.acme.dns01, pki.acme.tlsAlpn01Extension
 *
 * The RFC 8555 sec. 8.1 key authorization: `token || '.' ||
 * base64url(SHA-256 JWK thumbprint of the account key)`. The token is validated
 * (entropy floor + alphabet) first; the thumbprint is the RFC 7638 canonical
 * digest, so changing the account key changes the key authorization.
 *
 * @example
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
 * @status     experimental
 * @spec       RFC 8555
 * @related    pki.acme.keyAuthorization
 *
 * The http-01 challenge computation (RFC 8555 sec. 8.3): the resource `path`
 * `/.well-known/acme-challenge/<token>` and the `body` (the ASCII key
 * authorization, no trailing newline). Validation reaches TCP port 80 over HTTP.
 *
 * @example
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
 * @status     experimental
 * @spec       RFC 8555
 * @related    pki.acme.keyAuthorization
 *
 * The dns-01 challenge computation (RFC 8555 sec. 8.4): the TXT record `name`
 * `_acme-challenge.<domain>` (exactly one leading `*.` is stripped for a wildcard
 * order) and the `value` `base64url(SHA-256(keyAuthorization))`.
 *
 * @example
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
 * @status     experimental
 * @spec       RFC 8737
 * @related    pki.acme.verifyTlsAlpn01
 *
 * Build the DER of the critical `id-pe-acmeIdentifier` extension (RFC 8737
 * sec. 3): `SEQUENCE { extnID 1.3.6.1.5.5.7.1.31, critical TRUE, extnValue OCTET
 * STRING wrapping Authorization ::= OCTET STRING (SIZE 32) of the
 * SHA-256(keyAuthorization) }`. Placed in the validation certificate.
 *
 * @example
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
 * @status     experimental
 * @spec       RFC 8737, RFC 8738
 * @related    pki.acme.tlsAlpn01Extension
 *
 * Verify a tls-alpn-01 validation certificate (RFC 8737 sec. 3): a CRITICAL
 * `id-pe-acmeIdentifier` extension whose 32-octet Authorization equals
 * SHA-256(keyAuthorization), AND a SubjectAltName with EXACTLY ONE entry -- a
 * dNSName equal to the `dns` identifier (case-insensitive) or a single iPAddress
 * for an `ip` identifier (RFC 8738 sec. 6). Any deviation throws `acme/bad-tlsalpn`.
 *
 * @example
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
  if (Object.prototype.hasOwnProperty.call(o, "kid")) h.kid = o.kid;
  if (Object.prototype.hasOwnProperty.call(o, "jwk")) h.jwk = o.jwk;
  return h;
}
function _payloadBuf(obj) {
  if (obj === undefined) return Buffer.alloc(0);                 // POST-as-GET
  return Buffer.from(JSON.stringify(obj), "utf8");
}
function _signOuter(o, payloadObj) {
  if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
  if (!o.key) throw E("acme/bad-input", "a signing key (opts.key) is required");
  return jose.sign({ protected: _outerHeader(o), payload: _payloadBuf(payloadObj), key: o.key, jwk: o.jwk, profile: "acme-outer" });
}

/**
 * @primitive  pki.acme.postAsGet
 * @signature  pki.acme.postAsGet(opts) -> Promise<object>
 * @since      0.1.25
 * @status     experimental
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
  if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
  // An authenticated read is ALWAYS kid-signed; copy only the kid-mode fields so a
  // leftover jwk (e.g. reused from a newAccount options object) cannot embed a key.
  return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, undefined);
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
      if ((addr.match(/@/g) || []).length !== 1) throw E("acme/bad-contact", "a mailto contact must be exactly one addr-spec");
    }
  });
}

/**
 * @primitive  pki.acme.newAccount
 * @signature  pki.acme.newAccount(opts) -> Promise<object>
 * @since      0.1.25
 * @status     experimental
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
  return jose.sign({ protected: { alg: o.alg, nonce: o.nonce, url: o.url, jwk: o.jwk }, payload: _payloadBuf(payload), key: o.key, jwk: o.jwk, profile: "acme-outer" });
}

var _HMAC_HASH = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" };

/**
 * @primitive  pki.acme.externalAccountBinding
 * @signature  pki.acme.externalAccountBinding(opts) -> Promise<object>
 * @since      0.1.25
 * @status     experimental
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
  if (!_isObject(id) || !_isString(id.type) || !_isString(id.value)) throw E("acme/bad-identifier", "an order identifier must be { type, value } strings");
  if (id.type === "dns") {
    var v = id.value;
    if (v.indexOf("*.") === 0) {
      v = v.slice(2);
      if (v.indexOf("*") !== -1) throw E("acme/bad-identifier", "a wildcard order identifier permits exactly one leading *. label (RFC 8555 sec. 7.1.3)");
    } else if (v.indexOf("*") !== -1) {
      throw E("acme/bad-identifier", "a wildcard must be a single leading *. label (RFC 8555 sec. 7.1.3)");
    }
    _assertDnsName(v);
  } else if (id.type === "ip") {
    if (id.value.indexOf("*") !== -1) throw E("acme/bad-identifier", "an ip identifier has no wildcard form (RFC 8738)");
    _assertIpAddress(id.value);
  }
  return id;
}

/**
 * @primitive  pki.acme.newOrder
 * @signature  pki.acme.newOrder(opts) -> Promise<object>
 * @since      0.1.25
 * @status     experimental
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
  if (!_isObject(o) || !Array.isArray(o.identifiers) || o.identifiers.length === 0) throw E("acme/bad-order", "newOrder requires a non-empty identifiers array (RFC 8555 sec. 7.4)");
  o.identifiers.forEach(_validateOrderIdentifier);
  var payload = { identifiers: o.identifiers };
  if (o.notBefore !== undefined) { if (!_isRfc3339(o.notBefore)) throw E("acme/bad-order", "notBefore must be an RFC 3339 date-time"); payload.notBefore = o.notBefore; }
  if (o.notAfter !== undefined) { if (!_isRfc3339(o.notAfter)) throw E("acme/bad-order", "notAfter must be an RFC 3339 date-time"); payload.notAfter = o.notAfter; }
  if (o.replaces !== undefined) { if (!_isString(o.replaces)) throw E("acme/bad-order", "replaces must be an ARI certID string (RFC 9773 sec. 5)"); payload.replaces = o.replaces; }
  return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, payload);
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
function _subjectCommonNames(subject) {
  var names = [];
  if (!subject || !Array.isArray(subject.rdns)) return names;
  subject.rdns.forEach(function (atvs) {
    atvs.forEach(function (atv) {
      if ((atv.name === "commonName" || atv.type === OID_CN) && _isString(atv.value)) names.push(atv.value);
    });
  });
  return names;
}

// An iPAddress SAN octet string (4 = IPv4, 16 = IPv6) to its RFC 8738 canonical
// text -- the same form an order ip identifier carries -- or null on a bad length.
function _ipBytesToText(buf) {
  if (!Buffer.isBuffer(buf)) return null;
  if (buf.length === 4) return buf[0] + "." + buf[1] + "." + buf[2] + "." + buf[3];
  if (buf.length === 16) {
    var groups = [];
    for (var i = 0; i < 16; i += 2) groups.push(((buf[i] << 8) | buf[i + 1]).toString(16));
    return _canonicalizeIpv6(groups.join(":"));
  }
  return null;
}

// The set of identifiers a CSR requests: the subject CN (counted as dns) plus the
// SAN dNSName / iPAddress entries in the extensionRequest attribute, keyed
// "dns:<lower>" / "ip:<canonical>" for an order-insensitive compare.
function _csrIdentifierSet(parsedCsr) {
  var set = {};
  _subjectCommonNames(parsedCsr.subject).forEach(function (cn) { set["dns:" + cn.toLowerCase()] = true; });
  // PKCS#10 permits duplicate attribute types, so aggregate EVERY extensionRequest
  // attribute and EVERY subjectAltName within each -- taking only the first would let
  // a second extensionRequest smuggle identifiers past the order-set comparison.
  (parsedCsr.attributes || []).forEach(function (a) {
    if (a.type !== oid.byName("extensionRequest") || !Array.isArray(a.extensions)) return;
    a.extensions.forEach(function (e) {
      if (e.oid !== OID_SAN) return;
      var dec = _extDecoders.byOid[OID_SAN](e.value, _extCtx);
      (dec.names || []).forEach(function (n) {
        if (n.tagNumber === 2) set["dns:" + String(n.value).toLowerCase()] = true;
        else if (n.tagNumber === 7) { var t = _ipBytesToText(n.value); if (t) set["ip:" + t] = true; }
      });
    });
  });
  return set;
}

function _orderIdentifierSet(identifiers) {
  var set = {};
  identifiers.forEach(function (id) {
    if (id.type === "dns") set["dns:" + id.value.toLowerCase()] = true;
    else if (id.type === "ip") set["ip:" + id.value] = true;
  });
  return set;
}

function _assertCsrIdentifiers(parsedCsr, identifiers) {
  var have = _csrIdentifierSet(parsedCsr);
  var want = _orderIdentifierSet(identifiers);
  var haveKeys = Object.keys(have), wantKeys = Object.keys(want);
  var mismatch = haveKeys.length !== wantKeys.length ||
    wantKeys.some(function (k) { return !have[k]; }) ||
    haveKeys.some(function (k) { return !want[k]; });
  if (mismatch) {
    throw E("acme/csr-identifier-mismatch", "the finalize CSR identifier set " + JSON.stringify(haveKeys.sort()) +
      " does not equal the order identifiers " + JSON.stringify(wantKeys.sort()) + " (RFC 8555 sec. 7.4)");
  }
}

/**
 * @primitive  pki.acme.finalize
 * @signature  pki.acme.finalize(opts) -> Promise<object>
 * @since      0.1.25
 * @status     experimental
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
  if (!_isObject(o) || !Buffer.isBuffer(o.csr)) throw E("acme/bad-input", "finalize requires a DER CSR Buffer (opts.csr)");
  var parsed = csr.parse(o.csr);                         // strict DER; rejects PEM/garbage
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
  var payload = { csr: jose.base64url.encode(o.csr) };
  return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, payload);
}

/**
 * @primitive  pki.acme.challengeResponse
 * @signature  pki.acme.challengeResponse(opts) -> Promise<object>
 * @since      0.1.25
 * @status     experimental
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
 *   await pki.acme.challengeResponse({ key, alg: "ES256", nonce, url: challUrl, kid });
 */
function challengeResponse(o) {
  if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
  var payload = o.payload !== undefined ? o.payload : {};
  if (!_isObject(payload)) throw E("acme/bad-input", "a challenge response payload must be a JSON object (RFC 8555 sec. 7.5.1)");
  return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, payload);
}

/**
 * @primitive  pki.acme.deactivate
 * @signature  pki.acme.deactivate(opts) -> Promise<object>
 * @since      0.1.25
 * @status     experimental
 * @spec       RFC 8555
 * @related    pki.acme.validate
 *
 * Build a deactivation POST (RFC 8555 sec. 7.3.6 account / sec. 7.5.2
 * authorization): a kid-signed JWS with the payload `{"status":"deactivated"}` --
 * the only client-settable status. `opts` = `{ key, alg, nonce, url, kid }`.
 *
 * @example
 *   await pki.acme.deactivate({ key, alg: "ES256", nonce, url: authzUrl, kid });
 */
function deactivate(o) {
  if (!_isObject(o)) throw E("acme/bad-input", "a request options object is required");
  return _signOuter({ key: o.key, alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, { status: "deactivated" });
}

/**
 * @primitive  pki.acme.revokeCert
 * @signature  pki.acme.revokeCert(opts) -> Promise<object>
 * @since      0.1.25
 * @status     experimental
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
 *   await pki.acme.revokeCert({ key, alg: "ES256", nonce, url, kid, certificate: certDer, reason: 1 });
 */
function revokeCert(o) {
  if (!_isObject(o) || !Buffer.isBuffer(o.certificate)) throw E("acme/bad-input", "revokeCert requires a DER certificate Buffer (opts.certificate)");
  x509.parse(o.certificate);                              // structural validation of the target
  var hasKid = Object.prototype.hasOwnProperty.call(o, "kid");
  var hasJwk = Object.prototype.hasOwnProperty.call(o, "jwk");
  if (hasKid === hasJwk) throw E("acme/bad-input", "revokeCert must be signed with EXACTLY ONE of the account kid or the certificate jwk (RFC 8555 sec. 7.6)");
  var payload = { certificate: jose.base64url.encode(o.certificate) };
  if (o.reason !== undefined) {
    if (typeof o.reason !== "number" || !isFinite(o.reason) || Math.floor(o.reason) !== o.reason || CRL_REASONS.indexOf(o.reason) === -1) {
      throw E("acme/bad-revocation-reason", "reason must be an assigned RFC 5280 CRLReason (0-6, 8-10; value 7 is unassigned)");
    }
    payload.reason = o.reason;
  }
  var header = { alg: o.alg, nonce: o.nonce, url: o.url };
  if (hasKid) header.kid = o.kid; else header.jwk = o.jwk;
  return jose.sign({ protected: header, payload: _payloadBuf(payload), key: o.key, jwk: o.jwk, profile: "acme-outer" });
}

/**
 * @primitive  pki.acme.keyChange
 * @signature  pki.acme.keyChange(opts) -> Promise<object>
 * @since      0.1.25
 * @status     experimental
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
    key: o.newKey, jwk: o.newJwk, profile: "keychange-inner",
  });
  return jose.sign({ protected: { alg: o.alg, nonce: o.nonce, url: o.url, kid: o.kid }, payload: _payloadBuf(inner), key: o.key, profile: "acme-outer" });
}

// ---- ARI (RFC 9773 renewal information) ----------------------------------

/**
 * @primitive  pki.acme.ariCertId
 * @signature  pki.acme.ariCertId(certDer) -> string
 * @since      0.1.25
 * @status     experimental
 * @spec       RFC 9773
 * @related    pki.acme.parseAriCertId, pki.acme.newOrder
 *
 * The RFC 9773 sec. 4.1 ARI certificate identifier of a DER certificate:
 * `base64url(AKI keyIdentifier) || '.' || base64url(serial content octets)`. The
 * serial is the raw DER INTEGER content -- its leading `00` sign-padding byte is
 * PRESERVED (dropping it is the documented mass-404 client bug). Throws
 * `acme/bad-certid` if the certificate lacks an AKI keyIdentifier.
 *
 * @example
 *   pki.acme.ariCertId(certDer);   // -> "<b64u-aki>.<b64u-serial>"
 */
function ariCertId(certDer) {
  if (!Buffer.isBuffer(certDer)) throw E("acme/bad-input", "ariCertId requires a DER certificate Buffer");
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
 * @status     experimental
 * @spec       RFC 9773
 * @related    pki.acme.ariCertId
 *
 * Parse an ARI certID string (RFC 9773 sec. 4.1) into `{ keyIdentifier, serial }`
 * Buffers. The two dot-joined halves are each strict base64url (padding /
 * non-alphabet rejected); anything but exactly two parts throws `acme/bad-certid`.
 *
 * @example
 *   pki.acme.parseAriCertId("<b64u-aki>.<b64u-serial>").serial;   // -> Buffer
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
 * @status     experimental
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

module.exports = {
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
  finalize: finalize,
  challengeResponse: challengeResponse,
  deactivate: deactivate,
  revokeCert: revokeCert,
  keyChange: keyChange,
  // ARI (RFC 9773)
  ariCertId: ariCertId,
  parseAriCertId: parseAriCertId,
  // re-exported for the ACME consumer / test surface
  jose: jose,
};
