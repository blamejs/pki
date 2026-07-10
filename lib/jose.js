// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.jose
 * @nav        Protocols
 * @title      JOSE (JWS / JWK)
 * @order      10
 * @slug       jose
 *
 * @intro
 *   The JOSE message envelope (RFC 7515 JWS, RFC 7518 JWA, RFC 7638 JWK
 *   thumbprint), profiled for RFC 8555 ACME but usable on its own. A JWS here
 *   is the Flattened JSON Serialization only -- `{ protected, payload,
 *   signature }` -- with the multi-signature `signatures` member, the
 *   unprotected `header` member, and the RFC 7797 unencoded-payload `b64`
 *   option all structurally forbidden. Every base64url field is decoded by a
 *   STRICT codec (Node's `Buffer.from(s, "base64url")` accepts padding,
 *   whitespace, and non-canonical trailing bits -- all of which are rejected
 *   here), and every JSON document is read by a bounded reader that rejects a
 *   duplicate member at any nesting depth (the parser-differential smuggling
 *   class `JSON.parse` silently allows).
 *
 *   Algorithms resolve through an `alg`-keyed registry (ES256/384/512,
 *   RS256/384/512, PS256/384/512, EdDSA, and the RFC 9964 ML-DSA-44/65/87 PQC
 *   rows), never a switch: the registry binds `alg` to a key type and pins the
 *   exact signature byte length BEFORE any crypto call, so `alg:"none"`, a MAC
 *   algorithm on the outer profile, an ES256/RSA-key confusion, and a DER-vs-raw
 *   ECDSA signature all fail closed. `sign` and `verify` are driven by ONE
 *   declarative profile table each -- the same data drives both directions.
 *
 * @card
 *   RFC 7515 Flattened JWS sign/verify + RFC 7638 JWK thumbprints, ACME-profiled:
 *   strict base64url + duplicate-rejecting JSON, an alg registry (ES/RS/PS/EdDSA
 *   + ML-DSA), signature-length pinning, fail-closed everywhere.
 */

var constants = require("./constants");
var webcrypto = require("./webcrypto").webcrypto;
var frameworkError = require("./framework-error");

var JoseError = frameworkError.JoseError;
function E(code, message, cause) { return new JoseError(code, message, cause); }

var LIMITS = constants.LIMITS;

// ---- strict base64url codec (RFC 7515 sec. 2 / RFC 4648 sec. 5) ----------

var B64U_ALPHABET = /^[A-Za-z0-9_-]*$/;

/**
 * @primitive  pki.jose.base64url.encode
 * @signature  pki.jose.base64url.encode(bytes) -> string
 * @since      0.1.25
 * @status     experimental
 * @spec       RFC 7515, RFC 4648
 * @related    pki.jose.base64url.decode
 *
 * Encode a `Buffer` as unpadded base64url (RFC 4648 sec. 5): the `+`/`/`
 * characters become `-`/`_` and the trailing `=` padding is omitted.
 *
 * @example
 *   pki.jose.base64url.encode(Buffer.from([1, 2, 3]));   // -> "AQID"
 */
function b64uEncode(bytes) {
  if (!Buffer.isBuffer(bytes)) throw E("jose/bad-input", "base64url.encode requires a Buffer");
  return bytes.toString("base64url");
}

/**
 * @primitive  pki.jose.base64url.decode
 * @signature  pki.jose.base64url.decode(text) -> Buffer
 * @since      0.1.25
 * @status     experimental
 * @spec       RFC 7515, RFC 4648, RFC 8555
 * @related    pki.jose.base64url.encode
 *
 * Decode base64url to a `Buffer`, STRICTLY (RFC 8555 sec. 6.1): trailing `=`
 * padding, any non-alphabet character (`+`, `/`, whitespace), and a
 * non-canonical final character (one whose discarded low bits are non-zero)
 * each throw `jose/bad-base64url`. The canonical check is a re-encode round-trip.
 *
 * @example
 *   pki.jose.base64url.decode("AQID");   // -> <Buffer 01 02 03>
 */
function b64uDecode(text) {
  if (typeof text !== "string") throw E("jose/bad-base64url", "base64url.decode requires a string");
  if (!B64U_ALPHABET.test(text)) throw E("jose/bad-base64url", "value is not base64url (padding or a non-alphabet character)");
  // length % 4 === 1 is not a possible base64 encoding length.
  if (text.length % 4 === 1) throw E("jose/bad-base64url", "base64url value has an impossible length");
  var buf = Buffer.from(text, "base64url");
  // Re-encode: a non-canonical final character (non-zero discarded bits) yields
  // a different canonical form, so the round-trip fails closed.
  if (buf.toString("base64url") !== text) throw E("jose/bad-base64url", "base64url value is not canonical");
  return buf;
}

// ---- strict bounded JSON reader ------------------------------------------

// A single hand-written recursive-descent reader (never JSON.parse, which
// silently takes the LAST of a duplicate member -- the smuggling class). It
// enforces the byte-size cap, the depth cap, and duplicate-member rejection at
// EVERY nesting level, and reads UTF-8 strictly. Returns the parsed value.
function _jsonReader(str) {
  var i = 0, n = str.length;
  function ws() { while (i < n) { var c = str.charCodeAt(i); if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++; else break; } }
  function fail(msg) { throw E("jose/bad-json", "invalid JSON at offset " + i + ": " + msg); }
  function value(depth) {
    if (depth > LIMITS.JSON_MAX_DEPTH) throw E("jose/too-deep", "JSON nesting exceeds the depth cap");
    ws();
    if (i >= n) fail("unexpected end of input");
    var c = str[i];
    if (c === "{") return object(depth);
    if (c === "[") return array(depth);
    if (c === "\"") return string();
    if (c === "-" || (c >= "0" && c <= "9")) return number();
    if (str.substr(i, 4) === "true") { i += 4; return true; }
    if (str.substr(i, 5) === "false") { i += 5; return false; }
    if (str.substr(i, 4) === "null") { i += 4; return null; }
    fail("unexpected token");
    return undefined;
  }
  function object(depth) {
    i++; // {
    var out = {};
    ws();
    if (str[i] === "}") { i++; return out; }
    for (;;) {
      ws();
      if (str[i] !== "\"") fail("expected a string key");
      var key = string();
      if (Object.prototype.hasOwnProperty.call(out, key)) throw E("jose/duplicate-member", "duplicate JSON member " + JSON.stringify(key));
      ws();
      if (str[i] !== ":") fail("expected ':'");
      i++;
      // Assign as an OWN data property via defineProperty (not out[key] = ...): a
      // "__proto__" key must become a normal own member, not mutate the object's
      // prototype. A bare `out["__proto__"] = v` would pollute the returned object
      // AND (for a primitive v) create no own property, silently defeating the
      // duplicate-member gate above on a repeated __proto__.
      Object.defineProperty(out, key, { value: value(depth + 1), writable: true, enumerable: true, configurable: true });
      ws();
      if (str[i] === ",") { i++; continue; }
      if (str[i] === "}") { i++; return out; }
      fail("expected ',' or '}'");
    }
  }
  function array(depth) {
    i++; // [
    var out = [];
    ws();
    if (str[i] === "]") { i++; return out; }
    for (;;) {
      out.push(value(depth + 1));
      ws();
      if (str[i] === ",") { i++; continue; }
      if (str[i] === "]") { i++; return out; }
      fail("expected ',' or ']'");
    }
  }
  function string() {
    i++; // opening quote
    var s = "";
    for (;;) {
      if (i >= n) fail("unterminated string");
      var c = str[i++];
      if (c === "\"") return s;
      if (c === "\\") {
        if (i >= n) fail("unterminated escape");
        var e = str[i++];
        if (e === "\"") s += "\"";
        else if (e === "\\") s += "\\";
        else if (e === "/") s += "/";
        else if (e === "b") s += "\b";
        else if (e === "f") s += "\f";
        else if (e === "n") s += "\n";
        else if (e === "r") s += "\r";
        else if (e === "t") s += "\t";
        else if (e === "u") {
          var hex = str.substr(i, 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad \\u escape");
          s += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else fail("bad escape");
      } else if (c.charCodeAt(0) < 0x20) {
        fail("control character in string");
      } else s += c;
    }
  }
  function number() {
    var start = i;
    if (str[i] === "-") i++;
    while (i < n && str[i] >= "0" && str[i] <= "9") i++;
    if (str[i] === ".") { i++; while (i < n && str[i] >= "0" && str[i] <= "9") i++; }
    if (str[i] === "e" || str[i] === "E") { i++; if (str[i] === "+" || str[i] === "-") i++; while (i < n && str[i] >= "0" && str[i] <= "9") i++; }
    var tok = str.slice(start, i);
    // Enforce the RFC 8259 number grammar the greedy scan does not: no leading zero
    // ("01"), a fraction and an exponent each need at least one digit ("1.", "1e",
    // "1.e1"), and a bare "-" is not a number. A lenient Number() would accept these
    // and reintroduce a parser differential against a strict JSON reader.
    if (!/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/.test(tok)) fail("malformed number");
    var v = Number(tok);
    if (!isFinite(v)) fail("bad number");
    return v;
  }
  var result = value(0);
  ws();
  if (i !== n) fail("trailing content after JSON value");
  return result;
}

/**
 * @primitive  pki.jose.parseJson
 * @signature  pki.jose.parseJson(input) -> value
 * @since      0.1.25
 * @status     experimental
 * @spec       RFC 7515, RFC 8259
 * @related    pki.jose.base64url.decode
 *
 * Parse a JSON document (a `Buffer` or a string) with a bounded, strict reader:
 * the byte size is capped (`jose/too-large`), nesting is capped
 * (`jose/too-deep`), a duplicate member at ANY depth is rejected
 * (`jose/duplicate-member`), and a `Buffer` is decoded as strict UTF-8 (invalid
 * bytes throw). Unlike `JSON.parse`, a duplicate key never silently resolves to
 * the last value.
 *
 * @example
 *   pki.jose.parseJson('{"a":1}');   // -> { a: 1 }
 */
function parseJson(input) {
  var str;
  if (Buffer.isBuffer(input)) {
    if (input.length > LIMITS.JSON_MAX_BYTES) throw E("jose/too-large", "the JSON document exceeds the size cap");
    try { str = new TextDecoder("utf-8", { fatal: true }).decode(input); }
    catch (e) { throw E("jose/bad-json", "the JSON document is not valid UTF-8", e); }
  } else if (typeof input === "string") {
    if (Buffer.byteLength(input, "utf8") > LIMITS.JSON_MAX_BYTES) throw E("jose/too-large", "the JSON document exceeds the size cap");
    str = input;
  } else {
    throw E("jose/bad-input", "parseJson requires a Buffer or string");
  }
  return _jsonReader(str);
}

// ---- JOSE algorithm registry (RFC 7518 / 8037 / 9964) --------------------

// One data row per JWS `alg`, keyed for O(1) resolution -- never a switch. Each
// row binds the alg to its JWK key type (and, for EC/OKP, the exact curve), the
// hash, and the WebCrypto import/verify parameters, plus the exact signature
// byte length (fixed for EC / EdDSA / ML-DSA; the RSA modulus length for RS*/PS*,
// resolved from the key). Binding alg->kty in DATA is what kills the RS256->HS256
// key-confusion class: an ES256 header with an RSA key is rejected here, before
// any crypto call. `HS*`/`none` are absent from this table by construction.
var SIG_ALGS = {
  ES256: { kty: "EC", crv: "P-256", hash: "SHA-256", subtle: "ECDSA", sigBytes: 64 },
  ES384: { kty: "EC", crv: "P-384", hash: "SHA-384", subtle: "ECDSA", sigBytes: 96 },
  ES512: { kty: "EC", crv: "P-521", hash: "SHA-512", subtle: "ECDSA", sigBytes: 132 },
  RS256: { kty: "RSA", hash: "SHA-256", subtle: "RSASSA-PKCS1-V1_5" },
  RS384: { kty: "RSA", hash: "SHA-384", subtle: "RSASSA-PKCS1-V1_5" },
  RS512: { kty: "RSA", hash: "SHA-512", subtle: "RSASSA-PKCS1-V1_5" },
  PS256: { kty: "RSA", hash: "SHA-256", subtle: "RSA-PSS", saltLength: 32 },
  PS384: { kty: "RSA", hash: "SHA-384", subtle: "RSA-PSS", saltLength: 48 },
  PS512: { kty: "RSA", hash: "SHA-512", subtle: "RSA-PSS", saltLength: 64 },
  EdDSA: { kty: "OKP", subtle: "EdDSA", sigBytesByCrv: { Ed25519: 64, Ed448: 114 } },
  "ML-DSA-44": { kty: "AKP", subtle: "ML-DSA-44", sigBytes: 2420 },
  "ML-DSA-65": { kty: "AKP", subtle: "ML-DSA-65", sigBytes: 3309 },
  "ML-DSA-87": { kty: "AKP", subtle: "ML-DSA-87", sigBytes: 4627 },
};

// The MAC table exists ONLY for the RFC 8555 sec. 7.3.4 externalAccountBinding
// inner JWS -- HS* appears nowhere in the outer/signature profiles, so an
// `alg:"HS256"` on an ACME request rejects (the RS256->HS256 downgrade class).
var MAC_ALGS = {
  HS256: { kty: "oct", hash: "SHA-256", sigBytes: 32 },
  HS384: { kty: "oct", hash: "SHA-384", sigBytes: 48 },
  HS512: { kty: "oct", hash: "SHA-512", sigBytes: 64 },
};

// The header parameter names this implementation understands. A `crit` naming
// anything outside this set is unprocessable -> the JWS is invalid (RFC 7515
// sec. 4.1.11); ACME defines no extension params, so any `crit` entry rejects.
var UNDERSTOOD_HEADER = { alg: 1, nonce: 1, url: 1, jwk: 1, kid: 1, crit: 1 };

// ---- JWS profiles (declarative -- one table drives sign AND verify) ------

// Each profile is DATA: the algorithm table it permits, the required params,
// whether `nonce` is required/forbidden, and the key-identification rule
// (exactly-one-of jwk/kid, or one specifically). The profile carries the rule,
// not the code path -- so the EAB-inner table ACCEPTS HS256 where the ACME-outer
// table REJECTS it, from the same walker.
var PROFILES = {
  "acme-outer":     { algs: SIG_ALGS, nonce: "required",  keyId: "one-of", requireUrl: true },
  "eab-inner":      { algs: MAC_ALGS, nonce: "forbidden", keyId: "kid",    requireUrl: true },
  "keychange-inner": { algs: SIG_ALGS, nonce: "forbidden", keyId: "jwk",    requireUrl: true },
};

// Validate a decoded protected header against a profile. Returns the resolved
// { alg, algRow, header }; throws a typed jose/* fault on any violation.
function _checkHeader(header, profileName) {
  var profile = PROFILES[profileName];
  if (!profile) throw E("jose/bad-input", "unknown JWS profile " + JSON.stringify(profileName));
  if (!header || typeof header !== "object" || Array.isArray(header)) throw E("jose/bad-header", "the protected header must be a JSON object");
  // b64 (RFC 7797) MUST NOT be present at all -- the unencoded-payload downgrade.
  if (Object.prototype.hasOwnProperty.call(header, "b64")) throw E("jose/bad-jws", "the RFC 7797 b64 header parameter is forbidden");
  var alg = header.alg;
  if (typeof alg !== "string") throw E("jose/bad-header", "the protected header must carry a string alg");
  var algRow = profile.algs[alg];
  if (!algRow) throw E("jose/bad-alg", "unsupported or forbidden algorithm " + JSON.stringify(alg) + " for this JWS profile");
  if (profile.requireUrl && typeof header.url !== "string") throw E("jose/bad-header", "the protected header must carry a string url");
  // nonce discipline.
  var hasNonce = Object.prototype.hasOwnProperty.call(header, "nonce");
  if (profile.nonce === "required") {
    if (typeof header.nonce !== "string") throw E("jose/bad-header", "the protected header must carry a nonce");
    // a nonce that is not valid base64url is malformed (RFC 8555 sec. 6.5.2).
    try { b64uDecode(header.nonce); } catch (e) { throw E("jose/bad-header", "the nonce is not valid base64url", e); }
  } else if (profile.nonce === "forbidden" && hasNonce) {
    throw E("jose/bad-header", "a nonce is forbidden in this inner JWS");
  }
  // key identification.
  var hasJwk = Object.prototype.hasOwnProperty.call(header, "jwk");
  var hasKid = Object.prototype.hasOwnProperty.call(header, "kid");
  if (profile.keyId === "one-of") {
    if (hasJwk === hasKid) throw E("jose/bad-header", "the protected header must carry EXACTLY ONE of jwk / kid");
  } else if (profile.keyId === "kid") {
    if (!hasKid || hasJwk) throw E("jose/bad-header", "this JWS must identify its key by kid, not jwk");
    if (typeof header.kid !== "string") throw E("jose/bad-header", "kid must be a string");
  } else if (profile.keyId === "jwk") {
    if (!hasJwk || hasKid) throw E("jose/bad-header", "this JWS must carry an embedded jwk, not kid");
  }
  if (hasJwk && (!header.jwk || typeof header.jwk !== "object" || Array.isArray(header.jwk))) throw E("jose/bad-header", "jwk must be a JSON object");
  // crit: protected-only, non-empty, no standard names, no duplicates, all understood.
  if (Object.prototype.hasOwnProperty.call(header, "crit")) {
    var crit = header.crit;
    if (!Array.isArray(crit) || crit.length === 0) throw E("jose/bad-crit", "crit must be a non-empty array");
    var seen = {};
    for (var c = 0; c < crit.length; c++) {
      var name = crit[c];
      if (typeof name !== "string") throw E("jose/bad-crit", "crit entries must be strings");
      if (Object.prototype.hasOwnProperty.call(seen, name)) throw E("jose/bad-crit", "duplicate crit entry " + JSON.stringify(name));
      seen[name] = 1;
      if (UNDERSTOOD_HEADER[name]) throw E("jose/bad-crit", "crit must not name a standard header parameter " + JSON.stringify(name));
      // Anything else is an extension parameter this implementation does not process.
      throw E("jose/bad-crit", "unprocessed critical header parameter " + JSON.stringify(name));
    }
  }
  return { alg: alg, algRow: algRow, header: header };
}

// ---- flattened-JWS verify (RFC 7515 sec. 5.2) ----------------------------

// Resolve the WebCrypto import parameters for a JWK under an alg row.
function _importParams(algRow, jwk) {
  if (algRow.kty === "EC") return { name: "ECDSA", namedCurve: algRow.crv };
  if (algRow.kty === "RSA") return { name: algRow.subtle, hash: algRow.hash };
  if (algRow.kty === "OKP") return { name: jwk.crv };            // Ed25519 / Ed448
  if (algRow.kty === "AKP") return { name: algRow.subtle };      // ML-DSA-44/65/87
  if (algRow.kty === "oct") return { name: "HMAC", hash: algRow.hash }; // EAB inner (HS*)
  throw E("jose/bad-alg", "unsupported key type");
}

// The WebCrypto verify/sign algorithm for an alg row + JWK.
function _cryptoAlg(algRow, jwk) {
  if (algRow.kty === "EC") return { name: "ECDSA", hash: algRow.hash };
  if (algRow.kty === "RSA") return algRow.subtle === "RSA-PSS" ? { name: "RSA-PSS", saltLength: algRow.saltLength } : { name: "RSASSA-PKCS1-V1_5" };
  if (algRow.kty === "OKP") return { name: jwk.crv };
  if (algRow.kty === "AKP") return { name: algRow.subtle };
  if (algRow.kty === "oct") return { name: "HMAC" };
  throw E("jose/bad-alg", "unsupported key type");
}

// The key type the JWK MUST have for this alg (fail closed on confusion).
function _assertKeyType(algRow, jwk) {
  if (!jwk || typeof jwk !== "object" || typeof jwk.kty !== "string") throw E("jose/bad-key", "a JWK object with a kty is required");
  if (jwk.kty !== algRow.kty) throw E("jose/bad-alg", "the key type " + JSON.stringify(jwk.kty) + " does not match the algorithm");
  if (algRow.kty === "EC" && jwk.crv !== algRow.crv) throw E("jose/bad-alg", "the EC curve does not match the algorithm");
  if (algRow.kty === "OKP" && jwk.crv !== "Ed25519" && jwk.crv !== "Ed448") throw E("jose/bad-alg", "unsupported OKP curve " + JSON.stringify(jwk.crv));
}

// The exact signature byte length this alg + key must produce.
function _expectedSigBytes(algRow, jwk) {
  if (algRow.sigBytes != null) return algRow.sigBytes;
  if (algRow.sigBytesByCrv) return algRow.sigBytesByCrv[jwk.crv] || null;
  if (algRow.kty === "RSA") { var nBytes = b64uDecode(jwk.n).length; return nBytes; }   // modulus length
  return null;
}

/**
 * @primitive  pki.jose.verify
 * @signature  pki.jose.verify(jws, opts) -> Promise<{ header, payload }>
 * @since      0.1.25
 * @status     experimental
 * @spec       RFC 7515, RFC 7518, RFC 8555
 * @related    pki.jose.sign, pki.jose.parseJson
 *
 * Verify a Flattened JSON JWS against a profile (`opts.profile`, default
 * `"acme-outer"`). Structural rules fail closed BEFORE any crypto: the
 * `signatures`/`header` members and a detached payload are rejected, the
 * protected header is validated against the profile (alg registry, nonce, url,
 * exactly-one-of jwk/kid, crit), the signature byte length is pinned per alg, and
 * the verification key is the header `jwk` (only where the profile permits it) or
 * `opts.key` (a JWK). Returns the decoded `{ header, payload }` (payload a raw
 * `Buffer`); a failed signature throws `jose/verify-failed`.
 *
 * @opts
 *   profile: string   // "acme-outer" | "eab-inner" | "keychange-inner"
 *   key: object       // a public JWK, required unless the profile embeds jwk
 *
 * @example
 *   var v = await pki.jose.verify(jws, { profile: "acme-outer", key: accountJwk });
 *   v.header.alg;   // -> "ES256"
 */
async function verify(jws, opts) {
  opts = opts || {};
  if (!jws || typeof jws !== "object" || Array.isArray(jws)) throw E("jose/bad-jws", "a flattened JWS object is required");
  if (Object.prototype.hasOwnProperty.call(jws, "signatures")) throw E("jose/bad-jws", "the multi-signature signatures member is forbidden");
  if (Object.prototype.hasOwnProperty.call(jws, "header")) throw E("jose/bad-jws", "the unprotected header member is forbidden");
  if (typeof jws.protected !== "string" || typeof jws.signature !== "string") throw E("jose/bad-jws", "protected and signature must be base64url strings");
  if (typeof jws.payload !== "string") throw E("jose/bad-jws", "payload must be a base64url string (never detached)");
  var header = parseJson(b64uDecode(jws.protected));
  var profileName = opts.profile || "acme-outer";
  var checked = _checkHeader(header, profileName);
  var jwk = header.jwk || opts.key;
  if (!jwk) throw E("jose/bad-key", "a verification key is required (opts.key) when the profile does not embed a jwk");
  _assertKeyType(checked.algRow, jwk);
  var sig = b64uDecode(jws.signature);
  var want = _expectedSigBytes(checked.algRow, jwk);
  if (want != null && sig.length !== want) throw E("jose/bad-signature", "the signature length " + sig.length + " is not the " + want + " bytes " + checked.alg + " requires");
  // Signing input from the RECEIVED base64url strings verbatim (never a re-serialize).
  var signingInput = Buffer.from(jws.protected + "." + jws.payload, "ascii");
  var key;
  try { key = await webcrypto.subtle.importKey("jwk", jwk, _importParams(checked.algRow, jwk), false, ["verify"]); }
  catch (e) { throw E("jose/bad-key", "the JWK could not be imported for verification", e); }
  var ok = await webcrypto.subtle.verify(_cryptoAlg(checked.algRow, jwk), key, sig, signingInput);
  if (!ok) throw E("jose/verify-failed", "the JWS signature did not verify");
  return { header: header, payload: b64uDecode(jws.payload) };
}

// ---- flattened-JWS sign (RFC 7515 sec. 5.1) ------------------------------

/**
 * @primitive  pki.jose.sign
 * @signature  pki.jose.sign(opts) -> Promise<{ protected, payload, signature }>
 * @since      0.1.25
 * @status     experimental
 * @spec       RFC 7515, RFC 7518, RFC 8555
 * @related    pki.jose.verify
 *
 * Produce a Flattened JSON JWS. `opts.protected` is the protected-header object
 * (validated against `opts.profile`), `opts.payload` the raw payload octets (a
 * `Buffer`; the empty `Buffer` yields the POST-as-GET `payload:""`), and
 * `opts.key` a private `CryptoKey`. The signing input is built from the encoded
 * header and payload and signed with the alg the header names.
 *
 * @opts
 *   protected: object    // the protected header (alg, nonce, url, jwk|kid)
 *   payload: Buffer      // the raw payload octets ("" for POST-as-GET)
 *   key: CryptoKey       // the private signing key
 *   profile: string      // default "acme-outer"
 *   jwk: object          // the public JWK, when the header embeds jwk
 *
 * @example
 *   var jws = await pki.jose.sign({ protected: hdr, payload: Buffer.from("{}"), key: priv });
 */
async function sign(opts) {
  opts = opts || {};
  var header = opts.protected;
  var payload = opts.payload;
  if (!Buffer.isBuffer(payload)) throw E("jose/bad-input", "payload must be a Buffer (empty Buffer for POST-as-GET)");
  if (!opts.key) throw E("jose/bad-input", "a private CryptoKey (opts.key) is required");
  var checked = _checkHeader(header, opts.profile || "acme-outer");
  var protectedB64 = b64uEncode(Buffer.from(JSON.stringify(header), "utf8"));
  var payloadB64 = payload.length === 0 ? "" : b64uEncode(payload);
  var signingInput = Buffer.from(protectedB64 + "." + payloadB64, "ascii");
  var jwk = header.jwk || opts.jwk || {};
  var sigBuf = Buffer.from(await webcrypto.subtle.sign(_cryptoAlg(checked.algRow, jwk), opts.key, signingInput));
  return { protected: protectedB64, payload: payloadB64, signature: b64uEncode(sigBuf) };
}

// ---- JWK thumbprint (RFC 7638 + RFC 8037 + RFC 9964) ---------------------

// The required-member templates per key type (RFC 7638 sec. 3.2 / RFC 8037 sec. 2
// / RFC 9964). ONLY these members, in lexicographic order, no whitespace, feed
// the SHA-256; optional members (alg/use/kid) never enter the hash.
var THUMBPRINT_MEMBERS = {
  EC: ["crv", "kty", "x", "y"],
  RSA: ["e", "kty", "n"],
  oct: ["k", "kty"],
  OKP: ["crv", "kty", "x"],
  AKP: ["kty", "pub"],
};

/**
 * @primitive  pki.jose.thumbprint
 * @signature  pki.jose.thumbprint(jwk) -> Promise<string>
 * @since      0.1.25
 * @status     experimental
 * @spec       RFC 7638, RFC 8037, RFC 9964
 * @related    pki.jose.verify
 *
 * The RFC 7638 JWK SHA-256 thumbprint as base64url: the canonical JSON of ONLY
 * the key type's required members, lexicographically ordered, no whitespace,
 * hashed. Optional members (`alg`, `use`, `kid`) are excluded, so the same key
 * always yields the same thumbprint (the ACME key-authorization anchor).
 *
 * @example
 *   await pki.jose.thumbprint(accountJwk);   // -> "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
 */
async function thumbprint(jwk) {
  if (!jwk || typeof jwk !== "object" || typeof jwk.kty !== "string") throw E("jose/bad-key", "a JWK object with a kty is required");
  var members = THUMBPRINT_MEMBERS[jwk.kty];
  if (!members) throw E("jose/bad-key", "unsupported JWK key type " + JSON.stringify(jwk.kty));
  var parts = [];
  for (var i = 0; i < members.length; i++) {
    var m = members[i];
    if (typeof jwk[m] !== "string") throw E("jose/bad-key", "the JWK is missing the required member " + JSON.stringify(m));
    parts.push(JSON.stringify(m) + ":" + JSON.stringify(jwk[m]));
  }
  var canonical = "{" + parts.join(",") + "}";
  var digest = Buffer.from(await webcrypto.subtle.digest("SHA-256", Buffer.from(canonical, "utf8")));
  return b64uEncode(digest);
}

module.exports = {
  base64url: { encode: b64uEncode, decode: b64uDecode },
  parseJson: parseJson,
  verify: verify,
  sign: sign,
  thumbprint: thumbprint,
};
