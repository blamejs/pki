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
var guard = require("./guard-all");

var JoseError = frameworkError.JoseError;
function E(code, message, cause) { return new JoseError(code, message, cause); }

var LIMITS = constants.LIMITS;

// ---- strict base64url codec (RFC 7515 sec. 2 / RFC 4648 sec. 5) ----------

/**
 * @primitive  pki.jose.base64url.encode
 * @signature  pki.jose.base64url.encode(bytes) -> string
 * @since      0.1.25
 * @status     stable
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
  // Re-view through the byte guard: a detached-backed Buffer reads as zero-length,
  // so a bare .toString would silently encode "" -- fail closed instead.
  bytes = guard.bytes.view(bytes, JoseError, "jose/bad-input", "base64url.encode input");
  return bytes.toString("base64url");
}

/**
 * @primitive  pki.jose.base64url.decode
 * @signature  pki.jose.base64url.decode(text) -> Buffer
 * @since      0.1.25
 * @status     stable
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
  // The strict alphabet + impossible-length + canonical-round-trip discipline
  // lives once in the shared encoding guard (RFC 4648 sec. 5 / RFC 8555 sec. 6.1);
  // the frozen jose/bad-base64url code is threaded through.
  return guard.encoding.base64url(text, null, E, "jose/bad-base64url", "base64url value");
}

// ---- strict bounded JSON reader ------------------------------------------

/**
 * @primitive  pki.jose.parseJson
 * @signature  pki.jose.parseJson(input) -> value
 * @since      0.1.25
 * @status     stable
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
  // The strict bounded reader (byte + depth caps, duplicate-member reject at every
  // depth, __proto__-safe own-property assignment, fatal UTF-8, RFC 8259 grammar)
  // lives once in the shared JSON guard; the frozen jose/* codes are threaded through.
  return guard.json.parse(input, JoseError, {
    maxBytes: LIMITS.JSON_MAX_BYTES, maxDepth: LIMITS.JSON_MAX_DEPTH,
    badJson: "jose/bad-json", tooDeep: "jose/too-deep", duplicateMember: "jose/duplicate-member",
    tooLarge: "jose/too-large", badInput: "jose/bad-input", label: "the JSON document",
  });
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
  // Every field is read as an OWN property. JSON.stringify (used by sign) omits
  // inherited members, so an alg/nonce/url living on the prototype (a polluted or
  // Object.create(...) header) would pass here yet serialize to a header MISSING
  // them -- so require own-ness, matching what the serialized JWS will actually carry.
  var own = function (k) { return Object.prototype.hasOwnProperty.call(header, k); };
  // b64 (RFC 7797) MUST NOT be present at all -- the unencoded-payload downgrade.
  if (own("b64")) throw E("jose/bad-jws", "the RFC 7797 b64 header parameter is forbidden");
  var alg = header.alg;
  if (!own("alg") || typeof alg !== "string") throw E("jose/bad-header", "the protected header must carry a string alg");
  var algRow = profile.algs[alg];
  if (!algRow) throw E("jose/bad-alg", "unsupported or forbidden algorithm " + JSON.stringify(alg) + " for this JWS profile");
  if (profile.requireUrl && (!own("url") || typeof header.url !== "string" || header.url.length === 0)) throw E("jose/bad-header", "the protected header must carry a non-empty string url");
  // nonce discipline.
  var hasNonce = own("nonce");
  if (profile.nonce === "required") {
    // A Replay-Nonce is 1*base64url -- NON-empty (RFC 8555 sec. 6.5.2); "" decodes as
    // canonical base64url but no server issues it, so reject it locally.
    if (!hasNonce || typeof header.nonce !== "string" || header.nonce.length === 0) throw E("jose/bad-header", "the protected header must carry a non-empty nonce");
    // a nonce that is not valid base64url is malformed (RFC 8555 sec. 6.5.2).
    try { b64uDecode(header.nonce); } catch (e) { throw E("jose/bad-header", "the nonce is not valid base64url", e); }
  } else if (profile.nonce === "forbidden" && hasNonce) {
    throw E("jose/bad-header", "a nonce is forbidden in this inner JWS");
  }
  // key identification.
  var hasJwk = own("jwk");
  var hasKid = own("kid");
  // A kid is a non-empty account URL string.
  if (hasKid && (typeof header.kid !== "string" || header.kid.length === 0)) throw E("jose/bad-header", "kid must be a non-empty string");
  if (profile.keyId === "one-of") {
    if (hasJwk === hasKid) throw E("jose/bad-header", "the protected header must carry EXACTLY ONE of jwk / kid");
  } else if (profile.keyId === "kid") {
    if (!hasKid || hasJwk) throw E("jose/bad-header", "this JWS must identify its key by kid, not jwk");
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
function _cryptoAlg(algRow, jwk, key) {
  if (algRow.kty === "EC") return { name: "ECDSA", hash: algRow.hash };
  if (algRow.kty === "RSA") return algRow.subtle === "RSA-PSS" ? { name: "RSA-PSS", saltLength: algRow.saltLength } : { name: "RSASSA-PKCS1-V1_5" };
  // EdDSA carries the curve (Ed25519 / Ed448) as the WebCrypto algorithm name. In
  // a kid-signed request there is no header/opts jwk to read it from, so fall back
  // to the signing key's own algorithm -- an Ed25519 account key must stay usable
  // after account creation, not only in the embedded-jwk (newAccount) case.
  if (algRow.kty === "OKP") return { name: (jwk && jwk.crv) || (key && key.algorithm && key.algorithm.name) };
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
  // An AKP (ML-DSA) JWK carries its parameter set in `alg` (RFC 9964); it MUST match
  // the algorithm's set, or an ML-DSA-44 key could embed an ML-DSA-65 public JWK.
  if (algRow.kty === "AKP" && jwk.alg !== algRow.subtle) throw E("jose/bad-alg", "the AKP parameter set " + JSON.stringify(jwk.alg) + " does not match the algorithm " + algRow.subtle);
}

// The exact signature byte length this alg + key must produce.
function _expectedSigBytes(algRow, jwk, key) {
  if (algRow.sigBytes != null) return algRow.sigBytes;
  // EdDSA: the curve fixes the length. On the verify side it is read from the JWK;
  // on the sign side (kid mode, no JWK) it comes from the signing key's algorithm.
  if (algRow.sigBytesByCrv) return algRow.sigBytesByCrv[(jwk && jwk.crv) || (key && key.algorithm && key.algorithm.name)] || null;
  if (algRow.kty === "RSA") {
    if (jwk && typeof jwk.n === "string") return b64uDecode(jwk.n).length;          // verify: modulus from the JWK
    if (key && key.algorithm && key.algorithm.modulusLength) return key.algorithm.modulusLength / 8; // sign: from the key
    return null;
  }
  return null;
}

// The JWK members that carry PRIVATE key material across every key type -- EC/OKP
// `d`, the RSA CRT set, the symmetric `k`, and the AKP `priv`.
var PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k", "priv"];

/**
 * @primitive  pki.jose.assertPublicJwk
 * @signature  pki.jose.assertPublicJwk(jwk) -> jwk
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 7517, RFC 7518
 * @related    pki.jose.sign, pki.jose.thumbprint
 *
 * Assert that a JWK is PUBLIC-ONLY before it is published (embedded in a JWS
 * protected header or an ACME External Account Binding payload). A JWK carrying any
 * private member (`d`, the RSA CRT parameters `p`/`q`/`dp`/`dq`/`qi`, the symmetric
 * `k`, or the AKP `priv`) throws `jose/private-key-material` -- so an accidentally
 * exported private JWK is never sent to a server. Returns the JWK.
 *
 * @example
 *   pki.jose.assertPublicJwk({ kty: "EC", crv: "P-256", x: "...", y: "..." });
 */
function assertPublicJwk(jwk) {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) throw E("jose/bad-key", "a JWK object is required");
  for (var i = 0; i < PRIVATE_JWK_MEMBERS.length; i++) {
    if (Object.prototype.hasOwnProperty.call(jwk, PRIVATE_JWK_MEMBERS[i])) {
      throw E("jose/private-key-material", "a published JWK must be public-only; it carries the private member " + JSON.stringify(PRIVATE_JWK_MEMBERS[i]));
    }
  }
  return jwk;
}

/**
 * @primitive  pki.jose.verify
 * @signature  pki.jose.verify(jws, opts) -> Promise<{ header, payload }>
 * @since      0.1.25
 * @status     stable
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
 * @status     stable
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
  // Re-view before the length===0 fast-path: a DETACHED payload reads as zero-length
  // and would be silently signed as an empty POST-as-GET body -- fail closed instead.
  payload = guard.bytes.view(payload, JoseError, "jose/bad-input", "payload");
  // A non-CryptoKey (a raw Buffer, a string, a JWK object) would reach subtle.sign
  // and throw a bare TypeError; require a CryptoKey (it carries an `algorithm`) so
  // every caller -- and every acme builder that composes sign -- fails closed.
  if (!opts.key || typeof opts.key !== "object" || typeof opts.key.algorithm !== "object") throw E("jose/bad-input", "a private or secret CryptoKey (opts.key) is required");
  var checked = _checkHeader(header, opts.profile || "acme-outer");
  // An RSA / HMAC key binds its hash at import; the signature-length pin below cannot
  // see a hash mismatch (the modulus / MAC size is unchanged), so a SHA-512 key under
  // RS256 would sign here yet fail verification. Reject the hash disagreement up front.
  if ((checked.algRow.kty === "RSA" || checked.algRow.kty === "oct") &&
      (!opts.key.algorithm.hash || opts.key.algorithm.hash.name !== checked.algRow.hash)) {
    throw E("jose/bad-key", "the signing key's hash does not match the algorithm " + checked.alg);
  }
  // An embedded jwk (jwk mode / keychange-inner) is the public key a verifier will
  // use, so it MUST match the alg exactly as verify enforces -- otherwise the header
  // advertises a key that cannot verify this signature. (No jwk in kid mode.) It is
  // also PUBLISHED to the server, so it must be public-only: an accidentally exported
  // private JWK must never be serialized into the protected header.
  if (header.jwk) { _assertKeyType(checked.algRow, header.jwk); assertPublicJwk(header.jwk); }
  var protectedB64 = b64uEncode(Buffer.from(JSON.stringify(header), "utf8"));
  var payloadB64 = payload.length === 0 ? "" : b64uEncode(payload);
  var signingInput = Buffer.from(protectedB64 + "." + payloadB64, "ascii");
  var jwk = header.jwk || opts.jwk || {};
  var sigBuf = Buffer.from(await webcrypto.subtle.sign(_cryptoAlg(checked.algRow, jwk, opts.key), opts.key, signingInput));
  // Pin the produced signature length the same way verify does. A key whose curve /
  // hash / modulus does not match the header alg (a P-384 key under ES256, an
  // HS512 key under HS256) still signs, but emits the wrong length -- caught here
  // so the builder fails locally instead of shipping a JWS the server will reject.
  var want = _expectedSigBytes(checked.algRow, jwk, opts.key);
  if (want != null && sigBuf.length !== want) throw E("jose/bad-key", "the signing key produced a " + sigBuf.length + "-byte signature but " + checked.alg + " requires " + want + " (the key does not match the algorithm)");
  // In jwk mode the EMBEDDED public jwk is what verifiers use. Confirm it actually
  // verifies this signature -- i.e. it is the signing key's public half -- so a
  // key-pair mix-up (a jwk from a different key of the same type) fails locally
  // instead of producing a JWS the CA rejects. Same-type/curve is not enough.
  if (header.jwk) {
    var pubKey;
    try { pubKey = await webcrypto.subtle.importKey("jwk", header.jwk, _importParams(checked.algRow, header.jwk), false, ["verify"]); }
    catch (e) { throw E("jose/bad-key", "the embedded jwk could not be imported to confirm it matches the signing key", e); }
    if (!(await webcrypto.subtle.verify(_cryptoAlg(checked.algRow, header.jwk), pubKey, sigBuf, signingInput))) {
      throw E("jose/bad-key", "the embedded jwk does not match the signing key (it cannot verify the produced signature)");
    }
  }
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
  AKP: ["alg", "kty", "pub"],   // RFC 9964 sec. 6: alg, kty, pub in lexicographic order
};

/**
 * @primitive  pki.jose.thumbprint
 * @signature  pki.jose.thumbprint(jwk) -> Promise<string>
 * @since      0.1.25
 * @status     stable
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
  assertPublicJwk: assertPublicJwk,
};
