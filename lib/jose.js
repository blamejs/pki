// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.jose
 * @nav        Protocols
 * @title      JOSE (JWS / JWK)
 * @fullname   JOSE: JWS signatures and JWK keys
 * @order      10
 * @slug       jose
 *
 * @intro
 *   The JOSE message envelope (RFC 7515 JWS, RFC 7518 JWA, RFC 7638 JWK
 *   thumbprint), profiled for RFC 8555 ACME but usable on its own. A JWS here
 *   is the Flattened JSON Serialization only, `{ protected, payload,
 *   signature }`, with the multi-signature `signatures` member, the
 *   unprotected `header` member, and the RFC 7797 unencoded-payload `b64`
 *   option all structurally forbidden. Every base64url field is decoded by a
 *   strict codec (Node's `Buffer.from(s, "base64url")` accepts padding,
 *   whitespace, and non-canonical trailing bits, all of which are rejected
 *   here), and every JSON document is read by a bounded reader that rejects a
 *   duplicate member at any nesting depth (the parser-differential smuggling
 *   class `JSON.parse` silently allows).
 *
 *   Algorithms resolve through an `alg`-keyed registry (ES256/384/512,
 *   RS256/384/512, PS256/384/512, EdDSA, and the RFC 9964 ML-DSA-44/65/87 PQC
 *   rows), never a switch: the registry binds `alg` to a key type and pins the
 *   exact signature byte length before any crypto call, so `alg:"none"`, a MAC
 *   algorithm on the outer profile, an ES256/RSA-key confusion, and a DER-vs-raw
 *   ECDSA signature all fail closed. `sign` and `verify` are each driven by one
 *   declarative profile table, so the same data drives both directions.
 *
 * @card
 *   RFC 7515 Flattened JWS sign/verify + RFC 7638 JWK thumbprints, ACME-profiled:
 *   strict base64url + duplicate-rejecting JSON, an alg registry (ES/RS/PS/EdDSA
 *   + ML-DSA), signature-length pinning, fail-closed everywhere.
 */

var constants = require("./constants");
var wcEngine = require("./webcrypto");
var webcrypto = wcEngine.webcrypto;
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var edwardsPoint = require("./edwards-point");
var intrinsic = require("./guard-intrinsic");
var _isArray = intrinsic.isArray;
var _hasOwn = intrinsic.hasOwn;
var _keys = intrinsic.keys;
var _isBuffer = intrinsic.isBuffer;
var _bufferFrom = intrinsic.bufferFrom;
var _stringify = intrinsic.stringify;
var _ObjectProto = intrinsic.ObjectProto;
var _push = intrinsic.uncurry(Array.prototype.push);
var _join = intrinsic.join;
var _map = intrinsic.map;
var _bufToString = intrinsic.uncurry(Buffer.prototype.toString);

var JoseError = frameworkError.JoseError;
function E(code, message, cause) { return new JoseError(code, message, cause); }

var LIMITS = constants.LIMITS;


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
  if (!_isBuffer(bytes)) throw E("jose/bad-input", "base64url.encode requires a Buffer");
  bytes = guard.bytes.view(bytes, JoseError, "jose/bad-input", "base64url.encode input");
  return _bufToString(bytes, "base64url");
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
  return guard.encoding.base64url(text, null, E, "jose/bad-base64url", "base64url value");
}


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
  return guard.json.parse(input, E, {
    maxBytes: LIMITS.JSON_MAX_BYTES, maxDepth: LIMITS.JSON_MAX_DEPTH,
    badJson: "jose/bad-json", tooDeep: "jose/too-deep", duplicateMember: "jose/duplicate-member",
    tooLarge: "jose/too-large", badInput: "jose/bad-input", label: "the JSON document",
  });
}


var SIG_ALGS = intrinsic.assign(intrinsic.create(null), {
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
});

var MAC_ALGS = intrinsic.assign(intrinsic.create(null), {
  HS256: { kty: "oct", hash: "SHA-256", sigBytes: 32 },
  HS384: { kty: "oct", hash: "SHA-384", sigBytes: 48 },
  HS512: { kty: "oct", hash: "SHA-512", sigBytes: 64 },
});

var UNDERSTOOD_HEADER = intrinsic.assign(intrinsic.create(null), { alg: 1, nonce: 1, url: 1, jwk: 1, kid: 1, crit: 1 });


var PROFILES = intrinsic.assign(intrinsic.create(null), {
  "acme-outer":     { algs: SIG_ALGS, nonce: "required",  keyId: "one-of", requireUrl: true },
  "eab-inner":      { algs: MAC_ALGS, nonce: "forbidden", keyId: "kid",    requireUrl: true },
  "keychange-inner": { algs: SIG_ALGS, nonce: "forbidden", keyId: "jwk",    requireUrl: true },
});

function _checkHeader(header, profileName) {
  var profile = PROFILES[profileName];
  if (!profile) throw E("jose/bad-input", "unknown JWS profile " + _stringify(profileName));
  if (!header || typeof header !== "object" || _isArray(header)) throw E("jose/bad-header", "the protected header must be a JSON object");
  var own = function (k) { return _hasOwn(header, k); };
  if (own("b64")) throw E("jose/bad-jws", "the RFC 7797 b64 header parameter is forbidden");
  var alg = header.alg;
  if (!own("alg") || typeof alg !== "string") throw E("jose/bad-header", "the protected header must carry a string alg");
  var algRow = profile.algs[alg];
  if (!algRow) throw E("jose/bad-alg", "unsupported or forbidden algorithm " + _stringify(alg) + " for this JWS profile");
  if (profile.requireUrl && (!own("url") || typeof header.url !== "string" || header.url.length === 0)) throw E("jose/bad-header", "the protected header must carry a non-empty string url");
  var hasNonce = own("nonce");
  if (profile.nonce === "required") {
    if (!hasNonce || typeof header.nonce !== "string" || header.nonce.length === 0) throw E("jose/bad-header", "the protected header must carry a non-empty nonce");
    try { b64uDecode(header.nonce); } catch (e) { throw E("jose/bad-header", "the nonce is not valid base64url", e); }
  } else if (profile.nonce === "forbidden" && hasNonce) {
    throw E("jose/bad-header", "a nonce is forbidden in this inner JWS");
  }
  var hasJwk = own("jwk");
  var hasKid = own("kid");
  if (hasKid && (typeof header.kid !== "string" || header.kid.length === 0)) throw E("jose/bad-header", "kid must be a non-empty string");
  if (profile.keyId === "one-of") {
    if (hasJwk === hasKid) throw E("jose/bad-header", "the protected header must carry EXACTLY ONE of jwk / kid");
  } else if (profile.keyId === "kid") {
    if (!hasKid || hasJwk) throw E("jose/bad-header", "this JWS must identify its key by kid, not jwk");
  } else if (profile.keyId === "jwk") {
    if (!hasJwk || hasKid) throw E("jose/bad-header", "this JWS must carry an embedded jwk, not kid");
  }
  if (hasJwk && (!header.jwk || typeof header.jwk !== "object" || _isArray(header.jwk))) throw E("jose/bad-header", "jwk must be a JSON object");
  if (_hasOwn(header, "crit")) {
    var crit = header.crit;
    if (!_isArray(crit) || crit.length === 0) throw E("jose/bad-crit", "crit must be a non-empty array");
    var seen = {};
    for (var c = 0; c < crit.length; c++) {
      var name = crit[c];
      if (typeof name !== "string") throw E("jose/bad-crit", "crit entries must be strings");
      if (_hasOwn(seen, name)) throw E("jose/bad-crit", "duplicate crit entry " + _stringify(name));
      seen[name] = 1;
      if (UNDERSTOOD_HEADER[name]) throw E("jose/bad-crit", "crit must not name a standard header parameter " + _stringify(name));
      throw E("jose/bad-crit", "unprocessed critical header parameter " + _stringify(name));
    }
  }
  return { alg: alg, algRow: algRow, header: header };
}


function _importParams(algRow, jwk) {
  if (algRow.kty === "EC") return { name: "ECDSA", namedCurve: algRow.crv };
  if (algRow.kty === "RSA") return { name: algRow.subtle, hash: algRow.hash };
  if (algRow.kty === "OKP") return { name: jwk.crv };
  if (algRow.kty === "AKP") return { name: algRow.subtle };
  if (algRow.kty === "oct") return { name: "HMAC", hash: algRow.hash };
  throw E("jose/bad-alg", "unsupported key type");
}

function _cryptoAlg(algRow, jwk, key) {
  if (algRow.kty === "EC") return { name: "ECDSA", hash: algRow.hash };
  if (algRow.kty === "RSA") return algRow.subtle === "RSA-PSS" ? { name: "RSA-PSS", saltLength: algRow.saltLength } : { name: "RSASSA-PKCS1-V1_5" };
  if (algRow.kty === "OKP") return { name: (jwk && jwk.crv) || (key && key.algorithm && key.algorithm.name) };
  if (algRow.kty === "AKP") return { name: algRow.subtle };
  if (algRow.kty === "oct") return { name: "HMAC" };
  throw E("jose/bad-alg", "unsupported key type");
}

function _assertKeyType(algRow, jwk) {
  if (!jwk || typeof jwk !== "object" || typeof jwk.kty !== "string") throw E("jose/bad-key", "a JWK object with a kty is required");
  if (jwk.kty !== algRow.kty) throw E("jose/bad-alg", "the key type " + _stringify(jwk.kty) + " does not match the algorithm");
  if (algRow.kty === "EC" && jwk.crv !== algRow.crv) throw E("jose/bad-alg", "the EC curve does not match the algorithm");
  if (algRow.kty === "OKP" && jwk.crv !== "Ed25519" && jwk.crv !== "Ed448") throw E("jose/bad-alg", "unsupported OKP curve " + _stringify(jwk.crv));
  if (algRow.kty === "OKP" && typeof jwk.x === "string" && !edwardsPoint.validate(b64uDecode(jwk.x), jwk.crv === "Ed25519" ? 6 : 7)) {
    throw E("jose/bad-key", "the OKP public key is not a valid, full-order Edwards point");
  }
  if (algRow.kty === "AKP" && jwk.alg !== algRow.subtle) throw E("jose/bad-alg", "the AKP parameter set " + _stringify(jwk.alg) + " does not match the algorithm " + algRow.subtle);
}

function _expectedSigBytes(algRow, jwk, key) {
  if (algRow.sigBytes != null) return algRow.sigBytes;
  if (algRow.sigBytesByCrv) return algRow.sigBytesByCrv[(jwk && jwk.crv) || (key && key.algorithm && key.algorithm.name)] || null;
  if (algRow.kty === "RSA") {
    if (jwk && typeof jwk.n === "string") return b64uDecode(jwk.n).length;
    if (key && key.algorithm && key.algorithm.modulusLength) return key.algorithm.modulusLength / 8;
    return null;
  }
  return null;
}

var PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k", "priv"];

/**
 * @primitive  pki.jose.assertPublicJwk
 * @signature  pki.jose.assertPublicJwk(jwk) -> jwk
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 7517, RFC 7518
 * @related    pki.jose.sign, pki.jose.thumbprint
 *
 * Assert that a JWK is public-only before it is published (embedded in a JWS
 * protected header or an ACME External Account Binding payload). A JWK carrying any
 * private member (`d`, the RSA CRT parameters `p`/`q`/`dp`/`dq`/`qi`, the symmetric
 * `k`, or the AKP `priv`) throws `jose/private-key-material`, so an accidentally
 * exported private JWK is never sent to a server. Returns the JWK.
 *
 * @example
 *   pki.jose.assertPublicJwk({ kty: "EC", crv: "P-256", x: "...", y: "..." });
 */
function assertPublicJwk(jwk) {
  if (!jwk || typeof jwk !== "object" || _isArray(jwk)) throw E("jose/bad-key", "a JWK object is required");
  for (var i = 0; i < PRIVATE_JWK_MEMBERS.length; i++) {
    if (_hasOwn(jwk, PRIVATE_JWK_MEMBERS[i])) {
      throw E("jose/private-key-material", "a published JWK must be public-only; it carries the private member " + _stringify(PRIVATE_JWK_MEMBERS[i]));
    }
  }
  return jwk;
}

/**
 * @primitive  pki.jose.verify
 * @signature  pki.jose.verify(jws, opts) -> Promise<{ header, payload, keySource }>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 7515, RFC 7518, RFC 8555
 * @related    pki.jose.sign, pki.jose.parseJson
 *
 * Verify a Flattened JSON JWS against a profile (`opts.profile`, default
 * `"acme-outer"`). Structural rules fail closed before any crypto: the
 * `signatures`/`header` members and a detached payload are rejected, the
 * protected header is validated against the profile (alg registry, nonce, url,
 * exactly-one-of jwk/kid, crit), and the signature byte length is pinned per alg.
 *
 * `opts.key` names the key the message must be signed under, and it governs: where
 * the profile also permits an embedded header `jwk`, the two must be the same key
 * or the message is refused with `jose/key-mismatch`. They are compared as RFC 7638
 * thumbprints, so member order and members outside the key itself cannot make equal
 * keys look different. Without `opts.key` the embedded `jwk` is used where the
 * profile permits one, which verifies that the message is internally consistent,
 * not that any particular signer produced it. `keySource` reports which of the two
 * answered, so a signature checked against a caller-named key is distinguishable
 * from one checked against the key the message brought with it.
 *
 * Returns `{ header, payload, keySource }` (payload a raw `Buffer`); a failed
 * signature throws `jose/verify-failed`.
 *
 * @opts
 *   profile: string   // "acme-outer" | "eab-inner" | "keychange-inner"
 *   key: object       // a public JWK, required unless the profile embeds jwk
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var accountJwk = await pki.webcrypto.subtle.exportKey("jwk", ec.publicKey);
 *   var jws = await pki.jose.sign({ protected: { alg: "ES256", jwk: accountJwk,
 *     nonce: "oFvnlFP1wIhRlYS2jTaXbA", url: "https://ca.example/acme/new-acct" },
 *     payload: Buffer.from("{}"), key: ec.privateKey });
 *   var v = await pki.jose.verify(jws, { profile: "acme-outer", key: accountJwk });
 *   v.header.alg;   // -> "ES256"
 */
var _VERIFY_KEYS = { key: 1, profile: 1 };
async function verify(jws, opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _VERIFY_KEYS, E, "jose/bad-input", "unknown pki.jose.verify option ");
  if (!jws || typeof jws !== "object" || _isArray(jws)) throw E("jose/bad-jws", "a flattened JWS object is required");
  if (_hasOwn(jws, "signatures")) throw E("jose/bad-jws", "the multi-signature signatures member is forbidden");
  if (_hasOwn(jws, "header")) throw E("jose/bad-jws", "the unprotected header member is forbidden");
  if (typeof jws.protected !== "string" || typeof jws.signature !== "string") throw E("jose/bad-jws", "protected and signature must be base64url strings");
  if (typeof jws.payload !== "string") throw E("jose/bad-jws", "payload must be a base64url string (never detached)");
  var header = parseJson(b64uDecode(jws.protected));
  var profileName = opts.profile || "acme-outer";
  var checked = _checkHeader(header, profileName);
  if (opts.key !== undefined && (typeof opts.key !== "object" || opts.key === null || _isArray(opts.key))) {
    throw E("jose/bad-key", "opts.key was supplied but is not a JWK object, so the key this message must be signed under cannot be established");
  }
  var jwk = header.jwk || opts.key;
  if (!jwk) throw E("jose/bad-key", "a verification key is required (opts.key) when the profile does not embed a jwk");
  var keySource = "embedded-jwk";
  if (opts.key) {
    keySource = "opts.key";
    if (header.jwk) {
      var embeddedTp, suppliedTp;
      try { embeddedTp = await thumbprint(header.jwk); suppliedTp = await thumbprint(opts.key); }
      catch (e) { throw E("jose/bad-key", "the embedded jwk and opts.key could not be compared as RFC 7638 thumbprints", e); }
      if (embeddedTp !== suppliedTp) {
        throw E("jose/key-mismatch",
          "the JWS embeds a jwk that is not the key supplied as opts.key, so the message names a " +
          "different signer than the caller expects (embedded thumbprint " + embeddedTp +
          ", supplied " + suppliedTp + ")");
      }
    }
    jwk = opts.key;
  }
  _assertKeyType(checked.algRow, jwk);
  var sig = b64uDecode(jws.signature);
  var want = _expectedSigBytes(checked.algRow, jwk);
  if (want != null && sig.length !== want) throw E("jose/bad-signature", "the signature length " + sig.length + " is not the " + want + " bytes " + checked.alg + " requires");
  var signingInput = _bufferFrom(jws.protected + "." + jws.payload, "ascii");
  var key;
  try { key = await webcrypto.subtle.importKey("jwk", jwk, _importParams(checked.algRow, jwk), false, ["verify"]); }
  catch (e) { throw E("jose/bad-key", "the JWK could not be imported for verification", e); }
  var ok = await webcrypto.subtle.verify(_cryptoAlg(checked.algRow, jwk), key, sig, signingInput);
  if (!ok) throw E("jose/verify-failed", "the JWS signature did not verify");
  return { header: header, payload: b64uDecode(jws.payload), keySource: keySource };
}


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
 * The key need not have been created by this toolkit's own WebCrypto: one from the platform's, or from a
 * separately-installed copy of this toolkit, is re-imported through this engine, since it carries none of
 * the material this engine signs with. A key created non-extractable cannot be re-imported, and is refused
 * with that as the reason, as is one whose implementation keeps its material out of reach entirely.
 *
 * @opts
 *   protected: object    // the protected header (alg, nonce, url, jwk|kid)
 *   payload: Buffer      // the raw payload octets ("" for POST-as-GET)
 *   key: CryptoKey       // the private signing key
 *   profile: string      // default "acme-outer"
 *   jwk: object          // the public JWK, in kid mode (a header that embeds jwk supplies its own)
 *
 * @example
 *   var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var priv = ec.privateKey;
 *   var hdr = { alg: "ES256", jwk: await pki.webcrypto.subtle.exportKey("jwk", ec.publicKey),
 *     nonce: "oFvnlFP1wIhRlYS2jTaXbA", url: "https://ca.example/acme/new-acct" };
 *   var jws = await pki.jose.sign({ protected: hdr, payload: Buffer.from("{}"), key: priv });
 */
var _SIGN_KEYS = { protected: 1, payload: 1, key: 1, jwk: 1, profile: 1 };
var _SIGN_KEYS_EMBEDDED_JWK = { protected: 1, payload: 1, key: 1, profile: 1 };
async function sign(opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _SIGN_KEYS, E, "jose/bad-input", "unknown pki.jose.sign option ");
  var headerJson;
  try { headerJson = _stringify(opts.protected); }
  catch (e) { throw E("jose/bad-header", "the protected header must be JSON-serializable", e); }
  var headerBytes = headerJson === undefined ? null : _bufferFrom(headerJson, "utf8");
  var header = headerBytes === null ? opts.protected : parseJson(headerBytes);
  var embedsJwk = !!(header && typeof header === "object" && header.jwk);
  if (embedsJwk) {
    guard.identifier.assertKnownKeys(opts, _SIGN_KEYS_EMBEDDED_JWK, E, "jose/bad-input", function (k) {
      return "unknown pki.jose.sign option " + _stringify(k) +
        (k === "jwk" ? "; the protected header already embeds the public JWK" : "");
    });
  }
  var payload = opts.payload;
  if (!_isBuffer(payload)) throw E("jose/bad-input", "payload must be a Buffer (empty Buffer for POST-as-GET)");
  payload = guard.bytes.view(payload, JoseError, "jose/bad-input", "payload");
  if (!wcEngine.isCryptoKeyLike(opts.key)) throw E("jose/bad-input", "a private or secret CryptoKey (opts.key) is required");
  var checked = _checkHeader(header, opts.profile || "acme-outer");
  if ((checked.algRow.kty === "RSA" || checked.algRow.kty === "oct") &&
      (!opts.key.algorithm.hash || opts.key.algorithm.hash.name !== checked.algRow.hash)) {
    throw E("jose/bad-key", "the signing key's hash does not match the algorithm " + checked.alg);
  }
  if (header.jwk) { _assertKeyType(checked.algRow, header.jwk); assertPublicJwk(header.jwk); }
  var protectedB64 = b64uEncode(headerBytes);
  var payloadB64 = payload.length === 0 ? "" : b64uEncode(payload);
  var signingInput = _bufferFrom(protectedB64 + "." + payloadB64, "ascii");
  var jwk = header.jwk || opts.jwk || {};
  var signKey = await wcEngine.adoptKey(opts.key, null, ["sign"], E, "jose/bad-input");
  var sigBuf = _bufferFrom(await webcrypto.subtle.sign(_cryptoAlg(checked.algRow, jwk, signKey), signKey, signingInput));
  var want = _expectedSigBytes(checked.algRow, jwk, opts.key);
  if (want != null && sigBuf.length !== want) throw E("jose/bad-key", "the signing key produced a " + sigBuf.length + "-byte signature but " + checked.alg + " requires " + want + " (the key does not match the algorithm)");
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


var THUMBPRINT_MEMBERS = intrinsic.assign(intrinsic.create(null), {
  EC: ["crv", "kty", "x", "y"],
  RSA: ["e", "kty", "n"],
  oct: ["k", "kty"],
  OKP: ["crv", "kty", "x"],
  AKP: ["alg", "kty", "pub"],
});

/**
 * @primitive  pki.jose.thumbprint
 * @signature  pki.jose.thumbprint(jwk) -> Promise<string>
 * @since      0.1.25
 * @status     stable
 * @spec       RFC 7638, RFC 8037, RFC 9964
 * @related    pki.jose.verify
 *
 * The RFC 7638 JWK SHA-256 thumbprint as base64url: the canonical JSON of just
 * the key type's required members, lexicographically ordered, no whitespace,
 * hashed. Optional members (`alg`, `use`, `kid`) are excluded, so the same key
 * always yields the same thumbprint (the ACME key-authorization anchor).
 *
 * @example
 *   // the RFC 7638 sec. 3.1 worked example, so the thumbprint below is the spec's own
 *   var accountJwk = { kty: "RSA", e: "AQAB", n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L" +
 *     "hWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXA" +
 *     "rwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajr" +
 *     "n1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-" +
 *     "kEgU8awapJzKnqDKgw" };
 *   await pki.jose.thumbprint(accountJwk);   // -> "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
 */
async function thumbprint(jwk) {
  if (!jwk || typeof jwk !== "object" || typeof jwk.kty !== "string") throw E("jose/bad-key", "a JWK object with a kty is required");
  var members = THUMBPRINT_MEMBERS[jwk.kty];
  if (!members) throw E("jose/bad-key", "unsupported JWK key type " + _stringify(jwk.kty));
  var parts = [];
  for (var i = 0; i < members.length; i++) {
    var m = members[i];
    if (typeof jwk[m] !== "string") throw E("jose/bad-key", "the JWK is missing the required member " + _stringify(m));
    _push(parts, _stringify(m) + ":" + _stringify(jwk[m]));
  }
  var canonical = "{" + _join(parts, ",") + "}";
  var digest = _bufferFrom(await webcrypto.subtle.digest("SHA-256", _bufferFrom(canonical, "utf8")));
  return b64uEncode(digest);
}

/**
 * @primitive  pki.jose.sigAlgs
 * @signature  pki.jose.sigAlgs() -> Array<{alg,kty,crv,hash,saltLength}>
 * @since      0.5.3
 * @status     stable
 * @spec       RFC 7518 sec. 3, RFC 8037, RFC 9964
 * @related    pki.jose.verify
 *
 * The JWS signature algorithms this toolkit verifies, one row per `alg`, each
 * naming the JWK key type it requires (`kty`, plus the exact `crv` where the
 * curve is fixed), the hash, and the RSASSA-PSS salt length where the algorithm
 * is PSS. Rows describe key material in RFC 7517 / 7518 vocabulary only, so a
 * caller can decide whether a key it holds can sign or verify a given `alg`
 * without a table of its own.
 *
 * MAC algorithms are deliberately absent: `HS*` is not a signature algorithm and
 * listing it beside `RS256` is how the HMAC key-confusion class starts. `none`
 * does not exist here at all.
 *
 * Each call returns a fresh array of fresh rows. The registry that drives
 * verification is never handed out, so nothing a caller does to the result can
 * widen what a signature check accepts.
 *
 * @example
 *   var pss = pki.jose.sigAlgs().filter(function (r) { return r.saltLength; });
 *   pss.map(function (r) { return r.alg; });   // -> ["PS256", "PS384", "PS512"]
 */
function sigAlgs() {
  return _map(_keys(SIG_ALGS), function (alg) {
    var row = SIG_ALGS[alg];
    var out = { alg: alg, kty: row.kty };
    if (row.crv) out.crv = row.crv;
    if (row.hash) out.hash = row.hash;
    if (row.saltLength) out.saltLength = row.saltLength;
    return out;
  });
}

module.exports = {
  base64url: { encode: b64uEncode, decode: b64uDecode },
  sigAlgs: sigAlgs,
  parseJson: parseJson,
  verify: verify,
  sign: sign,
  thumbprint: thumbprint,
  assertPublicJwk: assertPublicJwk,
};
