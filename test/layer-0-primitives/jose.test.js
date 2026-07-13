// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.jose (RFC 7515 JWS / RFC 7518 JWA / RFC 7638 thumbprint).
 * RED-first: pki.jose is undefined until the module lands, so every vector
 * throws. Strict base64url + a duplicate-rejecting bounded JSON reader are the
 * two engine gaps; the alg registry, JWS sign/verify against the three profiles,
 * and JWK thumbprints compose on top.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var C = require("../../lib/constants");
var subtle = require("../../lib/webcrypto").webcrypto.subtle;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
async function acode(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }

var OUTER = { profile: "acme-outer" };
function outerHeader(o) { o = o || {}; var h = { alg: o.alg || "ES256", nonce: o.nonce !== undefined ? o.nonce : "AAAA", url: o.url !== undefined ? o.url : "https://ca.example/o" }; if (o.jwk) h.jwk = o.jwk; if (o.kid) h.kid = o.kid; if (o.extra) Object.keys(o.extra).forEach(function (k) { h[k] = o.extra[k]; }); return h; }

// ---- JWS sign/verify (jose, ACME outer profile) ----------------------
async function testJws() {
  var ec = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var ecJwk = await subtle.exportKey("jwk", ec.publicKey);
  var jws = await pki.jose.sign({ protected: outerHeader({ jwk: ecJwk }), payload: Buffer.from("{}"), key: ec.privateKey });
  // 25. a well-formed ES256 JWS verifies; one flipped signature byte fails.
  var v = await pki.jose.verify(jws, OUTER);
  check("25. ES256 JWS verify + payload", v.header.alg === "ES256" && v.payload.equals(Buffer.from("{}")));
  var flipped = Object.assign({}, jws, { signature: pki.jose.base64url.encode((function () { var b = Buffer.from(pki.jose.base64url.decode(jws.signature)); b[0] ^= 1; return b; })()) });
  check("25b. flipped signature fails", (await acode(function () { return pki.jose.verify(flipped, OUTER); })) === "jose/verify-failed");
  // 31/32. payload / header tamper fails verify (signing-input pin).
  check("31. payload tamper fails", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { payload: pki.jose.base64url.encode(Buffer.from("{ }")) }), OUTER); })) === "jose/verify-failed");
  check("32. header tamper fails", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ jwk: ecJwk, url: "https://ca.example/x" })))) }), OUTER); })) === "jose/verify-failed");
  // 9-11. alg none / MAC / unknown rejected.
  check("9. alg none rejected", (await acode(function () { return pki.jose.verify({ protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ alg: "none", jwk: ecJwk })))), payload: "", signature: "" }, OUTER); })) === "jose/bad-alg");
  check("10. HS256 on outer rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ alg: "HS256", jwk: ecJwk })))) }), OUTER); })) === "jose/bad-alg");
  check("11. unknown alg rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ alg: "ES256K", jwk: ecJwk })))) }), OUTER); })) === "jose/bad-alg");
  // 12. ES256 header with an RSA key rejected BEFORE crypto.
  var rsa = await subtle.generateKey({ name: "RSASSA-PKCS1-V1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  var rsaJwk = await subtle.exportKey("jwk", rsa.publicKey);
  check("12. ES256/RSA-key confusion rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ alg: "ES256", jwk: rsaJwk })))) }), OUTER); })) === "jose/bad-alg");
  // 13/14. both jwk+kid / neither rejected.
  check("13. both jwk+kid rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ jwk: ecJwk, kid: "https://ca.example/acct/1" })))) }), OUTER); })) === "jose/bad-header");
  check("14. neither jwk nor kid rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify({ alg: "ES256", nonce: "AAAA", url: "https://ca.example/o" }))) }), OUTER); })) === "jose/bad-header");
  // 15-18. missing nonce/url + bad nonce encoding rejected.
  check("15. missing nonce rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify({ alg: "ES256", url: "https://ca.example/o", jwk: ecJwk }))) }), OUTER); })) === "jose/bad-header");
  check("16. missing url rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify({ alg: "ES256", nonce: "AAAA", jwk: ecJwk }))) }), OUTER); })) === "jose/bad-header");
  check("18. bad nonce encoding rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ jwk: ecJwk, nonce: "ab==" })))) }), OUTER); })) === "jose/bad-header");
  // 19-21. unprotected header / multi-sig / b64 rejected.
  check("19. unprotected header rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { header: {} }), OUTER); })) === "jose/bad-jws");
  check("20. multi-signature rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { signatures: [] }), OUTER); })) === "jose/bad-jws");
  check("21. b64 header rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ jwk: ecJwk, extra: { b64: false } })))) }), OUTER); })) === "jose/bad-jws");
  // 22-24. crit variants rejected.
  check("22. crit unknown rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ jwk: ecJwk, extra: { crit: ["exp"] } })))) }), OUTER); })) === "jose/bad-crit");
  check("23. crit empty rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ jwk: ecJwk, extra: { crit: [] } })))) }), OUTER); })) === "jose/bad-crit");
  check("24. crit standard-name rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { protected: pki.jose.base64url.encode(Buffer.from(JSON.stringify(outerHeader({ jwk: ecJwk, extra: { crit: ["alg"] } })))) }), OUTER); })) === "jose/bad-crit");
  // 26/27. DER-encoded sig (wrong length) + all-zero sig rejected.
  check("26. DER-length ECDSA sig rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { signature: pki.jose.base64url.encode(Buffer.alloc(70)) }), OUTER); })) === "jose/bad-signature");
  check("27. all-zero ES256 sig fails (psychic canary)", (await acode(function () { return pki.jose.verify(Object.assign({}, jws, { signature: pki.jose.base64url.encode(Buffer.alloc(64)) }), OUTER); })) === "jose/verify-failed");
  // 28/29/30. EdDSA / ML-DSA / RS256 round-trip through the registry.
  var ed = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var edJwk = await subtle.exportKey("jwk", ed.publicKey);
  var edJws = await pki.jose.sign({ protected: outerHeader({ alg: "EdDSA", jwk: edJwk }), payload: Buffer.from("{}"), key: ed.privateKey });
  check("28. EdDSA round-trip", (await pki.jose.verify(edJws, OUTER)).header.alg === "EdDSA");
  // 28b. an EdDSA kid-signed request (no embedded jwk) must still sign -- the curve
  // comes from the signing key, not the absent header jwk.
  var edKidJws = await pki.jose.sign({ protected: { alg: "EdDSA", nonce: "aGVsbG8", url: "https://ca.example/o", kid: "https://ca.example/acct/1" }, payload: Buffer.from("{}"), key: ed.privateKey });
  check("28b. EdDSA kid-signed (no jwk) signs and verifies", typeof edKidJws.signature === "string" && (await pki.jose.verify(edKidJws, { profile: "acme-outer", key: edJwk })).header.kid === "https://ca.example/acct/1");
  // 28c. a non-string kid in the one-of (acme-outer) profile is rejected before serialization.
  check("28c. non-string kid rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "EdDSA", nonce: "aGVsbG8", url: "https://ca.example/o", kid: 123 }, payload: Buffer.from("{}"), key: ed.privateKey }); })) === "jose/bad-header");
  // 28d. a non-CryptoKey signing key fails closed (not a bare TypeError from subtle.sign).
  check("28d. non-CryptoKey key rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", nonce: "aGVsbG8", url: "https://ca.example/o", kid: "https://ca.example/a" }, payload: Buffer.from("{}"), key: Buffer.from("notakey") }); })) === "jose/bad-input");
  // 28e. a key whose curve does not match the alg produces the wrong signature length -> caught at sign.
  var ec384 = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
  check("28e. wrong-curve signing key (P-384 under ES256) rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", nonce: "aGVsbG8", url: "https://ca.example/o", kid: "https://ca.example/a" }, payload: Buffer.from("{}"), key: ec384.privateKey }); })) === "jose/bad-key");
  // 28f. an embedded jwk must match the alg (verify enforces the same binding), so a
  // header advertising an RSA key while signing with an EC key is rejected.
  check("28f. embedded jwk not matching the alg rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", nonce: "aGVsbG8", url: "https://ca.example/o", jwk: { kty: "RSA", e: "AQAB", n: "0vx7" } }, payload: Buffer.from("{}"), key: ec.privateKey }); })) === "jose/bad-alg");
  // 28g/h. a private JWK must never be embedded in a protected header (key leak).
  var ecPrivJwk = await subtle.exportKey("jwk", ec.privateKey);   // carries the private `d`
  check("28g. sign with a private embedded jwk rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", nonce: "aGVsbG8", url: "https://ca.example/o", jwk: ecPrivJwk }, payload: Buffer.from("{}"), key: ec.privateKey }); })) === "jose/private-key-material");
  check("28h. assertPublicJwk rejects private, accepts public", code(function () { pki.jose.assertPublicJwk(ecPrivJwk); }) === "jose/private-key-material" && pki.jose.assertPublicJwk(ecJwk) === ecJwk);
  // 28i. inherited (prototype) header fields are rejected -- JSON.stringify would drop them.
  check("28i. inherited header fields rejected", (await acode(function () { return pki.jose.sign({ protected: Object.create({ alg: "ES256", nonce: "aGVsbG8", url: "https://ca.example/o", kid: "https://ca.example/a" }), payload: Buffer.from("{}"), key: ec.privateKey }); })) === "jose/bad-header");
  // 28j. an embedded jwk from a DIFFERENT key of the same type is rejected (it cannot verify).
  var ecOther = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var ecOtherJwk = await subtle.exportKey("jwk", ecOther.publicKey);
  check("28j. embedded jwk not matching the signing key rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", nonce: "aGVsbG8", url: "https://ca.example/o", jwk: ecOtherJwk }, payload: Buffer.from("{}"), key: ec.privateKey }); })) === "jose/bad-key");
  // 28k-m. empty nonce / url / kid are each rejected (a Replay-Nonce / URL / account kid is non-empty).
  check("28k. empty nonce rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", nonce: "", url: "https://ca.example/o", kid: "https://ca.example/a" }, payload: Buffer.from("{}"), key: ec.privateKey }); })) === "jose/bad-header");
  check("28l. empty url rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", nonce: "aGVsbG8", url: "", kid: "https://ca.example/a" }, payload: Buffer.from("{}"), key: ec.privateKey }); })) === "jose/bad-header");
  check("28m. empty kid rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", nonce: "aGVsbG8", url: "https://ca.example/o", kid: "" }, payload: Buffer.from("{}"), key: ec.privateKey }); })) === "jose/bad-header");
  var md = await subtle.generateKey({ name: "ML-DSA-65" }, true, ["sign", "verify"]);
  var mdJwk = await subtle.exportKey("jwk", md.publicKey);
  var mdJws = await pki.jose.sign({ protected: outerHeader({ alg: "ML-DSA-65", jwk: mdJwk }), payload: Buffer.from("{}"), key: md.privateKey });
  check("29. ML-DSA-65 round-trip + siglen 3309", pki.jose.base64url.decode(mdJws.signature).length === 3309 && (await pki.jose.verify(mdJws, OUTER)).header.alg === "ML-DSA-65");
  // 29b. an AKP jwk whose parameter set disagrees with the alg is rejected (an
  // ML-DSA-65 header must not embed an ML-DSA-44-labelled JWK).
  check("29b. AKP param-set mismatch rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ML-DSA-65", nonce: "aGVsbG8", url: "https://ca.example/o", jwk: Object.assign({}, mdJwk, { alg: "ML-DSA-44" }) }, payload: Buffer.from("{}"), key: md.privateKey }); })) === "jose/bad-alg");
  var rsJws = await pki.jose.sign({ protected: outerHeader({ alg: "RS256", jwk: rsaJwk }), payload: Buffer.from("{}"), key: rsa.privateKey });
  check("30. RS256 round-trip", (await pki.jose.verify(rsJws, OUTER)).header.alg === "RS256");
  // 30b. an RSA key whose bound hash disagrees with the alg is rejected at sign
  // (the modulus length is identical, so the length pin cannot catch it).
  var rsa512 = await subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-512" }, true, ["sign", "verify"]);
  check("30b. RSA SHA-512 key under RS256 rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "RS256", nonce: "aGVsbG8", url: "https://ca.example/o", kid: "https://ca.example/a" }, payload: Buffer.from("{}"), key: rsa512.privateKey }); })) === "jose/bad-key");
  // 33. POST-as-GET payload is the empty string; challenge-response is b64u("{}").
  var getJws = await pki.jose.sign({ protected: outerHeader({ jwk: ecJwk }), payload: Buffer.alloc(0), key: ec.privateKey });
  check("33. POST-as-GET payload empty vs {}", getJws.payload === "" && jws.payload === pki.jose.base64url.encode(Buffer.from("{}")));
}

// ---- JWK thumbprint (RFC 7638 / RFC 8037 / RFC 9964) -----------------
async function testThumbprint() {
  // 34. RFC 7638 sec. 3.1 RSA known answer.
  var rsaJwk = { kty: "RSA", n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", e: "AQAB" };
  check("34. RFC 7638 RSA thumbprint KAT", (await pki.jose.thumbprint(rsaJwk)) === "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
  // 35. RFC 8037 sec. A.3 OKP Ed25519 known answer.
  var okpJwk = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
  check("35. RFC 8037 OKP thumbprint KAT", (await pki.jose.thumbprint(okpJwk)) === "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  // 36. optional members (alg/use/kid) never enter the hash.
  var withOpt = Object.assign({}, rsaJwk, { alg: "RS256", use: "sig", kid: "x" });
  check("36. thumbprint ignores optional members", (await pki.jose.thumbprint(withOpt)) === (await pki.jose.thumbprint(rsaJwk)));
  // 38. AKP (ML-DSA) thumbprint members per RFC 9964.
  var md = await subtle.generateKey({ name: "ML-DSA-44" }, true, ["sign", "verify"]);
  var mdJwk = await subtle.exportKey("jwk", md.publicKey);
  check("38. AKP ML-DSA thumbprint", typeof (await pki.jose.thumbprint(mdJwk)) === "string" && (await pki.jose.thumbprint(mdJwk)).length > 0);
  // 38b. the AKP thumbprint includes alg (RFC 9964 sec. 6) -- required, and part of the digest.
  var tpA = await pki.jose.thumbprint({ kty: "AKP", alg: "ML-DSA-65", pub: "AQID" });
  var tpB = await pki.jose.thumbprint({ kty: "AKP", alg: "ML-DSA-44", pub: "AQID" });
  check("38b. AKP thumbprint requires and includes alg", tpA !== tpB && (await acode(function () { return pki.jose.thumbprint({ kty: "AKP", pub: "AQID" }); })) === "jose/bad-key");
}

// ---- base64url codec (RFC 7515 sec. 2 / RFC 8555 sec. 6.1) -----------
function testBase64url() {
  var b64u = pki.jose.base64url;
  // 4. encode/decode round-trip across all length classes (0..3 mod 4).
  var ok = true;
  for (var len = 0; len <= 12; len++) {
    var buf = Buffer.alloc(len); for (var k = 0; k < len; k++) buf[k] = (k * 37 + 11) & 0xff;
    if (!b64u.decode(b64u.encode(buf)).equals(buf)) ok = false;
  }
  check("4. base64url round-trip across lengths", ok && b64u.encode(Buffer.from([1, 2, 3])) === "AQID");
  // 1. trailing '=' padding rejected (RFC 8555 MUST-reject).
  check("1. base64url padding rejected", code(function () { b64u.decode("AQAB="); }) === "jose/bad-base64url");
  // 2. non-alphabet characters rejected (+, /, space, newline).
  check("2a. base64url '+' rejected", code(function () { b64u.decode("ab+d"); }) === "jose/bad-base64url");
  check("2b. base64url '/' rejected", code(function () { b64u.decode("ab/d"); }) === "jose/bad-base64url");
  check("2c. base64url space rejected", code(function () { b64u.decode("ab d"); }) === "jose/bad-base64url");
  check("2d. base64url newline rejected", code(function () { b64u.decode("ab\nd"); }) === "jose/bad-base64url");
  // 3. non-canonical final character (non-zero discarded bits) rejected.
  check("3. non-canonical base64url rejected", code(function () { b64u.decode("AB"); }) === "jose/bad-base64url");
  check("3b. canonical short value accepted", b64u.decode("AA").equals(Buffer.from([0])) && b64u.decode("AQ").equals(Buffer.from([1])));
}

// ---- strict bounded JSON reader --------------------------------------
function testJsonReader() {
  // 5. a duplicate member (top-level and nested) rejected -- JSON.parse would last-win.
  check("5a. duplicate top-level member rejected", code(function () { pki.jose.parseJson('{"a":1,"a":2}'); }) === "jose/duplicate-member");
  check("5b. duplicate nested member rejected", code(function () { pki.jose.parseJson('{"o":{"x":1,"x":2}}'); }) === "jose/duplicate-member");
  check("5c. distinct members parse", pki.jose.parseJson('{"a":1,"b":2}').b === 2);
  // A "__proto__" member must become an OWN property -- never mutate the returned
  // object's prototype (pollution) and never slip past the duplicate-member gate
  // (a primitive assignment to __proto__ creates no own property, so a naive
  // hasOwnProperty check would miss the repeat).
  check("5d. __proto__ member does not pollute the prototype", (function () {
    var r = pki.jose.parseJson('{"__proto__":{"polluted":1}}');
    return Object.getPrototypeOf(r) === Object.prototype && r.polluted === undefined && Object.prototype.hasOwnProperty.call(r, "__proto__");
  })());
  check("5e. duplicate __proto__ member rejected", code(function () { pki.jose.parseJson('{"__proto__":1,"__proto__":2}'); }) === "jose/duplicate-member");
  // 5f. a detached-backed Buffer reads as zero-length: fail closed typed here
  // (the text guard re-views through the byte guard), not decode as empty.
  check("5f. detached-backed Buffer rejected", code(function () {
    var ab = new ArrayBuffer(8); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] });
    pki.jose.parseJson(b);
  }) === "jose/bad-input");
  check("5f. duplicate __proto__ member at depth rejected", code(function () { pki.jose.parseJson('{"h":{"__proto__":1,"__proto__":2}}'); }) === "jose/duplicate-member");
  // 6. nesting one past the depth cap rejected.
  var deep = "[".repeat(C.LIMITS.JSON_MAX_DEPTH + 1) + "1" + "]".repeat(C.LIMITS.JSON_MAX_DEPTH + 1);
  check("6. depth cap enforced", code(function () { pki.jose.parseJson(deep); }) === "jose/too-deep");
  var atCap = "[".repeat(C.LIMITS.JSON_MAX_DEPTH) + "1" + "]".repeat(C.LIMITS.JSON_MAX_DEPTH);
  check("6b. depth at cap accepted", Array.isArray(pki.jose.parseJson(atCap)));
  // 7. a document over the byte cap rejected BEFORE parsing.
  var big = Buffer.concat([Buffer.from('"'), Buffer.alloc(C.LIMITS.JSON_MAX_BYTES, 0x61), Buffer.from('"')]);
  check("7. size cap enforced", code(function () { pki.jose.parseJson(big); }) === "jose/too-large");
  // 8. invalid UTF-8 in a decoded document rejected.
  check("8. invalid UTF-8 rejected", code(function () { pki.jose.parseJson(Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])); }) === "jose/bad-json");
  // trailing content after the value rejected.
  check("8b. trailing content rejected", code(function () { pki.jose.parseJson('{"a":1} junk'); }) === "jose/bad-json");
  // 8c. malformed JSON numbers (RFC 8259 grammar) rejected -- a lenient Number()
  // would accept these, reintroducing a parser differential.
  ["01", "1.", "1.e1", "-", "1e", "1e+", "00", "-01", ".5", "+1"].forEach(function (bad) {
    check("8c. malformed number " + JSON.stringify(bad) + " rejected", code(function () { pki.jose.parseJson('{"n":' + bad + '}'); }) === "jose/bad-json");
  });
  // 8d. well-formed numbers still parse.
  check("8d. valid numbers parse", pki.jose.parseJson('{"a":0,"b":-1.5,"c":1e10,"d":-1.5E+3,"e":0.5}').d === -1500);
}

function detach() { var ab = new ArrayBuffer(8); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] }); return b; }

async function testEncodeBoundaryGuards() {
  // The encode side must fail closed on a detached-backed Buffer (which reads as
  // zero-length) rather than silently encoding / signing an EMPTY value.
  check("base64url.encode rejects a detached Buffer", code(function () { pki.jose.base64url.encode(detach()); }) === "jose/bad-input");
  var kp = await pki.webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var err = null;
  try { await pki.jose.sign({ protected: { alg: "ES256" }, payload: detach(), key: kp.privateKey }); }
  catch (e) { err = e; }
  check("sign rejects a detached payload (no silent empty POST-as-GET signature)", err && err.code === "jose/bad-input");
}

// ---- profile dispatch + fail-closed error branches -------------------
// Every path here is an adversarial / malformed input that must fail closed with
// a typed jose/* fault (or, for the EAB / keychange / PS256 rows, an alg the
// registry permits that must ROUND-TRIP), driving the shipped verify/sign path.
async function testProfileAndErrorBranches() {
  var ec = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var ecJwk = await subtle.exportKey("jwk", ec.publicKey);
  var enc = function (o) { return pki.jose.base64url.encode(Buffer.from(JSON.stringify(o))); };
  var good = await pki.jose.sign({ protected: outerHeader({ jwk: ecJwk }), payload: Buffer.from("{}"), key: ec.privateKey });

  // 40. an unknown JWS profile name fails closed -- never silently a default profile.
  check("40. unknown profile rejected", (await acode(function () { return pki.jose.verify(good, { profile: "no-such-profile", key: ecJwk }); })) === "jose/bad-input");
  // 41. a protected header that decodes to a non-object (array / number / null) rejected.
  check("41a. array protected header rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc([1, 2, 3]) }), OUTER); })) === "jose/bad-header");
  check("41b. numeric protected header rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc(5) }), OUTER); })) === "jose/bad-header");
  check("41c. null protected header rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc(null) }), OUTER); })) === "jose/bad-header");
  // 42. a jwk present but not a JSON object (a bare string) rejected.
  check("42. non-object jwk rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc(outerHeader({ jwk: "notanobject" })) }), OUTER); })) === "jose/bad-header");
  // 43. a jwk object lacking kty reaches the key-type gate and fails closed.
  check("43. jwk without kty rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc(outerHeader({ jwk: { foo: 1 } })) }), OUTER); })) === "jose/bad-key");
  // 44. an EC jwk whose curve disagrees with the alg (P-384 under ES256) rejected.
  check("44. EC curve mismatch rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc(outerHeader({ jwk: { kty: "EC", crv: "P-384", x: "AAAA", y: "AAAA" } })) }), OUTER); })) === "jose/bad-alg");
  // 45. an OKP jwk on an unsupported curve (X25519 under EdDSA) rejected.
  check("45. unsupported OKP curve rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc(outerHeader({ alg: "EdDSA", jwk: { kty: "OKP", crv: "X25519", x: "AAAA" } })) }), OUTER); })) === "jose/bad-alg");
  // 46. a crit entry that is not a string rejected.
  check("46. non-string crit entry rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc(outerHeader({ jwk: ecJwk, extra: { crit: [123] } })) }), OUTER); })) === "jose/bad-crit");
  // 47. an EC jwk with the right kty/curve but an unimportable point fails closed at import
  // (the length pin passes on a 64-byte sig; the invalid point throws inside importKey).
  check("47. unimportable EC point rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc(outerHeader({ jwk: { kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA" } })), signature: pki.jose.base64url.encode(Buffer.alloc(64)) }), OUTER); })) === "jose/bad-key");
  // 47b. an RS256 jwk missing the modulus n: the signature-length pin cannot be
  // resolved (no modulus to measure and no signing key on the verify side), so it is
  // skipped and the malformed key fails closed at importKey -- never a length bypass.
  check("47b. RSA jwk without modulus n fails closed at import", (await acode(function () { return pki.jose.verify(Object.assign({}, good, { protected: enc(outerHeader({ alg: "RS256", jwk: { kty: "RSA", e: "AQAB" } })) }), OUTER); })) === "jose/bad-key");

  // 48. verify with NO opts at all still verifies an embedded-jwk JWS (opts defaulting).
  check("48. verify with no opts (embedded jwk) succeeds", (await pki.jose.verify(good)).header.alg === "ES256");
  // 49. a kid-mode JWS with no opts.key has no verification key and fails closed.
  var kidJws = await pki.jose.sign({ protected: { alg: "ES256", nonce: "AAAA", url: "https://ca.example/o", kid: "https://ca.example/a" }, payload: Buffer.from("{}"), key: ec.privateKey });
  check("49. kid-mode JWS without opts.key rejected", (await acode(function () { return pki.jose.verify(kidJws, { profile: "acme-outer" }); })) === "jose/bad-key");
  // 50. a non-object / array / string JWS envelope rejected.
  check("50a. null JWS rejected", (await acode(function () { return pki.jose.verify(null, OUTER); })) === "jose/bad-jws");
  check("50b. array JWS rejected", (await acode(function () { return pki.jose.verify([], OUTER); })) === "jose/bad-jws");
  check("50c. string JWS rejected", (await acode(function () { return pki.jose.verify("nope", OUTER); })) === "jose/bad-jws");
  // 51. a non-string (detached) payload rejected -- payload is never detached here.
  check("51. non-string payload rejected", (await acode(function () { return pki.jose.verify({ protected: "x", signature: "y", payload: null }, OUTER); })) === "jose/bad-jws");
  // 51b. a string protected header with a NON-string signature rejected: the second
  // arm of the protected/signature type gate must fire independently of the first.
  check("51b. non-string signature rejected", (await acode(function () { return pki.jose.verify({ protected: "abc", signature: 123, payload: "x" }, OUTER); })) === "jose/bad-jws");

  // 52. an embedded jwk that passes the key-type + public-only gates but is an
  // unimportable point fails closed when sign confirms it matches the signing key.
  check("52. sign embedded unimportable jwk rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", nonce: "AAAA", url: "https://ca.example/o", jwk: { kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA" } }, payload: Buffer.from("{}"), key: ec.privateKey }); })) === "jose/bad-key");
  // 53. sign with no opts / a non-Buffer payload fails closed (never a bare TypeError).
  check("53a. sign with no opts rejected", (await acode(function () { return pki.jose.sign(); })) === "jose/bad-input");
  check("53b. sign with a non-Buffer payload rejected", (await acode(function () { return pki.jose.sign({ protected: {}, payload: "notabuffer", key: {} }); })) === "jose/bad-input");

  // 54. the base64url encoder requires a Buffer.
  check("54. base64url.encode requires a Buffer", (code(function () { pki.jose.base64url.encode("notabuffer"); })) === "jose/bad-input");
  // 55. assertPublicJwk requires a JWK object (null / array rejected).
  check("55a. assertPublicJwk(null) rejected", (code(function () { pki.jose.assertPublicJwk(null); })) === "jose/bad-key");
  check("55b. assertPublicJwk([]) rejected", (code(function () { pki.jose.assertPublicJwk([1]); })) === "jose/bad-key");
  // 56. thumbprint requires a JWK object with a kty, and a known kty.
  check("56a. thumbprint(null) rejected", (await acode(function () { return pki.jose.thumbprint(null); })) === "jose/bad-key");
  check("56b. thumbprint without kty rejected", (await acode(function () { return pki.jose.thumbprint({ x: "a" }); })) === "jose/bad-key");
  check("56c. thumbprint unsupported kty rejected", (await acode(function () { return pki.jose.thumbprint({ kty: "XYZ", x: "a" }); })) === "jose/bad-key");
}

// ---- eab-inner (HS*) + keychange-inner (jwk) + PS256/RS256 profiles ---
// The EAB-inner profile is the ONLY place HS* is accepted (RFC 8555 sec. 7.3.4);
// its key-id rule is kid-only and a nonce is forbidden. keychange-inner is jwk-only.
async function testInnerProfilesAndRsaVariants() {
  // eab-inner: an HS256 MAC JWS round-trips through _importParams / _cryptoAlg (oct).
  var hmac = await subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"]);
  var octJwk = await subtle.exportKey("jwk", hmac);
  var eab = await pki.jose.sign({ protected: { alg: "HS256", url: "https://ca.example/o", kid: "eab-kid" }, payload: Buffer.from("{}"), key: hmac, profile: "eab-inner" });
  check("57. eab-inner HS256 round-trip", (await pki.jose.verify(eab, { profile: "eab-inner", key: octJwk })).header.alg === "HS256");
  // 58. a nonce is forbidden in the eab-inner JWS.
  check("58. eab-inner nonce forbidden", (await acode(function () { return pki.jose.sign({ protected: { alg: "HS256", nonce: "AAAA", url: "https://ca.example/o", kid: "eab-kid" }, payload: Buffer.from("{}"), key: hmac, profile: "eab-inner" }); })) === "jose/bad-header");
  // 59. eab-inner identifies its key by kid, not jwk -- an embedded jwk is rejected.
  check("59. eab-inner jwk (not kid) rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "HS256", url: "https://ca.example/o", jwk: octJwk }, payload: Buffer.from("{}"), key: hmac, profile: "eab-inner" }); })) === "jose/bad-header");

  // keychange-inner: jwk-only. A kid is rejected; an embedded jwk round-trips.
  var ec = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var ecJwk = await subtle.exportKey("jwk", ec.publicKey);
  check("60. keychange-inner kid (not jwk) rejected", (await acode(function () { return pki.jose.sign({ protected: { alg: "ES256", url: "https://ca.example/o", kid: "x" }, payload: Buffer.from("{}"), key: ec.privateKey, profile: "keychange-inner" }); })) === "jose/bad-header");
  var kc = await pki.jose.sign({ protected: { alg: "ES256", url: "https://ca.example/o", jwk: ecJwk }, payload: Buffer.from("{}"), key: ec.privateKey, profile: "keychange-inner" });
  check("61. keychange-inner jwk round-trip", (await pki.jose.verify(kc, { profile: "keychange-inner" })).header.alg === "ES256");

  // PS256 exercises the RSA-PSS arm of _cryptoAlg (the RS* rows take the PKCS1-v1_5 arm).
  var pss = await subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  var pssJwk = await subtle.exportKey("jwk", pss.publicKey);
  var pj = await pki.jose.sign({ protected: outerHeader({ alg: "PS256", jwk: pssJwk }), payload: Buffer.from("{}"), key: pss.privateKey });
  check("62. PS256 (RSA-PSS) round-trip", (await pki.jose.verify(pj, OUTER)).header.alg === "PS256");

  // An RS256 kid-mode JWS derives its signature length from the signing key's
  // modulusLength (no embedded jwk to read the modulus from), and round-trips.
  var rsa = await subtle.generateKey({ name: "RSASSA-PKCS1-V1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  var rsaJwk = await subtle.exportKey("jwk", rsa.publicKey);
  var rj = await pki.jose.sign({ protected: { alg: "RS256", nonce: "AAAA", url: "https://ca.example/o", kid: "https://ca.example/a" }, payload: Buffer.from("{}"), key: rsa.privateKey });
  check("63. RS256 kid-mode sign (modulus from key) round-trip", pki.jose.base64url.decode(rj.signature).length === 256 && (await pki.jose.verify(rj, { profile: "acme-outer", key: rsaJwk })).header.alg === "RS256");
  // 64. an RS256 signature of the wrong length is caught by the per-alg length pin.
  check("64. RS256 wrong-length signature rejected", (await acode(function () { return pki.jose.verify(Object.assign({}, rj, { signature: pki.jose.base64url.encode(Buffer.alloc(100)) }), { profile: "acme-outer", key: rsaJwk }); })) === "jose/bad-signature");
}

async function run() {
  testBase64url();
  testJsonReader();
  await testJws();
  await testThumbprint();
  await testEncodeBoundaryGuards();
  await testProfileAndErrorBranches();
  await testInnerProfilesAndRsaVariants();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () {},
    function (e) { console.error(e && e.stack || e); process.exit(1); }
  );
}
