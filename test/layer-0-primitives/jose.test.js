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

async function run() {
  testBase64url();
  testJsonReader();
  await testJws();
  await testThumbprint();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () {},
    function (e) { console.error(e && e.stack || e); process.exit(1); }
  );
}
