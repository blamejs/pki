// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- lib/http-digest.js, the @internal HTTP Digest (RFC 7616) challenge parser + response
// computer that pki.est's _drive composes. White-box (require the module directly) because the RFC
// 7616 sec. 3.9.1 KNOWN-ANSWER (its uri /dir/index.html + method GET) cannot be reproduced through a
// pki.est.* verb (whose request-target is a /.well-known/est/<op> path). The KAT is the independent-
// implementation oracle for A1/A2/KD; the parseChallenge vectors pin the UNTRUSTED-challenge parser
// fail-closed (a quoted comma is not a delimiter; a missing realm/nonce is rejected, not defaulted).

var helpers = require("../helpers");
var check = helpers.check;
var crypto = require("crypto");
var httpDigest = require("../../lib/http-digest");

// A (code, msg) FACTORY -- http-digest never sees a defineClass CLASS (feedback_guard_error_factory_not_class).
function E(code, msg) { var e = new Error(msg); e.code = code; return e; }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }
// Pull one param out of an emitted `Digest a="x", b=y, ...` header.
function param(header, name) {
  var m = new RegExp("(?:^Digest |, )" + name + "=(\"(?:[^\"\\\\]|\\\\.)*\"|[^,]*)").exec(header);
  if (!m) return null;
  var v = m[1];
  return v.charAt(0) === "\"" ? v.slice(1, -1).replace(/\\(.)/g, "$1") : v;
}
function h(hash, s) { return crypto.createHash(hash).update(s, "latin1").digest("hex"); }
function kd(hash, secret, data) { return h(hash, secret + ":" + data); }

// The RFC 7616 sec. 3.9.1 SHA-256 known-answer (verbatim from the RFC).
var KAT_WWW = 'Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256, ' +
  'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"';
var KAT_CNONCE = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
var KAT_RESPONSE = "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1";
var POL = { allowMD5: false, allowLegacyQop: false };
var CODES = { unsupportedAlgorithm: "est/digest-unsupported-algorithm", weakAlgorithm: "est/digest-weak-algorithm", noQop: "est/digest-no-qop", badChallenge: "est/digest-bad-challenge" };

async function run() {
  // ===== DG-KAT: the RFC 7616 sec. 3.9.1 known-answer anchors A1/A2/KD byte-exact =====
  var chKat = httpDigest.parseChallenge(KAT_WWW, E, "bad");
  var hdrKat = httpDigest.answer(chKat, { method: "GET", uri: "/dir/index.html", username: "Mufasa", password: "Circle of Life", policy: POL, rng: function () { return KAT_CNONCE; } }, E);
  check("DG-KAT. the RFC 7616 sec. 3.9.1 SHA-256 known-answer response matches byte-exact", param(hdrKat, "response") === KAT_RESPONSE);
  check("DG-KAT. the answer carries the RFC's qop/nc/opaque/algorithm/uri", param(hdrKat, "qop") === "auth" && param(hdrKat, "nc") === "00000001" && param(hdrKat, "opaque") === "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS" && param(hdrKat, "algorithm") === "SHA-256" && param(hdrKat, "uri") === "/dir/index.html" && param(hdrKat, "cnonce") === KAT_CNONCE && param(hdrKat, "username") === "Mufasa");

  // ===== DG-KAT-sess: -sess mixes nonce:cnonce into A1, so the response differs from the base =====
  var chSess = httpDigest.parseChallenge(KAT_WWW.replace("algorithm=SHA-256", "algorithm=SHA-256-sess"), E, "bad");
  var hdrSess = httpDigest.answer(chSess, { method: "GET", uri: "/dir/index.html", username: "Mufasa", password: "Circle of Life", policy: POL, rng: function () { return KAT_CNONCE; } }, E);
  var ha1base = h("sha256", "Mufasa:http-auth@example.org:Circle of Life");
  var ha1sess = h("sha256", ha1base + ":7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v:" + KAT_CNONCE);
  var ha2sess = h("sha256", "GET:/dir/index.html");
  check("DG-KAT-sess. a -sess algorithm hashes nonce:cnonce into A1 -> response differs from the base and matches the -sess recompute", param(hdrSess, "response") !== KAT_RESPONSE && param(hdrSess, "response") === kd("sha256", ha1sess, "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v:00000001:" + KAT_CNONCE + ":auth:" + ha2sess));

  // ===== DG-512: SHA-512-256 answered with the sha512-256 digest =====
  var ch512 = httpDigest.parseChallenge('Digest realm="r", qop="auth", algorithm=SHA-512-256, nonce="n"', E, "bad");
  var hdr512 = httpDigest.answer(ch512, { method: "GET", uri: "/x", username: "u", password: "p", policy: POL, rng: function () { return "cc"; } }, E);
  var a1 = h("sha512-256", "u:r:p"), a2 = h("sha512-256", "GET:/x");
  check("DG-512. SHA-512-256 uses the sha512-256 digest for A1/A2/KD", param(hdr512, "algorithm") === "SHA-512-256" && param(hdr512, "response") === kd("sha512-256", a1, "n:00000001:cc:auth:" + a2));

  // ===== DG-2069: no-qop (RFC 2069) math, opted in =====
  var ch2069 = httpDigest.parseChallenge('Digest realm="r", nonce="n", algorithm=SHA-256', E, "bad");
  var hdr2069 = httpDigest.answer(ch2069, { method: "GET", uri: "/x", username: "u", password: "p", policy: { allowLegacyQop: true }, rng: function () { return "cc"; } }, E);
  check("DG-2069. a no-qop challenge (opted in) emits no qop/nc/cnonce and the RFC 2069 KD(HA1, nonce:HA2)", param(hdr2069, "qop") === null && param(hdr2069, "nc") === null && param(hdr2069, "cnonce") === null && param(hdr2069, "response") === kd("sha256", h("sha256", "u:r:p"), "n:" + h("sha256", "GET:/x")));

  // ===== DG-authint: auth-int hashes the exact transfer body into A2 =====
  var chAi = httpDigest.parseChallenge('Digest realm="r", qop="auth-int", algorithm=SHA-256, nonce="n"', E, "bad");
  var hdrAi = httpDigest.answer(chAi, { method: "POST", uri: "/enroll", username: "u", password: "p", body: "BODYBYTES", policy: POL, rng: function () { return "cc"; } }, E);
  var a2ai = h("sha256", "POST:/enroll:" + h("sha256", "BODYBYTES"));
  check("DG-authint. auth-int folds H(entity-body) into A2", param(hdrAi, "qop") === "auth-int" && param(hdrAi, "response") === kd("sha256", h("sha256", "u:r:p"), "n:00000001:cc:auth-int:" + a2ai));

  // ===== DG-select: multiple Digest challenges -> the most secure USABLE algorithm is chosen =====
  var chSel = httpDigest.parseChallenge('Digest realm="r", nonce="n1", qop="auth", algorithm=MD5, Digest realm="r", nonce="n2", qop="auth", algorithm=SHA-256', E, "bad");
  check("DG-select. among multiple Digest challenges the most secure (SHA-256 > MD5) is selected", chSel.algorithm === "SHA-256" && chSel.nonce === "n2");
  // DG-select-usable: a higher-ALGORITHM but policy-UNUSABLE challenge (SHA-512-256 with no qop, refused under
  // the default policy) must NOT shadow a lower-ranked USABLE one (SHA-256 with qop=auth) -- else the client
  // selects the strong-but-unusable offer and fails to authenticate though a usable one was on the wire.
  var selMix = 'Digest realm="r", nonce="n1", algorithm=SHA-512-256, Digest realm="r", nonce="n2", qop="auth", algorithm=SHA-256';
  var chUsable = httpDigest.parseChallenge(selMix, E, "bad", POL);
  check("DG-select-usable. the highest-ranked USABLE challenge wins (SHA-256+qop over SHA-512-256 no-qop under default policy)", chUsable.algorithm === "SHA-256" && chUsable.nonce === "n2");
  // ...and the selected usable challenge actually answers (proves selection picked an answerable offer).
  var hdrUsable = httpDigest.answer(chUsable, { method: "GET", uri: "/x", username: "u", password: "p", policy: { codes: CODES }, rng: function () { return "cc"; } }, E);
  check("DG-select-usable-answers. the selected usable challenge produces a valid Authorization header", param(hdrUsable, "qop") === "auth" && param(hdrUsable, "nc") === "00000001");
  // DG-select-policy: the SAME wire, with allowLegacyQop set, makes the SHA-512-256 no-qop challenge usable, so
  // the stronger algorithm now wins -- selection genuinely follows the active policy, not a fixed table.
  var chPolicy = httpDigest.parseChallenge(selMix, E, "bad", { allowLegacyQop: true });
  check("DG-select-policy. selection follows the policy (SHA-512-256 no-qop wins once allowLegacyQop is set)", chPolicy.algorithm === "SHA-512-256" && chPolicy.nonce === "n1");
  // DG-select-none: when NO challenge is usable, the highest-ranked one is returned so answer() reports the
  // specific policy reason (which opt to set) rather than a generic "no challenge".
  var chNone = httpDigest.parseChallenge('Digest realm="r", nonce="n1", algorithm=SHA-256, Digest realm="r", nonce="n2", algorithm=SHA-512-256', E, "bad", POL);
  check("DG-select-none. all-unusable offers still return the strongest so answer() reports the specific reason", chNone.algorithm === "SHA-512-256" && codeOf(function () { httpDigest.answer(chNone, { method: "GET", uri: "/x", username: "u", password: "p", policy: { codes: CODES } }, E); }) === "est/digest-no-qop");
  // DG-select-skip-malformed: a MALFORMED offer (missing nonce) alongside a VALID one is skipped, not fatal --
  // parseChallenge throws only when NO valid Digest offer exists (RFC 7616 sec. 3.3).
  var chSkip = httpDigest.parseChallenge('Digest realm="r", qop="auth", algorithm=MD5, Digest realm="r", nonce="n2", qop="auth", algorithm=SHA-256', E, "est/digest-bad-challenge");
  check("DG-select-skip-malformed. a malformed Digest offer is skipped when a valid one remains", chSkip.algorithm === "SHA-256" && chSkip.nonce === "n2");
  check("DG-select-all-malformed. when EVERY Digest offer is malformed, parseChallenge throws (none valid)", codeOf(function () { httpDigest.parseChallenge('Digest realm="r", qop="auth", Digest realm="r2", qop="auth"', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");

  // ===== DG-space: the domain protection space (RFC 7616 sec. 3.3 / 3.5) =====
  var ORIG = "https://ca.example";
  var chDom = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, domain="/a /c/d"', E, "bad");
  check("DG-p-domain. the domain directive parses to the list of protection-space URIs", Array.isArray(chDom.domain) && chDom.domain.length === 2 && chDom.domain[0] === "/a" && chDom.domain[1] === "/c/d");
  check("DG-space-in. a path at or under a domain URI is in the protection space", httpDigest.inProtectionSpace(chDom, ORIG, "/a") === true && httpDigest.inProtectionSpace(chDom, ORIG, "/a/x") === true && httpDigest.inProtectionSpace(chDom, ORIG, "/c/d/e") === true);
  check("DG-space-out. a path outside every domain URI is NOT in the protection space", httpDigest.inProtectionSpace(chDom, ORIG, "/b") === false);
  check("DG-space-boundary. the prefix is path-segment aware (/a does not cover /ab)", httpDigest.inProtectionSpace(chDom, ORIG, "/ab") === false);
  var chNoDom = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256', E, "bad");
  check("DG-space-nodomain. an absent domain means the whole server (any path in space)", chNoDom.domain === null && httpDigest.inProtectionSpace(chNoDom, ORIG, "/anything") === true);
  var chEmptyDom = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, domain=""', E, "bad");
  check("DG-space-emptydomain. an empty domain is treated as the whole server (RFC 7616 sec. 3.3)", chEmptyDom.domain === null && httpDigest.inProtectionSpace(chEmptyDom, ORIG, "/x") === true);
  var chAbs = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, domain="https://ca.example/enroll"', E, "bad");
  check("DG-space-absuri. an absolute-URI domain entry matches by origin AND path", httpDigest.inProtectionSpace(chAbs, ORIG, "/enroll/x") === true && httpDigest.inProtectionSpace(chAbs, ORIG, "/other") === false);
  check("DG-space-absuri-foreign. an absolute-URI domain entry to a DIFFERENT origin never matches this origin's same path", httpDigest.inProtectionSpace(chAbs, "https://evil.example", "/enroll/x") === false);
  var chPort = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, domain="https://ca.example:443/enroll"', E, "bad");
  check("DG-space-absuri-port. an explicit default port in an absolute domain URI is normalized (matches the request's normalized origin)", httpDigest.inProtectionSpace(chPort, "https://ca.example", "/enroll/x") === true);
  var chPortAlt = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, domain="https://ca.example:8443/enroll"', E, "bad");
  check("DG-space-absuri-port-diff. a NON-default port is a different origin (not normalized away)", httpDigest.inProtectionSpace(chPortAlt, "https://ca.example", "/enroll/x") === false);
  var chQabs = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, domain="https://ca.example/enroll?tenant=a"', E, "bad");
  check("DG-space-query. a domain entry's QUERY is preserved and narrows the space (covers ?tenant=a, not ?tenant=b)", httpDigest.inProtectionSpace(chQabs, ORIG, "/enroll?tenant=a") === true && httpDigest.inProtectionSpace(chQabs, ORIG, "/enroll?tenant=b") === false);
  var chNoQ = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, domain="/enroll"', E, "bad");
  check("DG-space-query-noquery. a query-less domain entry covers its whole path (any query)", httpDigest.inProtectionSpace(chNoQ, ORIG, "/enroll?tenant=b") === true);
  check("DG-p-domain-unquoted. an UNQUOTED domain is rejected (fail closed, not silently widened to the whole server)", codeOf(function () { httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, domain=/a', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");

  // ===== DG-username: RFC 7616 sec. 3.4 username / username* (RFC 5987 extended value) =====
  var uNonAscii = "u" + String.fromCharCode(0xe9);   // "ue-acute" -- a non-ASCII username built without a raw source byte
  var chU8 = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, charset=UTF-8', E, "bad");
  var hdrU8 = httpDigest.answer(chU8, { method: "GET", uri: "/x", username: uNonAscii, password: "p", policy: { codes: CODES }, rng: function () { return "cc"; } }, E);
  check("DG-username-star. a non-ASCII UTF-8 username is sent as the extended username* form (RFC 5987), not the legacy username", param(hdrU8, "username") === null && hdrU8.indexOf("username*=UTF-8''u%C3%A9") !== -1);
  var reconHA1u = h("sha256", Buffer.from(uNonAscii, "utf8").toString("latin1") + ":r:p");
  check("DG-username-star-a1. the response still hashes A1 over the UTF-8 octets (username* is only a transport encoding)", param(hdrU8, "response") === kd("sha256", reconHA1u, "n:" + param(hdrU8, "nc") + ":cc:auth:" + h("sha256", "GET:/x")));
  var hdrAscii = httpDigest.answer(chU8, { method: "GET", uri: "/x", username: "alice", password: "p", policy: { codes: CODES }, rng: function () { return "cc"; } }, E);
  check("DG-username-ascii. an ASCII username under charset=UTF-8 keeps the legacy quoted username", param(hdrAscii, "username") === "alice" && hdrAscii.indexOf("username*") === -1);
  var chUhash = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, charset=UTF-8, userhash=true', E, "bad");
  var hdrUhash = httpDigest.answer(chUhash, { method: "GET", uri: "/x", username: uNonAscii, password: "p", policy: { codes: CODES }, rng: function () { return "cc"; } }, E);
  check("DG-username-userhash. userhash sends the hashed username in the legacy field, never username*", hdrUhash.indexOf("username*") === -1 && param(hdrUhash, "userhash") === "true" && /^[0-9a-f]+$/.test(param(hdrUhash, "username")));
  // DG-realm-utf8: a non-ASCII realm under charset=UTF-8 must contribute its UTF-8 octets to A1 (like user/pass),
  // not its Latin-1 code points, or the response disagrees with an RFC 7616 server.
  var realmU8 = "r" + String.fromCharCode(0xe9);   // a non-ASCII realm, built without a raw source byte
  var chRealm = httpDigest.parseChallenge('Digest realm="' + realmU8 + '", nonce="n", qop="auth", algorithm=SHA-256, charset=UTF-8', E, "bad");
  var hdrRealm = httpDigest.answer(chRealm, { method: "GET", uri: "/x", username: "u", password: "p", policy: { codes: CODES }, rng: function () { return "cc"; } }, E);
  var reconHA1r = h("sha256", "u:" + Buffer.from(realmU8, "utf8").toString("latin1") + ":p");
  check("DG-realm-utf8. a non-ASCII UTF-8 realm hashes as its UTF-8 octets in A1 (matches an RFC 7616 server)", param(hdrRealm, "response") === kd("sha256", reconHA1r, "n:" + param(hdrRealm, "nc") + ":cc:auth:" + h("sha256", "GET:/x")));

  // ===== DG-p-*: the UNTRUSTED challenge parser fails closed =====
  check("DG-p-realm. a Digest challenge missing realm is rejected (not defaulted)", codeOf(function () { httpDigest.parseChallenge('Digest nonce="n", qop="auth"', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-nonce. a Digest challenge missing nonce is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm="r", qop="auth"', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-unquoted. a bare-token realm (RFC requires quoted) is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm=r, nonce="n"', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-dupkey. a repeated challenge param is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm="a", realm="b", nonce="n"', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  var chQc = httpDigest.parseChallenge('Digest realm="x, Basic required", nonce="n", qop="auth", algorithm=SHA-256', E, "bad");
  check("DG-p-quotedcomma. a comma INSIDE a quoted value is not a delimiter -> one Digest challenge, realm verbatim", chQc.realm === "x, Basic required" && chQc.nonce === "n");
  var chEsc = httpDigest.parseChallenge('Digest realm="a\\",b", nonce="n", qop="auth", algorithm=SHA-256', E, "bad");
  check("DG-p-escquote. an escaped quote inside a quoted value is unescaped, its comma not a delimiter", chEsc.realm === "a\",b");
  check("DG-p-oversize. an over-length challenge header is rejected before the copy (bounded)", codeOf(function () { httpDigest.parseChallenge('Digest realm="' + "a".repeat(9000) + '"', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-none. a header with no Digest scheme returns null (a Basic-only challenge is not a Digest one)", httpDigest.parseChallenge('Basic realm="r"', E, "bad") === null);

  // ===== DG-a-*: the answer() security policy fails closed =====
  function ans(www, pol) { var ch = httpDigest.parseChallenge(www, E, "est/digest-bad-challenge"); return httpDigest.answer(ch, { method: "GET", uri: "/x", username: "u", password: "p", policy: { allowMD5: pol && pol.allowMD5, allowLegacyQop: pol && pol.allowLegacyQop, codes: CODES }, rng: function () { return "cc"; } }, E); }
  check("DG-a-unsup. an unsupported offered algorithm is refused, never downgraded", codeOf(function () { ans('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-1', {}); }) === "est/digest-unsupported-algorithm");
  check("DG-a-md5. MD5 is refused by default", codeOf(function () { ans('Digest realm="r", nonce="n", qop="auth", algorithm=MD5', {}); }) === "est/digest-weak-algorithm");
  check("DG-a-md5allow. MD5 is answered when opted in", param(ans('Digest realm="r", nonce="n", qop="auth", algorithm=MD5', { allowMD5: true }), "algorithm") === "MD5");
  check("DG-a-md5default. an absent algorithm defaults to MD5 and is refused by default", codeOf(function () { ans('Digest realm="r", nonce="n", qop="auth"', {}); }) === "est/digest-weak-algorithm");
  check("DG-a-noqop. a no-qop (RFC 2069) challenge is refused by default", codeOf(function () { ans('Digest realm="r", nonce="n", algorithm=SHA-256', {}); }) === "est/digest-no-qop");
  check("DG-a-badqop. a non-empty qop offering only unknown members is a bad challenge (not the RFC 2069 no-qop path)", codeOf(function () { ans('Digest realm="r", nonce="n", qop="foo", algorithm=SHA-256', { allowLegacyQop: true }); }) === "est/digest-bad-challenge");
  check("DG-p-algquoted. a QUOTED algorithm (must be a token) is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm="r", nonce="n", algorithm="SHA-256"', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-qopunquoted. an UNQUOTED qop (must be a quoted list) is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm="r", nonce="n", qop=auth', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-emptyqop. a present-but-empty qop directive is rejected (not the absent-qop RFC 2069 path)", codeOf(function () { httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="", algorithm=SHA-256', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-emptyqop-commas. a qop directive of only empty members is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm="r", nonce="n", qop=", ,", algorithm=SHA-256', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-unterminated. an unterminated quoted value is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm="unterminated', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-trailing. trailing garbage after a closing quote is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm="r"junk, nonce="n"', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  var chSn = httpDigest.parseChallenge('Digest realm="r", nonce="n", algorithm=MD5-sess', E, "bad");
  var hdrSn = httpDigest.answer(chSn, { method: "GET", uri: "/x", username: "u", password: "p", policy: { allowMD5: true, allowLegacyQop: true }, rng: function () { return "cc"; } }, E);
  check("DG-sess-noqop. a -sess algorithm on the no-qop path still emits cnonce (the server needs it to recompute A1)", param(hdrSn, "qop") === null && param(hdrSn, "nc") === null && param(hdrSn, "cnonce") === "cc");
  // Recompute the -sess no-qop response with an INDEPENDENT MD5 implementation, folding the emitted cnonce
  // into A1 exactly as a server would -- proving the emitted header is verifiable, not just that cnonce is present.
  function md5(s) { return crypto.createHash("md5").update(s, "utf8").digest("hex"); }
  var reconHA1 = md5(md5("u:r:p") + ":n:" + param(hdrSn, "cnonce"));
  var reconResp = md5(reconHA1 + ":n:" + md5("GET:/x"));
  check("DG-sess-noqop-recon. the emitted -sess no-qop response is reconstructible by the server from the header cnonce", param(hdrSn, "response") === reconResp);
  var hdrNc = httpDigest.answer(ch512, { method: "GET", uri: "/x", username: "u", password: "p", nc: 2, policy: POL, rng: function () { return "cc"; } }, E);
  check("DG-nc. the caller-supplied nonce-count is formatted as 8 lowercase hex", param(hdrNc, "nc") === "00000002");
  check("DG-p-ctl. a control octet (CR/LF) in a challenge value is rejected (RFC 7230 qdtext + header-injection)", codeOf(function () { httpDigest.parseChallenge('Digest realm="r", nonce="n\r\nX-Injected: 1", qop="auth", algorithm=SHA-256', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-nul. a NUL octet in a challenge value is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm="r' + String.fromCharCode(0) + '", nonce="n", qop="auth", algorithm=SHA-256', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-emptyrealm. an empty realm is rejected (not defaulted)", codeOf(function () { httpDigest.parseChallenge('Digest realm="", nonce="n", qop="auth", algorithm=SHA-256', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");
  check("DG-p-emptynonce. an empty nonce is rejected", codeOf(function () { httpDigest.parseChallenge('Digest realm="r", nonce="", qop="auth", algorithm=SHA-256', E, "est/digest-bad-challenge"); }) === "est/digest-bad-challenge");

  // ===== i18n (RFC 7616 sec. 4): charset=UTF-8 octets + userhash =====
  var chCs = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, charset=UTF-8', E, "bad");
  var hdrCs = httpDigest.answer(chCs, { method: "GET", uri: "/x", username: "u", password: ("p" + String.fromCharCode(0xe4) + "ss"), policy: POL, rng: function () { return "cc"; } }, E);
  var passOctets = Buffer.from(("p" + String.fromCharCode(0xe4) + "ss"), "utf8").toString("latin1");
  check("DG-charset. charset=UTF-8 hashes the credential over its UTF-8 octet string", chCs.charset === "UTF-8" && param(hdrCs, "response") === kd("sha256", h("sha256", "u:r:" + passOctets), "n:00000001:cc:auth:" + h("sha256", "GET:/x")));
  var chUh = httpDigest.parseChallenge('Digest realm="r", nonce="n", qop="auth", algorithm=SHA-256, userhash=true', E, "bad");
  var hdrUh = httpDigest.answer(chUh, { method: "GET", uri: "/x", username: "u", password: "p", policy: POL, rng: function () { return "cc"; } }, E);
  check("DG-userhash. userhash=true sends username = H(user:realm) and declares userhash=true (A1 uses the real username)", chUh.userhash === true && /(?:^|, )userhash=true/.test(hdrUh) && param(hdrUh, "username") === h("sha256", "u:r") && param(hdrUh, "response") === kd("sha256", h("sha256", "u:r:p"), "n:00000001:cc:auth:" + h("sha256", "GET:/x")));

  console.log("CHECKS " + helpers.getChecks());
}

if (require.main === module) { run().catch(function (e) { console.error(e); process.exit(1); }); }
module.exports = { run: run };
