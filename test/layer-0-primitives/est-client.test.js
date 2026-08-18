// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- pki.est network verbs (cacerts / simpleenroll / simplereenroll), the thin RFC 7030
// client over the shared pki.transport. RED-first: the verbs are undefined until the client lands,
// so every vector throws. Each is driven through the SHIPPED consumer path (pki.est.<verb>(...))
// over an INJECTED fake transport -- NO socket is opened -- so the full state machine (scheme gate,
// anchor gate, redirect follow-loop, 401 auth ordering, 202 surface, size cap) is deterministic.
// transport.calls proves a fail-closed gate ran BEFORE the transport (calls.length === 0). The
// socket-lifecycle branches (timeout / TLS floor / server-auth) are http-transport.test.js.

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var vectors = require("../helpers/vectors");
var signing = require("../helpers/signing");
var fakeTransport = require("../helpers/fake-transport").fakeTransport;
var makeSigner = signing.makeSigner;
var b = pki.asn1.build;

var BASE = "https://ca.example";
var ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var ID_DATA = "1.2.840.113549.1.7.1";
var SAN_OID = "2.5.29.17";
var EXTREQ_OID = "1.2.840.113549.1.9.14";
var ECDSA_SHA256 = "1.2.840.10045.4.3.2";
function algId(o) { return b.sequence([b.oid(o)]); }

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }

// A certs-only CMS Simple PKI Response (RFC 5272 sec. 4.1): SignedData, no eContent, EMPTY
// signerInfos, certificates in the [0] field (DER-sorted, mirroring the CMS SET-OF ordering).
function certsOnly(certs) {
  var sd = [b.integer(1n), b.set([]), b.sequence([b.oid(ID_DATA)])];
  if (certs && certs.length) sd.push(b.contextConstructed(0, Buffer.concat(certs.slice().sort(Buffer.compare))));
  sd.push(b.set([]));
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence(sd))]);
}
// A structurally valid PKCS#10 re-enroll CSR reusing REAL_CERT's subject + SPKI, with an
// extensionRequest SubjectAltName (csr.parse is structural, not signature-verifying).
function extReqAttr(sanVal) {
  var exts = b.sequence([b.sequence([b.oid(SAN_OID), b.octetString(sanVal)])]);
  return b.sequence([b.oid(EXTREQ_OID), b.set([exts])]);
}
function reenrollCsr(o) {
  o = o || {};
  var tbs = pki.asn1.decode(REAL_CERT).children[0];
  var subjectDer = o.subjectDer || tbs.children[5].bytes;
  var spkiDer = tbs.children[6].bytes;
  var attrs = o.san !== undefined ? extReqAttr(o.san) : Buffer.alloc(0);
  var cri = b.sequence([b.integer(0n), subjectDer, spkiDer, b.contextConstructed(0, attrs)]);
  return b.sequence([cri, algId(ECDSA_SHA256), b.bitString(Buffer.from([1, 2, 3]), 0)]);
}

// Response builders (a transport reply is {status, headers, body}; body is the base64 EST payload).
function ct(type) { return { "content-type": type }; }
function cacertsOK(certs) { return { status: 200, headers: ct("application/pkcs7-mime"), body: pki.est.transferEncode(certsOnly(certs)) }; }
function enrollOK(certs) { return { status: 200, headers: ct("application/pkcs7-mime; smime-type=certs-only"), body: pki.est.transferEncode(certsOnly(certs)) }; }

var S, DECOY, CSR, REAL_CERT, OLD_SAN, GOOD_REENROLL;
async function setup() {
  S = makeSigner("ec-p256", { serial: 0x51, cn: "enroll.example" });
  DECOY = makeSigner("rsa", { serial: 0xd0, cn: "Decoy" });
  CSR = await pki.csr.sign({ subject: "enroll.example", subjectPublicKey: S.spki }, { key: S.key });
  REAL_CERT = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM);
  OLD_SAN = pki.schema.x509.parse(REAL_CERT).extensions.filter(function (e) { return e.oid === SAN_OID; })[0].value;
  GOOD_REENROLL = reenrollCsr({ san: OLD_SAN });
}

// ---- 1 happy cacerts --------------------------------------------------------
async function testCacertsHappy() {
  var t = fakeTransport(cacertsOK([S.cert, DECOY.cert]));
  var r = await pki.est.cacerts(BASE, { transport: t });
  check("#1 cacerts returns both certificates", r.certificates.length === 2);
  check("#1 returned certs are the raw set (order-independent)",
    r.certificates.some(function (c) { return c.equals(S.cert); }) && r.certificates.some(function (c) { return c.equals(DECOY.cert); }));
  check("#1 crls default to empty", Array.isArray(r.crls) && r.crls.length === 0);
  check("#1 the request was a GET to /cacerts", t.calls.length === 1 && t.calls[0].method === "GET" && /\/\.well-known\/est\/cacerts$/.test(t.calls[0].url));
}

// ---- 2 happy simpleenroll (issued cert by SPKI match, not position) ---------
async function testEnrollHappy() {
  var t = fakeTransport(enrollOK([S.cert, DECOY.cert]));   // DECOY first-or-second by byte sort; the match must be by key
  var r = await pki.est.simpleenroll(BASE, CSR, { transport: t });
  check("#2 the issued cert is the SPKI match, not a positional guess", Buffer.isBuffer(r.certificate) && r.certificate.equals(S.cert));
  check("#2 the other cert is surfaced as chain", r.chain.length === 1 && r.chain[0].equals(DECOY.cert));
  check("#2 all certs are surfaced", r.certificates.length === 2);
  check("#2 the request POSTed application/pkcs10 with the base64 CSR", t.calls[0].method === "POST" &&
    t.calls[0].headers["content-type"] === "application/pkcs10" && t.calls[0].body === pki.est.transferEncode(CSR));
}

// ---- 3 happy simplereenroll (reenrollGuard passes, then POST) ---------------
async function testReenrollHappy() {
  var t = fakeTransport(enrollOK([REAL_CERT]));
  var r = await pki.est.simplereenroll(BASE, GOOD_REENROLL, { transport: t, oldCert: REAL_CERT });
  check("#3 re-enroll returns the reissued cert (SPKI match)", r.certificate.equals(REAL_CERT));
  check("#3 the request went to /simplereenroll", /\/\.well-known\/est\/simplereenroll$/.test(t.calls[0].url));
}

// ---- 4 reenroll identity gate precedes the transport ------------------------
async function testReenrollGatePrecedesTransport() {
  var drift = reenrollCsr({ subjectDer: b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("Drift")])])]), san: OLD_SAN });
  var t = fakeTransport(enrollOK([REAL_CERT]));
  check("#4 a drifted re-enroll subject is rejected", (await codeOf(pki.est.simplereenroll(BASE, drift, { transport: t, oldCert: REAL_CERT }))) === "est/reenroll-subject-mismatch");
  check("#4 and the transport was never called", t.calls.length === 0);
  check("#4 a re-enroll with no oldCert fails closed", (await codeOf(pki.est.simplereenroll(BASE, GOOD_REENROLL, { transport: fakeTransport(enrollOK([REAL_CERT])) }))) === "est/bad-input");
}

// ---- 5 202 Retry-After surfaced, never slept --------------------------------
async function test202Surfaced() {
  var t = fakeTransport({ status: 202, headers: { "retry-after": "120" }, body: "" });
  var r = await pki.est.simpleenroll(BASE, CSR, { transport: t });
  check("#5 a 202 surfaces retry (not a cert)", r.retry === true && r.retryAfterSeconds === 120);
  check("#5 the verb returned after one call (no internal sleep/loop)", t.calls.length === 1);
  // 202 is an ENROLLMENT response; a /cacerts 202 is nonconforming (RFC 7030 sec. 4.1.3) -> fail closed.
  check("#5 a 202 from cacerts is rejected (202 is enrollment-only)", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport({ status: 202, headers: { "retry-after": "120" }, body: "" }) }))) === "est/http-error");
}

// ---- 6/7 URL scheme gates precede the transport -----------------------------
async function testUrlGates() {
  var t = fakeTransport(cacertsOK([S.cert]));
  check("#6 an http: base URL is refused", (await codeOf(pki.est.cacerts("http://ca.example", { transport: t }))) === "est/insecure-url");
  check("#6 the transport was never called on an http: URL", t.calls.length === 0);
  var t2 = fakeTransport(cacertsOK([S.cert]));
  check("#7 an unparseable URL is refused", (await codeOf(pki.est.cacerts("not a url", { transport: t2 }))) === "est/bad-url");
  check("#7 the transport was never called on a bad URL", t2.calls.length === 0);
  // a query / fragment on the base URL would corrupt the concatenated operation path -> refused.
  var tq = fakeTransport(cacertsOK([S.cert]));
  check("#7 a base URL with a query component is refused", (await codeOf(pki.est.cacerts("https://ca.example?tenant=x", { transport: tq }))) === "est/bad-url");
  check("#7 a base URL with a fragment component is refused", (await codeOf(pki.est.cacerts("https://ca.example#frag", { transport: fakeTransport(cacertsOK([S.cert])) }))) === "est/bad-url");
  check("#7 the transport was never called on a query/fragment base", tq.calls.length === 0);
}

// ---- 8 default transport requires an explicit anchor (no socket) ------------
async function testNoTrustAnchors() {
  // No opts.transport -> the default node:https transport; with neither tls.anchors nor
  // tls.useSystemStore its config validation fails closed BEFORE any socket is opened.
  check("#8 the default transport with no trust anchors fails closed", (await codeOf(pki.est.cacerts(BASE, {}))) === "est/no-trust-anchors");
  check("#8 useSystemStore:false is not a trust opt-in", (await codeOf(pki.est.cacerts(BASE, { tls: { useSystemStore: false } }))) === "est/no-trust-anchors");
  check("#8 a verb called with no opts at all fails closed", (await codeOf(pki.est.cacerts(BASE))) === "est/no-trust-anchors");
}

// ---- 9 redirect scheme downgrade --------------------------------------------
async function testRedirectDowngrade() {
  var t = fakeTransport({ status: 302, headers: { location: "http://evil.example/.well-known/est/cacerts" }, body: "" });
  check("#9 a redirect to http: is refused", (await codeOf(pki.est.cacerts(BASE, { transport: t }))) === "est/insecure-redirect");
  check("#9 no follow crossed the downgrade", t.calls.length === 1);
}

// ---- 10 cross-origin redirect on a POST -------------------------------------
async function testCrossOriginRedirect() {
  var t = fakeTransport({ status: 302, headers: { location: "https://other.example/.well-known/est/simpleenroll" }, body: "" });
  check("#10 a cross-origin POST redirect is refused without opt-in", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: t }))) === "est/cross-origin-redirect");
  check("#10 the client did not blindly follow", t.calls.length === 1);
}

// ---- 11 same-origin redirect followed ---------------------------------------
async function testSameOriginRedirect() {
  var t = fakeTransport([
    { status: 302, headers: { location: "https://ca.example/.well-known/est/cacerts?x=1" }, body: "" },
    cacertsOK([S.cert]),
  ]);
  var r = await pki.est.cacerts(BASE, { transport: t });
  check("#11 a same-origin redirect is followed to success", r.certificates.length === 1 && r.certificates[0].equals(S.cert));
  check("#11 exactly two calls, both to ca.example", t.calls.length === 2 && t.calls.every(function (c) { return c.url.indexOf("https://ca.example") === 0; }));
}

// ---- 12 redirect loop bounded -----------------------------------------------
async function testRedirectLoop() {
  var t = fakeTransport(function (req, i) { return { status: 302, headers: { location: "https://ca.example/.well-known/est/cacerts?n=" + i }, body: "" }; });
  check("#12 an unbounded redirect loop is cut", (await codeOf(pki.est.cacerts(BASE, { transport: t, maxRedirects: 5 }))) === "est/too-many-redirects");
  check("#12 the follow chain stopped at maxRedirects+1", t.calls.length === 6);
}

// ---- 13 oversized body rejected before decode -------------------------------
async function testOversizedBody() {
  var t = fakeTransport({ status: 200, headers: { "content-type": "application/pkcs7-mime", "content-length": "101" }, body: "x".repeat(101) });
  // The oversize gate fires before transferDecode/cms.parse -- NOT est/bad-base64.
  check("#13 an oversized response is rejected before decode", (await codeOf(pki.est.cacerts(BASE, { transport: t, maxResponseBytes: 100 }))) === "est/response-too-large");
  // an injected STRING body is measured as UTF-8, not latin1: a non-ASCII body whose UTF-8 length exceeds
  // the cap but whose latin1 length does not must still be rejected before decode. U+1F600 = 2 UTF-16 units
  // (latin1) but 4 UTF-8 bytes, so 40 of them are 80 latin1 bytes but 160 UTF-8 bytes.
  var emojiBody = String.fromCodePoint(0x1f600).repeat(40);
  var tUtf8 = fakeTransport({ status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: emojiBody });
  check("#13 a non-ASCII string body is measured as UTF-8 against the cap", (await codeOf(pki.est.cacerts(BASE, { transport: tUtf8, maxResponseBytes: 100 }))) === "est/response-too-large");
}

// ---- 14 no credentials before authorization ---------------------------------
async function testAuthBeforeCreds() {
  var t = fakeTransport({ status: 401, headers: { "www-authenticate": "Basic realm=\"est\"" }, body: "" });
  check("#14 a 401 with no creds fails closed", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: t }))) === "est/auth-required");
  check("#14 no request ever carried an Authorization header", t.calls.every(function (c) { return !(c.headers && (c.headers.authorization || c.headers.Authorization)); }));
}

// ---- 15/16 401 -> Basic retry (empty username allowed) ----------------------
async function testAuthRetry() {
  var t = fakeTransport([{ status: 401, headers: { "www-authenticate": "Basic realm=\"est\"" }, body: "" }, enrollOK([S.cert])]);
  var r = await pki.est.simpleenroll(BASE, CSR, { transport: t, username: "u", password: "p" });
  check("#15 a 401 then a credentialed retry succeeds", r.certificate.equals(S.cert) && t.calls.length === 2);
  check("#15 the retry carried Basic auth", /^Basic /.test(t.calls[1].headers.authorization));
  // WWW-Authenticate is a LIST field (RFC 9110 sec. 11.6.1: one challenge per
  // element), so a server may offer several -- including across separately-cased
  // field lines, which are the same field. Every challenge must reach the scheme
  // scan: seeing only one of them would answer with a scheme the server may not
  // accept, or refuse an offer it did make.
  // The USABLE challenge is written FIRST, so a fold that keeps the last value
  // would lose it and the exchange would be refused for offering nothing this
  // client speaks. Putting it last would let the test pass on either behavior,
  // which is no test at all.
  var tMulti = fakeTransport([
    { status: 401, headers: { "www-authenticate": "Basic realm=\"est\"", "WWW-Authenticate": "Newfangled realm=\"est\"" }, body: "" },
    enrollOK([S.cert])]);
  var rMulti = await pki.est.simpleenroll(BASE, CSR, { transport: tMulti, username: "u", password: "p" });
  check("#15b a usable challenge is found even when another spelling of the field follows it",
    rMulti.certificate.equals(S.cert) && /^Basic /.test(tMulti.calls[1].headers.authorization));

  var t2 = fakeTransport([{ status: 401, headers: { "www-authenticate": "Basic realm=\"est\"" }, body: "" }, enrollOK([S.cert])]);
  await pki.est.simpleenroll(BASE, CSR, { transport: t2, username: "", password: "p" });
  var decoded = Buffer.from(t2.calls[1].headers.authorization.slice(6), "base64").toString("latin1");
  check("#16 an empty username is accepted (RFC 7030 sec. 3.2.3)", decoded === ":p");
}

// ---- 17/18/19 classifier-surfaced faults ------------------------------------
async function testClassifierFaults() {
  check("#17 a wrong content-type on 200 is rejected", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport({ status: 200, headers: ct("text/plain"), body: "oops" }) }))) === "est/bad-content-type");
  check("#18 a 200 with an empty body is rejected", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport({ status: 200, headers: ct("application/pkcs7-mime"), body: "" }) }))) === "est/empty-body");
  check("#19 a 5xx is surfaced as an http error", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: fakeTransport({ status: 500, headers: {}, body: "internal error" }) }))) === "est/http-error");
}

// ---- 20 issued cert not found -----------------------------------------------
async function testIssuedNotFound() {
  var t = fakeTransport(enrollOK([DECOY.cert]));   // a cert for a DIFFERENT key than the CSR
  check("#20 no SPKI match fails closed", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: t }))) === "est/issued-cert-not-found");
}

// ---- 21 strict exactly-one --------------------------------------------------
async function testStrict() {
  var t = fakeTransport(enrollOK([S.cert, DECOY.cert]));
  check("#21 strict rejects an issued cert with extra chain certs", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: t, strict: true }))) === "est/unexpected-certs");
  var t2 = fakeTransport(enrollOK([S.cert, DECOY.cert]));
  var r = await pki.est.simpleenroll(BASE, CSR, { transport: t2 });
  check("#21 without strict the extra cert is the chain", r.chain.length === 1);
}

// ---- 25 config budget guards ------------------------------------------------
async function testBudgetGuards() {
  var t = fakeTransport(cacertsOK([S.cert]));
  check("#25 a negative maxResponseBytes is a typed config reject", (await codeOf(pki.est.cacerts(BASE, { transport: t, maxResponseBytes: -1 }))) === "est/bad-input");
  check("#25 the guard fired before the transport", t.calls.length === 0);
  var t2 = fakeTransport(cacertsOK([S.cert]));
  check("#25 a NaN maxRedirects is a typed config reject", (await codeOf(pki.est.cacerts(BASE, { transport: t2, maxRedirects: NaN }))) === "est/bad-input");
}

// ---- CSR input forms + the default (non-injected) transport ----------------
async function testCsrFormsAndDefaultTransport() {
  var pem = pki.schema.csr.pemEncode(CSR, "CERTIFICATE REQUEST");
  var t = fakeTransport(enrollOK([S.cert]));
  var r = await pki.est.simpleenroll(BASE, pem, { transport: t });
  check("#26 a PEM CSR string is accepted and enrolls", r.certificate.equals(S.cert));
  check("#26 a non-Buffer/non-string CSR is refused", (await codeOf(pki.est.simpleenroll(BASE, 123, { transport: fakeTransport(enrollOK([S.cert])) }))) === "est/bad-input");
  // No injected transport + an explicit anchor -> the default node:https transport is built and
  // driven; an unresolvable reserved-TLD host (RFC 6761) fails closed as est/transport-error,
  // proving the default transport is wired and surfaces the est/* code prefix (offline, no connect).
  check("#26 the default transport is built and surfaces est/* on an unresolvable host",
    (await codeOf(pki.est.cacerts("https://est-server.invalid", { tls: { anchors: [S.cert] } }))) === "est/transport-error");
}

// ---- more redirect / auth conformance branches -----------------------------
async function testMoreBranches() {
  // a Buffer response body (the default transport returns Buffer bodies; the fake usually strings)
  var t = fakeTransport({ status: 200, headers: ct("application/pkcs7-mime"), body: Buffer.from(pki.est.transferEncode(certsOnly([S.cert])), "latin1") });
  check("#27 a Buffer response body decodes", (await pki.est.cacerts(BASE, { transport: t })).certificates.length === 1);
  // a Digest-only challenge is unsupported -> fail closed (Basic only)
  check("#27 a non-Basic (Digest) challenge fails closed", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: fakeTransport({ status: 401, headers: { "www-authenticate": "Digest realm=\"est\"" }, body: "" }), username: "u", password: "p" }))) === "est/auth-required");
  // a second 401 after a credentialed retry -> fail closed
  var t401 = fakeTransport([{ status: 401, headers: { "www-authenticate": "Basic realm=\"est\"" }, body: "" }, { status: 401, headers: { "www-authenticate": "Basic realm=\"est\"" }, body: "" }]);
  check("#27 a rejected credentialed retry fails closed", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: t401, username: "u", password: "p" }))) === "est/auth-required");
  check("#27 the client sent credentials exactly once", t401.calls.length === 2 && /^Basic /.test(t401.calls[1].headers.authorization));
  // a 3xx with no Location -> fail closed
  check("#27 a redirect with no Location fails closed", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport({ status: 302, headers: {}, body: "" }) }))) === "est/http-error");
  // a cross-origin GET redirect IS followed (RFC 7030 sec. 3.2.1 permits GET/HEAD cross-origin)
  var tco = fakeTransport([{ status: 302, headers: { location: "https://mirror.example/.well-known/est/cacerts" }, body: "" }, cacertsOK([S.cert])]);
  var rco = await pki.est.cacerts(BASE, { transport: tco });
  check("#27 a cross-origin GET redirect is followed", rco.certificates.length === 1 && tco.calls.length === 2 && tco.calls[1].url.indexOf("https://mirror.example") === 0);
  // HTTP credentials MUST NOT cross an origin boundary: a 401 adds Basic auth, then a cross-origin
  // redirect must drop it before the next request reaches the new origin.
  var tleak = fakeTransport([
    { status: 401, headers: { "www-authenticate": "Basic realm=\"est\"" }, body: "" },
    { status: 302, headers: { location: "https://mirror.example/.well-known/est/cacerts" }, body: "" },
    cacertsOK([S.cert]),
  ]);
  var rleak = await pki.est.cacerts(BASE, { transport: tleak, username: "u", password: "p" });
  check("#27 credentials are sent to the original origin", /^Basic /.test(tleak.calls[1].headers.authorization));
  check("#27 credentials are STRIPPED on the cross-origin redirect", !tleak.calls[2].headers.authorization && rleak.certificates.length === 1);
}

// ---- credential-scope + auth-scheme hardening ------------------------------
async function testAuthScopeAndScheme() {
  // a 401 arriving AFTER a cross-origin redirect is a different server -- credentials MUST NOT be
  // built and sent there, even though the client has them (the redirect-then-401 leak).
  var tredir = fakeTransport([
    { status: 302, headers: { location: "https://mirror.example/.well-known/est/cacerts" }, body: "" },
    { status: 401, headers: { "www-authenticate": "Basic realm=\"est\"" }, body: "" },
  ]);
  check("#28 a 401 after a cross-origin redirect refuses to send credentials", (await codeOf(pki.est.cacerts(BASE, { transport: tredir, username: "u", password: "p" }))) === "est/auth-required");
  check("#28 no credentials reached the redirected origin", tredir.calls.every(function (c) { return !(c.headers && c.headers.authorization); }));
  // a Digest/Bearer challenge that merely CONTAINS 'basic' in a parameter is not a Basic challenge.
  check("#28 a Digest challenge with 'basic' in a param is not answered with Basic", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: fakeTransport({ status: 401, headers: { "www-authenticate": "Digest realm=\"basic\"" }, body: "" }), username: "u", password: "p" }))) === "est/auth-required");
  check("#28 a Bearer challenge naming 'basic' is not answered with Basic", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: fakeTransport({ status: 401, headers: { "www-authenticate": "Bearer error=\"basic required\"" }, body: "" }), username: "u", password: "p" }))) === "est/auth-required");
  // a genuine Basic challenge inside a comma-separated challenge list IS honored.
  var tlist = fakeTransport([{ status: 401, headers: { "www-authenticate": "Digest realm=\"x\", Basic realm=\"y\"" }, body: "" }, enrollOK([S.cert])]);
  var rlist = await pki.est.simpleenroll(BASE, CSR, { transport: tlist, username: "u", password: "p" });
  check("#28 a Basic challenge in a comma-separated list is honored", rlist.certificate.equals(S.cert) && /^Basic /.test(tlist.calls[1].headers.authorization));
  // a non-standard 2xx (201/203/206) with a valid certs-only body must NOT be decoded and accepted --
  // only 200 (and 202-retry) are valid EST responses.
  check("#28 a non-standard 2xx status is rejected, not parsed as certificates", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport({ status: 203, headers: ct("application/pkcs7-mime"), body: pki.est.transferEncode(certsOnly([S.cert])) }) }))) === "est/http-error");
  // an injected transport using ordinary HTTP header casing is handled (the verb normalizes headers).
  var tcap = fakeTransport([{ status: 302, headers: { Location: "https://ca.example/.well-known/est/cacerts?x=1" }, body: "" }, cacertsOK([S.cert])]);
  var rcap = await pki.est.cacerts(BASE, { transport: tcap });
  check("#28 a capitalized Location header is followed (headers normalized)", rcap.certificates.length === 1 && tcap.calls.length === 2);
  var tcapAuth = fakeTransport([{ status: 401, headers: { "WWW-Authenticate": "Basic realm=\"est\"" }, body: "" }, enrollOK([S.cert])]);
  var rcapAuth = await pki.est.simpleenroll(BASE, CSR, { transport: tcapAuth, username: "u", password: "p" });
  check("#28 a capitalized WWW-Authenticate is honored (headers normalized)", rcapAuth.certificate.equals(S.cert) && /^Basic /.test(tcapAuth.calls[1].headers.authorization));
  // a comma + Basic INSIDE a quoted auth-param is not a Basic challenge (the list is tokenized honoring quotes).
  check("#28 a comma+Basic inside a quoted auth-param is not treated as a Basic challenge", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: fakeTransport({ status: 401, headers: { "www-authenticate": "Digest realm=\"x, Basic required\"" }, body: "" }), username: "u", password: "p" }))) === "est/auth-required");
  // a non-boolean tls.useSystemStore (e.g. a "false" string from JSON/env) is not an opt-in -> fail closed.
  check("#28 a non-boolean useSystemStore is not a trust opt-in", (await codeOf(pki.est.cacerts(BASE, { tls: { useSystemStore: "false" } }))) === "est/no-trust-anchors");
}

// ---- redirect credential scope + 303 method conversion --------------------
async function testRedirectCredentialScope() {
  // the mTLS client identity is origin-bound: a cross-origin redirect strips tls.cert/key (like Basic).
  var tmtls = fakeTransport([{ status: 302, headers: { location: "https://mirror.example/.well-known/est/cacerts" }, body: "" }, cacertsOK([S.cert])]);
  var rmtls = await pki.est.cacerts(BASE, { transport: tmtls, tls: { anchors: [S.cert], cert: Buffer.from("CLIENTCERT"), key: Buffer.from("CLIENTKEY") } });
  check("#29 the mTLS cert/key are presented on the original origin", !!(tmtls.calls[0].tls.cert && tmtls.calls[0].tls.key));
  check("#29 the mTLS cert/key are stripped on a cross-origin redirect", !tmtls.calls[1].tls.cert && !tmtls.calls[1].tls.key && rmtls.certificates.length === 1);
  // On a cross-origin redirect the origin-specific servername (SNI) is reset, but a caller's
  // checkServerIdentity pin is RETAINED -- it is an additional tightening constraint that node re-evaluates
  // against the redirected host, so a certificate/SPKI pin keeps applying (dropping it would let the
  // redirected host through under only default hostname validation, bypassing the pin).
  var pinnedCheck = function () { return undefined; };
  var tpin = fakeTransport([{ status: 302, headers: { location: "https://mirror.example/.well-known/est/cacerts" }, body: "" }, cacertsOK([S.cert])]);
  var rpin = await pki.est.cacerts(BASE, { transport: tpin, tls: { anchors: [S.cert], servername: "ca.example", checkServerIdentity: pinnedCheck } });
  check("#29 the pinned servername + checkServerIdentity are presented on the original origin", tpin.calls[0].tls.servername === "ca.example" && tpin.calls[0].tls.checkServerIdentity === pinnedCheck);
  check("#29 a cross-origin redirect resets the origin-specific servername but RETAINS the checkServerIdentity pin", tpin.calls[1].tls.servername === undefined && tpin.calls[1].tls.checkServerIdentity === pinnedCheck && rpin.certificates.length === 1);
  // A redirect that leaves the origin and then returns to it restores the origin-scoped SNI on the return hop
  // (per-hop TLS scoping, not a one-way strip): ca.example -> mirror.example (SNI dropped) -> ca.example (SNI back).
  var tbounce = fakeTransport([
    { status: 302, headers: { location: "https://mirror.example/.well-known/est/cacerts" }, body: "" },
    { status: 302, headers: { location: "https://ca.example/.well-known/est/cacerts" }, body: "" },
    cacertsOK([S.cert]),
  ]);
  var rbounce = await pki.est.cacerts(BASE, { transport: tbounce, tls: { anchors: [S.cert], servername: "ca.example" } });
  check("#29 a redirect off-origin then back restores the origin-scoped servername on the return hop", tbounce.calls[0].tls.servername === "ca.example" && tbounce.calls[1].tls.servername === undefined && tbounce.calls[2].tls.servername === "ca.example" && rbounce.certificates.length === 1);
  // The HTTP Basic credential is likewise origin-scoped per hop: after a 401 on the origin it is sent to that
  // origin, dropped off-origin, and RESTORED on a redirect back -- so an authenticated flow that bounces
  // off-origin and returns still completes instead of arriving unauthenticated and being re-challenged.
  var tcred = fakeTransport([
    { status: 401, headers: { "www-authenticate": "Basic realm=x" }, body: "" },
    { status: 302, headers: { location: "https://mirror.example/.well-known/est/cacerts" }, body: "" },
    { status: 302, headers: { location: "https://ca.example/.well-known/est/cacerts" }, body: "" },
    cacertsOK([S.cert]),
  ]);
  var rcred = await pki.est.cacerts(BASE, { transport: tcred, username: "u", password: "p" });
  check("#29 the Basic credential is restored on a redirect back to the original origin", /^Basic /.test(tcred.calls[1].headers.authorization) && !tcred.calls[2].headers.authorization && /^Basic /.test(tcred.calls[3].headers.authorization) && rcred.certificates.length === 1);
  // a 303 See Other converts the follow to a GET with no body (no duplicate CSR re-POST).
  var t303 = fakeTransport([{ status: 303, headers: { location: "https://ca.example/.well-known/est/simpleenroll?x=1" }, body: "" }, enrollOK([S.cert])]);
  var r303 = await pki.est.simpleenroll(BASE, CSR, { transport: t303 });
  check("#29 a 303 converts the follow to GET with no body", t303.calls[1].method === "GET" && (t303.calls[1].body == null || t303.calls[1].body === "") && r303.certificate.equals(S.cert));
}

// ---- an ambiguous issued certificate (multiple key matches) is rejected ----
async function testAmbiguousIssued() {
  // a second, distinct certificate minted from the SAME key as the CSR -> two response certs match
  // the submitted public key; with no issuance ordering, the issued cert is ambiguous.
  var dup = await pki.x509.sign(
    { subject: "renewed", subjectPublicKey: S.spki, serialNumber: 0x9999, notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2044-01-01T00:00:00Z") },
    { key: S.key });
  var t = fakeTransport(enrollOK([S.cert, dup]));
  check("#30 two certificates matching the CSR key are rejected as ambiguous", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: t }))) === "est/ambiguous-issued-cert");
}

// ---- HTTP Digest authentication (RFC 7616), driven cross-verb over the 401->200 flow ----
var _crypto = require("crypto");
function digestParam(header, name) {
  var m = new RegExp("(?:^Digest |, )" + name + "=(\"(?:[^\"\\\\]|\\\\.)*\"|[^,]*)").exec(String(header || ""));
  if (!m) return null;
  var v = m[1];
  return v.charAt(0) === "\"" ? v.slice(1, -1).replace(/\\(.)/g, "$1") : v;
}
// Recompute the Digest response from the EMITTED header (self-consistency; no rng injection) -- proves the
// answer is internally correct over the real request-target + the client's own cnonce.
function recomputeDigest(header, p) {
  var ALG = { "SHA-256": "sha256", "SHA-512-256": "sha512-256", "MD5": "md5" };
  var hash = ALG[digestParam(header, "algorithm")];
  if (!hash) return false;
  function h(s) { return _crypto.createHash(hash).update(s, "latin1").digest("hex"); }
  var nonce = digestParam(header, "nonce"), cnonce = digestParam(header, "cnonce"), nc = digestParam(header, "nc"),
    qop = digestParam(header, "qop"), realm = digestParam(header, "realm"), uri = digestParam(header, "uri");
  var HA1 = h((p.username || "") + ":" + realm + ":" + (p.password || ""));
  var A2 = qop === "auth-int" ? p.method + ":" + uri + ":" + h(p.body == null ? "" : p.body) : p.method + ":" + uri;
  var HA2 = h(A2);
  var expect = qop ? h(HA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HA2) : h(HA1 + ":" + nonce + ":" + HA2);
  return digestParam(header, "response") === expect;
}
function chal(o) {   // build a WWW-Authenticate Digest challenge from parts
  var parts = ['realm="' + (o.realm === undefined ? "est" : o.realm) + '"'];
  if (o.nonce !== undefined) parts.push('nonce="' + o.nonce + '"');
  if (o.qop !== undefined) parts.push('qop="' + o.qop + '"');
  if (o.algorithm !== undefined) parts.push("algorithm=" + o.algorithm);
  if (o.opaque !== undefined) parts.push('opaque="' + o.opaque + '"');
  if (o.domain !== undefined) parts.push('domain="' + o.domain + '"');
  if (o.stale) parts.push("stale=true");
  return { "www-authenticate": "Digest " + parts.join(", ") };
}
function chal401(o) { return { status: 401, headers: chal(o), body: "" }; }
async function testDigestAuth() {
  var DIG = { scheme: "digest", username: "u", password: "p" };
  var CACERTS_URI = "/.well-known/est/cacerts", ENROLL_URI = "/.well-known/est/simpleenroll";
  // D-1 Digest happy GET
  var t1 = fakeTransport([chal401({ nonce: "abc", qop: "auth", algorithm: "SHA-256" }), cacertsOK([S.cert])]);
  var r1 = await pki.est.cacerts(BASE, { transport: t1, auth: DIG });
  var a1 = t1.calls[1].headers.authorization;
  check("#D-1 a Digest 401 is answered and the GET succeeds", r1.certificates.length === 1 && t1.calls.length === 2 && /^Digest /.test(a1) &&
    digestParam(a1, "username") === "u" && digestParam(a1, "realm") === "est" && digestParam(a1, "nonce") === "abc" &&
    digestParam(a1, "uri") === CACERTS_URI && digestParam(a1, "nc") === "00000001" && digestParam(a1, "qop") === "auth" &&
    recomputeDigest(a1, { method: "GET", uri: CACERTS_URI, username: "u", password: "p" }));
  // D-oversize an oversized WWW-Authenticate is rejected by the auth handler's cap BEFORE any scheme scan /
  // copy, so an injected transport without its own header limit cannot force unbounded allocation.
  var tOversize = fakeTransport({ status: 401, headers: { "www-authenticate": 'Digest realm="' + "a".repeat(9000) + '"' }, body: "" });
  check("#D-oversize an over-length WWW-Authenticate is bounded before the scheme scan", (await codeOf(pki.est.cacerts(BASE, { transport: tOversize, auth: DIG }))) === "est/auth-required");
  // D-1p Digest happy POST (enroll)
  var t1p = fakeTransport([chal401({ nonce: "n", qop: "auth", algorithm: "SHA-256" }), enrollOK([S.cert])]);
  var r1p = await pki.est.simpleenroll(BASE, CSR, { transport: t1p, auth: DIG });
  var a1p = t1p.calls[1].headers.authorization;
  check("#D-1p a Digest 401 is answered and the POST enroll succeeds", r1p.certificate.equals(S.cert) && digestParam(a1p, "uri") === ENROLL_URI &&
    recomputeDigest(a1p, { method: "POST", uri: ENROLL_URI, username: "u", password: "p" }));
  // D-3 SHA-512-256
  var t3 = fakeTransport([chal401({ nonce: "n", qop: "auth", algorithm: "SHA-512-256" }), cacertsOK([S.cert])]);
  await pki.est.cacerts(BASE, { transport: t3, auth: DIG });
  check("#D-3 SHA-512-256 is answered", digestParam(t3.calls[1].headers.authorization, "algorithm") === "SHA-512-256" && recomputeDigest(t3.calls[1].headers.authorization, { method: "GET", uri: CACERTS_URI, username: "u", password: "p" }));
  // D-4 opaque echo / absent
  var t4 = fakeTransport([chal401({ nonce: "n", qop: "auth", algorithm: "SHA-256", opaque: "XYZ" }), cacertsOK([S.cert])]);
  await pki.est.cacerts(BASE, { transport: t4, auth: DIG });
  check("#D-4a opaque is echoed verbatim", digestParam(t4.calls[1].headers.authorization, "opaque") === "XYZ");
  check("#D-4b no opaque when the challenge omits it", digestParam(a1, "opaque") === null);
  // D-5 auth-int over the exact body
  var t5 = fakeTransport([chal401({ nonce: "n", qop: "auth-int", algorithm: "SHA-256" }), enrollOK([S.cert])]);
  await pki.est.simpleenroll(BASE, CSR, { transport: t5, auth: DIG });
  var a5 = t5.calls[1].headers.authorization;
  check("#D-5 auth-int hashes the exact transfer body", digestParam(a5, "qop") === "auth-int" && recomputeDigest(a5, { method: "POST", uri: ENROLL_URI, username: "u", password: "p", body: t5.calls[0].body }));
  // D-6 stale bounded retry
  var t6 = fakeTransport([chal401({ nonce: "n1", qop: "auth", algorithm: "SHA-256" }), chal401({ nonce: "n2", qop: "auth", algorithm: "SHA-256", stale: true }), enrollOK([S.cert])]);
  var r6 = await pki.est.simpleenroll(BASE, CSR, { transport: t6, auth: { scheme: "digest", username: "u", password: "p", maxStaleRetries: 1 } });
  check("#D-6 a stale=true re-challenge is retried (bounded) with the fresh nonce", r6.certificate.equals(S.cert) && t6.calls.length === 3 && digestParam(t6.calls[2].headers.authorization, "nonce") === "n2");
  // D-6-prefer-stale: a credentialed request is rejected with TWO same-realm offers -- a stronger stale=false
  // (terminal) and a weaker usable stale=true (retryable). Selection must prefer the RETRYABLE stale offer so
  // the request re-answers instead of being refused because the strongest offer happened to be non-stale.
  var tStale = fakeTransport([
    chal401({ realm: "est", nonce: "nA", qop: "auth", algorithm: "SHA-256" }),
    { status: 401, headers: { "www-authenticate": 'Digest realm="est", nonce="nB1", qop="auth", algorithm=SHA-512-256, Digest realm="est", nonce="nB2", qop="auth", algorithm=SHA-256, stale=true' }, body: "" },
    cacertsOK([S.cert]),
  ]);
  var rStale = await pki.est.cacerts(BASE, { transport: tStale, auth: DIG });
  check("#D-6-prefer-stale a retryable stale offer is preferred over a stronger non-stale one in a rejection", rStale.certificates.length === 1 && tStale.calls.length === 3 && digestParam(tStale.calls[2].headers.authorization, "algorithm") === "SHA-256" && digestParam(tStale.calls[2].headers.authorization, "nonce") === "nB2");
  // D-6-prefer-stale-fresh: two stale=true offers -- a STRONGER one repeating the just-rejected nonce (not
  // retryable) and a weaker one with a FRESH nonce. Selection must pick the retryable (fresh-nonce) offer.
  var tStaleN = fakeTransport([
    chal401({ realm: "est", nonce: "nA", qop: "auth", algorithm: "SHA-256" }),
    { status: 401, headers: { "www-authenticate": 'Digest realm="est", nonce="nA", qop="auth", algorithm=SHA-512-256, stale=true, Digest realm="est", nonce="nB", qop="auth", algorithm=SHA-256, stale=true' }, body: "" },
    cacertsOK([S.cert]),
  ]);
  var rStaleN = await pki.est.cacerts(BASE, { transport: tStaleN, auth: DIG });
  check("#D-6-prefer-stale-fresh a stale offer with a FRESH nonce beats a stronger one repeating the rejected nonce", rStaleN.certificates.length === 1 && tStaleN.calls.length === 3 && digestParam(tStaleN.calls[2].headers.authorization, "algorithm") === "SHA-256" && digestParam(tStaleN.calls[2].headers.authorization, "nonce") === "nB");
  // D-6-prefer-stale-realm: the stale-retry preference applies ONLY to the rejected realm. A stronger stale
  // offer for a DIFFERENT realm B must not shadow a genuinely retryable stale offer for the rejected realm A.
  var tRealmStale = fakeTransport([
    chal401({ realm: "A", nonce: "nA", qop: "auth", algorithm: "SHA-256" }),
    { status: 401, headers: { "www-authenticate": 'Digest realm="B", nonce="nB", qop="auth", algorithm=SHA-512-256, stale=true, Digest realm="A", nonce="nA2", qop="auth", algorithm=SHA-256, stale=true' }, body: "" },
    cacertsOK([S.cert]),
  ]);
  var rRealmStale = await pki.est.cacerts(BASE, { transport: tRealmStale, auth: DIG });
  check("#D-6-prefer-stale-realm the stale-retry preference is restricted to the rejected realm (retries A, not a stronger B)", rRealmStale.certificates.length === 1 && tRealmStale.calls.length === 3 && digestParam(tRealmStale.calls[2].headers.authorization, "realm") === "A" && digestParam(tRealmStale.calls[2].headers.authorization, "nonce") === "nA2");
  // D-7 / D-8 scheme mismatch
  check("#D-7 Digest requested but only Basic offered", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: fakeTransport({ status: 401, headers: { "www-authenticate": 'Basic realm="est"' }, body: "" }), auth: DIG }))) === "est/auth-required");
  var t8 = fakeTransport({ status: 401, headers: chal({ nonce: "n" }), body: "" });
  check("#D-8 Basic requested (legacy) but only Digest offered", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: t8, username: "u", password: "p" }))) === "est/auth-required" && !(t8.calls[0].headers && t8.calls[0].headers.authorization));
  // D-9 MD5 off / on
  check("#D-9a MD5 is refused by default", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport(chal401({ nonce: "n", qop: "auth", algorithm: "MD5" })), auth: DIG }))) === "est/digest-weak-algorithm");
  var t9b = fakeTransport([chal401({ nonce: "n", qop: "auth", algorithm: "MD5" }), enrollOK([S.cert])]);
  await pki.est.simpleenroll(BASE, CSR, { transport: t9b, auth: { scheme: "digest", username: "u", password: "p", allowMD5: true } });
  check("#D-9b MD5 is answered when opted in", digestParam(t9b.calls[1].headers.authorization, "algorithm") === "MD5" && recomputeDigest(t9b.calls[1].headers.authorization, { method: "POST", uri: ENROLL_URI, username: "u", password: "p" }));
  // D-10 / D-11 / D-12 malformed / unsupported
  check("#D-10 a Digest challenge missing nonce", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport({ status: 401, headers: { "www-authenticate": 'Digest realm="est", qop="auth"' }, body: "" }), auth: DIG }))) === "est/digest-bad-challenge");
  check("#D-11 a Digest challenge missing realm", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport({ status: 401, headers: { "www-authenticate": 'Digest nonce="n", qop="auth"' }, body: "" }), auth: DIG }))) === "est/digest-bad-challenge");
  check("#D-12 an unsupported Digest algorithm", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport(chal401({ nonce: "n", qop: "auth", algorithm: "SHA-1" })), auth: DIG }))) === "est/digest-unsupported-algorithm");
  // D-13 no-qop off / on
  check("#D-13a a no-qop (RFC 2069) challenge is refused by default", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport(chal401({ nonce: "n", algorithm: "SHA-256" })), auth: DIG }))) === "est/digest-no-qop");
  var t13b = fakeTransport([chal401({ nonce: "n", algorithm: "SHA-256" }), enrollOK([S.cert])]);
  await pki.est.simpleenroll(BASE, CSR, { transport: t13b, auth: { scheme: "digest", username: "u", password: "p", allowLegacyQop: true } });
  var a13b = t13b.calls[1].headers.authorization;
  check("#D-13b a no-qop challenge (opted in) emits no qop/nc/cnonce and the RFC 2069 response", digestParam(a13b, "qop") === null && digestParam(a13b, "nc") === null && recomputeDigest(a13b, { method: "POST", uri: ENROLL_URI, username: "u", password: "p" }));
  // D-14 401 after a cross-origin redirect refuses
  var t14 = fakeTransport([{ status: 302, headers: { location: "https://mirror.example/.well-known/est/cacerts" }, body: "" }, chal401({ nonce: "n", algorithm: "SHA-256", qop: "auth" })]);
  check("#D-14 a 401 after a cross-origin redirect refuses credentials", (await codeOf(pki.est.cacerts(BASE, { transport: t14, auth: DIG }))) === "est/auth-required" && t14.calls.every(function (c) { return !(c.headers && c.headers.authorization); }));
  // D-15 scheme digest, no creds
  var t15 = fakeTransport(chal401({ nonce: "n", qop: "auth", algorithm: "SHA-256" }));
  check("#D-15 scheme:digest with no credentials fails closed", (await codeOf(pki.est.cacerts(BASE, { transport: t15, auth: { scheme: "digest" } }))) === "est/auth-required" && t15.calls.length === 1);
  // D-16 second non-stale 401 terminates
  var t16 = fakeTransport([chal401({ nonce: "n1", qop: "auth", algorithm: "SHA-256" }), chal401({ nonce: "n2", qop: "auth", algorithm: "SHA-256" })]);
  check("#D-16 a second non-stale 401 terminates", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: t16, auth: { scheme: "digest", username: "u", password: "p", maxStaleRetries: 1 } }))) === "est/auth-required" && t16.calls.length === 2);
  // D-16b stale past the bound terminates
  var t16b = fakeTransport([chal401({ nonce: "n1", qop: "auth", algorithm: "SHA-256" }), chal401({ nonce: "n2", qop: "auth", algorithm: "SHA-256", stale: true }), chal401({ nonce: "n3", qop: "auth", algorithm: "SHA-256", stale: true })]);
  check("#D-16b stale retries past the bound terminate", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: t16b, auth: { scheme: "digest", username: "u", password: "p", maxStaleRetries: 1 } }))) === "est/auth-required" && t16b.calls.length === 3);
  // D-17 hostile challenge: a comma inside a quoted realm is not a Basic challenge
  var t17 = fakeTransport([{ status: 401, headers: { "www-authenticate": 'Digest realm="x, Basic required", nonce="n", qop="auth", algorithm=SHA-256' }, body: "" }, enrollOK([S.cert])]);
  var r17 = await pki.est.simpleenroll(BASE, CSR, { transport: t17, auth: DIG });
  check("#D-17 a comma inside a quoted realm is answered as Digest (not misread as Basic)", r17.certificate.equals(S.cert) && /^Digest /.test(t17.calls[1].headers.authorization) && digestParam(t17.calls[1].headers.authorization, "realm") === "x, Basic required");
  // D-empty-user empty username allowed
  var tE = fakeTransport([chal401({ nonce: "n", qop: "auth", algorithm: "SHA-256" }), enrollOK([S.cert])]);
  await pki.est.simpleenroll(BASE, CSR, { transport: tE, auth: { scheme: "digest", username: "", password: "p" } });
  var aE = tE.calls[1].headers.authorization;
  check("#D-empty an empty username is allowed", digestParam(aE, "username") === "" && recomputeDigest(aE, { method: "POST", uri: ENROLL_URI, username: "", password: "p" }));
  // D-basic-nocreds: an explicit scheme:"basic" with no credentials fails closed (never sends "Basic Og==")
  var tBn = fakeTransport({ status: 401, headers: { "www-authenticate": 'Basic realm="est"' }, body: "" });
  check("#D-basic-nocreds scheme:basic with no credentials fails closed, no Authorization sent", (await codeOf(pki.est.cacerts(BASE, { transport: tBn, auth: { scheme: "basic" } }))) === "est/auth-required" && tBn.calls.every(function (c) { return !(c.headers && c.headers.authorization); }));
  // D-stale-samenonce: a stale=true re-challenge that REUSES the nonce terminates (RFC 7616 requires a fresh nonce)
  var tSs = fakeTransport([chal401({ nonce: "n1", qop: "auth", algorithm: "SHA-256" }), chal401({ nonce: "n1", qop: "auth", algorithm: "SHA-256", stale: true })]);
  check("#D-stale-samenonce a stale=true re-challenge reusing the same nonce terminates (a fresh nonce is required)", (await codeOf(pki.est.simpleenroll(BASE, CSR, { transport: tSs, auth: { scheme: "digest", username: "u", password: "p", maxStaleRetries: 2 } }))) === "est/auth-required" && tSs.calls.length === 2);
  // D-redirect: a same-origin redirect after a Digest 401 recomputes the answer for the NEW request-target (a
  // Digest response is method+uri-bound, unlike Basic) -- the cached answer's stale uri would otherwise be rejected.
  var tRd = fakeTransport([
    chal401({ nonce: "n", qop: "auth", algorithm: "SHA-256" }),
    { status: 302, headers: { location: "https://ca.example/.well-known/est/mirror" }, body: "" },
    cacertsOK([S.cert]),
  ]);
  var rRd = await pki.est.cacerts(BASE, { transport: tRd, auth: { scheme: "digest", username: "u", password: "p" } });
  check("#D-redirect a same-origin redirect recomputes the Digest answer for the new request-target", rRd.certificates.length === 1 && tRd.calls.length === 3 &&
    digestParam(tRd.calls[1].headers.authorization, "uri") === "/.well-known/est/cacerts" &&
    digestParam(tRd.calls[2].headers.authorization, "uri") === "/.well-known/est/mirror" &&
    recomputeDigest(tRd.calls[2].headers.authorization, { method: "GET", uri: "/.well-known/est/mirror", username: "u", password: "p" }));
  check("#D-redirect-nc the reused nonce increments the nonce-count across the redirect (never repeats a (nonce, nc) pair)", digestParam(tRd.calls[1].headers.authorization, "nc") === "00000001" && digestParam(tRd.calls[2].headers.authorization, "nc") === "00000002");
  // D-select: the caller's Digest policy MUST flow into challenge SELECTION, not just the answer. A 401 offers
  // MD5 with qop=auth (usable only because this caller set allowMD5) and SHA-256 with no qop (a higher algorithm
  // rank, but UNusable under this policy). The client must answer the usable MD5+qop offer; were selection blind
  // to the policy it would pick the higher-ranked SHA-256 no-qop and then fail the no-qop gate at answer time.
  var tSel = fakeTransport([{ status: 401, headers: { "www-authenticate": 'Digest realm="est", nonce="s1", qop="auth", algorithm=MD5, Digest realm="est", nonce="s2", algorithm=SHA-256' }, body: "" }, cacertsOK([S.cert])]);
  var rSel = await pki.est.cacerts(BASE, { transport: tSel, auth: { scheme: "digest", username: "u", password: "p", allowMD5: true } });
  check("#D-select the caller policy flows into selection: the usable MD5+qop offer is answered, not the unusable SHA-256 no-qop one", rSel.certificates.length === 1 && digestParam(tSel.calls[1].headers.authorization, "algorithm") === "MD5" && digestParam(tSel.calls[1].headers.authorization, "nonce") === "s1");
  // D-select-applicable: a 401 offers a STRONGER challenge scoped (via domain) to a DIFFERENT resource and a
  // weaker one scoped to THIS request. Selection must prefer the one whose protection space covers the request,
  // or the client would omit the credential for the chosen (out-of-space) challenge and loop on 401s.
  var tApp = fakeTransport([
    { status: 401, headers: { "www-authenticate": 'Digest realm="r", nonce="n1", qop="auth", algorithm=SHA-512-256, domain="/other", Digest realm="r", nonce="n2", qop="auth", algorithm=SHA-256, domain="' + CACERTS_URI + '"' }, body: "" },
    cacertsOK([S.cert]),
  ]);
  var rApp = await pki.est.cacerts(BASE, { transport: tApp, auth: DIG });
  check("#D-select-applicable an offer whose domain covers THIS request beats a stronger one scoped elsewhere", rApp.certificates.length === 1 && tApp.calls.length === 2 && digestParam(tApp.calls[1].headers.authorization, "algorithm") === "SHA-256" && digestParam(tApp.calls[1].headers.authorization, "nonce") === "n2");
  // D-space: a same-origin redirect to a URI OUTSIDE the challenge's protection space (domain) is sent
  // unauthenticated, and the target resource's OWN Digest realm drives a fresh authentication instead of being
  // blocked by the first realm's one-shot guard. Realm "est" is scoped to /cacerts; the redirect enters realm
  // "mirror" at /mirror (RFC 7616 sec. 3.3 / 3.5).
  var MIRROR = "https://ca.example/.well-known/est/mirror";
  var tSp = fakeTransport([
    chal401({ realm: "est", nonce: "nA", qop: "auth", algorithm: "SHA-256", domain: CACERTS_URI }),
    { status: 302, headers: { location: MIRROR }, body: "" },
    chal401({ realm: "mirror", nonce: "nB", qop: "auth", algorithm: "SHA-256" }),
    cacertsOK([S.cert]),
  ]);
  var rSp = await pki.est.cacerts(BASE, { transport: tSp, auth: DIG });
  check("#D-space a redirect out of the challenge domain is unauthenticated, and the new realm authenticates fresh",
    rSp.certificates.length === 1 && tSp.calls.length === 4 &&
    digestParam(tSp.calls[1].headers.authorization, "realm") === "est" &&
    !(tSp.calls[2].headers && tSp.calls[2].headers.authorization) &&
    digestParam(tSp.calls[3].headers.authorization, "realm") === "mirror" && digestParam(tSp.calls[3].headers.authorization, "nonce") === "nB");
  // D-space-samerealm: a redirect out of the domain is sent unauthenticated, and if the new resource challenges
  // with the SAME realm it is still a FRESH authentication (the request carried no credential to be rejected) --
  // the rejection test keys on whether the request actually carried Digest credentials, not on the realm alone.
  var tSm = fakeTransport([
    chal401({ realm: "est", nonce: "nA", qop: "auth", algorithm: "SHA-256", domain: CACERTS_URI }),
    { status: 302, headers: { location: MIRROR }, body: "" },
    chal401({ realm: "est", nonce: "nM", qop: "auth", algorithm: "SHA-256" }),
    cacertsOK([S.cert]),
  ]);
  var rSm = await pki.est.cacerts(BASE, { transport: tSm, auth: DIG });
  check("#D-space-samerealm an unauthenticated out-of-domain request whose 401 reuses the realm still authenticates fresh",
    rSm.certificates.length === 1 && tSm.calls.length === 4 &&
    !(tSm.calls[2].headers && tSm.calls[2].headers.authorization) &&
    digestParam(tSm.calls[3].headers.authorization, "realm") === "est" && digestParam(tSm.calls[3].headers.authorization, "nonce") === "nM");
  // D-space-nonce-preserve: when the out-of-domain resource challenges with the SAME still-valid nonce, the
  // nonce-count must KEEP advancing (not reset to 1) -- a (nonce, nc) pair must never repeat or a server's
  // replay detection rejects it (RFC 7616 sec. 3.4).
  var tNp = fakeTransport([
    chal401({ realm: "est", nonce: "nA", qop: "auth", algorithm: "SHA-256", domain: CACERTS_URI }),
    { status: 302, headers: { location: MIRROR }, body: "" },
    chal401({ realm: "est", nonce: "nA", qop: "auth", algorithm: "SHA-256" }),
    cacertsOK([S.cert]),
  ]);
  var rNp = await pki.est.cacerts(BASE, { transport: tNp, auth: DIG });
  check("#D-space-nonce-preserve a fresh challenge reusing the same nonce keeps the nonce-count advancing (no nc replay)",
    rNp.certificates.length === 1 && tNp.calls.length === 4 &&
    digestParam(tNp.calls[1].headers.authorization, "nc") === "00000001" &&
    !(tNp.calls[2].headers && tNp.calls[2].headers.authorization) &&
    digestParam(tNp.calls[3].headers.authorization, "nc") === "00000002");
  // D-space-nonce-alt: NON-consecutive reuse. Nonce nA (space /cacerts), then nB (space /mirror), then a hop
  // back to /cacerts that REISSUES the still-valid nA. The count is tracked PER NONCE, so nA resumes at 2 --
  // tracking only the most-recent nonce would reset it and replay (nA, 1) (RFC 7616 sec. 3.4).
  var CACERTS_FULL = "https://ca.example/.well-known/est/cacerts";
  var tAlt = fakeTransport([
    chal401({ realm: "A", nonce: "nA", qop: "auth", algorithm: "SHA-256", domain: CACERTS_URI }),
    { status: 302, headers: { location: MIRROR }, body: "" },
    chal401({ realm: "B", nonce: "nB", qop: "auth", algorithm: "SHA-256", domain: "/.well-known/est/mirror" }),
    { status: 302, headers: { location: CACERTS_FULL }, body: "" },
    chal401({ realm: "A", nonce: "nA", qop: "auth", algorithm: "SHA-256", domain: CACERTS_URI }),
    cacertsOK([S.cert]),
  ]);
  var rAlt = await pki.est.cacerts(BASE, { transport: tAlt, auth: DIG });
  check("#D-space-nonce-alt a nonce reissued after another was used resumes its own count (per-nonce, no replay)",
    rAlt.certificates.length === 1 && tAlt.calls.length === 6 &&
    digestParam(tAlt.calls[1].headers.authorization, "nc") === "00000001" &&
    digestParam(tAlt.calls[3].headers.authorization, "nc") === "00000001" &&
    digestParam(tAlt.calls[5].headers.authorization, "nonce") === "nA" && digestParam(tAlt.calls[5].headers.authorization, "nc") === "00000002");
  // D-space-reject: a SAME-realm non-stale second 401 is a rejection of the credential, NOT a new protection
  // space -- the realm check must not turn a genuine rejection into an open re-answer loop.
  var tRej = fakeTransport([chal401({ realm: "est", nonce: "n1", qop: "auth", algorithm: "SHA-256" }), chal401({ realm: "est", nonce: "n2", qop: "auth", algorithm: "SHA-256" })]);
  check("#D-space-reject a same-realm non-stale second 401 is a rejection, not a new space", (await codeOf(pki.est.cacerts(BASE, { transport: tRej, auth: DIG }))) === "est/auth-required" && tRej.calls.length === 2);
  // D-space-bound: a server that loops with an endless stream of NEW realms is bounded (maxRedirects), never
  // answered forever.
  var manyRealms = [];
  for (var si = 0; si < 6; si++) manyRealms.push(chal401({ realm: "r" + si, nonce: "z" + si, qop: "auth", algorithm: "SHA-256" }));
  check("#D-space-bound an endless stream of new Digest realms is bounded (never an open loop)", (await codeOf(pki.est.cacerts(BASE, { transport: fakeTransport(manyRealms), auth: { scheme: "digest", username: "u", password: "p" }, maxRedirects: 3 }))) === "est/auth-required");
}

async function main() {
  await setup();
  await testCsrFormsAndDefaultTransport();
  await testMoreBranches();
  await testAuthScopeAndScheme();
  await testRedirectCredentialScope();
  await testAmbiguousIssued();
  await testDigestAuth();
  await testCacertsHappy();
  await testEnrollHappy();
  await testReenrollHappy();
  await testReenrollGatePrecedesTransport();
  await test202Surfaced();
  await testUrlGates();
  await testNoTrustAnchors();
  await testRedirectDowngrade();
  await testCrossOriginRedirect();
  await testSameOriginRedirect();
  await testRedirectLoop();
  await testOversizedBody();
  await testAuthBeforeCreds();
  await testAuthRetry();
  await testClassifierFaults();
  await testIssuedNotFound();
  await testStrict();
  await testBudgetGuards();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
