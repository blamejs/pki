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
}

// ---- 6/7 URL scheme gates precede the transport -----------------------------
async function testUrlGates() {
  var t = fakeTransport(cacertsOK([S.cert]));
  check("#6 an http: base URL is refused", (await codeOf(pki.est.cacerts("http://ca.example", { transport: t }))) === "est/insecure-url");
  check("#6 the transport was never called on an http: URL", t.calls.length === 0);
  var t2 = fakeTransport(cacertsOK([S.cert]));
  check("#7 an unparseable URL is refused", (await codeOf(pki.est.cacerts("not a url", { transport: t2 }))) === "est/bad-url");
  check("#7 the transport was never called on a bad URL", t2.calls.length === 0);
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
}

async function main() {
  await setup();
  await testCsrFormsAndDefaultTransport();
  await testMoreBranches();
  await testAuthScopeAndScheme();
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
