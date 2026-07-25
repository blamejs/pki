// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- pki.acme.client (the thin RFC 8555 client over the shared pki.transport). Driven through
// the SHIPPED consumer path (pki.acme.client(...).verb(...)) over a ROUTING fake transport (no socket),
// so the full session state machine (directory -> nonce -> account/kid -> order -> challenge -> finalize
// -> poll -> download) and every fail-closed gate is deterministic. transport.calls proves a gate ran
// before any POST (calls.length) and lets a test decode the exact JWS (protected nonce / kid) that
// crossed the seam.

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var signing = require("../helpers/signing");
var A = require("../helpers/acme-transport");

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }
function jwsProtected(bodyStr) { return JSON.parse(Buffer.from(JSON.parse(bodyStr).protected, "base64").toString("latin1")); }

var ACCT, CSR;
async function setup() {
  ACCT = await A.makeAccount();
  var certKp = signing.makeSigner("ec-p256", { cn: "example.org" });   // a DISTINCT key from the account (no key-reuse)
  CSR = await pki.csr.sign({ subject: "example.org", subjectPublicKey: certKp.spki, extensionRequest: { subjectAltName: [{ dNSName: "example.org" }] } }, { key: certKp.key });
}

// ---- 1 happy full flow ------------------------------------------------------
async function testHappyFlow() {
  var s = A.acmeServer({ orderStates: ["pending", "ready", "valid"] });
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
  var acct = await acme.newAccount({ termsOfServiceAgreed: true });
  check("#1 newAccount captures the account URL as kid", acct.url === A.URLS.account && acct.account.status === "valid");
  var ord = await acme.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
  check("#1 newOrder returns the order + url", ord.url === A.URLS.order && ord.order.status === "pending");
  var authz = await acme.getAuthorization(ord.order.authorizations[0]);
  check("#1 getAuthorization returns the challenge list", authz.challenges.length === 1 && authz.challenges[0].type === "http-01");
  var chal = await acme.respondToChallenge(authz.challenges[0].url);
  check("#1 respondToChallenge posts to the challenge URL", chal.status === "processing");
  var ready = await acme.pollOrder(ord.url, { onRetryAfter: function () {} });
  check("#1 pollOrder walks to a terminal (valid) state", ready.status === "valid" && ready.certificate === A.URLS.certificate);
  var dl = await acme.downloadCertificate(ready.certificate);
  check("#1 downloadCertificate returns the leaf + chain", Buffer.isBuffer(dl.certificate) && Array.isArray(dl.chain));
  // every post-account POST is kid-signed with the captured account URL; each carries its own nonce.
  var posts = s.calls.filter(function (c) { return c.method === "POST"; });
  var kidPosts = posts.filter(function (c) { return c.url !== A.URLS.newAccount; });
  check("#1 post-account requests are kid-signed with the account URL", kidPosts.every(function (c) { return jwsProtected(c.body).kid === A.URLS.account; }));
  check("#1 newAccount is jwk-signed (no kid)", jwsProtected(posts.filter(function (c) { return c.url === A.URLS.newAccount; })[0].body).jwk !== undefined);
  var nonces = posts.map(function (c) { return jwsProtected(c.body).nonce; });
  check("#1 every POST carried a distinct anti-replay nonce", new Set(nonces).size === nonces.length && nonces.every(Boolean));
}

// ---- 2 finalize (CSR identifiers must match the order) -----------------------
async function testFinalize() {
  var s = A.acmeServer({ orderStates: ["ready", "processing", "valid"] });
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
  await acme.newAccount({});
  var ord = await acme.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
  var res = await acme.finalize(ord.order, { csr: CSR, identifiers: [{ type: "dns", value: "example.org" }] });
  check("#2 finalize posts the CSR and returns the order", res.status === "processing" || res.status === "ready" || res.status === "valid");
  // a CSR whose identifiers do not match the order fails closed BEFORE the POST.
  var s2 = A.acmeServer({});
  var acme2 = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s2));
  await acme2.newAccount({});
  var before = s2.calls.length;
  check("#2 a mismatched CSR identifier set is rejected", (await codeOf(acme2.finalize({ finalize: A.URLS.finalize, identifiers: [{ type: "dns", value: "evil.example" }] }, { csr: CSR }))) === "acme/csr-identifier-mismatch");
  check("#2 the finalize gate ran before any POST to the finalize URL", s2.calls.filter(function (c, i) { return i >= before && c.url === A.URLS.finalize; }).length === 0);
}

// ---- 3 badNonce -> bounded retry with the fresh nonce ------------------------
async function testBadNonceRetry() {
  // first POST (newAccount) gets badNonce + a fresh nonce; the retry uses it and succeeds.
  var s = A.acmeServer({ badNonceRounds: 1 });
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
  var acct = await acme.newAccount({});
  check("#3 a badNonce is retried and the account is created", acct.url === A.URLS.account);
  var acctPosts = s.calls.filter(function (c) { return c.method === "POST" && c.url === A.URLS.newAccount; });
  check("#3 exactly two POSTs to newAccount (initial + one retry)", acctPosts.length === 2);
  check("#3 the retry used a different (fresh) nonce", jwsProtected(acctPosts[0].body).nonce !== jwsProtected(acctPosts[1].body).nonce);
}

// ---- 4 badNonce storm capped ------------------------------------------------
async function testBadNonceStorm() {
  var s = A.acmeServer({ badNonceRounds: 9 });   // more than maxNonceRetries (default 1)
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
  check("#4 an unbroken badNonce storm fails closed", (await codeOf(acme.newAccount({}))) === "acme/server-problem");
  check("#4 the retry count is bounded (maxNonceRetries+1)", s.calls.filter(function (c) { return c.url === A.URLS.newAccount; }).length === 2);
}

// ---- 5 problem+json surfaced ------------------------------------------------
async function testProblemSurfaced() {
  var s = A.acmeServer({ problemOn: { "/new-account": A.problem(403, "unauthorized", "account key not acceptable") } });
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
  var codeP = null, prob = null;
  try { await acme.newAccount({}); } catch (e) { codeP = e.code; prob = e.problem; }
  check("#5 a problem+json response is a typed acme/server-problem", codeP === "acme/server-problem");
  check("#5 the parsed problem type + detail are surfaced", prob && /:unauthorized$/.test(prob.type) && /not acceptable/.test(prob.detail));
}

// ---- 6 https-only + directory + nonce + kid-ordering gates -------------------
async function testFailClosedGates() {
  // a non-https directory URL is refused at construction.
  check("#6 a non-https directory is refused", (await codeOf(Promise.resolve().then(function () { return pki.acme.client("http://acme.example/directory", A.clientOpts(ACCT, A.acmeServer({}))); }))) === "acme/insecure-url");
  // a directory missing newNonce fails closed (via the directory validator).
  var sNoNonce = A.acmeServer({ directory: A.directory({ newNonce: undefined }) });
  var acmeNN = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sNoNonce));
  var dirCode = await codeOf(acmeNN.newAccount({}));
  check("#6 a directory missing a required resource fails closed", dirCode === "acme/missing-field" || dirCode === "acme/bad-directory");
  // no usable Replay-Nonce -> no POST is emitted.
  var routeNoNonce = require("../helpers/fake-transport").fakeTransport(function (req) {
    var p = new URL(req.url).pathname;
    if (p === "/directory") return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(A.directory()) };
    if (p === "/new-nonce") return { status: 200, headers: {}, body: "" };   // NO Replay-Nonce header
    return { status: 500, headers: {}, body: "" };
  });
  var acmeNoN = pki.acme.client(A.URLS.directory, { accountKey: ACCT.key, accountJwk: ACCT.jwk, alg: "ES256", transport: routeNoNonce });
  check("#6 no usable nonce fails closed with no POST", (await codeOf(acmeNoN.newAccount({}))) === "acme/no-nonce");
  check("#6 no POST was emitted without a nonce", routeNoNonce.calls.filter(function (c) { return c.method === "POST"; }).length === 0);
  // a kid-mode verb before newAccount -> acme/no-account, no POST to newOrder.
  var sKid = A.acmeServer({});
  var acmeKid = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sKid));
  check("#6 newOrder before newAccount fails closed (no account)", (await codeOf(acmeKid.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] }))) === "acme/no-account");
  check("#6 no POST reached newOrder without an account", sKid.calls.filter(function (c) { return c.url === A.URLS.newOrder; }).length === 0);
  // the DEFAULT transport (no opts.transport): with neither an explicit anchor nor a system-store opt-in
  // it fails closed at construction; with an anchor it constructs (the socket is built lazily, no I/O).
  check("#6 the default transport with no trust anchor fails closed", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client(A.URLS.directory, { accountKey: ACCT.key, accountJwk: ACCT.jwk, alg: "ES256" });
  }))) === "acme/no-trust-anchors");
  var anchored = pki.acme.client(A.URLS.directory, { accountKey: ACCT.key, accountJwk: ACCT.jwk, alg: "ES256", tls: { anchors: [ACCT.spki] } });
  check("#6 the default transport constructs with an explicit anchor", typeof anchored.newAccount === "function");
}

// ---- 7 poll Retry-After surfaced (never slept in real time), then exhausted --
async function testPolling() {
  var seen = [];
  var s = A.acmeServer({ orderStates: ["processing", "processing", "valid"] });
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s, { now: 0 }));
  await acme.newAccount({});
  await acme.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
  var ord = await acme.pollOrder(A.URLS.order, { onRetryAfter: function (d) { seen.push(d); } });
  check("#7 pollOrder reaches valid after processing", ord.status === "valid");
  check("#7 Retry-After was surfaced to the caller (not slept in real time)", seen.length >= 1);
  // an order stuck in processing exhausts the poll budget.
  var sStuck = A.acmeServer({ orderStates: ["processing"] });
  var acmeStuck = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sStuck, { maxPolls: 3 }));
  await acmeStuck.newAccount({});
  check("#7 a stuck order exhausts the poll budget", (await codeOf(acmeStuck.pollOrder(A.URLS.order))) === "acme/poll-exhausted");
}

var b = pki.asn1.build;
function akiExt(keyId) { return b.sequence([b.oid(pki.oid.byName("authorityKeyIdentifier")), b.octetString(b.sequence([b.contextPrimitive(0, keyId)]))]); }

// ---- 8 remaining verbs: revoke / deactivate / keyChange / renewalInfo -------
async function testRemainingVerbs() {
  var s = A.acmeServer({});
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
  await acme.newAccount({});
  var revCert = signing.makeSigner("ec-p256", { cn: "revoke.example" }).cert;
  check("#8 revokeCert (kid mode) succeeds and posts to revokeCert", (await acme.revokeCert({ certificate: revCert, reason: 1 })) === true && s.calls.some(function (c) { return c.url === A.URLS.revokeCert; }));
  var da = await acme.deactivateAccount();
  check("#8 deactivateAccount posts to the account URL and returns the account", da.status === "deactivated");
  // keyChange rotates the session account key: the post-rotation request signs with the NEW key.
  var neu = await A.makeAccount();
  await acme.keyChange({ newKey: neu.key, newJwk: neu.jwk, newAlg: "ES256" });
  await acme.revokeCert({ certificate: revCert });   // a subsequent request must still succeed under the new key
  var kcPost = s.calls.filter(function (c) { return c.url === A.URLS.keyChange; })[0];
  check("#8 keyChange posted a nested JWS to keyChange", kcPost && kcPost.method === "POST");
  // a finalize CSR whose public key IS the account key is rejected (RFC 8555 sec. 11.1). Use a FRESH
  // client (the client above rotated its account key, so ACCT is no longer its account key).
  var acct2 = await A.makeAccount();
  var s3 = A.acmeServer({});
  var acme3 = pki.acme.client(A.URLS.directory, A.clientOpts(acct2, s3));
  await acme3.newAccount({});
  var reuseCsr = await pki.csr.sign({ subject: "example.org", subjectPublicKey: acct2.spki, extensionRequest: { subjectAltName: [{ dNSName: "example.org" }] } }, { key: acct2.key });
  var reuseOrder = { finalize: A.URLS.finalize, identifiers: [{ type: "dns", value: "example.org" }] };
  check("#8 account-key reuse in the finalize CSR is rejected", (await codeOf(acme3.finalize(reuseOrder, { csr: reuseCsr }))) === "acme/key-reuse");
}

// ---- 9 ARI renewalInfo (unauthenticated GET) + inverted window --------------
async function testRenewalInfo() {
  var aki = require("node:crypto").createHash("sha1").update("issuer-key").digest();
  var certDer = signing.makeSigner("ec-p256", { cn: "renew.example", serial: 0x2a, exts: [akiExt(aki)] }).cert;
  var s = A.acmeServer({});
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s, { now: 0 }));
  var ri = await acme.renewalInfo(certDer);
  check("#9 renewalInfo returns the validated window", ri.renewalInfo && ri.renewalInfo.suggestedWindow);
  var riReq = s.calls.filter(function (c) { return c.url.indexOf(A.URLS.renewalInfo) === 0; })[0];
  check("#9 renewalInfo is an UNAUTHENTICATED GET (no JWS body)", riReq && riReq.method === "GET" && (riReq.body == null || riReq.body === ""));
  // an inverted suggested window is treated as no signal -> fail closed.
  var sInv = A.acmeServer({ renewalInfoResponse: A.json(200, { suggestedWindow: { start: "2027-02-01T00:00:00Z", end: "2027-01-01T00:00:00Z" } }) });
  var acmeInv = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sInv));
  check("#9 an inverted renewal window fails closed", (await codeOf(acmeInv.renewalInfo(certDer))) === "acme/bad-renewal-window");
}

// ---- 10 oversized response rejected before decode ---------------------------
async function testOversized() {
  var big = "-----BEGIN CERTIFICATE-----\n" + "A".repeat(2000) + "\n-----END CERTIFICATE-----";
  var s = A.acmeServer({ certPems: [big] });
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s, { maxResponseBytes: 500 }));
  await acme.newAccount({});
  check("#10 an oversized certificate download is rejected", (await codeOf(acme.downloadCertificate(A.URLS.certificate))) === "acme/response-too-large");
}

// ---- 11 pre-push audit hardening (RFC 8555 sec. 6.1/6.4/6.5/7.4, CWE-770) ----
async function testAuditHardening() {
  // (a) every request carries the sec. 6.1 REQUIRED User-Agent.
  var sUA = A.acmeServer({});
  var acmeUA = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sUA));
  await acmeUA.newAccount({});
  await acmeUA.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
  check("#11 every request sends a User-Agent (RFC 8555 sec. 6.1)", sUA.calls.length > 0 && sUA.calls.every(function (c) {
    return Object.keys(c.headers || {}).some(function (k) { return k.toLowerCase() === "user-agent" && /^blamejs-pki\//.test(String(c.headers[k])); });
  }));

  // (b) the client is the sole https gate: a directory advertising an http POST resource fails closed
  // BEFORE any nonce/JWS/socket, so the account-key JWS is never sent in cleartext.
  var sHttp = A.acmeServer({ directory: A.directory({ newAccount: "http://acme.example/new-account" }) });
  var acmeHttp = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sHttp));
  check("#11 an http directory resource fails closed (acme/insecure-url)", (await codeOf(acmeHttp.newAccount({}))) === "acme/insecure-url");
  check("#11 no request reached an http endpoint", sHttp.calls.every(function (c) { return new URL(c.url).protocol === "https:"; }));

  // (c) _clientUrl preserves the exact server URL: a non-canonical Location (:443) is the kid verbatim
  // (RFC 8555 sec. 6.4/7.3), not a URL.href-normalized value.
  var sLoc = A.acmeServer({ accountLocation: "https://acme.example:443/acct/1" });
  var acmeLoc = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sLoc));
  var acctLoc = await acmeLoc.newAccount({});
  check("#11 the account URL is the exact server Location, not normalized", acctLoc.url === "https://acme.example:443/acct/1");
  await acmeLoc.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
  var orderPost = sLoc.calls.filter(function (c) { return c.url === A.URLS.newOrder; })[0];
  check("#11 the kid in a following JWS is the exact Location", jwsProtected(orderPost.body).kid === "https://acme.example:443/acct/1");

  // (d) downloadCertificate advertises the pem-certificate-chain media type (sec. 7.4.2); a server that
  // content-negotiates on the cert resource still returns the chain.
  var sAccept = A.acmeServer({ certRequiresPemAccept: true });
  var acmeAccept = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sAccept));
  await acmeAccept.newAccount({});
  var dl = await acmeAccept.downloadCertificate(A.URLS.certificate);
  check("#11 downloadCertificate resolves against a pem-Accept-gated cert resource", dl.certificate != null);
  var certPost = sAccept.calls.filter(function (c) { return c.url === A.URLS.certificate; })[0];
  check("#11 the recorded cert-download Accept is pem-certificate-chain", String(certPost.headers.accept || "").indexOf("application/pem-certificate-chain") === 0);

  // (e) finalize enforces the sec. 7.4 CSR-set match even when the caller OMITS identifiers (defaults to
  // the order's authoritative set) -- the natural client call shape acme.finalize(order, { csr }).
  var sFin = A.acmeServer({});
  var acmeFin = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sFin));
  await acmeFin.newAccount({});
  var realOrder = await acmeFin.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
  var evilKp = signing.makeSigner("ec-p256", { cn: "evil.example" });
  var evilCsr = await pki.csr.sign({ subject: "evil.example", subjectPublicKey: evilKp.spki, extensionRequest: { subjectAltName: [{ dNSName: "evil.example" }] } }, { key: evilKp.key });
  var beforeFin = sFin.calls.length;
  check("#11 finalize enforces sec. 7.4 with NO caller identifiers (defaults to the order set)", (await codeOf(acmeFin.finalize(realOrder.order, { csr: evilCsr }))) === "acme/csr-identifier-mismatch");
  check("#11 the finalize gate ran before any finalize POST", sFin.calls.filter(function (c, i) { return i >= beforeFin && c.url === A.URLS.finalize; }).length === 0);

  // (f) a cert-key (jwk-mode) revoke inherits the badNonce bounded retry the kid path has (RFC 8555 sec. 6.5).
  var revKp = await A.makeAccount();
  var revCert = signing.makeSigner("ec-p256", { cn: "revoke.example" }).cert;
  var sRev = A.acmeServer({ badNonceRounds: 1 });
  var acmeRev = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sRev));
  check("#11 a cert-key revoke retries a badNonce (RFC 8555 sec. 6.5)", (await acmeRev.revokeCert({ certificate: revCert, certKey: revKp.key, certJwk: revKp.jwk })) === true);

  // (g) the badNonce retry consumes the ERROR response's fresh nonce, not a staler pooled one. Seed the
  // pool with two decoy nonces (a renewalInfo GET harvests directory + ARI nonces); a strict server
  // rejects any nonce it did not issue as valid, so only a retry that pops the fresh nonce (LIFO)
  // succeeds -- a FIFO retry reuses the second decoy and exhausts the bounded retry.
  var aki = require("node:crypto").createHash("sha1").update("issuer").digest();
  var certDer = signing.makeSigner("ec-p256", { cn: "seed.example", serial: 0x2a, exts: [akiExt(aki)] }).cert;
  var revKp2 = await A.makeAccount();
  var revCert2 = signing.makeSigner("ec-p256", { cn: "revoke2.example" }).cert;
  var sStrict = A.acmeServer({ strictNonce: true });
  var acmeStrict = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sStrict));
  await acmeStrict.renewalInfo(certDer);   // seeds two decoy nonces into the pool
  check("#11 a badNonce retry uses the error's fresh nonce over a stale pooled one (sec. 6.5)",
    (await acmeStrict.revokeCert({ certificate: revCert2, certKey: revKp2.key, certJwk: revKp2.jwk })) === true);

  // (h) the single-use nonce pool is bounded: many unauthenticated renewalInfo harvests do not grow it
  // without bound (CWE-770), and a subsequent authenticated verb still succeeds.
  var sPool = A.acmeServer({ strictNonce: true });
  var acmePool = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sPool));
  for (var i = 0; i < 40; i++) await acmePool.renewalInfo(certDer);
  var acctPool = await acmePool.newAccount({});
  check("#11 the client still functions after many nonce harvests (bounded pool)", acctPool.url === A.URLS.account);

  // (i) an invalid (non-base64url) Replay-Nonce on a response is DISCARDED (RFC 8555 sec. 6.5.1), not
  // pooled: newAccount still succeeds (it signed with a freshly fetched nonce).
  var sBadN = A.acmeServer({ accountNonceInvalid: true });
  var acmeBadN = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sBadN));
  check("#11 an invalid Replay-Nonce is discarded, not used", (await acmeBadN.newAccount({})).url === A.URLS.account);

  // (j) a problem response whose body is NOT valid JSON still surfaces a typed acme/server-problem
  // (the client falls back to the HTTP status when it cannot parse the problem document).
  var sBadBody = A.acmeServer({ problemOn: { "/new-order": { status: 400, headers: { "content-type": "application/problem+json" }, body: "not json{" } } });
  var acmeBadBody = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sBadBody));
  await acmeBadBody.newAccount({});
  check("#11 a non-JSON problem body still surfaces acme/server-problem", (await codeOf(acmeBadBody.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] }))) === "acme/server-problem");

  // (k) keyChange succeeds even when the server's 200 body is not JSON (the account view is best-effort).
  var sKC = A.acmeServer({ keyChangeBody: "not-json{" });
  var acmeKC = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sKC));
  await acmeKC.newAccount({});
  var neuKC = await A.makeAccount();
  var kc = await acmeKC.keyChange({ newKey: neuKC.key, newJwk: neuKC.jwk, newAlg: "ES256" });
  check("#11 keyChange resolves with a null account on a non-JSON body", kc.account === null && kc.url === A.URLS.account);
}

// ---- 12 review hardening: cert-parse, receipt clock, order binding, account, poll caps ----
async function testReviewHardening() {
  // (a) a downloaded certificate is STRUCTURALLY parsed, not just armor-decoded: PEM wrapping arbitrary
  // base64 is rejected; a real certificate downloads and is returned as DER.
  var sBad = A.acmeServer({ certPems: ["-----BEGIN CERTIFICATE-----\nMIIBLEAF\n-----END CERTIFICATE-----"] });
  var acmeBad = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sBad));
  await acmeBad.newAccount({});
  check("#12 a downloaded non-X.509 certificate body is rejected", (await codeOf(acmeBad.downloadCertificate(A.URLS.certificate))) === "acme/bad-certificate-chain");
  var sOk = A.acmeServer({});
  var acmeOk = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sOk));
  await acmeOk.newAccount({});
  check("#12 a real downloaded certificate is parsed + returned as DER", Buffer.isBuffer((await acmeOk.downloadCertificate(A.URLS.certificate)).certificate));

  // (b) an HTTP-date Retry-After delay is computed at the RESPONSE RECEIPT time (an injectable clock),
  // not collapsed to 1s: the surfaced delay reflects (date - receipt).
  var clockMs = Date.UTC(2026, 9, 21, 7, 27, 0);
  var seen = [];
  var sHd = A.acmeServer({ orderStates: ["processing", "valid"], pollRetryAfter: "Wed, 21 Oct 2026 07:29:00 GMT" });
  var acmeHd = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sHd, { clock: function () { return clockMs; } }));
  await acmeHd.newAccount({});
  await acmeHd.pollOrder(A.URLS.order, { onRetryAfter: function (d) { seen.push(d); } });
  check("#12 an HTTP-date Retry-After is computed at receipt time via the clock", seen.length > 0 && seen[0] === 120);

  // (c) finalize is bound to the ORDER's identifiers -- a caller cannot loosen the sec. 7.4 check by
  // passing a matching-but-wrong identifier set.
  var sFb = A.acmeServer({});
  var acmeFb = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sFb));
  await acmeFb.newAccount({});
  var ordFb = await acmeFb.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
  var evilKp = signing.makeSigner("ec-p256", { cn: "evil.example" });
  var evilCsr = await pki.csr.sign({ subject: "evil.example", subjectPublicKey: evilKp.spki, extensionRequest: { subjectAltName: [{ dNSName: "evil.example" }] } }, { key: evilKp.key });
  check("#12 a caller identifier override cannot bypass the order binding", (await codeOf(acmeFb.finalize(ordFb.order, { csr: evilCsr, identifiers: [{ type: "dns", value: "evil.example" }] }))) === "acme/csr-identifier-mismatch");

  // (d) newAccount validates the account object BEFORE committing the kid: a malformed account fails
  // closed and no authenticated operation proceeds.
  var sMa = A.acmeServer({ account: {} });
  var acmeMa = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sMa));
  check("#12 a malformed newAccount object fails closed", (await codeOf(acmeMa.newAccount({}))) !== "NO-THROW");
  check("#12 the kid was not committed on a malformed account", (await codeOf(acmeMa.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] }))) === "acme/no-account");

  // (e) per-call poll overrides are validated through the same bounds as the constructor budget.
  var sCap = A.acmeServer({ orderStates: ["processing", "processing", "valid"] });
  var acmeCap = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sCap));
  await acmeCap.newAccount({});
  check("#12 an over-ceiling per-call maxPolls is rejected", (await codeOf(acmeCap.pollOrder(A.URLS.order, { maxPolls: 999999 }))) === "acme/bad-input");
  check("#12 a non-finite per-call maxTotalWait is rejected", (await codeOf(acmeCap.pollOrder(A.URLS.order, { maxTotalWait: Infinity }))) === "acme/bad-input");
}

async function main() {
  await setup();
  await testHappyFlow();
  await testRemainingVerbs();
  await testRenewalInfo();
  await testOversized();
  await testAuditHardening();
  await testReviewHardening();
  await testFinalize();
  await testBadNonceRetry();
  await testBadNonceStorm();
  await testProblemSurfaced();
  await testFailClosedGates();
  await testPolling();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
