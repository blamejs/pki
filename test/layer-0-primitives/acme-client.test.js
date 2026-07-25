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
  var readyOrder = await acme.pollOrder(ord.url, { onRetryAfter: function () {} });
  check("#1 pollOrder returns when the order is ready to finalize", readyOrder.status === "ready");
  var finalized = await acme.finalize(readyOrder, { csr: CSR });
  check("#1 finalize submits the CSR", finalized.status === "processing" || finalized.status === "valid");
  var valid = await acme.pollOrder(ord.url, { onRetryAfter: function () {} });
  check("#1 pollOrder walks to a terminal (valid) state", valid.status === "valid" && valid.certificate === A.URLS.certificate);
  var dl = await acme.downloadCertificate(valid.certificate);
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

  // (c) _clientUrl preserves the exact (canonical) server URL: a non-default port the server chose is the
  // kid verbatim (RFC 8555 sec. 6.4/7.3), not a URL.href-normalized value.
  var sLoc = A.acmeServer({ accountLocation: "https://acme.example:8443/acct/1" });
  var acmeLoc = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sLoc));
  var acctLoc = await acmeLoc.newAccount({});
  check("#11 the account URL is the exact server Location, not normalized", acctLoc.url === "https://acme.example:8443/acct/1");
  await acmeLoc.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
  var orderPost = sLoc.calls.filter(function (c) { return c.url === A.URLS.newOrder; })[0];
  check("#11 the kid in a following JWS is the exact Location", jwsProtected(orderPost.body).kid === "https://acme.example:8443/acct/1");

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
  check("#11 a cert-key revoke retries a badNonce (RFC 8555 sec. 6.5)", (await acmeRev.revokeCert({ certificate: revCert, certKey: revKp.key, certJwk: revKp.jwk, certAlg: "ES256" })) === true);

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
    (await acmeStrict.revokeCert({ certificate: revCert2, certKey: revKp2.key, certJwk: revKp2.jwk, certAlg: "ES256" })) === true);

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

  // (k) keyChange VALIDATES the account response before rotating: a malformed / non-account 200 body
  // fails closed (RFC 8555 sec. 7.3.5), so the session is never left on a key the server did not accept.
  var sKC = A.acmeServer({ keyChangeBody: "not-json{" });
  var acmeKC = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sKC));
  await acmeKC.newAccount({});
  var neuKC = await A.makeAccount();
  check("#11 keyChange with a malformed account body fails closed", (await codeOf(acmeKC.keyChange({ newKey: neuKC.key, newJwk: neuKC.jwk, newAlg: "ES256" }))) === "acme/bad-response");
  // the session key was NOT rotated -- a subsequent authenticated request still succeeds.
  check("#11 a failed keyChange leaves the working key intact", (await acmeKC.revokeCert({ certificate: signing.makeSigner("ec-p256", { cn: "kc.example" }).cert })) === true);
  // a BODYLESS 200 is a valid rollover (RFC 8555 sec. 7.3.5 requires only the status): the key rotates.
  var sKcEmpty = A.acmeServer({ keyChangeBody: "" });
  var acmeKcE = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sKcEmpty));
  await acmeKcE.newAccount({});
  var neuE = await A.makeAccount();
  var kcE = await acmeKcE.keyChange({ newKey: neuE.key, newJwk: neuE.jwk, newAlg: "ES256" });
  check("#11 a bodyless keyChange 200 succeeds and rotates the key", kcE.account === null && kcE.url === A.URLS.account);
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

  // (f) a safe-method (GET) redirect is FOLLOWED to its https Location, honoring the maxRedirects budget:
  // a directory served behind a 301 works; a redirect past the budget fails closed.
  var sRedir = A.acmeServer({ redirects: { "/dir-redirect": A.URLS.directory } });
  var acmeRedir = pki.acme.client(A.URLS.base + "/dir-redirect", A.clientOpts(ACCT, sRedir));
  check("#12 a directory behind a 301 redirect is followed", (await acmeRedir.newAccount({})).url === A.URLS.account);
  var sRedir0 = A.acmeServer({ redirects: { "/dir-redirect": A.URLS.directory } });
  var acmeRedir0 = pki.acme.client(A.URLS.base + "/dir-redirect", A.clientOpts(ACCT, sRedir0, { maxRedirects: 0 }));
  check("#12 a redirect past the maxRedirects budget fails closed", (await codeOf(acmeRedir0.newAccount({}))) === "acme/too-many-redirects");
  var sBadR = A.acmeServer({ redirectNoLocationPath: "/dir-badredir" });
  var acmeBadR = pki.acme.client(A.URLS.base + "/dir-badredir", A.clientOpts(ACCT, sBadR));
  check("#12 a redirect with no Location header fails closed", (await codeOf(acmeBadR.newAccount({}))) === "acme/bad-redirect");

  // (g) revokeCert cert-key mode requires BOTH certKey and certJwk: an incomplete pair must NOT silently
  // fall through to the account-key path.
  var kp = await A.makeAccount();
  var revCertG = signing.makeSigner("ec-p256", { cn: "revoke3.example" }).cert;
  var sInc = A.acmeServer({});
  var acmeInc = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sInc));
  await acmeInc.newAccount({});
  check("#12 revokeCert with only certKey is rejected", (await codeOf(acmeInc.revokeCert({ certificate: revCertG, certKey: kp.key }))) === "acme/bad-input");
  check("#12 revokeCert with only certJwk is rejected", (await codeOf(acmeInc.revokeCert({ certificate: revCertG, certJwk: kp.jwk }))) === "acme/bad-input");
  check("#12 revokeCert with NEITHER cert-key field uses the account key", (await acmeInc.revokeCert({ certificate: revCertG })) === true);
  check("#12 revokeCert cert-key mode without certAlg is rejected", (await codeOf(acmeInc.revokeCert({ certificate: revCertG, certKey: kp.key, certJwk: kp.jwk }))) === "acme/bad-input");
}

// ---- 13 review hardening (round 3): order-ready terminal, relative redirect ----
async function testReadyAndRelativeRedirect() {
  // (a) pollOrder RETURNS on `ready` (the stable pre-finalize state) rather than spinning to exhaustion.
  var sReady = A.acmeServer({ orderStates: ["pending", "ready"], maxPolls: 5 });
  var acmeReady = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sReady));
  await acmeReady.newAccount({});
  var ord = await acmeReady.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });
  var r = await acmeReady.pollOrder(ord.url, { maxPolls: 5 });
  check("#13 pollOrder returns at the stable ready state (no exhaustion)", r.status === "ready");

  // (b) a RELATIVE redirect Location is resolved against the request URL, then https-gated.
  var sRel = A.acmeServer({ redirects: { "/dir-relative": "/directory" } });
  var acmeRel = pki.acme.client(A.URLS.base + "/dir-relative", A.clientOpts(ACCT, sRel));
  check("#13 a relative redirect Location is resolved and followed", (await acmeRel.newAccount({})).url === A.URLS.account);

  // (c) a Location that cannot resolve to a valid URL (even relative) fails closed.
  var sMalLoc = A.acmeServer({ redirects: { "/dir-malloc": "http://" } });
  var acmeMalLoc = pki.acme.client(A.URLS.base + "/dir-malloc", A.clientOpts(ACCT, sMalLoc));
  check("#13 an unresolvable redirect Location fails closed", (await codeOf(acmeMalLoc.newAccount({}))) === "acme/bad-redirect");

  // (d) an mTLS client credential is STRIPPED on a CROSS-origin redirect (open-redirect leak) but KEPT on
  // a same-origin one.
  var mk = Buffer.from([1, 2, 3]);
  var sXo = A.acmeServer({ redirects: { "/dir-xo": "https://other.example/directory" } });
  var acmeXo = pki.acme.client(A.URLS.base + "/dir-xo", A.clientOpts(ACCT, sXo, { tls: { anchors: [ACCT.spki], cert: mk, key: mk } }));
  await acmeXo.newAccount({});
  var xoReqs = sXo.calls.filter(function (c) { return new URL(c.url).origin === "https://other.example"; });
  check("#13 a cross-origin redirect strips the mTLS cert/key", xoReqs.length > 0 && xoReqs.every(function (c) { return (c.tls || {}).cert == null && (c.tls || {}).key == null; }));
  var sSo = A.acmeServer({ redirects: { "/dir-so": "/directory" } });
  var acmeSo = pki.acme.client(A.URLS.base + "/dir-so", A.clientOpts(ACCT, sSo, { tls: { anchors: [ACCT.spki], cert: mk, key: mk } }));
  await acmeSo.newAccount({});
  var soDir = sSo.calls.filter(function (c) { return new URL(c.url).pathname === "/directory"; })[0];
  check("#13 a same-origin redirect keeps the mTLS cert/key", soDir && (soDir.tls || {}).cert != null && (soDir.tls || {}).key != null);

  // (e) an unexpected 2xx on a POST fails closed (a verb must not act on an incomplete result).
  var revCertS = signing.makeSigner("ec-p256", { cn: "revoke4.example" }).cert;
  var s202 = A.acmeServer({ revokeStatus: 202 });
  var acme202 = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s202));
  await acme202.newAccount({});
  check("#13 an unexpected 2xx POST status fails closed", (await codeOf(acme202.revokeCert({ certificate: revCertS }))) === "acme/unexpected-status");

  // (f) a certificate download with the wrong media type fails closed even if the body is parseable PEM.
  var sCt = A.acmeServer({ certContentType: "text/plain" });
  var acmeCt = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sCt));
  await acmeCt.newAccount({});
  check("#13 a wrong cert media type fails closed", (await codeOf(acmeCt.downloadCertificate(A.URLS.certificate))) === "acme/bad-certificate-chain");

  // (g) caller PAYLOAD options cannot override the client-owned JWS session fields (url / nonce): the
  // protected header stays bound to the actual request, not a value spread from a lower-level config.
  var sOv = A.acmeServer({});
  var acmeOv = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sOv));
  await acmeOv.newAccount({ termsOfServiceAgreed: true, url: "https://evil.example/x", nonce: "Zm9vYmFyYmF6" });
  var ovHdr = jwsProtected(sOv.calls.filter(function (c) { return c.url === A.URLS.newAccount; })[0].body);
  check("#13 payload options cannot override the JWS url/nonce", ovHdr.url === A.URLS.newAccount && ovHdr.nonce !== "Zm9vYmFyYmF6");

  // (h) pollAuthorization reaches a terminal state a pending authorization can legitimately enter
  // (deactivated by the client, or expired) rather than rejecting the transition (RFC 8555 sec. 7.1.6).
  var sDeact = A.acmeServer({ authzStates: ["pending", "deactivated"] });
  var acmeDeact = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sDeact));
  await acmeDeact.newAccount({});
  var az = await acmeDeact.pollAuthorization(A.URLS.authz);
  check("#13 pollAuthorization returns a pending->deactivated terminal", az.status === "deactivated");
  // pending -> expired is NOT a valid transition (expired is an outgoing state from valid, RFC 8555
  // sec. 7.1.6); the poller rejects it rather than accepting the terminal.
  var sExp = A.acmeServer({ authzStates: ["pending", "expired"] });
  var acmeExp = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sExp));
  await acmeExp.newAccount({});
  check("#13 pollAuthorization rejects an invalid pending->expired transition", (await codeOf(acmeExp.pollAuthorization(A.URLS.authz))) === "acme/bad-transition");

  // (i) a verb whose RFC success status is 200 rejects a 201 (only newAccount/newOrder may return 201).
  var revCertI = signing.makeSigner("ec-p256", { cn: "revoke5.example" }).cert;
  var s201 = A.acmeServer({ revokeStatus: 201 });
  var acme201 = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s201));
  await acme201.newAccount({});
  check("#13 a 201 on a 200-only verb fails closed", (await codeOf(acme201.revokeCert({ certificate: revCertI }))) === "acme/unexpected-status");

  // (j) the certificate media type is matched as an EXACT token -- a lookalike does not slip through.
  var sLook = A.acmeServer({ certContentType: "application/pem-certificate-chain-evil" });
  var acmeLook = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sLook));
  await acmeLook.newAccount({});
  check("#13 a lookalike cert media type fails closed", (await codeOf(acmeLook.downloadCertificate(A.URLS.certificate))) === "acme/bad-certificate-chain");
  // and the exact token WITH parameters is accepted.
  var sParam = A.acmeServer({ certContentType: "application/pem-certificate-chain; charset=utf-8" });
  var acmeParam = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sParam));
  await acmeParam.newAccount({});
  check("#13 the exact media type with parameters is accepted", Buffer.isBuffer((await acmeParam.downloadCertificate(A.URLS.certificate)).certificate));

  // (k) the mTLS credential is bound to the CONFIGURED directory origin: a directory-advertised
  // cross-origin URL (a compromised/redirected directory) does NOT receive the client certificate/key,
  // while the trusted directory origin does.
  var mk2 = Buffer.from([9, 8, 7]);
  var sXoDir = A.acmeServer({ directory: A.directory({ newAccount: "https://other.example/new-account" }) });
  var acmeXoDir = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sXoDir, { tls: { anchors: [ACCT.spki], cert: mk2, key: mk2 } }));
  await acmeXoDir.newAccount({});
  var naXo = sXoDir.calls.filter(function (c) { return c.url === "https://other.example/new-account"; })[0];
  check("#13 mTLS is stripped for a directory-advertised cross-origin URL", naXo && (naXo.tls || {}).cert == null && (naXo.tls || {}).key == null);
  var dirTrust = sXoDir.calls.filter(function (c) { return c.url === A.URLS.directory; })[0];
  check("#13 mTLS is kept for the trusted directory origin", dirTrust && (dirTrust.tls || {}).cert != null);

  // (l) a valid URL WHATWG would normalize (a default :443 port, an uppercase host) is ACCEPTED -- a
  // conforming CA may emit either spelling; the transport re-parses it for the connection.
  var acme443 = pki.acme.client("https://acme.example:443/directory", A.clientOpts(ACCT, A.acmeServer({})));
  check("#13 a default-port (:443) directory URL is accepted", (await acme443.newAccount({})).url === A.URLS.account);
  // a genuinely unparseable URL (a space in the authority) still fails closed.
  check("#13 an unparseable URL is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://ex ample/directory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");

  // (m) a JSON response body with malformed UTF-8 fails closed (the strict RFC 8259 UTF-8 validation runs
  // on the raw wire bytes, not a lossy replacement-char decode).
  var badUtf8 = Buffer.concat([Buffer.from('{"status":"valid","_x":"'), Buffer.from([0xff]), Buffer.from('"}')]);
  var sUtf8 = A.acmeServer({ accountBodyBuffer: badUtf8 });
  var acmeUtf8 = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sUtf8));
  check("#13 a malformed-UTF-8 JSON response fails closed", (await codeOf(acmeUtf8.newAccount({}))) === "acme/bad-response");

  // (n) newOrder requires 201 Created (RFC 8555 sec. 7.4) -- a 200 is a non-conforming response.
  var s200o = A.acmeServer({ newOrderStatus: 200 });
  var acme200o = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s200o));
  await acme200o.newAccount({});
  check("#13 a 200 from newOrder fails closed (201 required)", (await codeOf(acme200o.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] }))) === "acme/unexpected-status");

  // (o) a RELATIVE account Location (a valid HTTP URI-reference) is resolved against the request URL.
  var sRelLoc = A.acmeServer({ accountLocation: "/acct/1" });
  var acmeRelLoc = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sRelLoc));
  check("#13 a relative account Location is resolved against the request URL", (await acmeRelLoc.newAccount({})).url === A.URLS.account);

  // (p) the DEFAULT poll sleeper splits an oversized (but valid, sub-year) Retry-After so a single
  // setTimeout never exceeds Node's 32-bit ceiling (which clamps to 1ms and rapidly re-polls).
  var base = Date.UTC(2026, 0, 1);
  var bigDate = new Date(Date.UTC(2026, 0, 31)).toUTCString();   // 30 days ahead -> delay ms > 2^31-1
  var sBig = A.acmeServer({ orderStates: ["processing", "valid"], pollRetryAfter: bigDate });
  var acmeBig = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sBig, { clock: function () { return base; }, sleep: undefined }));
  await acmeBig.newAccount({});
  var realST = global.setTimeout;
  var maxDelay = 0;
  global.setTimeout = function (fn, d) { maxDelay = Math.max(maxDelay, d || 0); return realST(fn, 0); };
  try { await acmeBig.pollOrder(A.URLS.order, { onRetryAfter: function () {} }); }
  finally { global.setTimeout = realST; }
  check("#13 an oversized Retry-After sleep is split below Node's setTimeout ceiling", maxDelay > 0 && maxDelay <= 2147483647);

  // (q) pending -> revoked is NOT valid (revoked is an outgoing state from valid, RFC 8555 sec. 7.1.6);
  // the poller rejects the transition rather than accepting the terminal.
  var sRev = A.acmeServer({ authzStates: ["pending", "revoked"] });
  var acmeRev = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sRev));
  await acmeRev.newAccount({});
  check("#13 pollAuthorization rejects an invalid pending->revoked transition", (await codeOf(acmeRev.pollAuthorization(A.URLS.authz))) === "acme/bad-transition");

  // (r) a URL with a fragment is rejected (the transport drops the fragment; the JWS url would retain it).
  check("#13 a URL with a fragment is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/directory#frag", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");

  // (s) a URL whose spelling the transport would REPAIR into a different path (whitespace, backslash) is
  // rejected, so the signed and requested URLs cannot differ.
  check("#13 a URL with whitespace in the path is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/dir ectory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  check("#13 a URL with a backslash in the path is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/dir\\ectory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");

  // (t) a CROSS-origin request resets the origin-specific servername + checkServerIdentity (pinned to the
  // trusted host), while the trusted origin keeps them.
  var sSni = A.acmeServer({ directory: A.directory({ newAccount: "https://other.example/new-account" }) });
  var acmeSni = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sSni, { tls: { anchors: [ACCT.spki], servername: "acme.example", checkServerIdentity: function () {} } }));
  await acmeSni.newAccount({});
  var naSni = sSni.calls.filter(function (c) { return c.url === "https://other.example/new-account"; })[0];
  check("#13 a cross-origin request resets servername + checkServerIdentity", naSni && (naSni.tls || {}).servername == null && (naSni.tls || {}).checkServerIdentity == null);
  var dirSni = sSni.calls.filter(function (c) { return c.url === A.URLS.directory; })[0];
  check("#13 the trusted origin keeps the servername override", dirSni && (dirSni.tls || {}).servername === "acme.example");

  // (u) an ABSOLUTE Location with a normalization-sensitive spelling (an uppercase host) is the account
  // kid VERBATIM (RFC 8555 sec. 6.4/7.3), not a URL.href-normalized value.
  var sAbsLoc = A.acmeServer({ accountLocation: "https://ACME.EXAMPLE/acct/1" });
  var acmeAbsLoc = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sAbsLoc));
  check("#13 an absolute Location's exact spelling is preserved as the kid", (await acmeAbsLoc.newAccount({})).url === "https://ACME.EXAMPLE/acct/1");

  // (v) an application/problem+json body is an ERROR even with a 2xx status (a CA/proxy returning a
  // problem with a bogus 200): the verb surfaces acme/server-problem rather than reporting success.
  var sProb200 = A.acmeServer({ problemOn: { "/revoke-cert": { status: 200, headers: { "content-type": "application/problem+json" }, body: JSON.stringify({ type: "urn:ietf:params:acme:error:malformed", detail: "nope" }) } } });
  var acmeProb200 = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sProb200));
  await acmeProb200.newAccount({});
  check("#13 a 2xx problem+json response is surfaced as a server problem", (await codeOf(acmeProb200.revokeCert({ certificate: signing.makeSigner("ec-p256", { cn: "p.example" }).cert }))) === "acme/server-problem");
}

async function main() {
  await setup();
  await testHappyFlow();
  await testRemainingVerbs();
  await testRenewalInfo();
  await testOversized();
  await testAuditHardening();
  await testReviewHardening();
  await testReadyAndRelativeRedirect();
  await testFinalize();
  await testBadNonceRetry();
  await testBadNonceStorm();
  await testProblemSurfaced();
  await testFailClosedGates();
  await testPolling();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
