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

var ACCT, CSR, CSR_SPKI, ISSUED_PEM;
// downloadCertificate binds the issued certificate to the order by default. A vector exercising some
// OTHER download gate (media type, size cap, Link parsing, chain selection) passes this to say so:
// what it is testing is reached, and the binding it is not testing is declared rather than assumed.
var NO_BIND = { requireBinding: false };
async function setup() {
  ACCT = await A.makeAccount();
  var certKp = signing.makeSigner("ec-p256", { cn: "example.org" });   // a DISTINCT key from the account (no key-reuse)
  CSR_SPKI = certKp.spki;
  CSR = await pki.csr.sign({ subject: "example.org", subjectPublicKey: certKp.spki, extensionRequest: { subjectAltName: [{ dNSName: "example.org" }] } }, { key: certKp.key });
  // The certificate the happy flow's CA issues: the CSR's own key, the order's own identifier. The
  // default fixture certificate answers neither, so a flow served that one is not an enrollment this
  // caller could use -- which is exactly what the download binding now says.
  var b = pki.asn1.build;
  var san = b.sequence([b.oid(pki.oid.byName("subjectAltName")),
    b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("example.org", "latin1"))]))]);
  var issued = signing.minimalCert(certKp.spki, { cn: "example.org", exts: [san] });
  ISSUED_PEM = "-----BEGIN CERTIFICATE-----\n" + issued.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n+$/, "") + "\n-----END CERTIFICATE-----";
}

// ---- 1 happy full flow ------------------------------------------------------
async function testHappyFlow() {
  var s = A.acmeServer({ orderStates: ["pending", "ready", "valid"], certPems: [ISSUED_PEM] });
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
  check("#7g pollOrder refuses an unrecognized budget option",
    (await codeOf(acme.pollOrder(ord.url, { onRetryAfterz: function () {} }))) === "acme/bad-input");
  check("#1 pollOrder returns when the order is ready to finalize", readyOrder.status === "ready");
  var finalized = await acme.finalize(readyOrder, { csr: CSR });
  check("#1 finalize submits the CSR", finalized.status === "processing" || finalized.status === "valid");
  var valid = await acme.pollOrder(ord.url, { onRetryAfter: function () {} });
  check("#1 pollOrder walks to a terminal (valid) state", valid.status === "valid" && valid.certificate === A.URLS.certificate);
  // The full flow binds for real: the key this order's CSR asked to have certified, and the order's
  // own identifiers. This is the one download in the suite driven end to end from a finalize, so it
  // is the one that must reach the certificate through the check rather than around it.
  var dl = await acme.downloadCertificate(valid.certificate, { expectedSpki: CSR_SPKI, identifiers: valid.identifiers, requireBinding: true });
  check("#8g downloadCertificate refuses an unrecognized option",
    (await codeOf(acme.downloadCertificate(valid.certificate, { expectedSpki: CSR_SPKI, requireBindings: true }))) === "acme/bad-input");
  check("#1 downloadCertificate returns the leaf + chain", Buffer.isBuffer(dl.certificate) && Array.isArray(dl.chain));
  check("#1 downloadCertificate reports both bindings as checked", dl.boundToKey === true && dl.boundToIdentifiers === true);
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
  // #2a the finalize CSR accepts any BufferSource: an ArrayBuffer CSR reaches the identifier check
  // (the mismatch here) rather than being refused at the CSR gate. Before the widening it threw acme/bad-input.
  var CSR_AB = new ArrayBuffer(CSR.length); new Uint8Array(CSR_AB).set(CSR);
  check("#2a a finalize CSR given as an ArrayBuffer passes the CSR gate (#68)",
    (await codeOf(acme2.finalize({ finalize: A.URLS.finalize, identifiers: [{ type: "dns", value: "evil.example" }] }, { csr: CSR_AB }))) === "acme/csr-identifier-mismatch");
  // #2b a CSR carrying the order's name in a SAN and an unauthorized one in its subject is a request
  // for a name the order does not cover: a CA that carries the common name through into the issued
  // certificate would put that name in it. Where the ISSUED certificate is read, a common name beside
  // a SAN is not an identity and is ignored -- the two sides answer different questions, and this one
  // is about what the request asks for.
  var smugKp = signing.makeSigner("ec-p256", { cn: "victim.example" });
  var smugCsr = await pki.csr.sign({ subject: "victim.example", subjectPublicKey: smugKp.spki,
    extensionRequest: { subjectAltName: [{ dNSName: "example.org" }] } }, { key: smugKp.key });
  check("#2b a CSR smuggling an unauthorized common name past an authorized SAN is rejected",
    (await codeOf(acme2.finalize({ finalize: A.URLS.finalize, identifiers: [{ type: "dns", value: "example.org" }] }, { csr: smugCsr }))) === "acme/csr-identifier-mismatch");
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
  // a near-miss client option (the dropped-letter typo maxRedirect for maxRedirects) is refused with a message
  // naming it, not read as undefined and silently defaulted -- a swallowed typo would change redirect behavior.
  check("#6 an unknown client option is refused, not silently swallowed", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client(A.URLS.directory, { accountKey: ACCT.key, accountJwk: ACCT.jwk, alg: "ES256", tls: { anchors: [ACCT.spki] }, maxRedirect: 0 });
  }))) === "acme/bad-input");
}

// ---- 7 poll Retry-After surfaced (never slept in real time), then exhausted --
async function testPolling() {
  var seen = [];
  var s = A.acmeServer({ orderStates: ["processing", "processing", "valid"] });
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
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
  // #8g: a per-method bag refuses a near-miss option the same way the constructor does, rather than
  // reading it as undefined and silently defaulting -- covering the reject-preserving contract of each.
  check("#8g revokeCert refuses an unrecognized option (a near-miss for reason)",
    (await codeOf(acme.revokeCert({ certificate: revCert, reasons: 1 }))) === "acme/bad-input");
  // A recognized-key getter that grows a misspelled key WHEN READ must not slip past the per-method gate:
  // the bag is settled (read-all, then re-checked) before use, so a bag that rewrites itself is refused
  // rather than carrying the unchecked key into the request. Without settling, reason() fires only later.
  check("#8g revokeCert refuses a bag whose reason getter grows a key mid-read",
    (await codeOf(acme.revokeCert({ certificate: revCert, get reason() { this.reasonz = 1; return 4; } }))) === "acme/bad-input");
  check("#8g keyChange refuses an unrecognized option",
    (await codeOf(acme.keyChange({ newKey: neu.key, newJwk: neu.jwk, newAlg: "ES256", newKeyz: 1 }))) === "acme/bad-input");
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
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
  var ri = await acme.renewalInfo(certDer);
  check("#9 renewalInfo returns the validated window", ri.renewalInfo && ri.renewalInfo.suggestedWindow);
  var riReq = s.calls.filter(function (c) { return c.url.indexOf(A.URLS.renewalInfo) === 0; })[0];
  check("#9 renewalInfo is an UNAUTHENTICATED GET (no JWS body)", riReq && riReq.method === "GET" && (riReq.body == null || riReq.body === ""));
  // an inverted suggested window is treated as no signal -> fail closed.
  var sInv = A.acmeServer({ renewalInfoResponse: A.json(200, { suggestedWindow: { start: "2027-02-01T00:00:00Z", end: "2027-01-01T00:00:00Z" } }) });
  var acmeInv = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sInv));
  check("#9 an inverted renewal window fails closed", (await codeOf(acmeInv.renewalInfo(certDer))) === "acme/bad-renewal-window");
  // RFC 9773 sec. 4.3: the RAW renewalInfo verb MUST NOT query an already-expired certificate (not only the
  // renewalWindow helper) -- gated before the unauthenticated GET, so a dead certificate never reaches the CA.
  var sExp = A.acmeServer({});
  var acmeExp = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sExp, { clock: function () { return Date.parse("2041-01-01T00:00:00Z"); } }));
  check("#9 renewalInfo refuses an expired certificate", (await codeOf(Promise.resolve().then(function () { return acmeExp.renewalInfo(certDer); }))) === "acme/certificate-expired");
  check("#9 renewalInfo made no request for the expired certificate", sExp.calls.filter(function (c) { return c.url.indexOf(A.URLS.renewalInfo) === 0; }).length === 0);
  // a non-finite client clock (NaN / Infinity) would make the expiry comparison silently false and bypass the
  // RFC 9773 sec. 4.3 gate -- the validating wrapper fails closed rather than issuing the GET on a dead cert.
  var acmeNaN = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, A.acmeServer({}), { clock: function () { return NaN; } }));
  check("#9 renewalInfo rejects a non-finite client clock", (await codeOf(Promise.resolve().then(function () { return acmeNaN.renewalInfo(certDer); }))) === "acme/bad-input");
  // RFC 9773 sec. 4.3: the expiry is re-checked immediately BEFORE the GET, so a certificate that crosses notAfter
  // WHILE the (uncached) directory is being fetched is caught -- a clock that reads not-expired first, expired next.
  var tocCalls = 0;
  var acmeToc = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, A.acmeServer({}), { clock: function () { return tocCalls++ === 0 ? Date.parse("2039-06-01T00:00:00Z") : Date.parse("2041-01-01T00:00:00Z"); } }));
  check("#9 renewalInfo re-checks expiry after the directory fetch (TOCTOU)", (await codeOf(Promise.resolve().then(function () { return acmeToc.renewalInfo(certDer); }))) === "acme/certificate-expired");
  // A bad argument leaves as a REJECTION, like every other verb on this client -- so a caller who
  // wrote the documented `.catch(...)` sees it instead of an uncaught exception.
  check("#9 renewalInfo requires a DER Buffer", (await codeOf(acme.renewalInfo("not-a-buffer"))) === "acme/bad-input");
}

// ---- 10 oversized response rejected before decode ---------------------------
async function testOversized() {
  var big = "-----BEGIN CERTIFICATE-----\n" + "A".repeat(2000) + "\n-----END CERTIFICATE-----";
  var s = A.acmeServer({ certPems: [big] });
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s, { maxResponseBytes: 500 }));
  await acme.newAccount({});
  check("#10 an oversized certificate download is rejected", (await codeOf(acme.downloadCertificate(A.URLS.certificate, NO_BIND))) === "acme/response-too-large");
}

// ---- 10b an injected transport may return a BufferSource (Uint8Array) body, not only a Buffer/string ----
async function testByteSourceBody() {
  var s = A.acmeServer({ certPems: [ISSUED_PEM] });
  // Convert the directory (JSON, read via _jsonInput) and the certificate chain (PEM text, read via
  // _bodyText) response bodies to a Uint8Array on the wire. A body read that String()-coerces a BufferSource
  // turns it into "123,45,..." and the JSON fails to parse or the PEM chain does not split.
  var u8 = function (req) {
    return s.transport(req).then(function (res) {
      if (req.url === A.URLS.directory && typeof res.body === "string") {   // a Uint8Array view
        return Object.assign({}, res, { body: new Uint8Array(Buffer.from(res.body, "utf8")) });
      }
      if (req.url === A.URLS.certificate && typeof res.body === "string") {   // a raw ArrayBuffer (the full BufferSource contract)
        return Object.assign({}, res, { body: new Uint8Array(Buffer.from(res.body, "utf8")).buffer });
      }
      return res;
    });
  };
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, u8));
  var acct = await acme.newAccount({ termsOfServiceAgreed: true });
  check("#10b a Uint8Array directory response body is normalized, not string-coerced (_jsonInput)", acct.account.status === "valid");
  var dl = await acme.downloadCertificate(A.URLS.certificate, NO_BIND);
  check("#10c an ArrayBuffer certificate-chain body is size-checked and read consistently (source, not view)", Buffer.isBuffer(dl.certificate) && Array.isArray(dl.chain));
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
  var dl = await acmeAccept.downloadCertificate(A.URLS.certificate, NO_BIND);
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

  // (k) a 200 keyChange COMMITS the rollover server-side, so the client rotates to stay in sync even when
  // the (optional, informational) account body is malformed -- it does NOT fail closed and desynchronize.
  var sKC = A.acmeServer({ keyChangeBody: "not-json{" });
  var acmeKC = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sKC));
  await acmeKC.newAccount({});
  var neuKC = await A.makeAccount();
  var kcMal = await acmeKC.keyChange({ newKey: neuKC.key, newJwk: neuKC.jwk, newAlg: "ES256" });
  check("#11 keyChange with a malformed body still rotates (account best-effort null)", kcMal.account === null && kcMal.url === A.URLS.account);
  // a subsequent authenticated request still works (the client is rotated and in sync with the server).
  check("#11 the session key is usable after the rollover", (await acmeKC.revokeCert({ certificate: signing.makeSigner("ec-p256", { cn: "kc.example" }).cert })) === true);
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
  check("#12 a downloaded non-X.509 certificate body is rejected", (await codeOf(acmeBad.downloadCertificate(A.URLS.certificate, NO_BIND))) === "acme/bad-certificate-chain");
  var sOk = A.acmeServer({});
  var acmeOk = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sOk));
  await acmeOk.newAccount({});
  check("#12 a real downloaded certificate is parsed + returned as DER", Buffer.isBuffer((await acmeOk.downloadCertificate(A.URLS.certificate, NO_BIND)).certificate));

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
  check("#12g finalize refuses an unrecognized option",
    (await codeOf(acmeFb.finalize(ordFb.order, { csr: evilCsr, csrs: 1 }))) === "acme/bad-input");

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
  // Overridden with null, not deleted: an omitted tls field falls back to a configured-transport default credential.
  check("#13 a cross-origin redirect overrides the mTLS cert/key", xoReqs.length > 0 && xoReqs.every(function (c) { return (c.tls || {}).cert === null && (c.tls || {}).key === null; }));
  // even when the client sets no credential in its tls, a cross-origin hop overrides cert/key/servername:
  // the transport may carry defaults that an omitted field would fall through to.
  var sXoBare = A.acmeServer({ redirects: { "/dir-xb": "https://other.example/directory" } });
  var acmeXoBare = pki.acme.client(A.URLS.base + "/dir-xb", A.clientOpts(ACCT, sXoBare, { tls: { anchors: [ACCT.spki] } }));
  await acmeXoBare.newAccount({});
  var xbReqs = sXoBare.calls.filter(function (c) { return new URL(c.url).origin === "https://other.example"; });
  check("#13 a cross-origin hop overrides tls credentials even when the client sets none", xbReqs.length > 0 && xbReqs.every(function (c) { return (c.tls || {}).cert === null && (c.tls || {}).key === null && (c.tls || {}).servername === null; }));
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
  check("#13 a wrong cert media type fails closed", (await codeOf(acmeCt.downloadCertificate(A.URLS.certificate, NO_BIND))) === "acme/bad-certificate-chain");

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
  check("#13 a lookalike cert media type fails closed", (await codeOf(acmeLook.downloadCertificate(A.URLS.certificate, NO_BIND))) === "acme/bad-certificate-chain");
  // and the exact token WITH parameters is accepted.
  var sParam = A.acmeServer({ certContentType: "application/pem-certificate-chain; charset=utf-8" });
  var acmeParam = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sParam));
  await acmeParam.newAccount({});
  check("#13 the exact media type with parameters is accepted", Buffer.isBuffer((await acmeParam.downloadCertificate(A.URLS.certificate, NO_BIND)).certificate));

  // (k) the mTLS credential is bound to the CONFIGURED directory origin: a directory-advertised
  // cross-origin URL (a compromised/redirected directory) does NOT receive the client certificate/key,
  // while the trusted directory origin does.
  var mk2 = Buffer.from([9, 8, 7]);
  var sXoDir = A.acmeServer({ directory: A.directory({ newAccount: "https://other.example/new-account" }) });
  var acmeXoDir = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sXoDir, { tls: { anchors: [ACCT.spki], cert: mk2, key: mk2 } }));
  await acmeXoDir.newAccount({});
  var naXo = sXoDir.calls.filter(function (c) { return c.url === "https://other.example/new-account"; })[0];
  check("#13 mTLS is overridden for a directory-advertised cross-origin URL", naXo && (naXo.tls || {}).cert === null && (naXo.tls || {}).key === null);
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
  // (r) an EMPTY fragment ("...#") is rejected too: url.hash is "" (falsy) but the verbatim URL keeps the `#`,
  // so the signed JWS url would still differ from the requested target.
  check("#13 a URL with an empty fragment is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/directory#", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  // (r) an EMPTY query ("...?") is rejected too (url.search is "" but the verbatim URL keeps the "?"); a
  // NON-empty query round-trips and is accepted (not every ACME URL is path-only).
  check("#13 a URL with an empty query is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/directory?", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  check("#13 a URL with a non-empty query is accepted", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/directory?x=1", A.clientOpts(ACCT, A.acmeServer({})));
  }))) !== "acme/bad-url");
  // (r) a repaired AUTHORITY (a bracket in userinfo, "a[b@host" -> "a%5Bb@host") is rejected on the DIRECT path
  // (a directory / Location / caller URL) too, not only the Link-alternate path -- the signed url must match the
  // requested authority (RFC 8555 sec. 6.4).
  check("#13 a URL with a bracket in userinfo is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://a[b@acme.example/directory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  // (r) an IPv4-address-form host WHATWG rewrites to a dotted-quad ("0x7f.1", "2130706433" -> 127.0.0.1) is
  // rejected: the JWS url would be signed over the raw host while the transport connects to a DIFFERENT (loopback /
  // internal, SSRF-adjacent) address (RFC 8555 sec. 6.4). Uppercase host / :443 are still honored (normalization).
  check("#13 a hex IPv4-coercion host is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://0x7f.1/directory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  check("#13 a decimal IPv4-coercion host is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://2130706433/directory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  check("#13 an uppercase host is still accepted (normalization, not a rewrite)", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://ACME.EXAMPLE/directory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) !== "acme/bad-url");
  // (r) an ACME URL must not carry userinfo: the transport connects to the host without it, so a signed JWS url
  // with userinfo would not match the requested URL (RFC 8555 sec. 6.4), and a directory URL never has userinfo.
  check("#13 a URL with userinfo is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://user@acme.example/directory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  // (r) an EMPTY userinfo ("https://@host", "https://:@host") is rejected too: WHATWG reports username/password
  // empty, but the verbatim URL keeps the "@" the transport drops -- so the raw "@" is the signal, not url.username.
  check("#13 a URL with an empty userinfo delimiter is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://@acme.example/directory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");

  // (s) a URL whose spelling the transport would REPAIR into a different path (whitespace, backslash) is
  // rejected, so the signed and requested URLs cannot differ.
  check("#13 a URL with whitespace in the path is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/dir ectory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  check("#13 a URL with a backslash in the path is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/dir\\ectory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  // a URL with dot-segments in the path (the transport would normalize them away) is rejected -- literal
  // or PERCENT-ENCODED.
  check("#13 a URL with path dot-segments is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/a/../directory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  check("#13 a URL with percent-encoded dot-segments is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example/a/%2e%2e/directory", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  // a path with a dot INSIDE a segment name (not a dot-segment) is accepted.
  check("#13 a URL with a dot inside a path segment is accepted", typeof pki.acme.client("https://acme.example/a.b/directory", A.clientOpts(ACCT, A.acmeServer({}))).newAccount === "function");
  // an authority-only URL with NO path (`https://acme.example`) is rejected: the transport requests `/`, so
  // the verbatim signed `url` (no slash) would differ from the request target (RFC 8555 sec. 6.4).
  check("#13 an authority-only URL (no path) is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");
  // an authority-only URL carrying only a query (`https://acme.example?x=1`) is likewise rejected: the
  // transport inserts the `/` the raw path omits.
  check("#13 an authority-only URL with only a query is rejected", (await codeOf(Promise.resolve().then(function () {
    return pki.acme.client("https://acme.example?x=1", A.clientOpts(ACCT, A.acmeServer({})));
  }))) === "acme/bad-url");

  // an injected STRING response body is measured as UTF-8 (the bytes _jsonInput re-encodes it to), not
  // latin1: a body of multi-byte emoji whose UTF-8 length exceeds the cap but whose latin1 length does not
  // must still be rejected before the decoder (CWE-770). U+1F600 is 2 UTF-16 units (latin1) but 4 UTF-8.
  var emoji = String.fromCodePoint(0x1f600);
  var padded = JSON.stringify(A.directory({ _pad: emoji.repeat(80) }));
  var capUtf8 = Buffer.byteLength(padded, "latin1") + 20;   // over the latin1 count, well under the UTF-8 count
  var routeUtf8 = require("../helpers/fake-transport").fakeTransport(function (req) {
    if (new URL(req.url).pathname === "/directory") return { status: 200, headers: { "content-type": "application/json" }, body: padded };
    return { status: 500, headers: {}, body: "" };
  });
  var acmeUtf8Cap = pki.acme.client(A.URLS.directory, { accountKey: ACCT.key, accountJwk: ACCT.jwk, alg: "ES256", transport: routeUtf8, maxResponseBytes: capUtf8 });
  check("#13 an injected string body is measured as UTF-8 against the cap", (await codeOf(acmeUtf8Cap.newAccount({}))) === "acme/response-too-large");

  // (t) a CROSS-origin request resets the origin-specific servername (SNI, pinned to the trusted host) but
  // RETAINS the caller's checkServerIdentity pin (an additional constraint node re-evaluates against the
  // actual host); the trusted origin keeps both.
  var sniPin = function () {};
  var sSni = A.acmeServer({ directory: A.directory({ newAccount: "https://other.example/new-account" }) });
  var acmeSni = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sSni, { tls: { anchors: [ACCT.spki], servername: "acme.example", checkServerIdentity: sniPin } }));
  await acmeSni.newAccount({});
  var naSni = sSni.calls.filter(function (c) { return c.url === "https://other.example/new-account"; })[0];
  check("#13 a cross-origin request resets servername but RETAINS the checkServerIdentity pin", naSni && (naSni.tls || {}).servername === null && (naSni.tls || {}).checkServerIdentity === sniPin);
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

  // (w) explanatory text outside the PEM certificate chain fails closed (RFC 8555 sec. 7.4.2 forbids it).
  var chainCert = signing.makeSigner("ec-p256", { cn: "chain.example" }).cert;
  var chainPem = "-----BEGIN CERTIFICATE-----\n" + Buffer.from(chainCert).toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "") + "\n-----END CERTIFICATE-----";
  var sText = A.acmeServer({ certPems: ["Here is your certificate:\n" + chainPem] });
  var acmeText = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sText));
  await acmeText.newAccount({});
  check("#13 explanatory text outside the PEM chain fails closed", (await codeOf(acmeText.downloadCertificate(A.URLS.certificate, NO_BIND))) === "acme/bad-certificate-chain");
  // a clean chain (whitespace-separated PEM only) still downloads.
  var sClean = A.acmeServer({ certPems: [chainPem] });
  var acmeClean = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sClean));
  await acmeClean.newAccount({});
  check("#13 a clean PEM chain downloads", Buffer.isBuffer((await acmeClean.downloadCertificate(A.URLS.certificate, NO_BIND)).certificate));

  // (x) an ERROR status from newNonce (a rate limit) fails closed rather than using the error's nonce.
  var sBadNonce = A.acmeServer({ newNonceStatus: 429 });
  var acmeBadNonce = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sBadNonce));
  check("#13 a newNonce error status fails closed", (await codeOf(acmeBadNonce.newAccount({}))) === "acme/server-problem");

  // (y) the ARI certID is appended to the PATH before any query string (RFC 9773), not concatenated after.
  var akiR = require("node:crypto").createHash("sha1").update("issuerR").digest();
  var certR = signing.makeSigner("ec-p256", { cn: "ari.example", serial: 0x2a, exts: [akiExt(akiR)] }).cert;
  var certIdR = pki.acme.ariCertId(certR);
  var sAri = A.acmeServer({ directory: A.directory({ renewalInfo: "https://acme.example/renewal-info?tenant=1" }) });
  var acmeAri = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, sAri));
  await acmeAri.renewalInfo(certR);
  var ariCall = sAri.calls.filter(function (c) { return new URL(c.url).pathname.indexOf("/renewal-info/") === 0; })[0];
  check("#13 the ARI certID is in the path with the query preserved", ariCall && new URL(ariCall.url).pathname === "/renewal-info/" + certIdR && new URL(ariCall.url).search === "?tenant=1");
}

// ---- 14 newAuthz pre-authorization (RFC 8555 sec. 7.4.1) --------------------
async function withAccount(server) {
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, server));
  await acme.newAccount({ termsOfServiceAgreed: true });
  return acme;
}
async function testNewAuthz() {
  var DNS = { type: "dns", value: "example.org" };
  // NA-1 happy: 201 pending authz; kid-signed { identifier } payload; identifier bound; url == Location.
  var s = A.acmeServer({});
  var acme = await withAccount(s);
  var r = await acme.newAuthz(DNS);
  check("#14 NA-1 newAuthz resolves the validated pending authorization", r.authorization.status === "pending" && r.authorization.challenges.length === 1 && r.url === A.URLS.authz);
  var naPost = s.calls.filter(function (c) { return new URL(c.url).pathname === "/new-authz"; })[0];
  check("#14 NA-1 newAuthz is kid-signed with a single-identifier payload", naPost && naPost.method === "POST" && jwsProtected(naPost.body).kid === A.URLS.account &&
    JSON.parse(Buffer.from(JSON.parse(naPost.body).payload, "base64").toString("utf8")).identifier.value === "example.org");
  // NA-2 unadvertised newAuthz.
  var acme2 = await withAccount(A.acmeServer({ directory: A.directory({ newAuthz: undefined }) }));
  check("#14 NA-2 an unadvertised newAuthz fails closed", (await codeOf(acme2.newAuthz(DNS))) === "acme/resource-unavailable");
  // NA-3 wildcard rejected pre-transport (no POST).
  var s3 = A.acmeServer({});
  var acme3 = await withAccount(s3);
  check("#14 NA-3 a wildcard authorization identifier is rejected before any POST", (await codeOf(acme3.newAuthz({ type: "dns", value: "*.example.org" }))) === "acme/bad-identifier" &&
    s3.calls.filter(function (c) { return new URL(c.url).pathname === "/new-authz"; }).length === 0);
  // NA-4 hostile authz object (missing challenges).
  var acme4 = await withAccount(A.acmeServer({ newAuthzObject: { status: "pending", identifier: DNS } }));
  check("#14 NA-4 an authorization missing challenges fails closed", (await codeOf(acme4.newAuthz(DNS))) === "acme/missing-field");
  // NA-5 no Location.
  var acme5 = await withAccount(A.acmeServer({ newAuthzLocation: null }));
  check("#14 NA-5 a 201 with no Location fails closed", (await codeOf(acme5.newAuthz(DNS))) === "acme/no-authorization-url");
  // NA-6 identifier mismatch (server authz names a different identifier than requested).
  var acme6 = await withAccount(A.acmeServer({ identifiers: [{ type: "dns", value: "other.org" }] }));
  check("#14 NA-6 an authz whose identifier differs from the request is rejected", (await codeOf(acme6.newAuthz(DNS))) === "acme/identifier-mismatch");
  // NA-7 https invariant on the directory newAuthz URL (no POST).
  var s7 = A.acmeServer({ directory: A.directory({ newAuthz: "http://acme.example/new-authz" }) });
  var acme7 = await withAccount(s7);
  check("#14 NA-7 an http newAuthz directory URL is refused", (await codeOf(acme7.newAuthz(DNS))) === "acme/insecure-url" &&
    s7.calls.filter(function (c) { return new URL(c.url).pathname === "/new-authz"; }).length === 0);
  // NA-8 403 unwilling server problem.
  var acme8 = await withAccount(A.acmeServer({ newAuthzProblem: A.problem(403, "rejectedIdentifier", "identifier not allowed") }));
  check("#14 NA-8 a 403 problem surfaces as acme/server-problem", (await codeOf(acme8.newAuthz(DNS))) === "acme/server-problem");
  // NA-9 an authorization the CA marks wildcard:true is a broader grant than the non-wildcard identifier requested.
  var acme9 = await withAccount(A.acmeServer({ newAuthzWildcard: true }));
  check("#14 NA-9 a wildcard authorization for a non-wildcard request is rejected", (await codeOf(acme9.newAuthz(DNS))) === "acme/identifier-mismatch");
  // NA-10 a pre-authorization is normally PENDING, but the CA MAY return an already-"valid" authz (RFC 8555 sec.
  // 7.4.1 -- the identifier is already authorized out of band); it is usable and accepted.
  var acme10a = await withAccount(A.acmeServer({ newAuthzStatus: "valid" }));
  var na10a = await acme10a.newAuthz(DNS);
  check("#14 NA-10 an already-valid newAuthz response is accepted", na10a.authorization.status === "valid");
  // NA-11 only a terminal failed status ("invalid"/"deactivated"/"expired"/"revoked") is not proceedable.
  var acme11 = await withAccount(A.acmeServer({ newAuthzStatus: "invalid" }));
  check("#14 NA-11 a terminal (invalid) newAuthz response is rejected", (await codeOf(acme11.newAuthz(DNS))) === "acme/unexpected-authorization-status");
  // NA-12 an already-valid authz the CA granted out of band MAY carry an empty challenges array (RFC 8555 sec.
  // 7.1.4 / 7.4.1 -- no challenge was validated); the schema accepts it rather than requiring >= 1 challenge.
  var acme12 = await withAccount(A.acmeServer({ newAuthzObject: { status: "valid", expires: "2040-01-01T00:00:00Z", identifier: DNS, challenges: [] } }));
  var na12 = await acme12.newAuthz(DNS);
  check("#14 NA-12 a valid authz with empty challenges is accepted", na12.authorization.status === "valid" && na12.authorization.challenges.length === 0);
  // NA-12 a PENDING authz still requires at least one challenge (an empty challenges array is malformed).
  var acme12b = await withAccount(A.acmeServer({ newAuthzObject: { status: "pending", expires: "2040-01-01T00:00:00Z", identifier: DNS, challenges: [] } }));
  check("#14 NA-12 a pending authz with empty challenges is rejected", (await codeOf(acme12b.newAuthz(DNS))) !== "NO-THROW");
  // NA-13 a CA MAY answer a pre-authorization with 200 (OK) rather than 201 (Created) -- e.g. an already-existing
  // authorization (RFC 8555 sec. 7.4.1), the same leniency newAccount applies for an existing account.
  var acme13 = await withAccount(A.acmeServer({ newAuthzHttpStatus: 200 }));
  var na13 = await acme13.newAuthz(DNS);
  check("#14 NA-13 a 200 pre-authorization response is accepted", na13.authorization && na13.authorization.status === "pending");
}

// ---- 15 renewalWindow ARI decision helper (RFC 9773 sec. 4.2 / 4.3) ---------
// A pure, timer-less decision over the shipped renewalInfo GET: the sec. 4.3 pre-fetch gates (expired /
// caller-replaced), the sec. 4.2 uniform-random instant in the suggested window, and the sec. 4.3.2
// Retry-After clamp -- surfaced to the caller as DATA, never a hidden background scheduler.
async function testRenewalWindow() {
  var DAY = 24 * 60 * 60 * 1000;
  var aki = require("node:crypto").createHash("sha1").update("renew-issuer-key").digest();
  var certDer = signing.makeSigner("ec-p256", { cn: "renew.example", exts: [akiExt(aki)] }).cert;   // validity notAfter 2040-01-01; AKI for the ARI certID
  function iso(ms) { return new Date(ms).toISOString(); }
  function riResp(startMs, endMs, extraHeaders) {
    return { status: 200, headers: Object.assign({ "content-type": "application/json" }, extraHeaders || {}),
      body: JSON.stringify({ suggestedWindow: { start: iso(startMs), end: iso(endMs) } }) };
  }
  function clientAt(server, atMs) { return pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, server, { clock: function () { return atMs; } })); }
  var T = Date.parse("2027-06-01T00:00:00Z");

  // RW-1 a uniform-random instant IN the window; renewNow false; the fetch is the unauthenticated GET.
  var s1 = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY) });
  var r1 = await clientAt(s1, T).renewalWindow(certDer, { random: function () { return 0.5; } });
  check("#15g renewalWindow refuses an unrecognized option",
    (await codeOf(clientAt(s1, T).renewalWindow(certDer, { randoms: function () { return 0.5; } }))) === "acme/bad-input");
  check("#15 RW-1 selects the window midpoint, renewNow false", Date.parse(r1.selectedTime) === T + 15 * DAY && r1.renewNow === false);
  var ri1 = s1.calls.filter(function (c) { return new URL(c.url).pathname.indexOf("/renewal-info") === 0; })[0];
  check("#15 RW-1 the ARI fetch is the unauthenticated GET (no JWS body)", ri1 && ri1.method === "GET" && (ri1.body == null || ri1.body === ""));

  // RW-2 a window entirely in the past -> renewNow true.
  var s2 = A.acmeServer({ renewalInfoResponse: riResp(T - 20 * DAY, T - 10 * DAY) });
  var r2 = await clientAt(s2, T).renewalWindow(certDer, { random: function () { return 0.5; } });
  check("#15 RW-2 a past window forces renewNow", r2.renewNow === true);

  // RW-3 an inverted window fails closed (validateRenewalInfo, sec. 4.2).
  var s3 = A.acmeServer({ renewalInfoResponse: riResp(T + 20 * DAY, T + 10 * DAY) });
  check("#15 RW-3 an inverted window fails closed", (await codeOf(clientAt(s3, T).renewalWindow(certDer, {}))) === "acme/bad-renewal-window");

  // RW-4 an expired certificate is refused BEFORE any fetch (sec. 4.3).
  var s4 = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY) });
  check("#15 RW-4 an expired certificate is refused", (await codeOf(clientAt(s4, Date.parse("2041-01-01T00:00:00Z")).renewalWindow(certDer, {}))) === "acme/certificate-expired");
  check("#15 RW-4 the expiry refusal precedes any request", s4.calls.length === 0);

  // RW-5 a caller-asserted replaced certificate is refused with ZERO fetch (sec. 4.3).
  var s5 = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY) });
  check("#15 RW-5 a replaced certificate is refused", (await codeOf(clientAt(s5, T).renewalWindow(certDer, { replaced: true }))) === "acme/certificate-replaced");
  check("#15 RW-5 the replaced refusal makes no request", s5.calls.length === 0);

  // RW-6 the ARI Retry-After is clamped to [60s, 24h] (sec. 4.3.2).
  var s6a = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY, { "retry-after": "5" }) });
  check("#15 RW-6 a tiny Retry-After clamps up to 60s", (await clientAt(s6a, T).renewalWindow(certDer, {})).retryAfterSeconds === 60);
  var s6b = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY, { "retry-after": "999999" }) });
  check("#15 RW-6 a huge Retry-After clamps down to 24h", (await clientAt(s6b, T).renewalWindow(certDer, {})).retryAfterSeconds === 86400);

  // RW-7 an unadvertised renewalInfo resource fails closed.
  var dir7 = A.directory(); delete dir7.renewalInfo;
  check("#15 RW-7 an unadvertised renewalInfo fails closed", (await codeOf(clientAt(A.acmeServer({ directory: dir7 }), T).renewalWindow(certDer, {}))) === "acme/resource-unavailable");

  // RW-8 the random draw spans the window endpoints inclusively (0 -> start, 1 -> end); deterministic.
  var s8 = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY) });
  var r8lo = await clientAt(s8, T).renewalWindow(certDer, { random: function () { return 0; } });
  var r8hi = await clientAt(s8, T).renewalWindow(certDer, { random: function () { return 1; } });
  check("#15 RW-8 draw 0 selects the window start", Date.parse(r8lo.selectedTime) === T + 10 * DAY);
  check("#15 RW-8 draw 1 selects the window end", Date.parse(r8hi.selectedTime) === T + 20 * DAY);

  // RW-9 input guards + the default random path: no opts is accepted (crypto-backed draw); a non-Buffer cert,
  // a non-function random, and a draw outside [0,1] each fail closed; an explanationURL is surfaced.
  var s9 = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY) });
  var r9 = await clientAt(s9, T).renewalWindow(certDer);   // no opts -> default crypto random
  check("#15 RW-9 renewalWindow with no opts selects within the window", Date.parse(r9.selectedTime) >= T + 10 * DAY && Date.parse(r9.selectedTime) <= T + 20 * DAY);
  check("#15 RW-9 a non-Buffer certificate is rejected", (await codeOf(clientAt(s9, T).renewalWindow("nope", {}))) === "acme/bad-input");
  check("#15 RW-9 a non-function random is rejected", (await codeOf(clientAt(s9, T).renewalWindow(certDer, { random: 5 }))) === "acme/bad-input");
  check("#15 RW-9 a non-boolean replaced is rejected (no fail-open past the sec. 4.3 gate)", (await codeOf(clientAt(s9, T).renewalWindow(certDer, { replaced: 12345 }))) === "acme/bad-input");
  check("#15 RW-9 a random draw outside [0,1] is rejected", (await codeOf(clientAt(s9, T).renewalWindow(certDer, { random: function () { return 2; } }))) === "acme/bad-input");
  check("#15 RW-9 a non-number random draw is rejected (not coerced)", (await codeOf(clientAt(s9, T).renewalWindow(certDer, { random: function () { return null; } }))) === "acme/bad-input" && (await codeOf(clientAt(s9, T).renewalWindow(certDer, { random: function () { return "0.5"; } }))) === "acme/bad-input");
  var s9e = A.acmeServer({ renewalInfoResponse: { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ suggestedWindow: { start: iso(T + 10 * DAY), end: iso(T + 20 * DAY) }, explanationURL: "https://ca.example/why" }) } });
  var r9e = await clientAt(s9e, T).renewalWindow(certDer, { random: function () { return 0.5; } });
  check("#15 RW-9 an explanationURL is surfaced", r9e.explanationURL === "https://ca.example/why");

  // RW-15 renewNow is decided against a FRESH clock read (after the fetch), not the pre-fetch time: a clock
  // that advances past the selected instant while the RenewalInfo GET is in flight yields renewNow true.
  var rwCalls = 0;
  var advancingClock = function () { return rwCalls++ === 0 ? T : T + 16 * DAY; };   // pre-fetch T; post-fetch T+16d
  var s15 = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY) });   // midpoint T+15d, no Retry-After
  var acme15rw = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s15, { clock: function () { return T; } }));
  var r15 = await acme15rw.renewalWindow(certDer, { clock: advancingClock, random: function () { return 0.5; } });
  check("#15 RW-15 renewNow uses a fresh post-fetch clock read", r15.renewNow === true && Date.parse(r15.selectedTime) === T + 15 * DAY);

  // RW-16 the selected renewal instant is bounded by the certificate's notAfter: a suggestedWindow extending
  // past expiry never yields a renewal time after the cert is dead (RFC 9773 -- you renew BEFORE notAfter).
  var NA = Date.parse("2040-01-01T00:00:00Z");   // the fixture cert's notAfter
  var s16 = A.acmeServer({ renewalInfoResponse: riResp(NA - 100 * DAY, NA + 100 * DAY) });   // window straddles notAfter
  var r16 = await clientAt(s16, NA - 200 * DAY).renewalWindow(certDer, { random: function () { return 1; } });   // draw the max
  check("#15 RW-16 the selected time is clamped to notAfter", Date.parse(r16.selectedTime) === NA);
  // RW-17 when the ENTIRE suggested window starts after notAfter, there is no valid renewal time in it, so the
  // caller must renew immediately (renewNow true), not schedule for the last-valid instant.
  var s17rw = A.acmeServer({ renewalInfoResponse: riResp(NA + 10 * DAY, NA + 20 * DAY) });   // window entirely past expiry
  var r17rw = await clientAt(s17rw, NA - 10 * DAY).renewalWindow(certDer, { random: function () { return 0.5; } });
  check("#15 RW-17 a window starting after expiry forces renewNow", r17rw.renewNow === true && Date.parse(r17rw.selectedTime) === NA);
  // RW-18 a window whose start is EXACTLY notAfter is equally unusable -- the >= boundary forces renewNow.
  var s18 = A.acmeServer({ renewalInfoResponse: riResp(NA, NA + 10 * DAY) });
  var r18 = await clientAt(s18, NA - 10 * DAY).renewalWindow(certDer, { random: function () { return 0.5; } });
  check("#15 RW-18 a window starting exactly at notAfter forces renewNow", r18.renewNow === true);
  // RW-19 the expiry gate is EXCLUSIVE of notAfter (X.509 validity is inclusive, matching path-validate's t > notAfter):
  // a cert at exactly notAfter is still renewable (not yet expired), so the decision proceeds.
  var s19 = A.acmeServer({ renewalInfoResponse: riResp(NA - 20 * DAY, NA - 10 * DAY) });
  var r19 = await clientAt(s19, NA).renewalWindow(certDer, { random: function () { return 0.5; } });
  check("#15 RW-19 a certificate at exactly notAfter is still renewable, not expired", r19.renewNow === true);
  // RW-20 a straddling window (starts before notAfter, ends at/after it) whose draw lands EXACTLY on notAfter
  // leaves no margin -- renewNow is true even though the window opened before expiry.
  var s20 = A.acmeServer({ renewalInfoResponse: riResp(NA - 10 * DAY, NA + 10 * DAY) });
  var r20 = await clientAt(s20, NA - 5 * DAY).renewalWindow(certDer, { random: function () { return 1; } });
  check("#15 RW-20 a selection landing on notAfter forces renewNow", r20.renewNow === true && Date.parse(r20.selectedTime) === NA);
  // RW-21 a clock that returns a NON-finite value (NaN / Infinity) must fail closed, not silently make every
  // comparison false and bypass the expiry gate.
  check("#15 RW-21 a NaN clock reading is rejected", (await codeOf(clientAt(s20, T).renewalWindow(certDer, { clock: function () { return NaN; } }))) === "acme/bad-input");
  check("#15 RW-21 an infinite clock reading is rejected", (await codeOf(clientAt(s20, T).renewalWindow(certDer, { clock: function () { return Infinity; } }))) === "acme/bad-input");

  // RW-13 a syntactically-valid Retry-After beyond the shared parser's 1-year ceiling clamps to 24h rather
  // than failing the decision; RW-14 a garbage Retry-After falls back to the default (an advisory header must
  // never discard the usable window). Both keep the decision fail-OPEN on the poll cadence, fail-closed on data.
  var s13ra = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY, { "retry-after": "99999999999" }) });
  check("#15 RW-13 an over-ceiling Retry-After clamps to 24h", (await clientAt(s13ra, T).renewalWindow(certDer, { random: function () { return 0.5; } })).retryAfterSeconds === 86400);
  var s14ra = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY, { "retry-after": "not-a-delay" }) });
  check("#15 RW-14 a garbage Retry-After falls back to the default", (await clientAt(s14ra, T).renewalWindow(certDer, { random: function () { return 0.5; } })).retryAfterSeconds === 21600);

  // RW-10 a non-200 renewalInfo (a server problem) after the pre-fetch gates surfaces as acme/server-problem.
  var s10 = A.acmeServer({ renewalInfoResponse: A.problem(503, "serverInternal", "renewalInfo unavailable") });
  check("#15 RW-10 a renewalInfo server problem propagates", (await codeOf(clientAt(s10, T).renewalWindow(certDer, { random: function () { return 0.5; } }))) === "acme/server-problem");

  // RW-11 a per-call clock overrides the client clock for the whole decision (expiry gate + renewNow).
  var s11 = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY) });
  var r11 = await clientAt(s11, T).renewalWindow(certDer, { clock: function () { return T + 30 * DAY; }, random: function () { return 0.5; } });
  check("#15 RW-11 a per-call clock governs renewNow", r11.renewNow === true);   // the window is in the past per the call clock
  check("#15 RW-11 a per-call clock past notAfter is expired", (await codeOf(clientAt(s11, T).renewalWindow(certDer, { clock: function () { return Date.parse("2041-01-01T00:00:00Z"); } }))) === "acme/certificate-expired");
  check("#15 RW-11 a non-function clock is rejected", (await codeOf(clientAt(s11, T).renewalWindow(certDer, { clock: 5 }))) === "acme/bad-input");

  // RW-12 when the CA omits Retry-After, a sensible clamped default (6h) is returned rather than null.
  var s12 = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY) });   // riResp sets no retry-after header
  check("#15 RW-12 an absent Retry-After yields the default poll delay", (await clientAt(s12, T).renewalWindow(certDer, { random: function () { return 0.5; } })).retryAfterSeconds === 21600);
  // RW-20 RFC 9773 sec. 4.2: passing back a prior result (opts.previous) whose window is UNCHANGED reuses its
  // selectedTime, even when a fresh draw would differ -- a repeated ARI refresh converges on one stable instant.
  var sReuse = A.acmeServer({ renewalInfoResponse: riResp(T + 10 * DAY, T + 20 * DAY) });
  var r20a = await clientAt(sReuse, T).renewalWindow(certDer, { random: function () { return 0.25; } });
  var r20b = await clientAt(sReuse, T).renewalWindow(certDer, { previous: r20a, random: function () { return 0.9; } });
  check("#15 RW-20 an unchanged window reuses the prior selected time", r20b.selectedTime === r20a.selectedTime && Date.parse(r20a.selectedTime) === T + 12.5 * DAY);
  // RW-21 a CHANGED window ignores the stale prior and draws fresh.
  var r21 = await clientAt(sReuse, T).renewalWindow(certDer, { previous: { suggestedWindow: { start: "1999-01-01T00:00:00Z", end: "1999-02-01T00:00:00Z" }, selectedTime: "1999-01-15T00:00:00Z" }, random: function () { return 0.5; } });
  check("#15 RW-21 a changed window draws fresh, not the stale prior", Date.parse(r21.selectedTime) === T + 15 * DAY);
  // RW-21 a non-object opts.previous is a config error.
  check("#15 RW-21 a non-object previous is rejected", (await codeOf(clientAt(sReuse, T).renewalWindow(certDer, { previous: "nope" }))) === "acme/bad-input");
  // RW-22 a previous whose window MATCHES but whose selectedTime is not a date is a config error (fails closed
  // rather than silently re-drawing, so a corrupted stored value surfaces).
  check("#15 RW-22 a matching-window previous with a malformed selectedTime is rejected", (await codeOf(clientAt(sReuse, T).renewalWindow(certDer, { previous: { suggestedWindow: { start: iso(T + 10 * DAY), end: iso(T + 20 * DAY) }, selectedTime: "not-a-date" } }))) === "acme/bad-input");
}

// ---- 17 the downloaded certificate answers THIS order (RFC 8555 sec. 7.4 / sec. 7.4.2) ------
// The outbound direction already binds: finalize refuses a CSR whose identifier set is not the
// order's (acme/csr-identifier-mismatch) and refuses the account key (acme/key-reuse). Nothing bound
// the INBOUND direction, so a certificate URL answering with any certificate at all was installed as
// "the certificate for this order" -- a different key (one the caller does not hold) or a different
// name. The sibling client fails closed on the same question: pki.est picks the issued certificate by
// public-key match against the submitted CSR and refuses when none matches.
async function testIssuedCertificateBinding() {
  function toPem(der) { return "-----BEGIN CERTIFICATE-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n+$/, "") + "\n-----END CERTIFICATE-----"; }
  async function withAccount(s) {
    var c = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
    await c.newAccount({ termsOfServiceAgreed: true });
    return c;
  }
  // The leaves are built directly rather than issued: the binding under test reads the subject public
  // key and the subjectAltName, so a real chain would add nothing the check consults.
  var b = pki.asn1.build;
  // A leaf whose common name is a UTF8String. signing.minimalCert encodes a PrintableString, which
  // admits neither the wildcard `*` nor a non-ASCII character, and both are needed below.
  function certWithUtf8Cn(spki, cn, exts) {
    var alg = b.sequence([b.oid(pki.oid.byName("ecdsaWithSHA256"))]);
    var name = b.sequence([b.set([b.sequence([b.oid(pki.oid.byName("commonName")), b.utf8(cn)])])]);
    var validity = b.sequence([b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2040-01-01T00:00:00Z"))]);
    var tbs = [b.explicit(0, b.integer(2n)), b.integer(0x77n), alg, name, validity, name, b.raw(spki)];
    if (exts && exts.length) tbs.push(b.explicit(3, b.sequence(exts)));
    return b.sequence([b.sequence(tbs), alg, b.bitString(Buffer.from([0, 0, 0, 0]), 0)]);
  }
  function sanExt(dns) {
    return b.sequence([b.oid(pki.oid.byName("subjectAltName")),
      b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from(dns, "latin1"))]))]);
  }
  var ca = signing.makeSigner("ec-p256", { cn: "Binding Test CA" });
  // The leaf the caller ASKED for: its own key, its own name.
  var mineKp = signing.makeSigner("ec-p256", { cn: "example.org", exts: [sanExt("example.org")] });
  var mine = { spki: mineKp.spki }, myLeaf = mineKp.cert;
  // A leaf for the SAME name under a key the caller does not hold.
  var otherKp = signing.makeSigner("ec-p256", { cn: "example.org", exts: [sanExt("example.org")] });
  var otherKeyLeaf = otherKp.cert, otherSpki = otherKp.spki;
  // A leaf for the caller's OWN key under a name the order never asked for.
  var otherNameLeaf = signing.minimalCert(mine.spki, { cn: "victim.example", exts: [sanExt("victim.example")] });
  var caPem = toPem(ca.cert);
  var ORDER_IDS = [{ type: "dns", value: "example.org" }];
  function serve(leafDer) { return A.acmeServer({ certPems: [toPem(leafDer), caPem] }); }

  // BD-1 the binding material is REQUIRED by default: a download that cannot be checked is refused
  // rather than returned unchecked, so an operator never installs a certificate nothing looked at.
  var acme1 = await withAccount(serve(myLeaf));
  check("#17 BD-1 a download with no binding material is refused by default",
    (await codeOf(acme1.downloadCertificate(A.URLS.certificate))) === "acme/binding-required");

  // BD-2 the certificate the order asked for passes, and the verdict SAYS what it checked.
  var acme2 = await withAccount(serve(myLeaf));
  var r2 = await acme2.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS });
  check("#17 BD-2 the asked-for certificate downloads", r2.certificate.equals(myLeaf));
  check("#17 BD-2 the verdict reports both bindings as checked", r2.boundToKey === true && r2.boundToIdentifiers === true);

  // BD-3 a certificate for a DIFFERENT key is refused -- the caller cannot use it, and installing it
  // would take a working service down while the CA's answer looked successful.
  var acme3 = await withAccount(serve(otherKeyLeaf));
  check("#17 BD-3 a certificate for another key is refused",
    (await codeOf(acme3.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }))) === "acme/certificate-key-mismatch");

  // BD-4 a certificate for a DIFFERENT name is refused, even though its key is the caller's.
  var acme4 = await withAccount(serve(otherNameLeaf));
  check("#17 BD-4 a certificate for another identifier is refused",
    (await codeOf(acme4.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }))) === "acme/certificate-identifier-mismatch");

  // BD-5 each half stands alone: supplying only one still checks that one.
  var acme5a = await withAccount(serve(otherKeyLeaf));
  check("#17 BD-5 expectedSpki alone still refuses another key",
    (await codeOf(acme5a.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, requireBinding: false }))) === "acme/certificate-key-mismatch");
  var acme5b = await withAccount(serve(otherNameLeaf));
  check("#17 BD-5 identifiers alone still refuses another name",
    (await codeOf(acme5b.downloadCertificate(A.URLS.certificate, { identifiers: ORDER_IDS, requireBinding: false }))) === "acme/certificate-identifier-mismatch");

  // BD-6 requireBinding:false waives the REQUIREMENT to supply material, never the check on material
  // that IS supplied -- so the waiver cannot become the place a mismatch hides. With nothing supplied
  // the verdict says so rather than reading as a pass.
  var acme6 = await withAccount(serve(otherNameLeaf));
  var r6 = await acme6.downloadCertificate(A.URLS.certificate, { requireBinding: false });
  check("#17 BD-6 an explicit waiver downloads", r6.certificate.equals(otherNameLeaf));
  check("#17 BD-6 the verdict reports both bindings as unchecked", r6.boundToKey === false && r6.boundToIdentifiers === false);
  var acme6b = await withAccount(serve(otherKeyLeaf));
  check("#17 BD-6 a waiver does not disable a supplied check",
    (await codeOf(acme6b.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS, requireBinding: false }))) === "acme/certificate-key-mismatch");

  // BD-7 the binding holds on the chain that is RETURNED, not only the primary one. A selectChain
  // caller ends up with an alternate, and an alternate is fetched from a URL the server named.
  var s7 = A.acmeServer({ certPems: [toPem(myLeaf), caPem], alternateChains: [[toPem(myLeaf), caPem]] });
  var acme7 = await withAccount(s7);
  var r7 = await acme7.downloadCertificate(A.URLS.certificate,
    { expectedSpki: mine.spki, identifiers: ORDER_IDS, selectChain: function (c) { return c.certificates.length === 2; } });
  check("#17 BD-7 a selected chain is bound too", r7.certificate.equals(myLeaf) && r7.boundToKey === true);

  // BD-8a the key the certificate is checked against is the one supplied at the call, not whatever the
  // caller's Buffer holds when the response lands. The comparison happens after a network round trip,
  // so a retained reference would let a caller rewrite the answer mid-flight: here the buffer is
  // overwritten with the OTHER key's bytes while the certificate request is outstanding, and the
  // correct certificate must still be accepted.
  var mutable = Buffer.from(mine.spki);
  var sMut = serve(myLeaf);
  var baseTransport = A.clientOpts(ACCT, sMut).transport;
  var acmeMut = pki.acme.client(A.URLS.directory, Object.assign(A.clientOpts(ACCT, sMut), {
    transport: function (req) {
      // Rewrite the caller's buffer at the moment the certificate request goes out.
      if (String(req.url).indexOf("/cert/") !== -1) otherSpki.copy(mutable);
      return baseTransport(req);
    },
  }));
  await acmeMut.newAccount({ termsOfServiceAgreed: true });
  var rMut = await acmeMut.downloadCertificate(A.URLS.certificate, { expectedSpki: mutable, identifiers: ORDER_IDS });
  check("#17 BD-8a a caller Buffer rewritten mid-flight does not change what the certificate is checked against",
    rMut.certificate.equals(myLeaf) && rMut.boundToKey === true);

  // BD-8b the identifier sets are asked `set[key]`, so against an ordinary object that question would
  // reach Object.prototype: a name planted there answers for an identifier neither side carried, and
  // since the comparison is set-equality, a planted extra can hide a real mismatch by making the
  // certificate's own extra name read as one the order wanted. The sets are built with no prototype,
  // so a planted name answers for nothing.
  //
  // What this vector can assert END TO END is that the download does not succeed under a polluted
  // prototype. The refusal an operator sees arrives EARLIER than the comparison -- the unknown-option
  // door refuses any options bag carrying a name the verb does not define, inherited names included --
  // so the pollution never reaches the binding through a client verb. The null prototype is therefore
  // defense in depth here rather than the only thing standing in the way, and it is what the
  // comparison would rely on if a future caller reached it another way. The planted names are chosen
  // to be exactly the two keys that would flip this comparison.
  var plantedA = "dns:victim.example", plantedB = "dns:example.org";
  var acmePlant = await withAccount(serve(otherNameLeaf));
  Object.defineProperty(Object.prototype, plantedA, { value: true, writable: true, configurable: true });
  Object.defineProperty(Object.prototype, plantedB, { value: true, writable: true, configurable: true });
  var plantedCode;
  try {
    plantedCode = await codeOf(acmePlant.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }));
  } finally {
    delete Object.prototype[plantedA];
    delete Object.prototype[plantedB];
  }
  check("#17 BD-8b a download under a polluted Object.prototype does not succeed (got " + plantedCode + ")",
    plantedCode !== "NO-THROW");
  // And the comparison's own sets carry no prototype, which is what makes the planted keys inert if a
  // caller ever reaches the binding without passing an options bag through the door above.
  check("#17 BD-8b the identifier comparison is not reachable through Object.prototype",
    (await codeOf(acmePlant.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }))) === "acme/certificate-identifier-mismatch");

  // BD-9 an identifier the comparison cannot map is REFUSED, never dropped. The ACME identifier
  // registry (RFC 8555 sec. 9.7.7) is open, and only dns and ip map to a name a certificate carries.
  // Dropping an unmapped one would leave the comparison answering about the identifiers it happens to
  // understand while reporting the whole set as checked: an order for example.org plus one other type
  // would be satisfied by a certificate naming only example.org, with boundToIdentifiers true.
  var acme9 = await withAccount(serve(myLeaf));
  check("#17 BD-9 an order identifier type this build cannot map is refused",
    (await codeOf(acme9.downloadCertificate(A.URLS.certificate,
      { expectedSpki: mine.spki, identifiers: [{ type: "dns", value: "example.org" }, { type: "device", value: "wanted-device" }] }))) === "acme/unsupported-identifier-type");

  // BD-9b the same rule on the certificate's own side: a subjectAltName that maps to no order
  // identifier -- an rfc822Name here -- is a name the set-equality comparison would otherwise never
  // see, so a certificate additionally naming a mailbox would compare equal to an order covering only
  // the dns name.
  var emailSan = b.sequence([b.oid(pki.oid.byName("subjectAltName")),
    b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("example.org", "latin1")),
      b.contextPrimitive(1, Buffer.from("ops@example.org", "latin1"))]))]);
  var extraNameLeaf = signing.minimalCert(mine.spki, { cn: "example.org", exts: [emailSan] });
  var acme9b = await withAccount(serve(extraNameLeaf));
  check("#17 BD-9b a certificate subjectAltName that maps to no order identifier is refused",
    (await codeOf(acme9b.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }))) === "acme/unsupported-identifier-type");

  // BD-10 the traversal that reads the certificate's own names is taken at load. The identifier set is
  // built AFTER the download returns, from a certificate the server chose, so a caller who replaces
  // Array.prototype.forEach while the request is outstanding would otherwise decide what names that
  // certificate appears to carry -- presenting the order's name for a certificate that carries only
  // another, and the comparison would agree the sets are equal.
  // The leaf carries its name ONLY in the subject common name, so that walk is the whole source of
  // the certificate's identifier set and a replaced traversal decides all of it.
  var cnOnlyLeaf = signing.minimalCert(mine.spki, { cn: "victim.example" });
  var sFe = serve(cnOnlyLeaf);
  var feBase = A.clientOpts(ACCT, sFe).transport;
  var realForEach = Array.prototype.forEach;
  var acmeFe = pki.acme.client(A.URLS.directory, Object.assign(A.clientOpts(ACCT, sFe), {
    transport: function (req) {
      if (String(req.url).indexOf("/cert/") !== -1) {
        // Surgical: pass through for every array except the attribute-and-value arrays a subject DN
        // walk visits, where it presents the order's name INSTEAD of the one the certificate carries.
        Object.defineProperty(Array.prototype, "forEach", {
          value: function (cb, thisArg) {
            var first = this.length ? this[0] : null;
            if (first && typeof first === "object" && "value" in first && ("name" in first || "type" in first)) {
              return cb.call(thisArg, { name: "commonName", value: "example.org" }, 0, this);
            }
            return realForEach.call(this, cb, thisArg);
          },
          writable: true, configurable: true,
        });
      }
      return feBase(req);
    },
  }));
  await acmeFe.newAccount({ termsOfServiceAgreed: true });
  var feCode;
  try {
    feCode = await codeOf(acmeFe.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }));
  } finally {
    Object.defineProperty(Array.prototype, "forEach", { value: realForEach, writable: true, configurable: true });
  }
  check("#17 BD-10 a replaced traversal cannot present a name the certificate does not carry (got " + feCode + ")",
    feCode === "acme/certificate-identifier-mismatch");

  // BD-11 an IP certificate carries the address in the common name AND in an iPAddress SAN, which
  // CABF TLS BR 7.1.4.2.2 permits (a commonName may match either a dNSName or an iPAddress SAN), and
  // the order carries it once as an ip identifier. Counting that common name as a dns name would make
  // a correct issuance compare as two identifiers against the order's one and refuse it.
  var ipSan = b.sequence([b.oid(pki.oid.byName("subjectAltName")),
    b.octetString(b.sequence([b.contextPrimitive(7, Buffer.from([192, 0, 2, 1]))]))]);
  var ipLeaf = signing.minimalCert(mine.spki, { cn: "192.0.2.1", exts: [ipSan] });
  var acme11 = await withAccount(serve(ipLeaf));
  var r11 = await acme11.downloadCertificate(A.URLS.certificate,
    { expectedSpki: mine.spki, identifiers: [{ type: "ip", value: "192.0.2.1" }] });
  check("#17 BD-11 an IP certificate naming the address in both CN and SAN binds to an ip order",
    r11.certificate.equals(ipLeaf) && r11.boundToIdentifiers === true);
  // BD-11b a common name that reads as an address but is not its canonical form is not an identifier
  // this comparison can express, and it is left out rather than normalized into one. Leaving a name
  // out of the CERTIFICATE's set can only make that set smaller, so equality with the order fails
  // rather than passes -- the opposite of dropping an ORDER identifier, which is why that one is
  // refused instead. Here the iPAddress SAN carries the address the order asked for, and the
  // authoritative name matches.
  var badIpLeaf = signing.minimalCert(mine.spki, { cn: "192.0.2.01", exts: [ipSan] });
  var acme11b = await withAccount(serve(badIpLeaf));
  var r11b = await acme11b.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: [{ type: "ip", value: "192.0.2.1" }] });
  check("#17 BD-11b a non-canonical IP-literal common name contributes nothing; the SAN decides",
    r11b.certificate.equals(badIpLeaf) && r11b.boundToIdentifiers === true);
  // BD-11c where there is no SAN the common name IS consulted, and one that maps to no order
  // identifier is refused rather than left out. Dropping it is unsafe even though a smaller
  // certificate set can only fail equality, because a subject may carry several common names: drop the
  // unmappable one while another supplies the match and the set reports as bound while the certificate
  // still names something the order never covered. BD-11d is that shape.
  var badIpNoSan = signing.minimalCert(mine.spki, { cn: "192.0.2.01" });
  var acme11c = await withAccount(serve(badIpNoSan));
  check("#17 BD-11c a certificate whose only name is an unmappable common name is refused",
    (await codeOf(acme11c.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: [{ type: "ip", value: "192.0.2.1" }] }))) === "acme/unsupported-identifier-type");

  // BD-11f the ordinary IP request shape: the address in the subject common name AND in the matching
  // iPAddress SAN, which CABF TLS BR 7.1.4.2.2 permits and issuers write. The common name repeats a
  // name the alternative names already carry, so it adds no identifier and the request stands. A
  // common name naming a DIFFERENT address is nowhere in those names, so it is one the order never
  // covered. Driven through finalize, which is the side that reads every common name.
  var ipReqKp = signing.makeSigner("ec-p256", { cn: "192.0.2.1" });
  var ipReqCsr = await pki.csr.sign({ subject: "192.0.2.1", subjectPublicKey: ipReqKp.spki,
    extensionRequest: { subjectAltName: [{ iPAddress: "192.0.2.1" }] } }, { key: ipReqKp.key });
  var acmeIpReq = await withAccount(serve(myLeaf));
  check("#17 BD-11f an IP CSR naming the address in both the common name and the matching SAN is accepted",
    (await codeOf(acmeIpReq.finalize({ finalize: A.URLS.finalize, identifiers: [{ type: "ip", value: "192.0.2.1" }] }, { csr: ipReqCsr }))) === "NO-THROW");
  var ipOtherKp = signing.makeSigner("ec-p256", { cn: "192.0.2.9" });
  var ipOtherCsr = await pki.csr.sign({ subject: "192.0.2.9", subjectPublicKey: ipOtherKp.spki,
    extensionRequest: { subjectAltName: [{ iPAddress: "192.0.2.1" }] } }, { key: ipOtherKp.key });
  check("#17 BD-11f an IP CSR whose common name names another address is rejected",
    (await codeOf(acmeIpReq.finalize({ finalize: A.URLS.finalize, identifiers: [{ type: "ip", value: "192.0.2.1" }] }, { csr: ipOtherCsr }))) === "acme/unsupported-identifier-type");

  // BD-11e an address in a common name is not an ip identity even spelled canonically. Address
  // matching reads the iPAddress SAN and never falls back to the common name, so a certificate naming
  // the ordered address only there cannot authenticate it.
  var ipCnOnly = signing.minimalCert(mine.spki, { cn: "192.0.2.1" });
  var acme11e = await withAccount(serve(ipCnOnly));
  check("#17 BD-11e a canonical address in a common name alone is not an ip identity",
    (await codeOf(acme11e.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: [{ type: "ip", value: "192.0.2.1" }] }))) === "acme/unsupported-identifier-type");

  // BD-11d two common names, no SAN: one is the order's, the other a trailing-dot spelling that a
  // hostname matcher accepts as a name this certificate covers. Leaving the second out would let the
  // first satisfy the comparison and report boundToIdentifiers true for a certificate that also names
  // something the order never authorized.
  var twoCn = b.sequence([
    b.set([b.sequence([b.oid(pki.oid.byName("commonName")), b.printable("example.org")])]),
    b.set([b.sequence([b.oid(pki.oid.byName("commonName")), b.printable("victim.example.")])]),
  ]);
  var alg2 = b.sequence([b.oid(pki.oid.byName("ecdsaWithSHA256"))]);
  var val2 = b.sequence([b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2040-01-01T00:00:00Z"))]);
  var twoCnLeaf = b.sequence([
    b.sequence([b.explicit(0, b.integer(2n)), b.integer(0x78n), alg2, twoCn, val2, twoCn, b.raw(mine.spki)]),
    alg2, b.bitString(Buffer.from([0, 0, 0, 0]), 0),
  ]);
  var acme11d = await withAccount(serve(twoCnLeaf));
  check("#17 BD-11d an unmappable common name beside a matching one is refused, not dropped",
    (await codeOf(acme11d.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }))) === "acme/unsupported-identifier-type");

  // BD-12 the common name is folded with ASCII case rules, never the Unicode mapping. Several
  // characters lowercase INTO ASCII -- U+212A KELVIN SIGN becomes "k" -- so a full fold would turn a
  // name the certificate does not carry as a DNS label into one that compares equal to an order
  // identifier. The certificate here names only the Kelvin-sign form and carries no SAN, so under a
  // Unicode fold it would satisfy an order for "k.example". (Source stays ASCII: the character is
  // built at runtime.)
  var kelvin = String.fromCharCode(0x212a);
  var kelvinLeaf = certWithUtf8Cn(mine.spki, kelvin + ".example", []);
  var acme12 = await withAccount(serve(kelvinLeaf));
  // Under an ASCII fold the name stays non-ASCII, so it maps to no order identifier and is refused;
  // under a Unicode fold it would BE "k.example" and the download would succeed.
  check("#17 BD-12 a Unicode common name that lowercases into ASCII does not satisfy the order",
    (await codeOf(acme12.downloadCertificate(A.URLS.certificate,
      { expectedSpki: mine.spki, identifiers: [{ type: "dns", value: "k.example" }] }))) === "acme/unsupported-identifier-type");

  // BD-12b a wildcard survives the same gate: an order identifier carries the `*.` verbatim
  // (RFC 8555 sec. 7.1.3) and the certificate carries it as a SAN, so both sides must still match.
  var wildSan = b.sequence([b.oid(pki.oid.byName("subjectAltName")),
    b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("*.example.org", "latin1"))]))]);
  var wildLeaf = certWithUtf8Cn(mine.spki, "*.example.org", [wildSan]);
  var acme12b = await withAccount(serve(wildLeaf));
  var r12b = await acme12b.downloadCertificate(A.URLS.certificate,
    { expectedSpki: mine.spki, identifiers: [{ type: "dns", value: "*.example.org" }] });
  check("#17 BD-12b a wildcard certificate binds to a wildcard order",
    r12b.certificate.equals(wildLeaf) && r12b.boundToIdentifiers === true);

  // BD-13 where the certificate asserts subject alternative names, those are its identity and the
  // subject common name is not an additional one. The common name here is itself a valid dns name and
  // a DIFFERENT one from the SAN -- the ordinary "CN=www.example.org, SAN=example.org" shape -- so
  // counting it would add a second identifier and make a SAN set that is exactly the order's compare
  // unequal. (An organizational common name would not discriminate: it is not a dns name at all, and
  // is left out either way.)
  var orgCnLeaf = signing.minimalCert(mine.spki, { cn: "www.example.org", exts: [sanExt("example.org")] });
  var acme13 = await withAccount(serve(orgCnLeaf));
  var r13 = await acme13.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS });
  check("#17 BD-13 an organizational common name beside a matching SAN does not break the binding",
    r13.certificate.equals(orgCnLeaf) && r13.boundToIdentifiers === true);
  // BD-13b with no SAN at all the common name is the only name there is, and it still has to match.
  var cnOnlyMatch = signing.minimalCert(mine.spki, { cn: "example.org" });
  var acme13b = await withAccount(serve(cnOnlyMatch));
  check("#17 BD-13b a certificate with no SAN binds on its common name",
    (await acme13b.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS })).boundToIdentifiers === true);

  // BD-14 the same rule one layer out: the subjectAltName decoder yields the names the comparison
  // reads, so its own traversal is taken at load too. A caller replacing Array.prototype.map while
  // the request is outstanding would otherwise present a name the encoded GeneralNames does not
  // carry -- here the order's name for a certificate that carries only another.
  var sanFeLeaf = signing.minimalCert(mine.spki, { cn: "victim.example", exts: [sanExt("victim.example")] });
  var sSan = serve(sanFeLeaf);
  var sanBase = A.clientOpts(ACCT, sSan).transport;
  var realMap = Array.prototype.map;
  var acmeSan = pki.acme.client(A.URLS.directory, Object.assign(A.clientOpts(ACCT, sSan), {
    transport: function (req) {
      if (String(req.url).indexOf("/cert/") !== -1) {
        // Surgical: pass through except for the decoded GeneralName items, where it presents the
        // order's name in place of the one the certificate encodes.
        Object.defineProperty(Array.prototype, "map", {
          value: function (cb, thisArg) {
            var first = this.length ? this[0] : null;
            if (first && typeof first === "object" && first.value && first.value.tagNumber === 2) {
              return [{ tagNumber: 2, value: "example.org" }].map.call(
                [{ tagNumber: 2, value: "example.org" }], function (x) { return x; });
            }
            return realMap.call(this, cb, thisArg);
          },
          writable: true, configurable: true,
        });
      }
      return sanBase(req);
    },
  }));
  await acmeSan.newAccount({ termsOfServiceAgreed: true });
  var sanCode;
  try {
    sanCode = await codeOf(acmeSan.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }));
  } finally {
    Object.defineProperty(Array.prototype, "map", { value: realMap, writable: true, configurable: true });
  }
  check("#17 BD-14 a replaced decoder traversal cannot present a name the certificate does not encode (got " + sanCode + ")",
    sanCode === "acme/certificate-identifier-mismatch");

  // BD-14b the traversal is one spelling of the same thing. The dNSName itself is the decoder's
  // conversion of the encoded octets, so a replaced Buffer.prototype.toString presents whatever
  // string it likes for a certificate that carries only another name.
  var strFeLeaf = signing.minimalCert(mine.spki, { cn: "victim.example", exts: [sanExt("victim.example")] });
  var sStr = serve(strFeLeaf);
  var strBase = A.clientOpts(ACCT, sStr).transport;
  var realBufToString = Buffer.prototype.toString;
  var acmeStr = pki.acme.client(A.URLS.directory, Object.assign(A.clientOpts(ACCT, sStr), {
    transport: function (req) {
      if (String(req.url).indexOf("/cert/") !== -1) {
        Object.defineProperty(Buffer.prototype, "toString", {
          value: function (enc, s, e) {
            var real = realBufToString.call(this, enc, s, e);
            return enc === "latin1" && real === "victim.example" ? "example.org" : real;
          },
          writable: true, configurable: true,
        });
      }
      return strBase(req);
    },
  }));
  await acmeStr.newAccount({ termsOfServiceAgreed: true });
  var strCode;
  try {
    strCode = await codeOf(acmeStr.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }));
  } finally {
    Object.defineProperty(Buffer.prototype, "toString", { value: realBufToString, writable: true, configurable: true });
  }
  check("#17 BD-14b a replaced string conversion cannot present a dNSName the certificate does not carry (got " + strCode + ")",
    strCode === "acme/certificate-identifier-mismatch");

  // BD-14c and the address alternative reads its octets through a copy, so a replaced Buffer.concat
  // substitutes the order's address for the one the certificate encodes.
  var otherIpSan = b.sequence([b.oid(pki.oid.byName("subjectAltName")),
    b.octetString(b.sequence([b.contextPrimitive(7, Buffer.from([198, 51, 100, 7]))]))]);
  var ipFeLeaf = signing.minimalCert(mine.spki, { cn: "198.51.100.7", exts: [otherIpSan] });
  var sIp = serve(ipFeLeaf);
  var ipBase = A.clientOpts(ACCT, sIp).transport;
  var realConcat = Buffer.concat;
  var acmeIpFe = pki.acme.client(A.URLS.directory, Object.assign(A.clientOpts(ACCT, sIp), {
    transport: function (req) {
      if (String(req.url).indexOf("/cert/") !== -1) {
        Buffer.concat = function (list, total) {
          if (list && list.length === 1 && list[0] && list[0].length === 4 && list[0][0] === 198) {
            return realConcat.call(Buffer, [Buffer.from([192, 0, 2, 1])]);
          }
          return realConcat.call(Buffer, list, total);
        };
      }
      return ipBase(req);
    },
  }));
  await acmeIpFe.newAccount({ termsOfServiceAgreed: true });
  var ipFeCode;
  try {
    ipFeCode = await codeOf(acmeIpFe.downloadCertificate(A.URLS.certificate,
      { expectedSpki: mine.spki, identifiers: [{ type: "ip", value: "192.0.2.1" }] }));
  } finally {
    Buffer.concat = realConcat;
  }
  check("#17 BD-14c a replaced byte copy cannot present an iPAddress the certificate does not carry (got " + ipFeCode + ")",
    ipFeCode === "acme/certificate-identifier-mismatch");

  // BD-14d where there is no SAN the common name decides, and the subject is assembled by the same
  // kind of traversal. A replaced Array.prototype.push seats a common name the certificate's own
  // subject never encoded.
  var cnFeLeaf = signing.minimalCert(mine.spki, { cn: "victim.example" });
  var sCn = serve(cnFeLeaf);
  var cnBase = A.clientOpts(ACCT, sCn).transport;
  var realPush = Array.prototype.push;
  var acmeCnFe = pki.acme.client(A.URLS.directory, Object.assign(A.clientOpts(ACCT, sCn), {
    transport: function (req) {
      if (String(req.url).indexOf("/cert/") !== -1) {
        Object.defineProperty(Array.prototype, "push", {
          value: function (v) {
            if (arguments.length === 1 && v && typeof v === "object" && v.name === "commonName" && v.value === "victim.example") {
              return realPush.call(this, { type: v.type, name: v.name, value: "example.org" });
            }
            return realPush.apply(this, arguments);
          },
          writable: true, configurable: true,
        });
      }
      return cnBase(req);
    },
  }));
  await acmeCnFe.newAccount({ termsOfServiceAgreed: true });
  var cnFeCode;
  try {
    cnFeCode = await codeOf(acmeCnFe.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS }));
  } finally {
    Object.defineProperty(Array.prototype, "push", { value: realPush, writable: true, configurable: true });
  }
  check("#17 BD-14d a replaced subject traversal cannot seat a common name the certificate does not carry (got " + cnFeCode + ")",
    cnFeCode === "acme/certificate-identifier-mismatch");

  // BD-8 bad binding input is a config error, refused before the certificate is read.
  var acme8 = await withAccount(serve(myLeaf));
  check("#17 BD-8 a non-Buffer expectedSpki is refused",
    (await codeOf(acme8.downloadCertificate(A.URLS.certificate, { expectedSpki: "nope", identifiers: ORDER_IDS }))) === "acme/bad-input");
  check("#17 BD-8 an empty identifier array is refused",
    (await codeOf(acme8.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: [] }))) === "acme/bad-input");
  check("#17 BD-8 a non-boolean requireBinding is refused",
    (await codeOf(acme8.downloadCertificate(A.URLS.certificate, { expectedSpki: mine.spki, identifiers: ORDER_IDS, requireBinding: "no" }))) === "acme/bad-input");
}

// ---- 16 alternate-chain selection (RFC 8555 sec. 7.4.2 / RFC 8288 Link) ------
async function testAlternateChains() {
  function toPem(der) { return "-----BEGIN CERTIFICATE-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n+$/, "") + "\n-----END CERTIFICATE-----"; }
  var leafDer = signing.makeSigner("ec-p256", { cn: "leaf.example" }).cert;         // the shared end-entity cert
  var otherLeafDer = signing.makeSigner("ec-p256", { cn: "other-leaf.example" }).cert;
  var rootADer = signing.makeSigner("ec-p256", { cn: "Root CA A" }).cert;
  var rootBDer = signing.makeSigner("ec-p256", { cn: "Root CA B" }).cert;
  var leafPem = toPem(leafDer), rootAPem = toPem(rootADer), rootBPem = toPem(rootBDer), otherLeafPem = toPem(otherLeafDer);
  var primary = [leafPem, rootAPem], altB = [leafPem, rootBPem];
  var ALT0 = A.URLS.certificate + "/alt/0";
  function pickB(c) { return c.certificates[c.certificates.length - 1].equals(rootBDer); }   // DER identity, not a string compare
  function altCalls(s) { return s.calls.filter(function (c) { return new URL(c.url).pathname.indexOf("/cert/1/alt/") === 0; }).length; }

  // AL-1 no Link -> the primary chain, empty alternates.
  var r1 = await (await withAccount(A.acmeServer({ certPems: primary }))).downloadCertificate(A.URLS.certificate, NO_BIND);
  check("#16 AL-1 no Link resolves the primary chain with empty alternates", r1.certificate.equals(leafDer) && r1.alternates.length === 0);

  // AL-2 a well-formed Link is LISTED but not fetched without a predicate.
  var s2 = A.acmeServer({ certPems: primary, alternateChains: [altB] });
  var r2 = await (await withAccount(s2)).downloadCertificate(A.URLS.certificate, NO_BIND);
  check("#16 AL-2 a Link alternate is listed but not fetched", r2.alternates.length === 1 && r2.alternates[0] === ALT0 && altCalls(s2) === 0);

  // AL-3 a predicate selects the CA-B alternate (both cert URLs POST-as-GET'd, same leaf).
  var s3 = A.acmeServer({ certPems: primary, alternateChains: [altB] });
  var r3 = await (await withAccount(s3)).downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: pickB });
  check("#16 AL-3 selectChain picks the CA-B alternate", r3.certificate.equals(leafDer) && r3.certificates[r3.certificates.length - 1].equals(rootBDer) && altCalls(s3) === 1);

  // AL-4 a predicate that matches nothing fails closed.
  var acme4 = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB] }));
  check("#16 AL-4 no matching candidate fails closed", (await codeOf(acme4.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: function () { return false; } }))) === "acme/no-matching-chain");

  // AL-5 rel is a WHOLE-token, case-insensitive match (no substring); the param name folds too.
  async function altCount(link) { return (await (await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: link }))).downloadCertificate(A.URLS.certificate, NO_BIND)).alternates.length; }
  check("#16 AL-5 a multi-token rel matches alternate", (await altCount("<" + ALT0 + ">;rel=\"alternate index\"")) === 1);
  check("#16 AL-5 a substring rel does not match", (await altCount("<" + ALT0 + ">;rel=\"alternateX\"")) === 0 && (await altCount("<" + ALT0 + ">;rel=\"xalternate\"")) === 0);
  check("#16 AL-5 the rel token and param name are case-insensitive", (await altCount("<" + ALT0 + ">;Rel=\"ALTERNATE\"")) === 1);

  // AL-6 a malformed Link fails closed WHEN alternates are requested, is ignored otherwise; http target fails closed.
  var acme6a = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "not-a-link;rel=\"alternate\"" }));
  check("#16 AL-6 a malformed Link with selection fails closed", (await codeOf(acme6a.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: pickB }))) === "acme/bad-link");
  var r6b = await (await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "not-a-link;rel=\"alternate\"" }))).downloadCertificate(A.URLS.certificate, NO_BIND);
  check("#16 AL-6 a malformed Link without selection is ignored", r6b.certificate.equals(leafDer) && r6b.alternates.length === 0);
  var acme6c = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "<http://acme.example/cert/1/alt/0>;rel=\"alternate\"" }));
  check("#16 AL-6 an http alternate target fails closed", (await codeOf(acme6c.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: pickB }))) === "acme/bad-link");
  // A cross-origin https alternate is an SSRF vector -- an untrusted Link header MUST NOT steer the account-key
  // -signed POST-as-GET to another origin. It fails closed under selection, and is not even listed without one.
  var xLink = "<https://evil.example/cert/1/alt/0>;rel=\"alternate\"";
  var acme6d = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: xLink }));
  check("#16 AL-6 a cross-origin https alternate fails closed under selection", (await codeOf(acme6d.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: pickB }))) === "acme/bad-link");
  var r6e = await (await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: xLink }))).downloadCertificate(A.URLS.certificate, NO_BIND);
  check("#16 AL-6 a cross-origin alternate is not listed without selection", r6e.certificate.equals(leafDer) && r6e.alternates.length === 0);

  // AL-7 the alternate-fetch budget is bounded (CWE-770): 20 advertised, cap 4 -> reject after exactly 4 fetches.
  var many = []; for (var i = 0; i < 20; i++) many.push(altB);
  var s7 = A.acmeServer({ certPems: primary, alternateChains: many });
  var acme7 = await withAccount(s7);
  check("#16 AL-7 the alternate fetch budget is enforced", (await codeOf(acme7.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: function () { return false; }, maxAlternates: 4 }))) === "acme/too-many-alternates");
  check("#16 AL-7 exactly maxAlternates alternates were fetched", altCalls(s7) === 4);

  // AL-8 a fetched alternate inherits every download gate (media type, size).
  var acme8a = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], altContentType: "text/plain" }));
  check("#16 AL-8 a wrong-media-type alternate fails closed", (await codeOf(acme8a.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: function () { return false; } }))) === "acme/bad-certificate-chain");
  var bigRoot = "-----BEGIN CERTIFICATE-----\n" + "A".repeat(2000) + "\n-----END CERTIFICATE-----";
  var acme8b = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, A.acmeServer({ certPems: [leafPem], alternateChains: [[leafPem, bigRoot]] }), { maxResponseBytes: 1200 }));
  await acme8b.newAccount({ termsOfServiceAgreed: true });
  check("#16 AL-8 an oversize alternate is rejected", (await codeOf(acme8b.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: function () { return false; } }))) === "acme/response-too-large");

  // AL-9 same-leaf invariant, URL dedup, predicate-throw propagation.
  var acme9a = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [[otherLeafPem, rootBPem]] }));
  check("#16 AL-9 an alternate with a different leaf is rejected", (await codeOf(acme9a.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: function () { return false; } }))) === "acme/bad-alternate");
  var s9b = A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "<" + ALT0 + ">;rel=\"alternate\", <" + ALT0 + ">;rel=\"alternate\"" });
  var r9b = await (await withAccount(s9b)).downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: pickB });
  check("#16 AL-9 a duplicate alternate URL is fetched once", r9b.certificates[r9b.certificates.length - 1].equals(rootBDer) && altCalls(s9b) === 1);
  var acme9c = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB] }));
  check("#16 AL-9 a throwing selectChain propagates (not swallowed)", (await codeOf(acme9c.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: function () { throw new Error("boom"); } }))) === "RAW:boom");

  // AL-10 both header shapes parse: node's comma-joined string AND an injected array of Link values.
  var joined = "<" + A.URLS.certificate + "/alt/0>;rel=\"alternate\", <" + A.URLS.certificate + "/alt/1>;rel=\"alternate\"";
  var r10a = await (await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB, altB], certLinkHeader: joined }))).downloadCertificate(A.URLS.certificate, NO_BIND);
  check("#16 AL-10 a comma-joined Link string parses both alternates", r10a.alternates.length === 2);
  var arr = ["<" + A.URLS.certificate + "/alt/0>;rel=\"alternate\"", "<" + A.URLS.certificate + "/alt/1>;rel=\"alternate\""];
  var r10b = await (await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB, altB], certLinkHeader: arr }))).downloadCertificate(A.URLS.certificate, NO_BIND);
  check("#16 AL-10 an array of Link headers parses both alternates", r10b.alternates.length === 2);

  // AL-11 RFC 8288 tokenizer edges: a comma or semicolon inside a quoted param value is not a separator; a
  // bare (value-less) param and a trailing comma are tolerated; all still parse to the single alternate.
  check("#16 AL-11 a comma inside a quoted param is not a separator", (await altCount("<" + ALT0 + ">;title=\"a,b\";rel=\"alternate\"")) === 1);
  check("#16 AL-11 a semicolon inside a quoted param is not a separator", (await altCount("<" + ALT0 + ">;title=\"a;b\";rel=\"alternate\"")) === 1);
  check("#16 AL-11 a trailing comma is tolerated (empty link-value skipped)", (await altCount("<" + ALT0 + ">;rel=\"alternate\",")) === 1);
  check("#16 AL-11 a backslash-escaped quote inside a param value is handled", (await altCount("<" + ALT0 + ">;title=\"a\\\"b\";rel=\"alternate\"")) === 1);

  // AL-11b a certificate response with NO content-type (a non-conforming server) fails the media-type gate.
  var acme11b = await withAccount(A.acmeServer({ certPems: primary, certNoContentType: true }));
  check("#16 AL-11 a missing content-type on the chain fails closed", (await codeOf(acme11b.downloadCertificate(A.URLS.certificate, NO_BIND))) === "acme/bad-certificate-chain");

  // AL-12 malformed-header edges fail closed under selection: an unterminated quote, and an over-cap header.
  function codeForLink(link) { return withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: link })).then(function (a) { return codeOf(a.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: pickB })); }); }
  check("#16 AL-12 an unterminated quote fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate")) === "acme/bad-link");
  check("#16 AL-12 an over-cap Link header fails closed", (await codeForLink("<" + ALT0 + ">;title=\"" + "a".repeat(8300) + "\";rel=\"alternate\"")) === "acme/bad-link");

  // AL-13 selectChain must be a function; a predicate that accepts the PRIMARY returns it without fetching an alternate.
  var acme13 = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB] }));
  check("#16 AL-13 a non-function selectChain is rejected", (await codeOf(acme13.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: 5 }))) === "acme/bad-input");
  var s13 = A.acmeServer({ certPems: primary, alternateChains: [altB] });
  var r13 = await (await withAccount(s13)).downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: function () { return true; } });
  check("#16 AL-13 a predicate accepting the primary skips the alternate fetch", r13.certificate.equals(leafDer) && altCalls(s13) === 0);

  // AL-14 the Link header size cap is AGGREGATE, not per-field: an array of fields each under the per-field
  // size but summing over the cap fails closed (CWE-770 -- a duplicate/injected Link array cannot amplify).
  var bigField = "<" + ALT0 + ">;rel=\"alternate\";title=\"" + "a".repeat(5000) + "\"";
  var acme14 = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: [bigField, bigField] }));
  check("#16 AL-14 the Link header cap is aggregate across fields", (await codeOf(acme14.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: pickB }))) === "acme/bad-link");

  // AL-15 a Link parameter not introduced by ';' (RFC 8288: <URI> *(";" param)) is malformed -> fails closed.
  var acme15 = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "<" + ALT0 + ">rel=\"alternate\"" }));
  check("#16 AL-15 a Link param not preceded by a semicolon fails closed", (await codeOf(acme15.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: pickB }))) === "acme/bad-link");

  // AL-16 an UNQUOTED param value must be a single token (RFC 8288 / RFC 7230): whitespace in an unquoted rel
  // (rel=alternate garbage) is malformed and MUST NOT be split-and-matched -- a quoted list is the valid form.
  var acme16 = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "<" + ALT0 + ">;rel=alternate garbage" }));
  check("#16 AL-16 whitespace in an unquoted param value fails closed", (await codeOf(acme16.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: pickB }))) === "acme/bad-link");
  check("#16 AL-16 a well-formed UNQUOTED rel token still matches", (await altCount("<" + ALT0 + ">;rel=alternate")) === 1);

  // AL-17 the primary is evaluated BEFORE a malformed Link is rejected: if selectChain accepts the primary, a
  // malformed alternate Link (which is never needed) does not fail the download.
  var s17 = A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "not-a-link;rel=\"alternate\"" });
  var r17 = await (await withAccount(s17)).downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: function () { return true; } });
  check("#16 AL-17 a matching primary is returned despite a malformed Link", r17.certificate.equals(leafDer) && altCalls(s17) === 0);

  // AL-18 empty Link fields count toward the aggregate cap: a huge array of empty fields cannot amplify parse work.
  var empties = []; for (var e18 = 0; e18 < 10000; e18++) empties.push("");
  var acme18 = await withAccount(A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: empties }));
  check("#16 AL-18 many empty Link fields hit the aggregate cap", (await codeOf(acme18.downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: function () { return false; } }))) === "acme/bad-link");

  // AL-19 a relative Link URI carrying whitespace that URL parsing would REPAIR is rejected, not silently
  // resolved (RFC 3986: a URI-reference has no raw whitespace) -- mirrors the client's own URL canonicality gate.
  check("#16 AL-19 a Link URI with repairable whitespace fails closed", (await codeForLink("< /cert/1/alt/0>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-20 a Link parameter NAME must be a token too (RFC 8288 / RFC 7230): whitespace in a name is malformed.
  check("#16 AL-20 whitespace in a Link parameter name fails closed", (await codeForLink("<" + ALT0 + ">;bad name=x;rel=\"alternate\"")) === "acme/bad-link");
  // AL-21 a relative URI carrying any non-RFC-3986 character that URL parsing would percent-encode/repair (not
  // just whitespace) is rejected before resolution -- e.g. an unencoded brace.
  check("#16 AL-21 a relative Link URI with an invalid RFC 3986 char fails closed", (await codeForLink("</cert/1/alt/0{x}>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-22 a malformed percent-escape (% not followed by two hex digits) is not valid RFC 3986 pct-encoding.
  check("#16 AL-22 a malformed percent-escape in a Link URI fails closed", (await codeForLink("</cert/%ZZ>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-23 a control octet anywhere in the Link header (even inside a quoted param) is not a valid field-value.
  var ctlHeader = "<" + ALT0 + ">;title=\"" + String.fromCharCode(1) + "\";rel=\"alternate\"";
  check("#16 AL-23 a control octet in a Link header fails closed", (await codeForLink(ctlHeader)) === "acme/bad-link");
  // AL-24 a percent-encoded dot-segment (%2e%2e) in a relative URI would be DECODED and resolved into a path
  // traversal by URL parsing, changing the target -- reject it (the absolute path hits _clientUrl's own gate).
  check("#16 AL-24 a percent-encoded dot-segment in a relative Link URI fails closed", (await codeForLink("</cert/%2e%2e/alt/0>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-25 an encoded dot that is NOT a whole dot-segment (e.g. a filename 0%2ex == 0.x) is a valid target and
  // must NOT be rejected -- only a segment that decodes to "." or ".." is a traversal.
  check("#16 AL-25 an encoded dot outside a dot-segment is allowed", (await altCount("</cert/1/alt/0%2ex>;rel=\"alternate\"")) === 1);
  // AL-26 a quoted value must be a WELL-FORMED quoted-string (RFC 7230): an unescaped interior quote (a""b) or a
  // dangling backslash is malformed, not merely first/last-char-is-a-quote.
  check("#16 AL-26 a malformed quoted Link value fails closed", (await codeForLink("<" + ALT0 + ">;title=\"a\"\"b\";rel=\"alternate\"")) === "acme/bad-link");
  // AL-27 a valueless extension parameter (a bare token, no '=') is VALID per RFC 8288 (link-param has an
  // optional value) -- it is tolerated (ignored), not rejected, so the alternate is still found.
  check("#16 AL-27 a valueless Link extension parameter is permitted", (await altCount("<" + ALT0 + ">;rel=\"alternate\";flag")) === 1);
  // AL-28 an empty UNQUOTED value (foo=) is not a token (RFC 9110 sec. 5.6.6); an empty value must be quoted (foo="").
  check("#16 AL-28 an empty unquoted Link parameter value fails closed", (await codeForLink("<" + ALT0 + ">;foo=;rel=\"alternate\"")) === "acme/bad-link");
  // AL-29 the rel relation-type list is SPACE-separated (RFC 8288 sec. 3.3), not tab: a tab-joined value is a
  // SINGLE relation-type "alternate<TAB>index" -- which contains a tab, so it is not a valid relation-type and
  // the list is malformed (it does not match alternate and fails closed).
  var tabRel = "<" + ALT0 + ">;rel=\"alternate" + String.fromCharCode(9) + "index\"";
  check("#16 AL-29 a tab in a quoted rel is not a list separator", (await codeForLink(tabRel)) === "acme/bad-link");
  // AL-30 an empty parameter (a `;` with no parameter, e.g. `;;`) is malformed (RFC 8288 requires a link-param
  // after each `;`) -- reject it rather than silently skip the empty slot.
  check("#16 AL-30 an empty Link parameter (;;) fails closed", (await codeForLink("<" + ALT0 + ">;;rel=\"alternate\"")) === "acme/bad-link");

  // AL-31 an ASYNC selectChain (returns a Promise) is awaited, not treated as always-truthy.
  var s31 = A.acmeServer({ certPems: primary, alternateChains: [altB] });
  var r31 = await (await withAccount(s31)).downloadCertificate(A.URLS.certificate, { requireBinding: false, selectChain: async function (c) { return c.certificates[c.certificates.length - 1].equals(rootBDer); } });
  check("#16 AL-31 an async selectChain is awaited", r31.certificates[r31.certificates.length - 1].equals(rootBDer) && r31.certificate.equals(leafDer));

  // AL-32 a rel="alternate" link with an anchor param has a DIFFERENT context (RFC 8288 sec. 3.2): anchored to
  // another resource it is not a cert alternate (skipped); anchored to the certificate URL it is kept.
  check("#16 AL-32 an alternate anchored elsewhere is not a cert alternate", (await altCount("<" + ALT0 + ">;rel=\"alternate\";anchor=\"https://acme.example/other\"")) === 0);
  check("#16 AL-32 an alternate anchored to the certificate URL is kept", (await altCount("<" + ALT0 + ">;rel=\"alternate\";anchor=\"" + A.URLS.certificate + "\"")) === 1);
  // AL-32 an anchor that does not resolve to a URL cannot be our context -> skip (conservative).
  check("#16 AL-32 an unresolvable anchor is skipped", (await altCount("<" + ALT0 + ">;rel=\"alternate\";anchor=\"http://\"")) === 0);
  // AL-32 the RAW anchor is validated with the same RFC 3986 rules as the target: an encoded dot-segment anchor
  // that would traverse to the certificate URL cannot spoof a context match -- it is skipped, not kept.
  check("#16 AL-32 an anchor with an encoded dot-segment cannot spoof the context", (await altCount("<" + ALT0 + ">;rel=\"alternate\";anchor=\"/cert/x/%2e%2e/1\"")) === 0);
  // AL-33 a rel relation-type list is single-space-separated with no leading/trailing/repeated space (RFC 8288
  // sec. 3.3): "alternate " (trailing space) is malformed and must not be split-and-matched.
  check("#16 AL-33 a rel with a trailing space fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate \"")) === "acme/bad-link");
  // AL-34 the anchor parameter is URI-valued (RFC 8288 sec. 3.2): unlike a generic extension param, a VALUELESS
  // anchor is malformed (an empty anchor would resolve to the certificate URL and spoof a context match).
  check("#16 AL-34 a valueless anchor parameter fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate\";anchor")) === "acme/bad-link");
  // AL-35 the FIRST rel occurrence wins even when empty (RFC 8288 sec. 3.3): rel="";rel=alternate keeps the empty
  // first value, which is a malformed (zero-type) rel and fails closed -- it is NOT matched via the later alternate.
  check("#16 AL-35 an empty first rel value fails closed, not matched via a later rel", (await codeForLink("<" + ALT0 + ">;rel=\"\";rel=alternate")) === "acme/bad-link");
  // AL-36 an explicitly empty anchor URI-reference (anchor="") is valid -- it resolves to the context (the cert
  // URL) -- so the alternate is kept (distinct from a VALUELESS anchor with no '=' which is malformed).
  check("#16 AL-36 an explicitly empty anchor URI-reference is permitted", (await altCount("<" + ALT0 + ">;rel=\"alternate\";anchor=\"\"")) === 1);
  // AL-37 multiple spaces between relation types are allowed (RFC 8288 sec. 3.3 separator is 1*SP): "alternate
  // <SP><SP>index" still matches alternate; only a LEADING/TRAILING space is malformed (AL-33).
  check("#16 AL-37 multiple spaces between relation types are allowed", (await altCount("<" + ALT0 + ">;rel=\"alternate  index\"")) === 1);
  // AL-38 only HTTP OWS (SP / HTAB) is trimmed, not arbitrary Unicode whitespace: a non-breaking space (obs-text
  // U+00A0) before a parameter name is part of the (non-token) name, not stripped -> the parameter is malformed.
  check("#16 AL-38 a non-breaking space is not trimmed as OWS", (await codeForLink("<" + ALT0 + ">;" + String.fromCharCode(0xA0) + "rel=\"alternate\"")) === "acme/bad-link");
  // AL-39 EVERY relation-type in the list must be well-formed (RFC 8288 sec. 3.3 reg-rel-type / ext-rel-type):
  // "alternate @" contains an invalid token (@) -- the whole list is malformed, not a valid alternate.
  check("#16 AL-39 an invalid relation-type token fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate @\"")) === "acme/bad-link");
  // AL-40 an ext-rel-type (URI) relation-type is validated in FULL, not just its scheme: "http:%ZZ" has a scheme
  // but a malformed percent-escape, so it is not a valid URI relation-type and the list fails closed.
  check("#16 AL-40 a malformed URI relation-type fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http:%ZZ\"")) === "acme/bad-link");
  // AL-41 an ext-rel-type URI is PARSED in full (not just char-checked): "http://[" has only valid characters but
  // is a structurally invalid URL, so it is not a valid relation-type and the list fails closed.
  check("#16 AL-41 a structurally invalid URI relation-type fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http://[\"")) === "acme/bad-link");
  // AL-41 a well-formed ext-rel-type URI alongside alternate is accepted (the list is valid, alternate matches).
  check("#16 AL-41 a valid URI relation-type alongside alternate is accepted", (await altCount("<" + ALT0 + ">;rel=\"alternate https://example.com/rel\"")) === 1);
  // AL-42 a relation-type URI is validated by RFC 3986 grammar, NOT fetch-target normalization: an encoded dot
  // (%2e, a legal identifier char, not a resolved dot-segment) is accepted, so the alternate remains usable.
  check("#16 AL-42 a percent-encoded dot in a relation-type URI is accepted", (await altCount("<" + ALT0 + ">;rel=\"alternate https://relations.example/%2e%2e/chain\"")) === 1);
  // AL-43 an IPvFuture host is a valid RFC 3986 relation-type URI (WHATWG would reject it), and is accepted.
  check("#16 AL-43 an IPvFuture relation-type URI is accepted", (await altCount("<" + ALT0 + ">;rel=\"alternate http://[v1.a]/\"")) === 1);
  // AL-44 a TARGET (fetched) URI must not carry a bracket outside an authority IP-literal (a cert URL never uses
  // one): "/cert/[alt]" is structurally invalid and WHATWG would percent-encode it, so it fails closed.
  check("#16 AL-44 a bracket in a target URI path fails closed", (await codeForLink("</cert/[alt]>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-45 an ext-rel-type with an empty IP-literal authority ("http://[]") is a structurally invalid URI (a
  // balance-only check would accept it), so it fails closed.
  check("#16 AL-45 an empty IP-literal relation-type authority fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http://[]\"")) === "acme/bad-link");
  // AL-46 an ext-rel-type with a non-numeric port ("http://host:bad") is a structurally invalid URI, so it fails closed.
  check("#16 AL-46 a bad-port relation-type authority fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http://host:bad\"")) === "acme/bad-link");
  // AL-47 a same-origin IPv6-literal TARGET authority is valid (a bracket is legal in an authority, only invalid
  // in a path): an IPv6-hosted cert URL advertising a same-origin IPv6 alternate resolves it.
  var s47 = A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "<https://[2001:db8::1]/cert/1/alt/0>;rel=\"alternate\"" });
  var r47 = await (await withAccount(s47)).downloadCertificate("https://[2001:db8::1]/cert/1", { requireBinding: false, selectChain: pickB });
  check("#16 AL-47 a same-origin IPv6 target authority resolves the alternate", r47.certificates[r47.certificates.length - 1].equals(rootBDer));
  // AL-48 a valid authority IP-literal does not license a bracket elsewhere: "https://[::1]/cert/[alt]" carries a
  // stray bracket in the path and fails closed.
  check("#16 AL-48 a bracket in the path past a valid IP-literal authority fails closed", (await codeForLink("<https://[2001:db8::1]/cert/[alt]>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-49 a bracket outside an authority is invalid even for a scheme WHATWG parses leniently: "urn:[" has an
  // opaque part with a stray bracket (URL.canParse accepts it), so the ext-rel-type fails closed.
  check("#16 AL-49 a bracket in an opaque-scheme relation-type fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate urn:[\"")) === "acme/bad-link");
  // AL-50 an IPvFuture version marker is case-insensitive (RFC 5234 ABNF literal): "[V1.a]" is as valid as "[v1.a]".
  check("#16 AL-50 an uppercase-V IPvFuture relation-type URI is accepted", (await altCount("<" + ALT0 + ">;rel=\"alternate http://[V1.a]/\"")) === 1);
  // AL-51 a SEPARATE link-value carrying an empty rel fails the whole field closed (not silently skipped so a
  // later valid alternate is used): a malformed value is a hard reject.
  check("#16 AL-51 a separate link-value with an empty rel fails closed", (await codeForLink("<https://acme.example/bad>;rel=\"\", <" + ALT0 + ">;rel=alternate")) === "acme/bad-link");
  // AL-52 an ext-rel-type authority with two "@" is invalid RFC 3986 (WHATWG would accept it while rewriting the
  // first "@"); it fails closed rather than being passed by canParse's repair.
  check("#16 AL-52 a double-@ authority relation-type URI fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http://a@b@host/\"")) === "acme/bad-link");
  // AL-53 a scheme-relative (network-path) reference with an IP-literal authority ("//[2001:db8::1]/...", RFC 3986
  // sec. 4.2) is a valid same-origin alternate against an IPv6-hosted cert, and resolves.
  var s53 = A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "<//[2001:db8::1]/cert/1/alt/0>;rel=\"alternate\"" });
  var r53 = await (await withAccount(s53)).downloadCertificate("https://[2001:db8::1]/cert/1", { requireBinding: false, selectChain: pickB });
  check("#16 AL-53 a scheme-relative IPv6-authority alternate resolves", r53.certificates[r53.certificates.length - 1].equals(rootBDer));
  // AL-54 a reference with an EMPTY authority ("////acme.example/..." or "///x") fails closed: WHATWG would repair
  // it by promoting a path segment to the host (here back to the cert's own origin), so a malformed raw reference
  // must not be accepted just because its repaired form happens to pass the same-origin gate.
  check("#16 AL-54 an empty-authority (////) target fails closed", (await codeForLink("<////acme.example/cert/alt>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-55 the double-@ authority reject applies to a fetched TARGET too, not only an ext-rel-type: a target such
  // as "https://a@b@acme.example/cert/alt" (WHATWG repairs to the same origin) fails closed before any fetch.
  check("#16 AL-55 a double-@ target authority fails closed", (await codeForLink("<https://a@b@acme.example/cert/alt>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-56 a URI carries at most one "#" (a fragment cannot contain "#", RFC 3986 sec. 3.5); a second "#" is
  // invalid, which WHATWG accepts by folding it into the fragment. An ext-rel-type "urn:x#y#z" fails closed.
  check("#16 AL-56 a repeated fragment delimiter in a relation-type URI fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate urn:x#y#z\"")) === "acme/bad-link");
  // AL-57 the same repeated-"#" reject applies to a fetched TARGET too (swept to both, not only the ext-rel-type).
  check("#16 AL-57 a repeated fragment delimiter in a target URI fails closed", (await codeForLink("<https://acme.example/cert/alt#y#z>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-58 the empty-authority reject (shared with the target) also covers an ext-rel-type: "http:///relations"
  // has an empty authority WHATWG repairs by promoting the path segment to the host, so it fails closed.
  check("#16 AL-58 an empty-authority relation-type URI fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http:///relations.example\"")) === "acme/bad-link");
  // AL-59 an alternate target that is a valid RFC 3986 reference but not a canonical ACME URL (an empty fragment
  // "...alt#" -- unusable because the "#" is dropped from the request yet retained in the signed JWS url) is SKIPPED,
  // not fatal: a second valid alternate in the same header still resolves (RFC 8555 sec. 7.4.2 permits several).
  check("#16 AL-59 a non-canonical (empty-fragment) alternate is skipped, others kept", (await altCount("<https://acme.example/cert/alt#>;rel=\"alternate\", <" + ALT0 + ">;rel=\"alternate\"")) === 1);
  // AL-60 the same for an empty query ("...alt?"): the non-canonical alternate is skipped, the valid one survives.
  check("#16 AL-60 a non-canonical (empty-query) alternate is skipped, others kept", (await altCount("<https://acme.example/cert/alt?>;rel=\"alternate\", <" + ALT0 + ">;rel=\"alternate\"")) === 1);
  // AL-63 a raw "[" / "]" in userinfo is NOT permitted (RFC 3986 sec. 3.2.1/3.2.2 -- brackets only in the IP-literal
  // host); "a[b@[::1]" (WHATWG repairs to "a%5Bb@[::1]") is a structural violation and fails closed.
  check("#16 AL-63 a bracket in userinfo before an IP-literal host fails closed", (await codeForLink("<https://a[b@[::1]/cert>;rel=\"alternate\"")) === "acme/bad-link");
  check("#16 AL-63 the same bracket-in-userinfo reject applies to an ext-rel-type", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http://a[b@[::1]/\"")) === "acme/bad-link");
  // AL-64 a relative-path reference whose first segment carries a ":" is a path-noscheme violation (RFC 3986 sec.
  // 4.2), which WHATWG resolves against the base as same-origin; ":foo" fails closed.
  check("#16 AL-64 a colon in a relative-ref first segment fails closed", (await codeForLink("<:foo>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-65 an absolute alternate carrying literal dot-segments is a valid RFC 3986 URI but not a canonical ACME
  // request URL (WHATWG applies remove_dot_segments), so it is SKIPPED, keeping a co-advertised valid alternate --
  // rather than the old behavior where one non-canonical absolute alternate discarded ALL of them.
  check("#16 AL-65 a dot-segment absolute alternate is skipped, others kept", (await altCount("<https://acme.example/cert/1/../bad>;rel=\"alternate\", <" + ALT0 + ">;rel=\"alternate\"")) === 1);
  // AL-66 same for an apostrophe (a valid RFC 3986 sub-delim WHATWG re-encodes to %27 in a special-scheme query).
  check("#16 AL-66 an apostrophe-query absolute alternate is skipped, others kept", (await altCount("<https://acme.example/cert/1?x='1>;rel=\"alternate\", <" + ALT0 + ">;rel=\"alternate\"")) === 1);
  // AL-61 an empty authority is VALID for a scheme that permits one: an ext-rel-type "file:///relations/chain" is
  // accepted (unlike an http/https/scheme-relative authority, whose empty form WHATWG repairs to a host).
  check("#16 AL-61 a file:/// relation-type URI (valid empty authority) is accepted", (await altCount("<" + ALT0 + ">;rel=\"alternate file:///relations/chain\"")) === 1);
  // AL-62 RFC 3986 permits userinfo before an IP-literal / IPvFuture host: an ext-rel-type "http://user@[v1.a]/"
  // is a valid relation URI and is accepted.
  check("#16 AL-62 userinfo before an IPvFuture relation host is accepted", (await altCount("<" + ALT0 + ">;rel=\"alternate http://user@[v1.a]/\"")) === 1);
  // AL-67 two equivalent spellings of the same alternate (an uppercase host + explicit :443 vs the canonical form)
  // collapse to ONE fetch: dedup is by the WHATWG-normalized href, not the verbatim string (CWE-770 amplification).
  check("#16 AL-67 equivalent-spelling alternates are de-duplicated by normalized href", (await altCount("<" + ALT0 + ">;rel=\"alternate\", <https://ACME.EXAMPLE:443/cert/1/alt/0>;rel=\"alternate\"")) === 1);
  // AL-68 a percent-encoded unreserved char is equivalent (RFC 3986 sec. 6.2.2.2: "%61" == "a"), so "/alt" and
  // "/%61lt" de-duplicate to a single fetch too.
  check("#16 AL-68 an unreserved percent-escape is normalized for dedup", (await altCount("<" + ALT0 + ">;rel=\"alternate\", <https://acme.example/cert/1/%61lt/0>;rel=\"alternate\"")) === 1);
  // AL-68 a RESERVED escape is not decoded but its hex is case-normalized (RFC 3986 sec. 6.2.2.1): "%2f" and "%2F"
  // (both an encoded "/") are the same target and de-duplicate to one fetch.
  check("#16 AL-68 a reserved percent-escape is case-normalized for dedup", (await altCount("<https://acme.example/cert/1/alt%2f0>;rel=\"alternate\", <https://acme.example/cert/1/alt%2F0>;rel=\"alternate\"")) === 1);
  // AL-69 a RELATIVE alternate whose query WHATWG re-encodes on resolution (an apostrophe -> %27) is non-canonical
  // just like the absolute form, so it is SKIPPED (not silently resolved to the repaired query), keeping a valid one.
  check("#16 AL-69 a relative alternate with a re-encoded query is skipped, others kept", (await altCount("<alt/x?y='1>;rel=\"alternate\", <" + ALT0 + ">;rel=\"alternate\"")) === 1);
  // AL-70 the PRIMARY certificate URL advertised as a rel="alternate" (it is not an alternate of itself) is
  // de-duplicated against the download URL, so it is not collected + redundantly re-fetched.
  check("#16 AL-70 the primary URL advertised as an alternate is skipped", (await altCount("</cert/1>;rel=\"alternate\", <" + ALT0 + ">;rel=\"alternate\"")) === 1);
  // AL-71 an ext-rel-type identifier port is RFC 3986 *DIGIT (no 16-bit range limit -- it is never connected to),
  // so ":65536" is accepted, while a non-numeric port (":bad") is still rejected.
  check("#16 AL-71 an out-of-range port in a relation-type URI is accepted", (await altCount("<" + ALT0 + ">;rel=\"alternate http://relations.example:65536/type\"")) === 1);
  check("#16 AL-71 a non-numeric port in a relation-type URI is still rejected", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http://relations.example:bad/type\"")) === "acme/bad-link");
  // AL-72 a fetched TARGET keeps WHATWG's 16-bit port range (it is connected to over TCP): a target port ">65535"
  // is not usable and is skipped (not signed).
  check("#16 AL-72 an out-of-range port in a target URI is skipped", (await altCount("<https://acme.example:65536/cert/1/alt/0>;rel=\"alternate\", <" + ALT0 + ">;rel=\"alternate\"")) === 1);
  // AL-73 a numeric dotted reg-name in an ext-rel-type is a valid RFC 3986 reg-name (WHATWG mis-coerces it to an
  // invalid IPv4 literal): "1.2.3.4.5" is accepted, while an empty/invalid IP-literal host stays rejected.
  check("#16 AL-73 an IPv4-shaped reg-name in a relation-type URI is accepted", (await altCount("<" + ALT0 + ">;rel=\"alternate http://1.2.3.4.5/type\"")) === 1);
  check("#16 AL-73 an empty IP-literal host in a relation-type URI is still rejected", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http://[]/type\"")) === "acme/bad-link");
  // AL-74 an anchor whose query WHATWG re-encodes ("?x='" -> "?x=%27") must NOT spoof a context match against a
  // download URL that already carries the encoded form -- "'" is a reserved sub-delim, not equal to its escape
  // (RFC 3986 sec. 6.2.2.2), so the resolution repaired it and the anchor is an unreliable context (skipped).
  var s74 = A.acmeServer({ certPems: primary, alternateChains: [altB], certLinkHeader: "<" + ALT0 + ">;rel=\"alternate\";anchor=\"?x='\"" });
  var r74 = await (await withAccount(s74)).downloadCertificate("https://acme.example/cert/1?x=%27", NO_BIND);
  check("#16 AL-74 a re-encoded-query anchor does not spoof the certificate context", r74.alternates.length === 0);
  // AL-75 a non-numeric port ("host:bad") is malformed (RFC 3986 port = *DIGIT), not merely non-canonical, so a
  // target carrying one FAILS the whole header closed (a structural reject before resolution), not skipped.
  check("#16 AL-75 a malformed-port target fails closed", (await codeForLink("<https://acme.example:bad/cert>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-76 an IP-literal host must CONTAIN a valid IPv6/IPvFuture (RFC 3986 sec. 3.2.2); "[not-ip]" is malformed, not
  // merely non-canonical, so a target carrying one fails the header closed (structural reject before resolution).
  check("#16 AL-76 a malformed IP-literal target fails closed", (await codeForLink("<https://[not-ip]/cert>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-76 a valid IPv6 relation-type host is still accepted, and a malformed one is rejected (the same content check).
  check("#16 AL-76 a malformed IP-literal relation-type URI is rejected", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http://[not-ip]/x\"")) === "acme/bad-link");
  // AL-77 an ext-rel-type is validated by RFC 3986 GRAMMAR, not WHATWG: an empty reg-name authority ("foo://user@/")
  // is valid (reg-name = *(...), zero chars allowed), so it is accepted where WHATWG's special-scheme parse rejects it.
  check("#16 AL-77 an empty reg-name authority relation-type URI is accepted", (await altCount("<" + ALT0 + ">;rel=\"alternate foo://user@/type\"")) === 1);
  // AL-78 an IP-literal HOST must be followed only by a port or a path/query/fragment delimiter: "[::1]@acme.example"
  // (an IP-literal followed by "@host") is malformed (WHATWG re-parses to a different host) and fails closed.
  check("#16 AL-78 an IP-literal followed by authority text fails closed", (await codeForLink("<https://[::1]@acme.example/cert/alt>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-79 a DUPLICATE anchor is ambiguous (anchor is not an RFC 8288 sec. 3.3 singleton), and since anchor sets the
  // context it fails closed rather than silently taking the first.
  check("#16 AL-79 a duplicate anchor parameter fails closed", (await codeForLink("<" + ALT0 + ">;rel=\"alternate\";anchor=\"\";anchor=\"https://other.example/\"")) === "acme/bad-link");
  // AL-80 an empty HOST after userinfo or before a port ("https://user@/x", "https://:443/x") is an empty authority
  // for a special scheme -- not caught by looking only at the char after "//" -- and fails closed.
  check("#16 AL-80 an empty host after userinfo fails closed", (await codeForLink("<https://user@/bad>;rel=\"alternate\"")) === "acme/bad-link");
  check("#16 AL-80 an empty host before a port fails closed", (await codeForLink("<https://:443/bad>;rel=\"alternate\"")) === "acme/bad-link");
  // AL-81 an alternate TARGET with userinfo is not signed/fetched (ACME URLs have no userinfo; a signed url with it
  // would not match the request, RFC 8555 sec. 6.4) -- it is skipped, a co-advertised valid alternate survives.
  check("#16 AL-81 an alternate target with userinfo is skipped", (await altCount("<https://user@acme.example/cert/1/alt/0>;rel=\"alternate\", <" + ALT0 + ">;rel=\"alternate\"")) === 1);
  // AL-82 a bracketed userinfo disguised as an IP host ("[::1]:80@relations.example", where "[::1]:80" is userinfo
  // and "relations.example" the real host) fails closed: after an IP-literal host, only an optional ":port" may
  // follow, never "@" -- else the literal is in userinfo position, which RFC 3986 forbids.
  check("#16 AL-82 a bracketed userinfo before the real host fails closed (relation-type)", (await codeForLink("<" + ALT0 + ">;rel=\"alternate http://[::1]:80@relations.example/type\"")) === "acme/bad-link");
  check("#16 AL-82 the same bracketed-userinfo reject applies to a target", (await codeForLink("<http://[::1]:80@acme.example/cert>;rel=\"alternate\"")) === "acme/bad-link");
}

async function main() {
  await setup();
  await testHappyFlow();
  await testNewAuthz();
  await testRenewalWindow();
  await testAlternateChains();
  await testIssuedCertificateBinding();
  await testRemainingVerbs();
  await testRenewalInfo();
  await testOversized();
  await testByteSourceBody();
  await testAuditHardening();
  await testReviewHardening();
  await testReadyAndRelativeRedirect();
  await testFinalize();
  await testBadNonceRetry();
  await testBadNonceStorm();
  await testProblemSurfaced();
  await testFailClosedGates();
  await testPolling();
  await testUniformRejection();
  console.log("CHECKS " + helpers.getChecks());
}

// ---- every client verb REJECTS on bad input; none throws synchronously ------
//
// The rule was already written in this module three times and applied to four of its thirteen
// verbs. The shape it guards is not only a caller typo: the message layer deliberately accepts
// http as well as https, so a CA can return an order whose `authorizations` array carries an http
// URL, that order validates, and the very next step -- getAuthorization(order.authorizations[0])
// -- threw out of the middle of an async ACME loop instead of rejecting into the handler the
// caller already had around it.
async function testUniformRejection() {
  var s = A.acmeServer({ orderStates: ["pending"] });
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s));
  var HTTP = "http://acme.test/authz/1";                       // passes _isUrl, refused by _clientUrl
  var verbs = [
    ["getOrder", function () { return acme.getOrder(HTTP); }],
    ["getAuthorization", function () { return acme.getAuthorization(HTTP); }],
    ["getChallenge", function () { return acme.getChallenge(HTTP); }],
    ["respondToChallenge", function () { return acme.respondToChallenge(HTTP); }],
    ["deactivateAuthorization", function () { return acme.deactivateAuthorization(HTTP); }],
    ["finalize", function () { return acme.finalize({}); }],
    ["keyChange", function () { return acme.keyChange({}); }],
    ["renewalInfo", function () { return acme.renewalInfo("not-a-buffer"); }],
    ["pollOrder", function () { return acme.pollOrder(HTTP); }],
    ["downloadCertificate", function () { return acme.downloadCertificate(HTTP); }],
    ["revokeCert", function () { return acme.revokeCert({}); }],
    ["newAuthz", function () { return acme.newAuthz({ type: "dns", value: "*.example.org" }); }],
  ];
  var sync = [];
  for (var i = 0; i < verbs.length; i++) {
    var ret;
    try { ret = verbs[i][1](); }
    catch (_e) { sync.push(verbs[i][0]); continue; }
    if (ret && typeof ret.then === "function") {
      try { await ret; } catch (_e2) { /* a rejection is the correct shape; each verb's code is its own */ }
    }
  }
  check("every client verb rejects rather than throwing synchronously" +
    (sync.length ? " -- " + sync.length + " throw: " + sync.join(", ") : ""), sync.length === 0);
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
