// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- forward-proxy threading across the enrollment clients (pki.est.* / pki.acme.client /
// pki.cmp.transfer). The transport-level forward proxy (request.proxy = { url, auth?, tls? }, validated +
// tunneled by http-transport.js) shipped for pki.scep; these vectors prove the SAME opts.proxy reaches the
// shared transport, unchanged, from every other enrollment client. Driven through the SHIPPED consumer path
// over the routing fake transport each client's suite already uses (transport.calls records the request that
// crossed the seam, so calls[i].proxy IS what the client threaded). The proxy's on-wire behavior (CONNECT
// tunnel, Basic-over-https-only, identity checks) is owned by http-transport.test.js; these assert the wiring:
//   1. the client ACCEPTS opts.proxy (it was an unknown option before -- calls.length===0 was the RED state),
//   2. it PASSES proxy on the request options at every request site,
//   3. the value is a deep-copy SNAPSHOT (a mutation of the caller object after the call does not reach it),
//   4. it does NOT bypass the transport's _validateProxy (auth over a plaintext http proxy is refused).

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var signing = require("../helpers/signing");
var fakeTransport = require("../helpers/fake-transport").fakeTransport;
var acmeH = require("../helpers/acme-transport");
var cmpH = require("../helpers/cmp-transport");
var httpTransport = require("../../lib/http-transport");

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }

// A proxy option carrying every nested shape the snapshot must deep-copy: an auth record and a tls record
// whose anchors is an array holding a Buffer. Built fresh per vector so a post-call mutation is isolated.
function makePX() {
  return { url: "https://proxy.example:8080", auth: { username: "puser", password: "psecret" }, tls: { anchors: [Buffer.from("ANCHORBYTES")] } };
}

// The threaded proxy carries the caller's values (by value)...
function carriesValue(p) {
  return !!p && p.url === "https://proxy.example:8080" &&
    !!p.auth && p.auth.username === "puser" && p.auth.password === "psecret" &&
    !!p.tls && Array.isArray(p.tls.anchors) && p.tls.anchors.length === 1 &&
    Buffer.isBuffer(p.tls.anchors[0]) && p.tls.anchors[0].toString("latin1") === "ANCHORBYTES";
}
// ...but is a DISTINCT object graph from the caller's (a deep-copy snapshot, not an alias).
function isDistinctFrom(p, orig) {
  return !!p && p !== orig && p.auth !== orig.auth && p.tls !== orig.tls &&
    p.tls.anchors !== orig.tls.anchors && p.tls.anchors[0] !== orig.tls.anchors[0];
}

var ANCHOR;   // a real DER cert to satisfy each client's default-transport anchor gate.
var CSR;      // a real PKCS#10 for the est enroll-path verbs.
async function setup() {
  var s = signing.makeSigner("ec-p256", { cn: "anchor.example" });
  ANCHOR = await pki.x509.sign({
    subject: "anchor.example", subjectPublicKey: s.spki,
    notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2044-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true },
  }, { key: s.key });
  var e = signing.makeSigner("ec-p256", { cn: "enroll.example" });
  CSR = await pki.csr.sign({ subject: "enroll.example", subjectPublicKey: e.spki }, { key: e.key });
}

// ---- EST -------------------------------------------------------------------
async function testEst() {
  var BASE = "https://ca.example";
  // 1+2 accept + thread: cacerts (a GET) hands proxy to the transport. The body need not parse -- the request
  // is recorded before the response is read -- so a trivial 200 suffices to capture calls[0].
  var px = makePX();
  var t = fakeTransport({ status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: "" });
  await codeOf(pki.est.cacerts(BASE, { proxy: px, transport: t }));
  check("est cacerts accepts opts.proxy and threads it to the transport", t.calls.length === 1 && carriesValue(t.calls[0].proxy));
  check("est threads a deep-copy snapshot, not the caller object", t.calls.length === 1 && isDistinctFrom(t.calls[0].proxy, px));

  // 3 snapshot isolation against a SYNCHRONOUS post-call mutation (an est verb defers its work through
  // Promise.resolve().then, so the snapshot must be taken in the call frame, not the later microtask):
  // mutate the caller's proxy right after the call returns, before awaiting, and the recorded request keeps
  // the original values. The 302 -> 200 also proves the same snapshot rides the followed redirect.
  var px2 = makePX();
  var t2 = fakeTransport([
    { status: 302, headers: { location: BASE + "/.well-known/est/cacerts", "content-type": "text/plain" }, body: "" },
    { status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: "" },
  ]);
  var pEst = pki.est.cacerts(BASE, { proxy: px2, transport: t2 });
  px2.auth.password = "TAMPERED"; px2.tls.anchors[0][0] = 0;   // synchronous, before the deferred work runs
  await codeOf(pEst);
  check("est reuses the snapshot on the followed redirect (two requests carry proxy)", t2.calls.length === 2 && !!t2.calls[0].proxy && !!t2.calls[1].proxy);
  check("est snapshot is isolated from a synchronous post-call mutation", t2.calls.length === 2 && t2.calls[1].proxy.auth.password === "psecret" && t2.calls[1].proxy.tls.anchors[0].toString("latin1") === "ANCHORBYTES");

  // 3b the same synchronous-mutation isolation on the enroll path (verb -> _enroll -> _client).
  var px3 = makePX();
  var t3 = fakeTransport({ status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: "" });
  var pEnroll = pki.est.simpleenroll(BASE, CSR, { proxy: px3, transport: t3 });
  px3.auth.password = "TAMPERED";
  await codeOf(pEnroll);
  check("est simpleenroll isolates a synchronous post-call mutation", t3.calls.length === 1 && t3.calls[0].proxy.auth.password === "psecret");

  // 4 no validation bypass: over the REAL transport, auth on a plaintext http proxy is refused with the
  // transport's typed code, surfaced under the est namespace.
  check("est does not bypass _validateProxy (auth over an http proxy is refused)",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "http://p.example:3128", auth: { username: "u", password: "p" } } }))) === "est/proxy-auth-requires-tls");
}

// ---- ACME ------------------------------------------------------------------
async function testAcme() {
  var ACCT = await acmeH.makeAccount();
  // 1+2 accept + thread: directory() is a GET to the directory URL; the request records proxy.
  var px = makePX();
  var s = acmeH.acmeServer({});
  var acme = pki.acme.client(acmeH.URLS.directory, acmeH.clientOpts(ACCT, s, { proxy: px }));
  await codeOf(acme.directory());
  check("acme accepts opts.proxy and threads it to the transport", s.calls.length >= 1 && carriesValue(s.calls[0].proxy));
  check("acme threads a deep-copy snapshot, not the caller object", s.calls.length >= 1 && isDistinctFrom(s.calls[0].proxy, px));

  // 3 snapshot isolation: the client snapshots proxy when it is constructed (its budgets are built in the
  // synchronous client() frame), so a mutation after construction cannot reach an in-flight request.
  var px2 = makePX();
  var s2 = acmeH.acmeServer({});
  var acme2 = pki.acme.client(acmeH.URLS.directory, acmeH.clientOpts(ACCT, s2, { proxy: px2 }));
  px2.auth.password = "TAMPERED"; px2.tls.anchors[0][0] = 0;   // after construction, before any request
  await codeOf(acme2.directory());
  check("acme snapshot is isolated from a post-construction caller mutation", s2.calls.length >= 1 && s2.calls[0].proxy.auth.password === "psecret" && s2.calls[0].proxy.tls.anchors[0].toString("latin1") === "ANCHORBYTES");

  // 4 no validation bypass over the real transport.
  var acme3 = pki.acme.client(acmeH.URLS.directory, { accountKey: ACCT.key, accountJwk: ACCT.jwk, alg: "ES256", tls: { anchors: [ANCHOR] }, proxy: { url: "http://p.example:3128", auth: { username: "u", password: "p" } } });
  check("acme does not bypass _validateProxy (auth over an http proxy is refused)",
    (await codeOf(acme3.directory())) === "acme/proxy-auth-requires-tls");
}

// ---- CMP -------------------------------------------------------------------
async function testCmp() {
  var BASE = "https://ca.example/.well-known/cmp";
  var f = await cmpH.makeFixtures(pki);
  // 1+2 accept + thread: transfer is a single POST; the request records proxy.
  var px = makePX();
  var s = cmpH.cmpOpts(cmpH.pkixcmp(200, f.ipDer), { proxy: px });
  await codeOf(pki.cmp.transfer(BASE, f.irDer, s.opts));
  check("cmp transfer accepts opts.proxy and threads it to the transport", s.transport.calls.length === 1 && carriesValue(s.transport.calls[0].proxy));
  check("cmp threads a deep-copy snapshot, not the caller object", s.transport.calls.length === 1 && isDistinctFrom(s.transport.calls[0].proxy, px));

  // 3 snapshot isolation against a SYNCHRONOUS post-call mutation: transfer() runs through
  // guard.async.deferred, which invokes its body in the same synchronous frame, so proxy is snapshotted at
  // call time. Mutate right after the call, before awaiting, and the recorded request keeps the original.
  var px2 = makePX();
  var s2 = cmpH.cmpOpts(cmpH.pkixcmp(200, f.ipDer), { proxy: px2 });
  var pCmp = pki.cmp.transfer(BASE, f.irDer, s2.opts);
  px2.auth.password = "TAMPERED"; px2.tls.anchors[0][0] = 0;   // synchronous, before await
  await codeOf(pCmp);
  check("cmp snapshot is isolated from a synchronous post-call mutation", s2.transport.calls.length === 1 && s2.transport.calls[0].proxy.auth.password === "psecret" && s2.transport.calls[0].proxy.tls.anchors[0].toString("latin1") === "ANCHORBYTES");

  // 4 no validation bypass over the real transport.
  check("cmp does not bypass _validateProxy (auth over an http proxy is refused)",
    (await codeOf(pki.cmp.transfer(BASE, f.irDer, { tls: { anchors: [ANCHOR] }, proxy: { url: "http://p.example:3128", auth: { username: "u", password: "p" } } }))) === "cmp/proxy-auth-requires-tls");
}

// ---- snapshotProxy (the shared deep-copy the clients thread) --------------
function testSnapshotProxy() {
  // A non-object (or null) proxy passes through untouched -- the clients that receive no proxy.
  check("snapshotProxy passes undefined through", httpTransport.snapshotProxy(undefined) === undefined);
  check("snapshotProxy passes a non-object through", httpTransport.snapshotProxy("x") === "x");
  // An auth-only proxy: auth is a distinct copy, no tls.
  var a = { url: "https://p", auth: { username: "u", password: "p" } };
  var sa = httpTransport.snapshotProxy(a);
  check("snapshotProxy copies auth to a distinct object", sa.auth !== a.auth && sa.auth.password === "p" && sa.tls === undefined);
  // A single (non-array) Buffer anchor: copied to a distinct Buffer.
  var one = Buffer.from("A1");
  var t1 = httpTransport.snapshotProxy({ url: "https://p", tls: { anchors: one } });
  check("snapshotProxy copies a single Buffer anchor to a distinct Buffer", t1.tls.anchors !== one && Buffer.isBuffer(t1.tls.anchors) && t1.tls.anchors.toString("latin1") === "A1");
  // A single string anchor: carried by value (a string need not be copied).
  var ts = httpTransport.snapshotProxy({ url: "https://p", tls: { anchors: "PEM" } });
  check("snapshotProxy carries a string anchor by value", ts.tls.anchors === "PEM");
  // An array of anchors: each element copied, the array distinct.
  var arr = [Buffer.from("A1"), "PEM"];
  var ta = httpTransport.snapshotProxy({ url: "https://p", tls: { anchors: arr } });
  check("snapshotProxy copies an anchor array element-wise", ta.tls.anchors !== arr && ta.tls.anchors[0] !== arr[0] && ta.tls.anchors[0].toString("latin1") === "A1" && ta.tls.anchors[1] === "PEM");
}

async function run() {
  await setup();
  testSnapshotProxy();
  await testEst();
  await testAcme();
  await testCmp();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
