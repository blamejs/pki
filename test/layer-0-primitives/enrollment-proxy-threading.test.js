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
var nodeUtil = require("node:util");

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

  // 5 an exotic (Proxy) proxy option is refused, not laundered by the snapshot into a plain object that then
  // passes assertPlainRecord. Over the REAL transport the exotic record is refused with est/bad-proxy.
  check("est refuses a Proxy proxy option (not laundered by the snapshot)",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: new Proxy({ url: "https://p.example", tls: { useSystemStore: true } }, {}) }))) === "est/bad-proxy");
  var dateProxy = new Date(); dateProxy.url = "https://p.example"; dateProxy.tls = { useSystemStore: true };
  check("est refuses a Date-shaped proxy option (not laundered by the snapshot)",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: dateProxy }))) === "est/bad-proxy");
  check("est refuses a __proto__-laundering JSON proxy (unknown key survives the snapshot)",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: JSON.parse('{"__proto__":{"url":"https://evil.example","tls":{"useSystemStore":true}}}') }))) === "est/bad-proxy");
  var inheritedUnknown = Object.create({ unexpectedKey: 1 });
  inheritedUnknown.url = "https://p.example"; inheritedUnknown.tls = { useSystemStore: true };
  check("est refuses a proxy with an inherited unknown key (snapshot passes it through to validation)",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: inheritedUnknown }))) === "est/bad-proxy");
  // A proxy that is otherwise valid but not a simple data record (a non-enumerable url, an accessor field, a
  // custom prototype) is refused, so every ACCEPTED proxy is one the snapshot can isolate.
  var nonEnumUrl = { tls: { useSystemStore: true } };
  Object.defineProperty(nonEnumUrl, "url", { value: "https://p.example", enumerable: false });
  check("est refuses a valid-but-non-enumerable-url proxy (accepted set equals the isolable set)",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: nonEnumUrl }))) === "est/bad-proxy");
  var accessorUrl = { tls: { useSystemStore: true } };
  Object.defineProperty(accessorUrl, "url", { get: function () { return "https://p.example"; }, enumerable: true });
  check("est refuses an accessor-url proxy",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: accessorUrl }))) === "est/bad-proxy");
  // proxy.url must be a string: an object-valued url (even a URL instance) is refused with the typed
  // est/bad-proxy, not coerced -- and a url whose toString throws yields the same typed error, never the raw one.
  check("est refuses a URL-instance proxy.url with the typed error",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: new URL("https://p.example"), tls: { useSystemStore: true } } }))) === "est/bad-proxy");
  check("est refuses a throwing-toString proxy.url with the typed error, not a raw throw",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: { toString: function () { throw new Error("boom"); } }, tls: { useSystemStore: true } } }))) === "est/bad-proxy");
  var throwAnchors = [];
  Object.defineProperty(throwAnchors, "0", { get: function () { throw new Error("boom"); }, enumerable: true, configurable: true });
  check("est refuses a getter-backed anchors array with the typed error, not a raw throw",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: { anchors: throwAnchors } } }))) === "est/bad-proxy");
  var proxyArrAnchors = new Proxy([Buffer.from("A1")], { getPrototypeOf: function () { throw new Error("boom"); }, ownKeys: function () { throw new Error("boom"); } });
  check("est refuses a Proxy anchors array with the typed error, not a raw throw",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: { anchors: proxyArrAnchors } } }))) === "est/bad-proxy");
  var revokedAnchors = Proxy.revocable([Buffer.from("A1")], {}); revokedAnchors.revoke();
  check("est refuses a revoked Proxy anchors array with the typed error, not a native throw",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: { anchors: revokedAnchors.proxy } } }))) === "est/bad-proxy");
  check("est refuses a Proxy-wrapped Buffer anchor element with the typed error",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: { anchors: [new Proxy(Buffer.from("A1"), {})] } } }))) === "est/bad-proxy");
  // A falsy-but-present proxy.tls.minVersion is refused, not silently replaced by the default (a `|| default`
  // would have accepted false/0/"" as "unset").
  check("est refuses a falsy proxy.tls.minVersion instead of defaulting it",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: { useSystemStore: true, minVersion: false } } }))) === "est/bad-proxy");
  check("est refuses a non-string proxy.tls.minVersion without a raw throw",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: { useSystemStore: true, minVersion: 12 } } }))) === "est/bad-proxy");
  var revProxyRec = Proxy.revocable({ url: "https://p.example", tls: { useSystemStore: true } }, {}); revProxyRec.revoke();
  check("est refuses a revoked Proxy proxy record with the typed error, not a native throw",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: revProxyRec.proxy }))) === "est/bad-proxy");
  var revTlsRec = Proxy.revocable({ useSystemStore: true }, {}); revTlsRec.revoke();
  check("est refuses a revoked Proxy tls record with the typed error, not a native throw",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: revTlsRec.proxy } }))) === "est/bad-proxy");
  var inhRevEl = Proxy.revocable({}, {}); inhRevEl.revoke();
  check("est refuses an anchor inheriting from a revoked Proxy with the typed error, not a native throw",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: { anchors: [Object.create(inhRevEl.proxy)] } } }))) === "est/bad-proxy");
  // An input whose introspection throws a HOSTILE PROXY as the error: the boundary catch must not read
  // .isPkiError on it (re-triggering the trap); it checks isProxy first and yields the typed error.
  var hostileErr = new Proxy({}, { get: function () { throw new Error("boom"); } });
  var throwingProto = new Proxy({}, { getPrototypeOf: function () { throw hostileErr; } });
  check("est refuses an input that throws a hostile Proxy error, with the typed error",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: { anchors: [Object.create(throwingProto)] } } }))) === "est/bad-proxy");
  var errThrowGetter = {}; Object.defineProperty(errThrowGetter, "isPkiError", { get: function () { throw new Error("boom"); } });
  var protoThrowsErr = new Proxy({}, { getPrototypeOf: function () { throw errThrowGetter; } });
  check("est refuses an input that throws an error whose isPkiError getter throws, typed",
    (await codeOf(pki.est.cacerts(BASE, { tls: { anchors: [ANCHOR] }, proxy: { url: "https://p.example", tls: { anchors: [Object.create(protoThrowsErr)] } } }))) === "est/bad-proxy");
  // Threading proxy must not launder the OPTS bag past _knownOpts: an inherited unknown option is still
  // refused when a proxy is present (the snapshot is threaded separately, opts is not cloned).
  var optsBase = { totallyUnknownOption: 1 };
  var optsInh = Object.create(optsBase);
  optsInh.proxy = { url: "https://p.example", tls: { useSystemStore: true } };
  optsInh.transport = fakeTransport({ status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: "" });
  check("est refuses an inherited unknown option even with proxy present (opts not laundered)",
    (await codeOf(pki.est.cacerts(BASE, optsInh))) === "est/bad-input");

  // 6 a throwing proxy accessor yields a REJECTING promise, never a synchronous throw (the snapshot is taken
  // in the call frame but inside the rejection boundary).
  var threwSync = false, pth;
  try { pth = pki.est.cacerts(BASE, { get proxy() { throw new Error("boom"); }, transport: fakeTransport({ status: 200, headers: {}, body: "" }) }); }
  catch (_e) { threwSync = true; }
  var rejected = !!pth && typeof pth.then === "function" && (await pth.then(function () { return false; }, function () { return true; }));
  check("est snapshot throw becomes a rejection, not a synchronous throw", threwSync === false && rejected === true);
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
  // A caller-overridden .map on the anchors array cannot alias the original into the snapshot (a manual index
  // loop is used, not the instance method).
  var poisoned = [Buffer.from("A1")];
  poisoned.map = function () { return this; };
  var snPoison = httpTransport.snapshotProxy({ url: "https://p", tls: { anchors: poisoned } });
  check("snapshotProxy copies anchors without the caller's .map (poison cannot alias)",
    snPoison.tls.anchors !== poisoned && snPoison.tls.anchors[0] !== poisoned[0] && snPoison.tls.anchors[0].toString("latin1") === "A1");
  // A getter-backed anchor index is NOT read by the snapshot (only a simple array is copied), so a throwing
  // accessor cannot make snapshotProxy throw; the array is passed through for validation to refuse.
  var getterAnchors = [];
  Object.defineProperty(getterAnchors, "0", { get: function () { throw new Error("boom"); }, enumerable: true, configurable: true });
  var snGetter = httpTransport.snapshotProxy({ url: "https://p", tls: { anchors: getterAnchors } });
  check("snapshotProxy passes a getter-index anchors array through without reading it", snGetter.tls.anchors === getterAnchors);
  // A Proxy-wrapped anchors array is detected before any trap-invoking introspection, so snapshotProxy neither
  // launders it nor triggers a throwing trap; it is passed through for validation to refuse.
  var proxyArr = new Proxy([Buffer.from("A1")], { getPrototypeOf: function () { throw new Error("boom"); }, ownKeys: function () { throw new Error("boom"); } });
  var snProxyArr = httpTransport.snapshotProxy({ url: "https://p", tls: { anchors: proxyArr } });
  check("snapshotProxy passes a Proxy anchors array through without invoking its traps", snProxyArr.tls.anchors === proxyArr);
  // A REVOKED Proxy anchors array (Array.isArray throws natively on it) is still detected via isProxy first,
  // so snapshotProxy does not throw a native error.
  var revoked = Proxy.revocable([Buffer.from("A1")], {});
  revoked.revoke();
  var snRevoked = httpTransport.snapshotProxy({ url: "https://p", tls: { anchors: revoked.proxy } });
  check("snapshotProxy passes a revoked Proxy anchors through without throwing", snRevoked.tls.anchors === revoked.proxy);
  // A revoked Proxy as the proxy RECORD (or a nested tls record) is passed through without a native throw
  // (isPlainRecord checks isProxy before Array.isArray, which throws on a revoked proxy).
  var revokedRec = Proxy.revocable({ url: "https://p", tls: { useSystemStore: true } }, {}); revokedRec.revoke();
  check("snapshotProxy passes a revoked Proxy record through without throwing", httpTransport.snapshotProxy(revokedRec.proxy) === revokedRec.proxy);
  // A Proxy-wrapped Buffer ELEMENT inside a plain array is not Buffer.from-copied (which would throw or
  // launder it); it is carried unchanged for validation to refuse.
  var proxyBuf = new Proxy(Buffer.from("A1"), {});
  var snElem = httpTransport.snapshotProxy({ url: "https://p", tls: { anchors: [proxyBuf] } });
  check("snapshotProxy does not Buffer.from a Proxy-wrapped Buffer element", Array.isArray(snElem.tls.anchors) && snElem.tls.anchors[0] === proxyBuf);
  // An anchor element that INHERITS from a revoked Proxy makes Buffer.isBuffer traverse the chain and throw;
  // the snapshotProxy boundary catch returns the input unchanged rather than throwing a native error.
  var inhRev = Proxy.revocable({}, {}); inhRev.revoke();
  var didThrow = false;
  try { httpTransport.snapshotProxy({ url: "https://p", tls: { anchors: [Object.create(inhRev.proxy)] } }); } catch (_e) { didThrow = true; }
  check("snapshotProxy does not throw on an anchor inheriting from a revoked Proxy", didThrow === false);
  // Under Object.prototype pollution a record inherits an enumerable property; _copyableRecord treats it as
  // non-copyable, so snapshotProxy passes it through instead of stripping the pollution into a null-prototype
  // copy that would slip past validation (which walks the prototype chain).
  Object.prototype.pollutedOpt = "evil";
  var polluteHandled;
  try { var polP = { url: "https://p", tls: { useSystemStore: true } }; polluteHandled = httpTransport.snapshotProxy(polP) === polP; }
  finally { delete Object.prototype.pollutedOpt; }
  check("snapshotProxy passes a pollution-inheriting record through unchanged", polluteHandled === true);
  // Non-enumerable Object.prototype pollution is caught too (the own-property-count changes, not just Object.keys).
  Object.defineProperty(Object.prototype, "nePollute", { value: "x", enumerable: false, configurable: true });
  var nePolluteHandled;
  try { var neP = { url: "https://p", tls: { useSystemStore: true } }; nePolluteHandled = httpTransport.snapshotProxy(neP) === neP; }
  finally { delete Object.prototype.nePollute; }
  check("snapshotProxy passes a record through under non-enumerable proto pollution", nePolluteHandled === true);
  // An own property equal to the inherited method is de-shadowed in the original's readable-name surface but
  // not in a null-prototype copy; the record is non-copyable, so the copy cannot diverge from validation.
  var deShadow = { toString: Object.prototype.toString, url: "https://p", tls: { useSystemStore: true } };
  check("snapshotProxy passes a de-shadowing own-property record through", httpTransport.snapshotProxy(deShadow) === deShadow);
  // A Proxy is passed through, NOT Object.assign-laundered into a plain object -- else it would slip past the
  // transport's assertPlainRecord exotic-object refusal. The proxy option and each nested auth/tls member.
  var proxP = new Proxy({ url: "https://p", tls: { useSystemStore: true } }, {});
  check("snapshotProxy passes a Proxy proxy option through unchanged", httpTransport.snapshotProxy(proxP) === proxP && nodeUtil.types.isProxy(httpTransport.snapshotProxy(proxP)));
  var authP = new Proxy({ scheme: "basic", username: "u", password: "p" }, {});
  var snAuth = httpTransport.snapshotProxy({ url: "https://p", auth: authP });
  check("snapshotProxy does not launder a Proxy auth member", nodeUtil.types.isProxy(snAuth.auth));
  var tlsP = new Proxy({ useSystemStore: true }, {});
  var snTls = httpTransport.snapshotProxy({ url: "https://p", tls: tlsP });
  check("snapshotProxy does not launder a Proxy tls member", nodeUtil.types.isProxy(snTls.tls));
  // A built-in exotic (Date, Map, ...) with data properties is likewise passed through, never copied into a
  // plain record: assertPlainRecord refuses an exotic, and Object.assign would launder it into a valid one.
  var dp = new Date(); dp.url = "https://p"; dp.tls = { useSystemStore: true };
  check("snapshotProxy passes a Date-shaped proxy option through unchanged", httpTransport.snapshotProxy(dp) === dp && nodeUtil.types.isDate(httpTransport.snapshotProxy(dp)));
  var dAuth = { url: "https://p", auth: (function () { var d = new Date(); d.scheme = "basic"; d.username = "u"; d.password = "p"; return d; })() };
  check("snapshotProxy does not launder a Date auth member", nodeUtil.types.isDate(httpTransport.snapshotProxy(dAuth).auth));
  // A string url is carried unchanged; proxy.url must be a string (an object-valued url is refused by
  // validation, not coerced, so there is no mutable url object to isolate and no coercion that can throw).
  check("snapshotProxy leaves a string url unchanged", httpTransport.snapshotProxy({ url: "https://p", tls: { useSystemStore: true } }).url === "https://p");
  // A JSON object carrying an own enumerable __proto__ key is copied into a null-prototype target, so the key
  // stays an OWN property (unknown-key validation refuses it) instead of being laundered into the prototype
  // (which would make url/tls inherited and slip past the key check).
  var jsonProxy = JSON.parse('{"__proto__":{"url":"https://evil.example","tls":{"useSystemStore":true}}}');
  var snJson = httpTransport.snapshotProxy(jsonProxy);
  check("snapshotProxy preserves an own __proto__ key (not laundered to the prototype)",
    Object.prototype.hasOwnProperty.call(snJson, "__proto__") && snJson.url === undefined && Object.getPrototypeOf(snJson) === null);
  // A record whose keys/values the shallow copy cannot reproduce faithfully (a non-enumerable, inherited, or
  // accessor field) is passed through unchanged, so _validateProxy reads the original and its verdict is
  // identical to the snapshot's -- Object.assign would otherwise drop those and diverge from validation.
  var nonEnum = { tls: { useSystemStore: true } };
  Object.defineProperty(nonEnum, "url", { value: "https://p", enumerable: false });
  check("snapshotProxy passes a non-enumerable-field record through unchanged", httpTransport.snapshotProxy(nonEnum) === nonEnum);
  var inheritedRec = Object.create({ url: "https://p" }); inheritedRec.tls = { useSystemStore: true };
  check("snapshotProxy passes an inherited-field record through unchanged", httpTransport.snapshotProxy(inheritedRec) === inheritedRec);
  var accessorRec = { tls: { useSystemStore: true } };
  Object.defineProperty(accessorRec, "url", { get: function () { return "https://p"; }, enumerable: true });
  check("snapshotProxy passes an accessor-field record through unchanged", httpTransport.snapshotProxy(accessorRec) === accessorRec);
  // A copyable record with a nested non-copyable auth/tls copies the outer but passes the nested through.
  var nestedWeird = { url: "https://p", tls: Object.create({ useSystemStore: true }) };
  check("snapshotProxy passes a non-copyable nested tls through", httpTransport.snapshotProxy(nestedWeird).tls === nestedWeird.tls);
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
